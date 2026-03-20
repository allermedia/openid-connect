'use strict';

var express = require('express');
var node_crypto = require('node:crypto');
var Joi = require('joi');
var debug$8 = require('debug');
var node_assert = require('node:assert');
var jose = require('jose');
var openidClient = require('openid-client');
var onHeaders = require('on-headers');
var cookie = require('cookie');

function attemptSilentLogin() {
  /**
   * Silent login
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @param {import('express').NextFunction} next
   */
  return function silentLoginHandler(req, res, next) {
    if (!req.oidc) {
      return next(new Error('req.oidc is not found, did you include the auth middleware?'));
    }

    return res.oidc.silentLogin();
  };
}

/**
 * @param {string} name extend debug with name
 */
function Debug(name) {
  return debug$8('aller-openid-connect').extend(name);
}

const debug$7 = Debug('getLoginState');

/**
 * Generate the state value for use during login transactions. It is used to store the intended
 * return URL after the user authenticates. State is not used to carry unique PRNG values here
 * because the library utilizes either nonce or PKCE for CSRF protection.
 *
 * @param {import('express').Request} req
 * @param {any} options
 * @returns {Record<string, any>}
 */
function defaultState(req, options) {
  const state = { returnTo: options.returnTo || req.originalUrl };
  debug$7('adding default state %O', state);
  return state;
}

/**
 * Prepare a state object to send.
 * Filters out nonce, code_verifier, and max_age from the state object so that the values are
 * only stored in its dedicated transient cookie
 * @param {any} stateObject
 */
function encodeState(stateObject = {}) {
  const { nonce, code_verifier, max_age, ...filteredState } = stateObject;
  return Buffer.from(JSON.stringify(filteredState)).toString('base64url');
}

/**
 * Decode a state value.
 *
 * @param {string} stateValue
 */
function decodeState(stateValue) {
  try {
    // @ts-ignore
    return JSON.parse(Buffer.from(stateValue, 'base64'));
  } catch {
    return false;
  }
}

const debug$6 = Debug('config');

const isHttps = /^https:/i;

const defaultSessionIdGenerator = () => node_crypto.randomBytes(16).toString('hex');

const paramsSchema = Joi.object({
  secret: Joi.alternatives([
    Joi.string().min(8),
    Joi.binary().min(8),
    Joi.array().items(Joi.string().min(8), Joi.binary().min(8)),
  ]).required(),
  session: Joi.object({
    rolling: Joi.boolean().optional().default(true),
    rollingDuration: Joi.when(Joi.ref('rolling'), {
      is: true,
      then: Joi.number().integer().messages({
        'number.base': '"session.rollingDuration" must be provided an integer value when "session.rolling" is true',
      }),
      otherwise: Joi.boolean().valid(false).messages({
        'any.only': '"session.rollingDuration" must be false when "session.rolling" is disabled',
      }),
    })
      .optional()
      .default((parent) => (parent.rolling ? 24 * 60 * 60 : false)),
    absoluteDuration: Joi.when(Joi.ref('rolling'), {
      is: false,
      then: Joi.number().integer().messages({
        'number.base': '"session.absoluteDuration" must be provided an integer value when "session.rolling" is false',
      }),
      otherwise: Joi.alternatives([Joi.number().integer(), Joi.boolean().valid(false)]),
    })
      .optional()
      .default(7 * 24 * 60 * 60),
    name: Joi.string()
      .pattern(/^[0-9a-zA-Z_.-]+$/, { name: 'cookie name' })
      .optional()
      .default('appSession'),
    store: Joi.object()
      .optional()
      .when(Joi.ref('/backchannelLogout'), {
        not: false,
        then: Joi.when('/backchannelLogout.store', {
          not: Joi.exist(),
          then: Joi.when('/backchannelLogout.isLoggedOut', {
            not: Joi.exist(),
            then: Joi.object().required().messages({
              'any.required': `Back-Channel Logout requires a "backchannelLogout.store" (you can also reuse "session.store" if you have stateful sessions) or custom hooks for "isLoggedOut" and "onLogoutToken".`,
            }),
          }),
        }),
      }),
    genid: Joi.function()
      .maxArity(1)
      .optional()
      .default(() => defaultSessionIdGenerator),
    signSessionStoreCookie: Joi.boolean().optional().default(false),
    requireSignedSessionStoreCookie: Joi.boolean().optional().default(Joi.ref('signSessionStoreCookie')),
    cookie: Joi.object({
      domain: Joi.string().optional(),
      transient: Joi.boolean().optional().default(false),
      httpOnly: Joi.boolean().optional().default(true),
      sameSite: Joi.string().valid('lax', 'strict', 'none').lowercase().optional().default('Lax'),
      secure: Joi.when(Joi.ref('/baseURL'), {
        is: Joi.string().pattern(isHttps),
        then: Joi.boolean()
          .default(true)
          .custom((value, { warn }) => {
            if (!value) warn('insecure.cookie');
            return value;
          })
          .messages({
            'insecure.cookie': "Setting your cookie to insecure when over https is not recommended, I hope you know what you're doing.",
          }),
        otherwise: Joi.boolean().valid(false).default(false).messages({
          'any.only': 'Cookies set with the `Secure` property wont be attached to http requests',
        }),
      }),
      path: Joi.string().uri({ relativeOnly: true }).optional(),
    })
      .default()
      .unknown(false),
  })
    .default()
    .unknown(false),
  transactionCookie: Joi.object({
    sameSite: Joi.string().valid('Lax', 'Strict', 'None').optional().default(Joi.ref('...session.cookie.sameSite')),
    name: Joi.string().optional().default('auth_verification'),
  })
    .default()
    .unknown(false),
  tokenEndpointParams: Joi.object().optional(),
  authorizationParams: Joi.object({
    response_type: Joi.string().optional().valid('code id_token', 'code').default('code'),
    scope: Joi.string()
      .optional()
      .pattern(/\bopenid\b/, 'contains openid')
      .default('openid profile email'),
    response_mode: Joi.string()
      .optional()
      .when('response_type', {
        is: 'code',
        then: Joi.valid('query', 'form_post'),
        otherwise: Joi.valid('form_post').default('form_post'),
      }),
  })
    .optional()
    .unknown(true)
    .default(),
  logoutParams: Joi.object().optional(),
  backchannelLogout: Joi.alternatives([
    Joi.object({
      store: Joi.object().optional(),
      onLogin: Joi.alternatives([Joi.function(), Joi.boolean().valid(false)]).optional(),
      isLoggedOut: Joi.alternatives([Joi.function(), Joi.boolean().valid(false)]).optional(),
      onLogoutToken: Joi.function().optional(),
      isInsecure: Joi.boolean().optional(),
    }),
    Joi.boolean(),
  ]).default(false),
  baseURL: Joi.string()
    .uri()
    .required()
    .when(Joi.ref('authorizationParams.response_mode'), {
      is: 'form_post',
      then: Joi.string().pattern(isHttps).rule({
        warn: true,
        message: `Using 'form_post' for response_mode may cause issues for you logging in over http`,
      }),
    }),
  clientID: Joi.string().required(),
  clientSecret: Joi.string()
    .when(
      Joi.ref('clientAuthMethod', {
        adjust: (value) => value && value.includes('client_secret'),
      }),
      {
        is: true,
        then: Joi.string().required().messages({
          'any.required': `"clientSecret" is required for the "clientAuthMethod" "{{clientAuthMethod}}"`,
        }),
      }
    )
    .when(
      Joi.ref('idTokenSigningAlg', {
        adjust: (value) => value && value.startsWith('HS'),
      }),
      {
        is: true,
        then: Joi.string().required().messages({
          'any.required': '"clientSecret" is required for ID tokens with HMAC based algorithms',
        }),
      }
    ),
  clockTolerance: Joi.number().optional().default(60),
  errorOnRequiredAuth: Joi.boolean().optional().default(false),
  attemptSilentLogin: Joi.boolean().optional().default(false),
  getLoginState: Joi.function()
    .optional()
    .default(() => defaultState),
  afterCallback: Joi.function().optional(),
  identityClaimFilter: Joi.array()
    .optional()
    .default(['aud', 'iss', 'iat', 'exp', 'nbf', 'nonce', 'azp', 'auth_time', 's_hash', 'at_hash', 'c_hash']),
  idpLogout: Joi.boolean().optional().default(false),
  idTokenSigningAlg: Joi.string().insensitive().not('none').optional().default('RS256'),
  issuerBaseURL: Joi.string().uri().required(),
  legacySameSiteCookie: Joi.boolean().optional().default(true),
  authRequired: Joi.boolean().optional().default(true),
  pushedAuthorizationRequests: Joi.boolean().optional().default(false),
  routes: Joi.object({
    login: Joi.alternatives([Joi.string().uri({ relativeOnly: true }), Joi.boolean().valid(false)]).default('/login'),
    logout: Joi.alternatives([Joi.string().uri({ relativeOnly: true }), Joi.boolean().valid(false)]).default('/logout'),
    callback: Joi.alternatives([Joi.string().uri({ relativeOnly: true }), Joi.boolean().valid(false)]).default('/callback'),
    postLogoutRedirect: Joi.string().uri({ allowRelative: true }).default(''),
    backchannelLogout: Joi.string().uri({ allowRelative: true }).default('/backchannel-logout'),
  })
    .default()
    .unknown(false),
  clientAuthMethod: Joi.string()
    .valid('client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt', 'none')
    .optional()
    .default((parent) => {
      if (parent.clientAssertionSigningKey) {
        return 'private_key_jwt';
      }
      if (parent.clientSecret) {
        return 'client_secret_basic';
      }
      return 'none';
    })
    .when(Joi.ref('pushedAuthorizationRequests'), {
      is: true,
      then: Joi.string().invalid('none').messages({
        'any.only': 'Public PAR clients are not supported.',
      }),
    }),
  clientAssertionSigningKey: Joi.any()
    .optional()
    .when(Joi.ref('clientAuthMethod'), {
      is: 'private_key_jwt',
      then: Joi.any().required().messages({
        'any.required': '"clientAssertionSigningKey" is required for a "clientAuthMethod" of "private_key_jwt"',
      }),
    }),
  clientAssertionSigningAlg: Joi.string().optional(),
  discoveryCacheMaxAge: Joi.number()
    .optional()
    .min(0)
    .default(10 * 60 * 1000),
  httpTimeout: Joi.number().optional().min(500).default(5000),
  httpUserAgent: Joi.string().optional(),
  allowInsecureRequests: Joi.boolean().optional().default(false),
  customFetch: Joi.function().optional().description('custom fetch method'),
});

/**
 * Get normalized configuration
 * @param {Partial<import('types').ConfigParams>} config
 * @returns {import('types').ConfigParams}
 */
function getConfig(config) {
  const { value, error, warning } = paramsSchema.validate(config);
  if (error) {
    throw new TypeError(error.details[0].message);
  }

  if (warning) {
    debug$6(warning.message);
  }

  return value;
}

const COOKIES = Symbol('cookies');
const MAX_COOKIE_SIZE = 4096;
const REGENERATED_SESSION_ID = Symbol('regenerated_session_id');
const SESSION = Symbol('session');
const SESSION_ID = Symbol('session_id');
/**
 * Session store api pointer
 */
const SESSION_STORE = Symbol('session store');
const SET_SESSION_COOKIE = Symbol('set cookies');
const SKIP_SILENT_LOGIN_COOKIE_NAME = 'skipSilentLogin';

class OpenIDConnectError extends Error {
  /**
   * @param {string} error
   * @param {string} [errorDescription]
   * @param {string} [errorUri]
   */
  constructor(error, errorDescription, errorUri) {
    super(errorDescription || error);
    this.error = error;
    this.error_description = errorDescription;
    this.error_uri = errorUri;
    this.statusCode = 400;
  }
}

class OpenIDConnectBadRequest extends Error {
  /**
   * @param {string} message
   */
  constructor(message) {
    super(message);
    this.statusCode = 400;
  }
}

class UnauthorizedError extends Error {
  /**
   * @param {string} msg
   */
  constructor(msg) {
    super(msg);
    this.statusCode = 401;
  }
}

const debug$5 = Debug('client');

class OpenIDConnectClient {
  /**
   * @param {import('types').ConfigParams} config
   * @param {*} serverMetadata
   * @param {Configuration} configuration
   */
  constructor(config, serverMetadata, configuration) {
    this.client_id = config.clientID;
    this.serverMetadata = serverMetadata;
    this.config = config;
    this.configuration = configuration;
    if (config.customFetch) {
      configuration[openidClient.customFetch] = config.customFetch;
    }
  }

  /**
   * Auth callback
   * @param {string} redirectUri
   * @param {Record<string, any>} params
   * @param {import('types').AuthorizationParameters & {max_age?: number, code_verifier?: string}} checks
   * @param {*} extras
   */
  callback(redirectUri, params, checks, extras) {
    const callbackParams = new URLSearchParams(params);

    const error = callbackParams.get('error');
    if (error) {
      throw new OpenIDConnectError(error, callbackParams.get('error_description'), callbackParams.get('error_uri'));
    }

    if (!callbackParams.has('code')) {
      throw new OpenIDConnectBadRequest(
        'No authorization code found in callback parameters. Implicit flow is not supported - use authorization code flow with PKCE instead'
      );
    }

    // Determine if this is a form_post response (POST method with body params)
    // For form_post, we need to pass a Request object so openid-client can properly
    // handle hybrid flow (putting params in hash) vs code flow (putting params in query)
    const isFormPost = extras?.isFormPost === true;
    const redirectUrl = new URL(redirectUri);

    let currentUrlOrRequest;
    if (isFormPost) {
      // Create a web Request object for form_post handling
      // This allows openid-client to properly route hybrid vs code flow params
      currentUrlOrRequest = new Request(redirectUrl.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: callbackParams.toString(),
      });
    } else {
      for (const [key, value] of callbackParams.entries()) {
        redirectUrl.searchParams.set(key, value);
      }
      currentUrlOrRequest = redirectUrl;
    }

    return openidClient.authorizationCodeGrant(
      this.configuration,
      currentUrlOrRequest,
      {
        expectedState: checks?.state,
        expectedNonce: checks?.nonce,
        maxAge: checks?.max_age,
        pkceCodeVerifier: checks?.code_verifier,
      },
      extras?.exchangeBody,
      extras
    );
  }

  /**
   * Refresh
   * @param {string} refreshToken
   * @param {URLSearchParams | Record<string, string>} [extras]
   */
  refresh(refreshToken, extras) {
    return openidClient.refreshTokenGrant(this.configuration, refreshToken, extras);
  }

  /**
   * Fetch user info
   * @param {string} accessToken
   * @param {*} options
   */
  async userinfo(accessToken, options = {}) {
    const expectedSubject = options?.expectedSubject;
    return await openidClient.fetchUserInfo(this.configuration, accessToken, expectedSubject, options);
  }

  /**
   * @param {URLSearchParams | Record<string, string>} params
   */
  authorizationUrl(params) {
    return openidClient.buildAuthorizationUrl(this.configuration, params);
  }

  /**
   * Create end session URL
   * @param {Record<string, any>} params
   */
  endSessionUrl(params) {
    if (this.serverMetadata.end_session_endpoint) {
      const parsedUrl = new URL(this.serverMetadata.end_session_endpoint);

      for (const [key, value] of Object.entries(params)) {
        if (value === null || value === undefined) continue;
        parsedUrl.searchParams.set(key, value);
      }

      return parsedUrl.toString();
    } else {
      throw new Error('End session endpoint not supported by the issuer');
    }
  }
}

/**
 * @param {string} str
 */
function sortSpaceDelimitedString(str) {
  return str.split(' ').sort().join(' ');
}

/**
 * Create OpenID client
 * @param {import('types').ConfigParams} config
 */
async function createClient(config) {
  debug$5('Creating client for issuer %s', config.issuerBaseURL);

  /** @type {import('openid-client').DiscoveryRequestOptions} */
  const discoveryOptions = {
    ...(config.httpTimeout && { timeout: config.httpTimeout }),
    ...(config.allowInsecureRequests && { execute: [openidClient.allowInsecureRequests] }),
    ...(config.customFetch && { [openidClient.customFetch]: config.customFetch }),
  };

  const discoveredConfiguration = await openidClient.discovery(
    new URL(config.issuerBaseURL),
    config.clientID,
    {
      [openidClient.clockTolerance]: config.clockTolerance,
    },
    undefined,
    discoveryOptions
  );

  const serverMetadata = discoveredConfiguration.serverMetadata();

  debug$5('Discovery successful for %s', config.issuerBaseURL);

  validateConfiguration(config, serverMetadata);

  let clientAuthMethod = config.clientAuthMethod;
  if (!clientAuthMethod) {
    if (config.clientAssertionSigningKey) clientAuthMethod = 'private_key_jwt';
    else if (config.clientSecret) clientAuthMethod = 'client_secret_basic';
    else clientAuthMethod = 'none';
  }

  let clientAuthentication;

  switch (clientAuthMethod) {
    case 'private_key_jwt': {
      const privateKey = config.clientAssertionSigningKey;

      if (privateKey && (typeof privateKey === 'string' || Buffer.isBuffer(privateKey))) {
        const cryptoKey = await jose.importPKCS8(privateKey.toString('utf-8'), config.clientAssertionSigningAlg || 'RS256', {
          extractable: true,
        });
        clientAuthentication = openidClient.PrivateKeyJwt(cryptoKey);
      } else if (privateKey && typeof privateKey === 'object') {
        // @ts-ignore
        clientAuthentication = openidClient.PrivateKeyJwt({ key: privateKey });
      }
      break;
    }
    case 'client_secret_jwt': {
      const authAlgOptions = config.clientAssertionSigningAlg ? { algorithm: config.clientAssertionSigningAlg } : undefined;
      // @ts-ignore
      clientAuthentication = openidClient.ClientSecretJwt(config.clientSecret, authAlgOptions);
      break;
    }
    case 'client_secret_basic':
      clientAuthentication = openidClient.ClientSecretBasic(config.clientSecret);
      break;
    case 'none':
      clientAuthentication = openidClient.None();
      break;
    case 'client_secret_post':
    default:
      clientAuthentication = openidClient.ClientSecretPost(config.clientSecret);
  }

  const configuration = new openidClient.Configuration(
    serverMetadata,
    config.clientID,
    {
      client_id: config.clientID,
      id_token_signed_response_alg: config.idTokenSigningAlg,
      token_endpoint_auth_method: clientAuthMethod,
      ...(config.clientSecret && { client_secret: config.clientSecret }),
      ...(config.clientAssertionSigningAlg && {
        token_endpoint_auth_signing_alg: config.clientAssertionSigningAlg,
      }),
    },
    clientAuthentication
  );

  // Enable insecure (HTTP) requests if configured - must be called after Configuration is created
  if (config.allowInsecureRequests) {
    openidClient.allowInsecureRequests(configuration);
  }

  // Enable hybrid flow (code id_token) if configured
  const responseType = config.authorizationParams?.response_type || 'code';
  if (responseType.includes('code') && responseType.includes('id_token')) {
    openidClient.useCodeIdTokenResponseType(configuration);
  }

  const client = new OpenIDConnectClient(config, serverMetadata, configuration);

  return { client, issuer: serverMetadata };
}

/**
 * @param {import('types').ConfigParams} config
 * @param {*} serverMetadata
 */
function validateConfiguration(config, serverMetadata) {
  const issuerTokenAlgs = Array.isArray(serverMetadata.id_token_signing_alg_values_supported)
    ? serverMetadata.id_token_signing_alg_values_supported
    : [];
  if (!issuerTokenAlgs.includes(config.idTokenSigningAlg)) {
    debug$5(
      'ID token algorithm %o is not supported by the issuer. Supported ID token algorithms are: %o.',
      config.idTokenSigningAlg,
      issuerTokenAlgs
    );
  }

  const configRespType = sortSpaceDelimitedString(config.authorizationParams.response_type);
  const issuerRespTypes = Array.isArray(serverMetadata.response_types_supported)
    ? serverMetadata.response_types_supported.map(sortSpaceDelimitedString)
    : [];
  if (!issuerRespTypes.includes(configRespType)) {
    debug$5('Response type %o is not supported by the issuer. Supported response types are: %o.', configRespType, issuerRespTypes);
  }

  const configRespMode = config.authorizationParams.response_mode;
  const issuerRespModes = Array.isArray(serverMetadata.response_modes_supported) ? serverMetadata.response_modes_supported : [];
  if (configRespMode && !issuerRespModes.includes(configRespMode)) {
    debug$5('Response mode %o is not supported by the issuer. Supported response modes are %o.', configRespMode, issuerRespModes);
  }

  if (config.pushedAuthorizationRequests && !serverMetadata.pushed_authorization_request_endpoint) {
    throw new TypeError('pushed_authorization_request_endpoint must be configured on the issuer to use pushedAuthorizationRequests');
  }
}

const cache = new Map();
let timestamp = 0;

/**
 * Get client
 * @param {import('types').ConfigParams} config config
 * @returns {ReturnType<createClient>}
 */
function getClient(config) {
  const now = Date.now();
  if (cache.has(config) && now < timestamp + config.discoveryCacheMaxAge) {
    return cache.get(config);
  }
  timestamp = now;
  const promise = createClient(config).catch((e) => {
    cache.delete(config);
    throw e;
  });
  cache.set(config, promise);
  return promise;
}

const kClaims = Symbol.for('cached claims');

class Session {
  /**
   * @param {Record<string, any>} data
   * @param {import('types').SessionHeaders} headers
   */
  constructor(data, headers) {
    /** @type {import('openid-client').IDToken} */
    this[kClaims] = undefined;

    const { access_token, token_type, refresh_token, id_token, expires_at, expires_in, sub, sid, ...decorated } = data;

    /**
     * The access token issued by the authorization server.
     * @type {string}
     */
    this.access_token = access_token;

    /**
     * The lifetime in seconds of the access token.
     * For example, the value "3600" denotes that the access token will expire in one hour from the time the response was generated.
     * @type {number}
     */
    this.expires_in = expires_in;

    /**
     * The type of the token issued
     * @type {string}
     */
    this.token_type = token_type;

    /**
     * The refresh token, which can be used to obtain new access tokens. To retrieve it add the scope "offline" to your access token request.
     * @type {string}
     */
    this.refresh_token = refresh_token;

    /**
     * ID token
     * @type {string}
     */
    this.id_token = id_token;

    /**
     * Decorations from hook functions
     * @type {Record<string, any>?}
     */
    this.decorated = decorated;

    /** @type {import('types').SessionHeaders} */
    this.headers = { ...headers };

    /** @type {Partial<import('openid-client').IDToken>} */
    this.claims = {};

    /**
     * Expires at epoch seconds
     * @type {number}
     */
    this.expires_at = expires_at;

    if (!expires_at && expires_in && typeof expires_in === 'number') {
      this.expires_at = this.headers.iat + this.expires_in;
    }

    /**
     * ID token subject
     * @type {string}
     */
    this.sub = sub;
    /**
     * ID token session ID
     * @type {string}
     */
    this.sid = sid;
  }

  /**
   * Update session
   * @param {Session} session
   */
  update(session) {
    if (session.id_token) {
      this.id_token = session.id_token;
      this[kClaims] = session[kClaims];
    }

    this.access_token = session.access_token;
    this.token_type = session.token_type;
    this.refresh_token = session.refresh_token || this.refresh_token;
    this.expires_in = session.expires_in ?? this.expires_in;
    this.expires_at = session.expires_at ?? this.expires_at;
    this.sid = session.sid ?? this.sid;
    this.sub = session.sub ?? this.sub;
    return this;
  }

  /**
   * Decorate session
   * @param {Record<string, any>} decorationData
   */
  decorate(decorationData) {
    if (decorationData && typeof decorationData !== 'object') throw new TypeError('Decoration data must be an object');
    Object.assign(this.decorated, decorationData);
  }

  /**
   * Get ID token claims
   * @returns {{ -readonly [P in keyof import('openid-client').IDToken ]: import('openid-client').IDToken [P] }| undefined}
   */
  getClaims() {
    if (!this[kClaims] && this.id_token) {
      this[kClaims] = jose.decodeJwt(this.id_token);
    }
    return { sid: this.sid, ...this[kClaims] };
  }

  /**
   * Get session headers
   * @returns {Partial<import('types').SessionHeaders>}
   */
  getSessionHeaders() {
    const updatedAt = this.headers.uat ?? epoch$1();
    const issuedAt = this.headers?.iat ?? updatedAt;
    return { iat: issuedAt, uat: updatedAt };
  }

  /**
   * Get session data
   * @returns {import('types').Session}
   */
  getSessionData() {
    return {
      ...this.decorated,
      access_token: this.access_token,
      token_type: this.token_type,
      id_token: this.id_token,
      refresh_token: this.refresh_token,
      expires_in: this.expires_in,
      expires_at: this.expires_at,
      sub: this.sub,
      sid: this.sid,
    };
  }

  /**
   * Check if session has expired
   * @param {number} rollingDuration expired according to rolling duration
   * @param {number} absoluteDuration expired according to absolute duration
   */
  assertExpired(rollingDuration, absoluteDuration) {
    const { iat, exp, uat } = this.headers;

    const nowEpoch = epoch$1();
    node_assert.strict(exp > nowEpoch, 'it is expired based on options when it was established');

    if (rollingDuration) {
      node_assert.strict(uat + rollingDuration > nowEpoch, 'it is expired based on current rollingDuration rules');
    }
    if (absoluteDuration) {
      node_assert.strict(iat + absoluteDuration > nowEpoch, 'it is expired based on current absoluteDuration rules');
    }
  }
}

class StoredSession extends Session {
  /**
   * @param {any} data
   * @param {import('types').SessionHeaders} headers
   */
  constructor(data, headers) {
    super(data, headers);

    if (typeof data.id_token === 'string') {
      // @ts-ignore
      // eslint-disable-next-line no-var
      var claims = (this[kClaims] = jose.decodeJwt(data.id_token));
    } else {
      this.id_token = undefined;
    }

    this.sid = claims?.sid ?? data.sid;
    this.sub = claims?.sub ?? data.sub;
  }
}

class TokenSetSession extends Session {
  /**
   * @param {Awaited<ReturnType<import('./client.js').OpenIDConnectClient['callback']>>} tokenSet
   */
  constructor(tokenSet) {
    const claims = tokenSet.claims();
    super(tokenSet, {
      iat: claims?.iat,
      uat: claims?.iat,
      exp: claims?.exp,
    });

    this[kClaims] = claims;

    this.sid = claims?.sid?.toString();
    this.sub = claims?.sub?.toString();
  }
}

function epoch$1() {
  return (Date.now() / 1000) | 0;
}

class AccessToken {
  #config;
  #req;
  #res;
  /**
   * @param {import('types').ConfigParams} config
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   */
  constructor(config, req, res) {
    this.#config = config;
    this.#req = req;
    this.#res = res;
  }

  /**
   * Token type
   * @type {import('./session.js').Session}
   */
  get #session() {
    return this.#req[SESSION];
  }

  /** @type {ReturnType<import('./cookie-store.js').DefaultCookieStore['api']>} */
  get #cookieApi() {
    return this.#req[SESSION_STORE];
  }

  /**
   * Access token
   */
  get access_token() {
    return this.#session?.access_token;
  }

  /**
   * Token type
   */
  get token_type() {
    return this.#session?.token_type;
  }

  /**
   * Access token expires in seconds
   */
  get expires_in() {
    const expiresAt = this.#session?.expires_at;
    return expiresAt ? Math.max(0, Number(expiresAt) - Math.floor(Date.now() / 1000)) : undefined;
  }

  isExpired() {
    const session = this.#session;
    if (!session?.expires_at) return false;
    return Date.now() >= Number(this.#session.expires_at) * 1000;
  }

  /**
   * Refresh access token
   * @param {Partial<import('types').CallbackOptions>} param0
   * @returns {Promise<AccessToken>}
   */
  async refresh({ tokenEndpointParams } = {}) {
    const config = this.#config;
    const { client } = await getClient(config);
    const session = this.#session;

    if (!session?.refresh_token) {
      throw new OpenIDConnectBadRequest('No refresh token available');
    }

    /** @type {Record<string, any>} */
    let parameters = {};
    if (config.tokenEndpointParams || tokenEndpointParams) {
      parameters = { ...config.tokenEndpointParams, ...tokenEndpointParams };
    }

    const newTokenSet = await client.refresh(session.refresh_token, parameters);

    session.update(new TokenSetSession(newTokenSet));

    if (config.afterCallback) {
      const req = this.#req;
      const updatedSession = await config.afterCallback(req, this.#res, session.getSessionData(), {
        returnTo: req.query.return_to,
      });
      session.decorate(updatedSession);
    }

    await this.#cookieApi.setSessionCookie();

    // @ts-ignore
    return new this.constructor(config, this.#req);
  }

  toJSON() {
    const session = this.#session;
    if (!session) return;

    return {
      access_token: session.access_token,
      token_type: session.token_type,
      expires_in: this.expires_in,
    };
  }
}

/**
 * Remove any Back-Channel Logout tokens for this `sub` and `sid`
 * @param {import('express').Request} req
 * @param {import('types').ConfigParams} config
 */
async function onLogIn(req, config) {
  const {
    issuer: { issuer },
  } = await getClient(config);
  const { session, backchannelLogout } = config;
  const store = backchannelLogout && typeof backchannelLogout === 'object' ? backchannelLogout.store : session.store;

  // Get the sub and sid from the ID token claims
  const { sub, sid } = req.oidc.idTokenClaims;

  // Normalize issuer URL to handle trailing slashes consistently
  const normalizedIssuer = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;

  // Remove both sub and sid based entries for both normalized and non-normalized issuer URLs
  const keys = [
    `${normalizedIssuer}|${sub}`,
    `${normalizedIssuer}/|${sub}`,
    sid && `${normalizedIssuer}|${sid}`,
    sid && `${normalizedIssuer}/|${sid}`,
  ].filter(Boolean);

  await Promise.all(keys.map((key) => store.destroy(key)));
}

/**
 * Default hook stores an entry in the logout store for `sid` (if available) and `sub` (if available).
 * @param {any} token
 * @param {import('types').ConfigParams} config
 */
async function onLogoutToken(token, config) {
  const {
    session: { absoluteDuration, rolling: rollingEnabled, rollingDuration, store },
    backchannelLogout,
  } = config;
  const backchannelLogoutStore = backchannelLogout?.store || store;
  const maxAge = (rollingEnabled ? Math.min(Number(absoluteDuration), Number(rollingDuration)) : Number(absoluteDuration)) * 1000;
  const payload = {
    // The "cookie" prop makes the payload compatible with
    // `express-session` stores.
    cookie: {
      expires: Date.now() + maxAge,
      maxAge,
    },
  };
  const { iss, sid, sub } = token;

  if (!sid && !sub) {
    throw new Error(`The Logout Token must have a 'sid' or a 'sub'`);
  }
  await Promise.all([
    sid && backchannelLogoutStore.set(`${iss}|${sid}`, payload),
    sub && backchannelLogoutStore.set(`${iss}|${sub}`, payload),
  ]);
}

const debug$4 = Debug('context');
const validResponseTypes = ['id_token', 'code id_token', 'code'];

class RequestContext {
  #config;
  #req;
  #res;
  /**
   * @param {import('types').ConfigParams} config
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   */
  constructor(config, req, res) {
    this.#config = config;
    this.#req = req;
    this.#res = res;
  }

  /** @type {import('./session.js').Session} */
  get session() {
    return this.#req[SESSION];
  }

  get idToken() {
    // @ts-ignore
    return this.session?.id_token;
  }

  get refreshToken() {
    // @ts-ignore
    return this.session?.refresh_token;
  }

  get accessToken() {
    if (!this.session?.access_token) {
      return;
    }

    return new AccessToken(this.#config, this.#req, this.#res);
  }

  get idTokenClaims() {
    try {
      return this.session.getClaims();
    } catch {
      return undefined;
    }
  }

  get user() {
    const claims = this.idTokenClaims;
    if (!claims || !this.#config.identityClaimFilter?.length) return claims;

    this.#config.identityClaimFilter?.forEach((claim) => {
      delete claims[claim];
    });

    return claims;
  }

  isAuthenticated() {
    return !!this.idTokenClaims;
  }

  async fetchUserInfo() {
    const { client } = await getClient(this.#config);

    const accessToken = this.accessToken;
    if (!accessToken) {
      throw new OpenIDConnectBadRequest('No access token available');
    }

    const expectedSubject = this.idTokenClaims?.sub;

    return await client.userinfo(accessToken.access_token, { expectedSubject });
  }
}

class ResponseContext {
  /** @type {import('types').ConfigParams} config */
  #config;
  /** @type {import('express').Request} req */
  #req;
  /** @type {import('express').Response} res */
  #res;
  /** @type {import('express').NextFunction} next */
  #next;
  /** @type {import('./transientHandler.js').TransientCookieHandler} */
  #transient;
  /**
   * @param {import('types').ConfigParams} config
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @param {import('express').NextFunction} next
   * @param {import('./transientHandler.js').TransientCookieHandler} transient transient cookie handler
   */
  constructor(config, req, res, next, transient) {
    this.#config = config;
    this.#req = req;
    this.#res = res;
    this.#next = next;
    this.#transient = transient;
  }

  /** @type {import('./session.js').Session} */
  get session() {
    return this.#req[SESSION];
  }

  set session(value) {
    this.#req[SESSION] = value;
  }

  get hasBackchannelLogout() {
    return !!this.#config.backchannelLogout;
  }

  /** @type {ReturnType<import('./cookie-store.js').DefaultCookieStore['api']>} */
  get cookieApi() {
    return this.#req[SESSION_STORE];
  }

  /**
   * Backchannel logout configuration
   * @type {import('types').BackchannelLogoutOptions}
   */
  get backchannelLogoutOptions() {
    if (typeof this.#config.backchannelLogout === 'boolean') {
      return this.#config.backchannelLogout ? {} : undefined;
    }

    return this.#config.backchannelLogout;
  }

  get errorOnRequiredAuth() {
    return this.#config.errorOnRequiredAuth;
  }

  /**
   * @param {import('types').LoginOptions} [options]
   */
  silentLogin(options) {
    const req = this.#req;
    const silentLoginAttempted = !!(req[COOKIES] || {})[SKIP_SILENT_LOGIN_COOKIE_NAME];

    if (silentLoginAttempted || req.oidc.isAuthenticated() || !req.accepts('html')) {
      return this.#next();
    }

    debug$4('Attempting silent login');
    const { secure, domain, path, sameSite } = this.#config.session.cookie;

    this.#res.cookie(SKIP_SILENT_LOGIN_COOKIE_NAME, true, {
      httpOnly: true,
      secure,
      domain,
      path,
      sameSite,
    });

    return this.login({
      ...options,
      silent: true,
      authorizationParams: { ...options?.authorizationParams, prompt: 'none' },
    });
  }

  /**
   * Provided by default via the `/login` route. Call this to override or have other
   * login routes with custom {@link ConfigParams.authorizationParams authorizationParams} or returnTo
   *
   * ```js
   * app.get('/admin-login', (req, res) => {
   *   res.oidc.login({
   *     returnTo: '/admin',
   *     authorizationParams: {
   *       scope: 'openid profile email admin:user',
   *     }
   *   });
   * });
   * ```
   * @param {import('types').LoginOptions} [options]
   */
  async login(options) {
    const config = this.#config;
    const req = this.#req;
    const res = this.#res;
    const transient = this.#transient;
    try {
      const { client } = await getClient(config);

      // Set default returnTo value, allow passed-in options to override or use originalUrl on GET
      let returnTo = config.baseURL;
      if (options?.returnTo) {
        returnTo = options.returnTo;
        debug$4('req.oidc.login() called with returnTo: %s', returnTo);
      } else if (req.method === 'GET' && req.originalUrl) {
        // Collapse any leading slashes to a single slash to prevent Open Redirects
        returnTo = req.originalUrl.replace(/^\/+/, '/');
        debug$4('req.oidc.login() without returnTo, using: %s', returnTo);
      }

      /** @type {Record<string, any> & {authorizationParams: import('types').AuthorizationParameters}} */
      const authOptions = {
        ...options,
        authorizationParams: {
          redirect_uri: this.getRedirectUri(),
          ...config.authorizationParams,
          ...options?.authorizationParams,
        },
        returnTo,
      };

      const stateValue = await config.getLoginState(req, authOptions);
      if (typeof stateValue !== 'object') {
        return this.#next(new Error('Custom state value must be an object.'));
      }

      if (authOptions.silent) {
        stateValue.attemptingSilentLogin = true;
      }

      const { response_type, scope, max_age, response_mode } = authOptions.authorizationParams;

      node_assert.strict(validResponseTypes.includes(response_type), `response_type should be one of ${validResponseTypes.join(', ')}`);
      node_assert.strict(/\bopenid\b/.test(scope), 'scope should contain "openid"');

      /**
       * Transaction cookie payload
       * @type {Record<string, any>}
       */
      const authVerification = {
        nonce: openidClient.randomNonce(),
        state: encodeState(stateValue),
        ...(max_age && { max_age }),
      };

      const usePKCE = response_type.includes('code');
      if (usePKCE) {
        debug$4('response_type includes code, the authorization request will use PKCE');
        authVerification.code_verifier = openidClient.randomPKCECodeVerifier();
      }

      /** @type {Record<string, any>} */
      const authParams = {
        ...authOptions.authorizationParams,
        ...authVerification,
        ...(usePKCE && {
          code_challenge_method: 'S256',
          code_challenge: await openidClient.calculatePKCECodeChallenge(authVerification.code_verifier),
        }),
      };

      await transient.setTransactionCookie(res, JSON.stringify(authVerification), {
        sameSite: response_mode === 'form_post' ? 'none' : config.transactionCookie.sameSite,
      });

      const authorizationUrl = client.authorizationUrl(authParams);
      debug$4('redirecting to %s', authorizationUrl);
      res.redirect(authorizationUrl.toString());
    } catch (err) {
      this.#next(err);
    }
  }

  /**
   * Provided by default via the `/logout` route. Call this to override or have other
   * logout routes with custom returnTo
   *
   * ```js
   * app.get('/admin-logout', (req, res) => {
   *   res.oidc.logout({ returnTo: '/admin-welcome' })
   * });
   * ```
   * @param {import('types').LogoutOptions} [params]
   */
  async logout(params) {
    const config = this.#config;
    const req = this.#req;
    const res = this.#res;

    let returnUrl = params?.returnTo || config.routes.postLogoutRedirect;
    debug$4('req.oidc.logout() with return url: %s', returnUrl);

    if (new URL(returnUrl, 'http://__nohost').origin === 'http://__nohost') {
      returnUrl = new URL(returnUrl, config.baseURL).toString();
    }

    this.#res.oidc.cancelSilentLogin();

    if (!req.oidc.isAuthenticated()) {
      debug$4('end-user already logged out, redirecting to %s', returnUrl);

      // perform idp logout with no token hint
      return res.redirect(await this.getLogoutUrl(returnUrl, undefined, params?.logoutParams));
    }

    const idToken = req.oidc.idToken;

    this.session = undefined;

    returnUrl = await this.getLogoutUrl(returnUrl, idToken, params?.logoutParams);

    debug$4('logging out of identity provider, redirecting to %s', returnUrl);
    res.redirect(returnUrl);
  }

  /**
   * Provided by default via the `/callback` route. Call this to override or have other
   * callback routes with
   *
   * ```js
   * app.get('/callback', (req, res) => {
   *  res.oidc.callback({ redirectUri: 'https://example.com/callback' });
   * });
   * ```
   * @param {import('types').CallbackOptions & {params: Record<string, any>}} [options]
   */
  async callback(options) {
    const config = this.#config;
    const req = this.#req;
    const res = this.#res;

    let state;
    try {
      const { client, issuer } = await getClient(config);
      const redirectUri = options?.redirectUri || this.getRedirectUri();

      const callbackParams = req.method === 'POST' ? req.body : req.query;

      // Get auth verification for checks
      const authVerification = await this.#transient.getOnce(config.transactionCookie.name, req, res);

      const checks = authVerification ? JSON.parse(authVerification) : {};
      state = decodeState(checks.state);

      const tokenSet = await client.callback(redirectUri, callbackParams, checks, {
        exchangeBody: {
          ...config?.tokenEndpointParams,
          ...options?.tokenEndpointParams,
        },
        clientAssertionPayload: {
          aud: issuer.issuer,
        },
        isFormPost: req.method === 'POST',
      });

      const currentSession = this.session;
      const currentSub = currentSession?.sub;
      const newSession = new TokenSetSession(tokenSet);
      const newSub = newSession.sub;

      if (currentSub && newSub !== currentSub) {
        await this.cookieApi.replaceSession(newSession);
      } else if (currentSession && !currentSub && newSub) {
        currentSession.update(newSession);
        await this.cookieApi.replaceSession(currentSession);
      } else {
        this.session = newSession;
      }

      if (config.afterCallback) {
        const updatedSession = await config.afterCallback(req, res, this.session.getSessionData(), state);
        this.session.decorate(updatedSession);
      }

      this.#res.oidc.resumeSilentLogin();

      // Handle backchannel logout onLogin hook
      if (req.oidc.isAuthenticated() && this.hasBackchannelLogout && this.backchannelLogoutOptions.onLogin !== false) {
        await (this.backchannelLogoutOptions.onLogin || onLogIn)(req, config);
      }

      await this.cookieApi.setSessionCookie();
    } catch (err) {
      if (!state?.attemptingSilentLogin) {
        this.session = undefined;
        return this.#next(err);
      }
    }

    const redirectTo = state?.returnTo || config.baseURL;
    res.redirect(redirectTo);
  }

  async backchannelLogout() {
    const config = this.#config;
    const req = this.#req;
    const res = this.#res;

    res.setHeader('cache-control', 'no-store');

    const logoutToken = req.body?.logout_token;
    if (!logoutToken) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing logout_token',
      });
    }

    // Check if insecure mode is explicitly enabled for testing
    if (this.hasBackchannelLogout && this.backchannelLogoutOptions?.isInsecure) {
      // INSECURE MODE - Only for testing, requires explicit configuration
      debug$4('Using insecure backchannel logout mode - DO NOT USE IN PRODUCTION');
      const token = jose.decodeJwt(logoutToken);
      const onToken = this.backchannelLogoutOptions.onLogoutToken || onLogoutToken;
      try {
        await onToken(token, config);
        res.status(204).send();
      } catch (e) {
        debug$4('req.oidc.backchannelLogout() failed with: %s', e.message);
        res.status(400).json({
          error: 'application_error',
          error_description: 'The application failed to invalidate the session.',
        });
      }
      return;
    }

    try {
      const { issuer } = await getClient(config);
      let verifiedToken;
      try {
        const jwksUri = issuer.jwks_uri;
        if (!jwksUri) {
          throw new Error('No JWKS URI found in issuer metadata');
        }

        const jwks = jose.createRemoteJWKSet(new URL(jwksUri));

        const { payload, protectedHeader } = await jose.jwtVerify(logoutToken, jwks, {
          issuer: issuer.issuer,
          audience: config.clientID,
          clockTolerance: config.clockTolerance || 60,
        });

        verifiedToken = payload;

        // Manually validate typ if present in the protected header, see https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation
        if (protectedHeader.typ && protectedHeader.typ !== 'logout+jwt') {
          throw new Error(`Invalid token type: expected 'logout+jwt', got '${protectedHeader.typ}'`);
        }

        // @ts-ignore
        if (!verifiedToken.events?.['http://schemas.openid.net/event/backchannel-logout']) {
          throw new Error('Invalid logout token: missing backchannel logout event');
        }

        if (!verifiedToken.sid && !verifiedToken.sub) {
          throw new Error('Invalid logout token: missing sid or sub claim');
        }

        debug$4('Logout token verified successfully');
      } catch (verificationError) {
        debug$4('Logout token verification failed: %s', verificationError.message);
        res.status(400).json({
          error: 'invalid_token',
          error_description: 'Invalid logout token',
        });
        return;
      }

      // Process the verified logout token
      const onToken = this.backchannelLogoutOptions?.onLogoutToken || onLogoutToken;
      try {
        await onToken(verifiedToken, config);
        res.status(204).send();
      } catch (e) {
        debug$4('req.oidc.backchannelLogout() failed with: %s', e.message);
        res.status(400).json({
          error: 'application_error',
          error_description: 'The application failed to invalidate the session.',
        });
      }
    } catch (err) {
      debug$4('Backchannel logout error', err);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error processing logout token',
      });
    }
  }

  getRedirectUri() {
    const config = this.#config;
    if (config.routes.callback) {
      return new URL(config.routes.callback, config.baseURL).toString();
    }
  }

  /**
   * Cancel silent login, sets skip silent login cookie
   */
  cancelSilentLogin() {
    const { secure, domain, path, sameSite } = this.#config.session.cookie;
    this.#res.cookie(SKIP_SILENT_LOGIN_COOKIE_NAME, true, {
      httpOnly: true,
      secure,
      domain,
      path,
      sameSite,
    });
  }

  resumeSilentLogin() {
    const { secure, domain, path, sameSite } = this.#config.session.cookie;
    this.#res.clearCookie(SKIP_SILENT_LOGIN_COOKIE_NAME, {
      httpOnly: true,
      secure,
      domain,
      path,
      sameSite,
    });
  }

  /**
   * Generates the logout URL.
   *
   * Depending on the configuration, this function will either perform a local only logout
   * or a federated logout by redirecting to the appropriate URL.
   *
   * @param {string} returnUrl End session post logout redirect URI
   * @param {string} [idTokenHint] The ID token hint to be used for the logout request.
   * @param {Record<string, any>} [logoutParams] Override end session url params
   * @returns The URL to redirect the user to for logout.
   */
  async getLogoutUrl(returnUrl, idTokenHint, logoutParams) {
    const config = this.#config;

    if (!config.idpLogout) {
      debug$4('performing a local only logout, redirecting to %s', returnUrl);
      return returnUrl;
    }

    const { client } = await getClient(config);

    return client.endSessionUrl({
      ...config?.logoutParams,
      ...(idTokenHint && { id_token_hint: idTokenHint }),
      post_logout_redirect_uri: returnUrl,
      ...logoutParams,
    });
  }
}

/**
 * Default hook that checks if the user has been logged out via Back-Channel Logout
 * @param {import('express').Request} req
 * @param {import('types').ConfigParams} config
 */
async function isLoggedOut(req, config) {
  // @ts-ignore
  const store = config.backchannelLogout?.store || config.session.store;
  const {
    issuer: { issuer },
  } = await getClient(config);
  const { sid, sub } = req.oidc.idTokenClaims;

  // Normalize issuer URL to handle trailing slashes consistently
  const normalizedIssuer = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;

  if (!sid && !sub) {
    throw new Error(`The session must have a 'sid' or a 'sub'`);
  }

  // Try both normalized and non-normalized issuer URLs to handle inconsistencies
  const [logoutSid, logoutSidAlt, logoutSub, logoutSubAlt] = await Promise.all([
    sid && store.get(`${normalizedIssuer}|${sid}`),
    sid && store.get(`${normalizedIssuer}/|${sid}`),
    sub && store.get(`${normalizedIssuer}|${sub}`),
    sub && store.get(`${normalizedIssuer}/|${sub}`),
  ]);

  return !!(logoutSid || logoutSidAlt || logoutSub || logoutSubAlt);
}

const BYTE_LENGTH = 32;
const ENCRYPTION_INFO = 'JWE CEK';
const SIGNING_INFO = 'JWS Cookie Signing';
const DIGEST = 'sha256';
const ALG = 'HS256';
const CRITICAL_HEADER_PARAMS = ['b64'];

const header = { alg: ALG, b64: false, crit: CRITICAL_HEADER_PARAMS };

/**
 * Get current HKDF encryption keys
 * @param {string|string[]} secret secret or secrets
 * @returns {[Buffer, Buffer[]]} tuple with secrets [current, [current, ...]]
 */
function getEncryptionKeyStore(secret) {
  const secrets = Array.isArray(secret) ? secret : [secret];
  const keystore = secrets.map((s) => encryption(s));
  return [keystore[0], keystore];
}

/**
 * Get current HKDF encryption keys
 * @param {string|string[]} secret secret or secrets
 * @returns {[Buffer, Buffer[]]} tuple with secrets [current, [current, ...]]
 */
function getSigningKeyStore(secret) {
  const secrets = Array.isArray(secret) ? secret : [secret];
  const keystore = secrets.map((s) => signing(s));
  return [keystore[0], keystore];
}

/**
 * Verify cookie signature
 * @param {string} cookie
 * @param {string} value
 * @param {Buffer[]} keystore
 */
async function verifyCookie(cookie, value, keystore) {
  if (!value) return;

  const [part, signature] = value.split('.');
  if (await verifySignature(cookie, part, signature, keystore)) {
    return part;
  }
}

/**
 * Sign cookie
 * @param {string} cookie cookie name
 * @param {string} value cookie value
 * @param {Buffer} key signing key
 */
async function signCookie(cookie, value, key) {
  const signature = await generateSignature(cookie, value, key);
  return `${value}.${signature}`;
}

/**
 * Encrypt cookie
 * @param {Buffer} key encryption key
 * @param {string} payload encrypt payload
 * @param {Record<string, any>} [headers] extra headers
 */
async function encrypt(key, payload, headers) {
  const encrypted = await new jose.CompactEncrypt(Buffer.from(payload))
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM', ...headers })
    .encrypt(key);

  return encrypted;
}

/**
 * Decrypt cookie
 * @param {Buffer|Buffer[]} keystore
 * @param {string} jweCompact
 */
async function decrypt(keystore, jweCompact) {
  // Try each key in keystore (for key rotation support)
  const keysToTry = Array.isArray(keystore) ? keystore : [keystore];

  for (const key of keysToTry) {
    try {
      const { protectedHeader, plaintext } = await jose.compactDecrypt(jweCompact, key);

      return { header: protectedHeader, payload: new TextDecoder().decode(plaintext) };
    } catch (error) {
      // eslint-disable-next-line no-var
      var lastError = error;
    }
  }

  throw lastError;
}

/**
 * @param {string} cookie cookie name
 * @param {string} value cookie value
 * @param {Buffer} key signature key
 */
async function generateSignature(cookie, value, key) {
  return (await new jose.FlattenedSign(Buffer.from(`${cookie}=${value}`)).setProtectedHeader(header).sign(key)).signature;
}

/**
 * Verify cookie signature
 * @param {string} cookie cookie name
 * @param {string} value cookie value
 * @param {string} signature cookie signature
 * @param {Buffer[]} keystore signature secrets key store
 */
async function verifySignature(cookie, value, signature, keystore) {
  try {
    for (const key of keystore) {
      const expectedSignature = await generateSignature(cookie, value, key);
      if (node_crypto.timingSafeEqual(Buffer.from(signature, 'base64url'), Buffer.from(expectedSignature, 'base64url'))) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

/**
 *
 * Derives appropriate sized keys from the end-user provided secret random string/passphrase using
 * HKDF (HMAC-based Extract-and-Expand Key Derivation Function) defined in RFC 8569.
 *
 * @see https://tools.ietf.org/html/rfc5869
 * @param {string} secret
 */
function encryption(secret) {
  return Buffer.from(node_crypto.hkdfSync(DIGEST, secret, Buffer.alloc(0), ENCRYPTION_INFO, BYTE_LENGTH));
}

/**
 * @param {string} secret
 */
function signing(secret) {
  return Buffer.from(node_crypto.hkdfSync(DIGEST, secret, Buffer.alloc(0), SIGNING_INFO, BYTE_LENGTH));
}

/**
 * Transaction cookie handler to handle cookies between login and callback
 */
class TransientCookieHandler {
  #config;
  /**
   * @param {Partial<import('types').ConfigParams>} config
   */
  constructor(config) {
    this.#config = config;
    const [current, keystore] = getSigningKeyStore(config.secret);
    this.currentSigningKey = current;
    this.signingKeyStore = keystore;
    /** @type {Partial<import('types').CookieConfigParams>} */
    this.sessionCookieConfig = config.session?.cookie || {};
    this.legacySameSiteCookie = config.legacySameSiteCookie;
  }

  /**
   * Set transaction cookie with a value or a generated nonce.
   *
   * @param {import('express').Response} res Express Response object.
   * @param {string} value Cookie value
   * @param {Object} opts Cookie options
   * @param {"lax"|"none"|"strict"|boolean} [opts.sameSite] SameSite attribute of "none," "lax," or "strict". Default is "none".
   * @param {Boolean} [opts.legacySameSiteCookie] Should a fallback cookie be set? Default is true.
   *
   * @return {Promise<string>} Cookie value that was set.
   */
  async setTransactionCookie(res, value, opts) {
    // @ts-ignore
    const isSameSiteNone = (opts?.sameSite?.toLowerCase() ?? 'none') === 'none';
    const { domain, path, secure } = this.sessionCookieConfig;
    const cookieName = this.#config.transactionCookie.name;
    const basicAttr = {
      httpOnly: true,
      secure,
      domain,
      path,
    };

    const cookieValue = await signCookie(cookieName, value, this.currentSigningKey);
    // Set the cookie with the SameSite attribute and, if needed, the Secure flag.
    res.cookie(cookieName, cookieValue, {
      ...basicAttr,
      sameSite: opts?.sameSite ?? 'none',
      secure: isSameSiteNone ? true : basicAttr.secure,
    });

    if (isSameSiteNone && this.legacySameSiteCookie) {
      const cookieValue = await signCookie(`_${cookieName}`, value, this.currentSigningKey);
      // Set the fallback cookie with no SameSite or Secure attributes.
      res.cookie(`_${cookieName}`, cookieValue, basicAttr);
    }

    return value;
  }

  /**
   * Get a cookie value then delete it.
   *
   * @param {string} cookieName Cookie name
   * @param {import('express').Request} req Express Request object.
   * @param {import('express').Response} res Express Response object.
   *
   * @return {Promise<string|undefined>} Cookie value or undefined if cookie was not found.
   */
  async getOnce(cookieName, req, res) {
    if (!req[COOKIES]) {
      return undefined;
    }

    const { secure, sameSite } = this.sessionCookieConfig;

    let value = await verifyCookie(cookieName, req[COOKIES][cookieName], this.signingKeyStore);
    this.deleteCookie(cookieName, res, { secure, sameSite });

    if (this.legacySameSiteCookie) {
      const fallbackKey = `_${cookieName}`;
      if (!value) {
        value = await verifyCookie(fallbackKey, req[COOKIES][fallbackKey], this.signingKeyStore);
      }
      this.deleteCookie(fallbackKey, res);
    }

    return value;
  }

  /**
   * Clears the cookie from the browser by setting an empty value and an expiration date in the past
   *
   * @param {string} name Cookie name
   * @param {import('express').Response} res Express Response object
   * @param {any} opts Optional SameSite and Secure cookie options for modern browsers
   */
  deleteCookie(name, res, opts = {}) {
    const { domain, path } = this.sessionCookieConfig;
    const { sameSite, secure } = opts;
    res.clearCookie(name, {
      domain,
      path,
      sameSite,
      secure,
    });
  }
}

const debug$3 = Debug('cookie-store');

class DefaultCookieStore {
  /** @type {[Buffer, Buffer[]]} */
  #encryptionKeys;
  /** @type {[Buffer, Buffer[]]} */
  #signingKeys;
  /**
   * @param {import('types').ConfigParams} config
   */
  constructor(config) {
    this.config = config;
    const sessionName = (this.sessionName = config.session.name);
    this.cookieNamePattern = new RegExp(`^${sessionName}(?:\\.\\d)?$`);

    const { transient, ...cookieOptions } = (this.cookieConfig = config.session.cookie);

    const emptyCookie = cookie.serialize(`${this.sessionName}.0`, '', {
      ...cookieOptions,
      expires: transient ? new Date(0) : new Date(),
      path: cookieOptions.path || '/',
    });

    /**
     * Cookie chunk size
     * @type {number}
     */
    this.cookieChunkSize = MAX_COOKIE_SIZE - emptyCookie.length;
  }

  get encryptionKeys() {
    if (this.#encryptionKeys) {
      return this.#encryptionKeys;
    }
    this.#encryptionKeys = getEncryptionKeyStore(this.config.secret);
    return this.#encryptionKeys;
  }
  get signingKeys() {
    if (this.#signingKeys) {
      return this.#signingKeys;
    }
    this.#signingKeys = getSigningKeyStore(this.config.secret);
    return this.#signingKeys;
  }

  get encryptKey() {
    return this.encryptionKeys[0];
  }
  get decryptKeys() {
    return this.encryptionKeys[1];
  }

  get signingKey() {
    return this.signingKeys[0];
  }
  get verifyKeys() {
    return this.signingKeys[1];
  }

  /**
   * @param {string} sessionCookieValue
   * @returns {Promise<import('types').SessionStorePayload<import('types').Session>>}
   */
  async get(sessionCookieValue) {
    const { payload, header } = await decrypt(this.decryptKeys, sessionCookieValue);

    return {
      sessionId: sessionCookieValue,
      header,
      data: JSON.parse(payload),
    };
  }

  /**
   * Get session from request cookies
   * @param {import('express').Request} req
   * @returns {Promise<import('./session.js').Session>}
   */
  async getSession(req) {
    const sessionCookieValue = await this.getCookie(req);
    if (!sessionCookieValue) return;

    if (sessionCookieValue) {
      try {
        const sessionData = await this.get(sessionCookieValue);
        const storedSession = new StoredSession(sessionData.data, sessionData.header);
        storedSession.assertExpired(this.config.session.rollingDuration, Number(this.config.session.absoluteDuration));
        req[SESSION] = storedSession;
        return storedSession;
      } catch (err) {
        if (err instanceof node_assert.AssertionError) {
          debug$3('existing session was rejected because', err.message);
        } else {
          debug$3('unexpected error handling session', err);
        }
      }
    }
  }

  /**
   * Store session from request
   * @param {import('express').Request} req
   */
  set(req) {
    const session = req[SESSION];
    if (session) session.headers.uat = epoch();
    return Promise.resolve();
  }

  /**
   * Get session cookie from request
   * @param {import('express').Request} req
   * @returns session cookie value, if any
   */
  getCookie(req) {
    const sessionName = this.sessionName;
    const cookies = (req[COOKIES] = cookie.parse(req.get('cookie') || ''));
    if (sessionName in cookies) {
      return cookies[this.sessionName];
    } else if (`${sessionName}.0` in cookies) {
      return Object.entries(cookies)
        .map(([cookie, value]) => {
          const match = cookie.match(`^${sessionName}\\.(\\d+)$`);
          if (match) {
            return [match[1], value];
          }
        })
        .filter(Boolean)
        .sort(([a], [b]) => {
          return parseInt(a, 10) - parseInt(b, 10);
        })
        .map(([i, chunk]) => {
          debug$3('reading session chunk from %s.%d cookie', sessionName, i);
          return chunk;
        })
        .join('');
    }
  }

  /**
   * @param {string} name
   * @param {import('express').Response} res
   */
  clearCookie(name, res) {
    const { domain, path, sameSite, secure } = this.cookieConfig;
    res.clearCookie(name, {
      domain,
      path,
      sameSite,
      secure,
    });
  }

  /**
   * Clear session cookie[s]
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   */
  clearSessionCookies(req, res) {
    const { domain, path, sameSite, secure } = this.cookieConfig;
    for (const cookieName of Object.keys(req[COOKIES])) {
      if (cookieName.match(this.cookieNamePattern)) {
        res.clearCookie(cookieName, {
          domain,
          path,
          sameSite,
          secure,
        });
      }
    }
  }

  /**
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @param {object} options
   * @param {number} [options.uat]
   * @param {number} [options.iat]
   * @param {number} [options.exp]
   */
  setCookie(req, res) {
    const session = req[SESSION];
    const sessionCookieValue = req[SET_SESSION_COOKIE];

    if (!session || !sessionCookieValue) {
      debug$3('session was deleted or is empty, clearing all matching session cookies');
      return this.clearSessionCookies(req, res);
    }

    const { iat, uat } = session.getSessionHeaders();

    const cookies = req[COOKIES];
    const sessionName = this.sessionName;
    const { transient, ...cookieOptions } = this.cookieConfig;

    const options = {
      ...cookieOptions,
      ...(!transient && { expires: new Date(this.calculateExp(iat, uat) * 1000) }),
    };

    debug$3('found session, creating signed session cookie(s) with name %o(.i)', sessionName);

    const chunkCount = Math.ceil(sessionCookieValue.length / this.cookieChunkSize);

    if (chunkCount === 1) {
      res.cookie(sessionName, sessionCookieValue, options);
      for (const cookieName of Object.keys(cookies)) {
        debug$3('replacing chunked cookies with non chunked cookies');
        if (cookieName.match(`^${sessionName}\\.\\d$`)) {
          this.clearCookie(cookieName, res);
        }
      }
      return;
    }

    debug$3('cookie size greater than %d, chunking', this.cookieChunkSize);
    for (let i = 0; i < chunkCount; i++) {
      const chunkValue = sessionCookieValue.slice(i * this.cookieChunkSize, (i + 1) * this.cookieChunkSize);
      res.cookie(`${sessionName}.${i}`, chunkValue, options);
    }
    if (sessionName in cookies) {
      debug$3('replacing non chunked cookie with chunked cookies');
      this.clearCookie(sessionName, res);
    }
  }

  /**
   * Regenerate session cookie value
   * @param {import('express').Request} req
   */
  async #generateSessionCookie(req) {
    /** @type {import('./session.js').Session} */
    const session = req[SESSION];
    if (!session) {
      req[SET_SESSION_COOKIE] = undefined;
      return;
    }

    session.headers.uat = epoch();
    const { iat, uat } = session.getSessionHeaders();
    req[SET_SESSION_COOKIE] = await encrypt(this.encryptKey, JSON.stringify(session.getSessionData() || {}), {
      iat,
      uat,
      exp: this.calculateExp(iat, uat),
    });
  }

  /**
   * @param {number} iat
   * @param {number} uat
   */
  calculateExp(iat, uat) {
    const { rolling, absoluteDuration, rollingDuration } = this.config.session;
    const duration = Number(absoluteDuration);
    if (!rolling) {
      return iat + duration;
    }

    if (!duration) {
      return uat + rollingDuration;
    }

    return Math.min(uat + rollingDuration, iat + duration);
  }
  /**
   * @param {import('express').Request} req
   */
  api(req) {
    const self = this;
    return {
      /**
       * Set session cookie value
       */
      async setSessionCookie() {
        await self.#generateSessionCookie(req);
      },
      /**
       * Replace session
       * @param {import('./session.js').Session} session
       */
      replaceSession(session) {
        req[SESSION] = session;
        return Promise.resolve();
      },
    };
  }
}

class CustomCookieStore extends DefaultCookieStore {
  /**
   * @param {import('types').ConfigParams} config
   */
  constructor(config) {
    super(config);
    this.store = config.session.store;
  }

  /**
   * Get session from request cookies
   * @param {import('express').Request} req
   * @returns {Promise<import('./session.js').Session>}
   */
  async getSession(req) {
    const sessionCookieValue = this.getCookie(req);
    if (!sessionCookieValue) {
      req[SESSION_ID] = await this.config.session.genid(req);
      return;
    }

    try {
      const sessionData = await this.get(sessionCookieValue);
      req[SESSION_ID] = sessionData.sessionId;
      const storedSession = new StoredSession(sessionData.data, sessionData.header);
      storedSession.assertExpired(this.config.session.rollingDuration, Number(this.config.session.absoluteDuration));
      req[SESSION] = storedSession;
      return storedSession;
    } catch (err) {
      if (err instanceof node_assert.AssertionError) {
        debug$3('existing session was rejected because', err.message);
      } else {
        debug$3('unexpected error handling session', err);
      }
    }
  }

  /**
   * @param {string} id
   */
  async get(id) {
    const sessionName = this.sessionName;
    const { signSessionStoreCookie, requireSignedSessionStoreCookie } = this.config.session;

    let verifiedId = id;
    if (signSessionStoreCookie) {
      verifiedId = await verifyCookie(sessionName, id, this.verifyKeys);
      if (!verifiedId && !requireSignedSessionStoreCookie) {
        verifiedId = id;
      }
    }

    const storedSession = await this.store.get(verifiedId);
    return {
      sessionId: verifiedId,
      ...storedSession,
    };
  }

  /**
   * Store session from request
   * @param {import('express').Request} req
   */
  async set(req) {
    const sessionName = this.sessionName;
    const sessionId = req[SESSION_ID];
    const regenSessionId = req[REGENERATED_SESSION_ID];

    /** @type {import('./session.js').Session} */
    const session = req[SESSION];

    const currentSessionData = session?.getSessionData();
    if (req[COOKIES]?.[sessionName] && (regenSessionId || !currentSessionData)) {
      await this.store.destroy(sessionId);
    }
    if (currentSessionData) {
      const { iat, uat } = session.getSessionHeaders();
      const exp = this.calculateExp(iat, uat);

      await this.store.set(regenSessionId || sessionId, {
        header: { iat, uat, exp },
        data: currentSessionData,
        cookie: {
          expires: exp * 1000,
          maxAge: exp * 1000 - Date.now(),
        },
      });
    }
  }

  /**
   * Generate session cookie value
   * @param {import('express').Request} req
   */
  async #generateSessionCookie(req) {
    /** @type {import('./session.js').Session} */
    const session = req[SESSION];
    if (!session) {
      req[SET_SESSION_COOKIE] = undefined;
      return;
    }

    const sessionId = req[SESSION_ID];
    const sessionName = this.sessionName;
    const regenSessionId = req[REGENERATED_SESSION_ID];
    const value = regenSessionId || sessionId;
    req[SET_SESSION_COOKIE] = this.config.session.signSessionStoreCookie ? await signCookie(sessionName, value, this.signingKey) : value;
  }

  /**
   * @param {import('express').Request} req
   */
  api(req) {
    const self = this;
    return {
      async setSessionCookie() {
        await self.#generateSessionCookie(req);
      },
      /**
       * @param {import('./session.js').Session} session
       */
      async replaceSession(session) {
        req[REGENERATED_SESSION_ID] = await self.config.session.genid(req);
        req[SESSION] = session;
      },
    };
  }
}

function epoch() {
  return (Date.now() / 1000) | 0;
}

const debug$2 = Debug('session');

/**
 * Create appSession middleware
 * @param {import('types').ConfigParams} config
 * @returns {import('express').RequestHandler}
 */
function appSession(config) {
  const sessionName = config.session.name;

  const hasCustomStore = !!config.session.store;
  const store = hasCustomStore ? new CustomCookieStore(config) : new DefaultCookieStore(config);

  return async function appSessionHandler(req, res, next) {
    if (sessionName in req) {
      debug$2('request object (req) already has %o property, this is indicative of a middleware setup problem', sessionName);
      return next(new Error(`req[${sessionName}] is already set, did you run this middleware twice?`));
    }

    await store.getSession(req);

    attachSessionObject(req, sessionName);

    const cookieApi = (req[SESSION_STORE] = store.api(req));

    await cookieApi.setSessionCookie();

    onHeaders(res, () => {
      store.setCookie(req, res);
    });

    if (hasCustomStore) {
      res.end = customStoreEnd(store, req, res, next);
    }

    return next();
  };
}

/**
 * @param {import('express').Request} req
 * @param {string} sessionName
 */
function attachSessionObject(req, sessionName) {
  Object.defineProperty(req, sessionName, {
    enumerable: true,
    get() {
      return this[SESSION]?.getSessionData();
    },
    set(arg) {
      if (arg === null || arg === undefined) {
        this[SESSION] = undefined;
      } else {
        throw new TypeError('session object cannot be reassigned');
      }
    },
  });
}

/**
 * Response.end override function to store session
 * @param {CustomCookieStore|DefaultCookieStore} store cookie store
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 * @returns {import('express').Response['end']}
 */
function customStoreEnd(store, req, res, next) {
  const endFn = res.end;

  // @ts-ignore
  return async function customEnd(...args) {
    try {
      await store.set(req);
      // @ts-ignore
      endFn.call(res, ...args);
    } catch (err) {
      // need to restore the original `end` so that it gets
      // called after `next(e)` calls the express error handling mw
      res.end = endFn;
      process.nextTick(() => next(err));
    }
  };
}

const debug$1 = Debug('requiresAuth');

/**
 * Returns a middleware that checks whether an end-user is authenticated.
 * If end-user is not authenticated `res.oidc.login()` is triggered for an HTTP
 * request that can perform a redirect.
 * @param {CallableFunction} requiresLoginCheck
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function requiresLoginMiddleware(requiresLoginCheck, req, res, next) {
  if (!req.oidc) {
    next(new Error('req.oidc is not found, did you include the auth middleware?'));
    return;
  }

  if (requiresLoginCheck(req)) {
    if (!res.oidc.errorOnRequiredAuth && req.accepts('html')) {
      debug$1('authentication requirements not met with errorOnRequiredAuth() returning false, calling res.oidc.login()');
      return res.oidc.login();
    }
    debug$1('authentication requirements not met with errorOnRequiredAuth() returning true, calling next() with an Unauthorized error');
    next(new UnauthorizedError('Authentication is required for this route.'));
    return;
  }

  debug$1('authentication requirements met, calling next()');

  next();
}

function requiresAuth(requiresLoginCheck = defaultRequiresLogin) {
  return requiresLoginMiddleware.bind(undefined, requiresLoginCheck);
}

/**
 * ID token calim equals
 * @param {*} claim
 * @param {string|number|boolean|null} expected
 */
function claimEquals(claim, expected) {
  // check that claim is a string value
  if (typeof claim !== 'string') {
    throw new TypeError('"claim" must be a string');
  }
  // check that expected is a JSON supported primitive
  checkJSONprimitive(expected);

  /**
   * @param {import('express').Request} req
   */
  function authenticationCheck(req) {
    if (defaultRequiresLogin(req)) {
      return true;
    }
    const { idTokenClaims } = req.oidc;
    if (!(claim in idTokenClaims)) {
      return true;
    }
    const actual = idTokenClaims[claim];
    if (actual !== expected) {
      return true;
    }

    return false;
  }
  return requiresLoginMiddleware.bind(undefined, authenticationCheck);
}

/**
 * ID token claim includes
 * @param {string} claim
 * @param  {...(string|number|boolean|null)} expected
 */
function claimIncludes(claim, ...expected) {
  // check that claim is a string value
  if (typeof claim !== 'string') {
    throw new TypeError('"claim" must be a string');
  }
  // check that all expected are JSON supported primitives
  expected.forEach(checkJSONprimitive);

  /**
   * @param {import('express').Request} req
   */
  function authenticationCheck(req) {
    if (defaultRequiresLogin(req)) {
      return true;
    }

    const { idTokenClaims } = req.oidc;
    if (!(claim in idTokenClaims)) {
      return true;
    }

    const actual = idTokenClaims[claim];
    let expectedList;
    if (typeof actual === 'string') {
      expectedList = new Set(actual.split(' '));
    } else if (Array.isArray(actual)) {
      expectedList = new Set(actual);
    } else if (!Array.isArray(actual)) {
      debug$1('unexpected claim type. expected array or string, got %o', typeof actual);
      return true;
    }

    return !expected.every(Set.prototype.has.bind(expectedList));
  }

  return requiresLoginMiddleware.bind(undefined, authenticationCheck);
}

/**
 * @param {CallableFunction} func
 */
function claimCheck(func) {
  // check that func is a function
  if (typeof func !== 'function' || func.constructor.name !== 'Function') {
    throw new TypeError('"claimCheck" expects a function');
  }

  /**
   * @param {import('express').Request} req
   */
  function authenticationCheck(req) {
    if (defaultRequiresLogin(req)) {
      return true;
    }

    const { idTokenClaims } = req.oidc;

    return !func(req, idTokenClaims);
  }

  return requiresLoginMiddleware.bind(undefined, authenticationCheck);
}

/**
 * @param {import('express').Request} req
 */
function defaultRequiresLogin(req) {
  return !req.oidc.isAuthenticated();
}

/**
 * Check primitive value
 * @param {string|number|boolean|null} value
 */
function checkJSONprimitive(value) {
  if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean' && value !== null) {
    throw new TypeError('"expected" must be a string, number, boolean or null');
  }
}

const debug = Debug('');

/**
 * Returns a router with two routes /login and /callback
 *
 * @param {Partial<import('types').ConfigParams>} [params] The parameters object; see index.d.ts for types and descriptions.
 *
 * @returns {express.Router} the router
 */
function auth(params) {
  const config = getConfig(params);
  debug('configuration object processed, resulting configuration: %O', config);
  const router = express.Router();
  const transient = new TransientCookieHandler(config);

  router.use(appSession(config));

  // Express context and OpenID Issuer discovery.
  router.use((req, res, next) => {
    req.oidc = new RequestContext(config, req, res);
    res.oidc = new ResponseContext(config, req, res, next, transient);
    next();
  });

  // Login route, configurable with routes.login
  if (config.routes.login) {
    const path = enforceLeadingSlash(config.routes.login);
    debug(`adding GET ${path} route`);
    router.get(path, express.urlencoded({ extended: false }), (_req, res) => res.oidc.login({ returnTo: config.baseURL }));
  } else {
    debug('login handling route not applied');
  }

  // Logout route, configurable with routes.logout
  if (config.routes.logout) {
    const path = enforceLeadingSlash(config.routes.logout);
    debug(`adding GET ${path} route`);
    router.get(path, (_req, res) => res.oidc.logout());
  } else {
    debug('logout handling route not applied');
  }

  // Callback route, configured with routes.callback.
  if (config.routes.callback) {
    const path = enforceLeadingSlash(config.routes.callback);
    debug(`adding GET ${path} route`);
    router.get(path, (_req, res) => res.oidc.callback());
    debug(`adding POST ${path} route`);
    router.post(path, express.urlencoded({ extended: false }), (_req, res) => res.oidc.callback());
  } else {
    debug('callback handling route not applied');
  }

  if (config.backchannelLogout) {
    backchannelLogoutRoute(config, router);
  }

  if (config.authRequired) {
    debug('authentication is required for all routes this middleware is applied to');
    router.use(requiresAuth());
  } else {
    debug(
      'authentication is not required for any of the routes this middleware is applied to ' +
        'see and apply `requiresAuth` middlewares to your protected resources'
    );
  }
  if (config.attemptSilentLogin) {
    debug("silent login will be attempted on end-user's initial HTML request");
    router.use(attemptSilentLogin());
  }

  return router;
}

/**
 * Apply backchannel logout route
 * @param {import('types').ConfigParams} config
 * @param {import('express').Router} router
 */
function backchannelLogoutRoute(config, router) {
  const path = enforceLeadingSlash(config.routes.backchannelLogout);
  debug(`adding POST ${path} route`);
  router.post(path, express.urlencoded({ extended: false }), (_req, res) => res.oidc.backchannelLogout());

  // @ts-ignore
  if (config.backchannelLogout.isLoggedOut !== false) {
    backchannelIsLoggedOutMiddleware(config, router);
  }
}

/**
 * Backchannel is logged out middleware
 * @param {import('types').ConfigParams} config
 * @param {import('express').Router} router
 */
function backchannelIsLoggedOutMiddleware(config, router) {
  // @ts-ignore
  const isLoggedOutFn = config.backchannelLogout.isLoggedOut || isLoggedOut;
  router.use(async (req, _res, next) => {
    if (!req.oidc.isAuthenticated()) {
      return next();
    }

    const loggedOut = await isLoggedOutFn(req, config);

    if (loggedOut) {
      // @ts-ignore
      const session = req[config.session.name];
      // If using external store, try to destroy the session first
      if (config.session.store && typeof session?.destroy === 'function') {
        try {
          session.destroy();
        } catch {
          // Ignore errors during session destruction
        }
      }

      // Clear the session using replaceSession like it was originally
      req[SESSION] = undefined;
    }
    next();
  });
}

/**
 * Used for instantiating a custom session store. eg
 *
 * ```js
 * const { auth } = import('express-openid-connect');
 * const MemoryStore = import('memorystore');
 * const store = MemoryStore(auth);
 * ```
 *
 * @constructor
 */
auth.Store = function Store() {};

/**
 * @param {string} path endpoint path
 * @returns {string} endpoint path with leading slash
 */
function enforceLeadingSlash(path) {
  return path.split('')[0] === '/' ? path : '/' + path;
}

exports.attemptSilentLogin = attemptSilentLogin;
exports.auth = auth;
exports.claimCheck = claimCheck;
exports.claimEquals = claimEquals;
exports.claimIncludes = claimIncludes;
exports.requiresAuth = requiresAuth;
