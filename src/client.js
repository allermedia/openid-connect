import { importPKCS8 } from 'jose';
import {
  discovery,
  buildAuthorizationUrl,
  Configuration,
  authorizationCodeGrant,
  refreshTokenGrant,
  fetchUserInfo,
  allowInsecureRequests,
  useCodeIdTokenResponseType,
  PrivateKeyJwt,
  ClientSecretJwt,
  ClientSecretPost,
  ClientSecretBasic,
  customFetch,
  None,
} from 'openid-client';

import Debug from './debug.js';
import { OpenIDConnectError, OpenIDConnectBadRequest } from './errors.js';

const debug = Debug('client');

export class OpenIDConnectClient {
  /**
   * @param {import('types').ConfigParams} config
   * @param {*} serverMetadata
   * @param {Configuration} configuration
   */
  constructor(config, serverMetadata, configuration) {
    this.client_id = config.clientID;
    this.serverMetadata = serverMetadata;
    this.id_token_signed_response_alg = config.idTokenSigningAlg;
    this.config = config;
    this.configuration = configuration;
    if (config.customFetch) {
      configuration[customFetch] = config.customFetch;
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

    return authorizationCodeGrant(
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
    return refreshTokenGrant(this.configuration, refreshToken, extras);
  }

  /**
   * Fetch user info
   * @param {string} accessToken
   * @param {*} options
   */
  async userinfo(accessToken, options = {}) {
    const expectedSubject = options?.expectedSubject;
    return await fetchUserInfo(this.configuration, accessToken, expectedSubject, options);
  }

  /**
   * @param {URLSearchParams | Record<string, string>} params
   */
  authorizationUrl(params) {
    return buildAuthorizationUrl(this.configuration, params);
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
  debug('Creating client for issuer %s', config.issuerBaseURL);

  const discoveredConfiguration = await discovery(new URL(config.issuerBaseURL), config.clientID, config.clientSecret, undefined, {
    ...(config.httpTimeout && { timeout: config.httpTimeout }),
    ...(config.allowInsecureRequests && { execute: [allowInsecureRequests] }),
    ...(config.customFetch && { [customFetch]: config.customFetch }),
  });

  const serverMetadata = discoveredConfiguration.serverMetadata();

  debug('Discovery successful for %s', config.issuerBaseURL);

  validateConfiguration(config, serverMetadata);

  let clientAuthMethod = config.clientAuthMethod;
  if (!clientAuthMethod) {
    if (config.clientAssertionSigningKey) clientAuthMethod = 'private_key_jwt';
    else if (config.clientSecret) clientAuthMethod = 'client_secret_post';
    else clientAuthMethod = 'none';
  }

  let clientAuthentication;

  switch (clientAuthMethod) {
    case 'private_key_jwt': {
      const privateKey = config.clientAssertionSigningKey;

      if (privateKey && (typeof privateKey === 'string' || Buffer.isBuffer(privateKey))) {
        const cryptoKey = await importPKCS8(privateKey.toString('utf-8'), config.clientAssertionSigningAlg || 'RS256', {
          extractable: true,
        });
        clientAuthentication = PrivateKeyJwt(cryptoKey);
      } else if (privateKey && typeof privateKey === 'object') {
        // @ts-ignore
        clientAuthentication = PrivateKeyJwt({ key: privateKey });
      }
      break;
    }
    case 'client_secret_jwt': {
      const authAlgOptions = config.clientAssertionSigningAlg ? { algorithm: config.clientAssertionSigningAlg } : undefined;
      // @ts-ignore
      clientAuthentication = ClientSecretJwt(config.clientSecret, authAlgOptions);
      break;
    }
    case 'client_secret_basic':
      clientAuthentication = ClientSecretBasic(config.clientSecret);
      break;
    case 'none':
      clientAuthentication = None();
      break;
    case 'client_secret_post':
    default:
      clientAuthentication = ClientSecretPost(config.clientSecret);
  }

  const configuration = new Configuration(
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
    allowInsecureRequests(configuration);
  }

  // Enable hybrid flow (code id_token) if configured
  const responseType = config.authorizationParams?.response_type || 'code';
  if (responseType.includes('code') && responseType.includes('id_token')) {
    useCodeIdTokenResponseType(configuration);
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
    debug(
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
    debug('Response type %o is not supported by the issuer. Supported response types are: %o.', configRespType, issuerRespTypes);
  }

  const configRespMode = config.authorizationParams.response_mode;
  const issuerRespModes = Array.isArray(serverMetadata.response_modes_supported) ? serverMetadata.response_modes_supported : [];
  if (configRespMode && !issuerRespModes.includes(configRespMode)) {
    debug('Response mode %o is not supported by the issuer. Supported response modes are %o.', configRespMode, issuerRespModes);
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
export function getClient(config) {
  const { discoveryCacheMaxAge: cacheMaxAge } = config;
  const now = Date.now();
  if (cache.has(config) && now < timestamp + cacheMaxAge) {
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

export function clearCache() {
  cache.clear();
  timestamp = 0;
}
