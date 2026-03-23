import { strict } from 'node:assert';

import { decodeJwt, createRemoteJWKSet, jwtVerify } from 'jose';
import { randomNonce, randomPKCECodeVerifier, calculatePKCECodeChallenge } from 'openid-client';

import { encodeState, decodeState } from '../src/hooks/getLoginState.js';

import { AccessToken } from './access-token.js';
import { getClient } from './client.js';
import { SESSION, SESSION_STORE, COOKIES, SKIP_SILENT_LOGIN_COOKIE_NAME, BASE_URL_AUTODETECT } from './constants.js';
import Debug from './debug.js';
import { OpenIDConnectBadRequest } from './errors.js';
import onLogin from './hooks/backchannelLogout/onLogIn.js';
import onLogoutToken from './hooks/backchannelLogout/onLogoutToken.js';
import { TokenSetSession } from './session.js';

const debug = Debug('context');
const validResponseTypes = ['id_token', 'code id_token', 'code'];

export class RequestContext {
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

export class ResponseContext {
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

  get baseURL() {
    const base = this.#config.baseURL;
    if (base !== BASE_URL_AUTODETECT) return base;

    const req = this.#req;
    return `${req.protocol}://${req.host}`;
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

    debug('Attempting silent login');
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
      let returnTo = '/';

      if (options?.returnTo) {
        returnTo = options.returnTo;
        debug('req.oidc.login() called with returnTo: %s', returnTo);
      } else if (req.method === 'GET' && req.originalUrl) {
        // Collapse any leading slashes to a single slash to prevent Open Redirects
        returnTo = req.originalUrl.replace(/^\/+/, '/');
        debug('req.oidc.login() without returnTo, using: %s', returnTo);
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

      strict(validResponseTypes.includes(response_type), `response_type should be one of ${validResponseTypes.join(', ')}`);
      strict(/\bopenid\b/.test(scope), 'scope should contain "openid"');

      /**
       * Transaction cookie payload
       * @type {Record<string, any>}
       */
      const authVerification = {
        nonce: randomNonce(),
        state: encodeState(stateValue),
        ...(max_age && { max_age }),
      };

      const usePKCE = response_type.includes('code');
      if (usePKCE) {
        debug('response_type includes code, the authorization request will use PKCE');
        authVerification.code_verifier = randomPKCECodeVerifier();
      }

      /** @type {Record<string, any>} */
      const authParams = {
        ...authOptions.authorizationParams,
        ...authVerification,
        ...(usePKCE && {
          code_challenge_method: 'S256',
          code_challenge: await calculatePKCECodeChallenge(authVerification.code_verifier),
        }),
      };

      await transient.setTransactionCookie(res, JSON.stringify(authVerification), {
        sameSite: response_mode === 'form_post' ? 'none' : config.transactionCookie.sameSite,
      });

      const authorizationUrl = client.authorizationUrl(authParams);
      debug('redirecting to %s', authorizationUrl);
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
   * @param {import('types').LogoutOptions} [options]
   */
  async logout(options) {
    const config = this.#config;
    const req = this.#req;
    const res = this.#res;

    let returnUrl = options?.returnTo || config.routes.postLogoutRedirect;
    debug('req.oidc.logout() with return url: %s', returnUrl);

    if (new URL(returnUrl, 'http://__nohost').origin === 'http://__nohost') {
      returnUrl = new URL(returnUrl, this.baseURL).toString();
    }

    this.#res.oidc.cancelSilentLogin();

    if (!req.oidc.isAuthenticated()) {
      debug('end-user already logged out, redirecting to %s', returnUrl);

      // perform idp logout with no token hint
      return res.redirect(await this.getLogoutUrl(returnUrl, undefined, options?.logoutParams));
    }

    const idToken = req.oidc.idToken;

    this.session = undefined;

    returnUrl = await this.getLogoutUrl(returnUrl, idToken, options?.logoutParams);

    debug('logging out of identity provider, redirecting to %s', returnUrl);
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
        await (this.backchannelLogoutOptions.onLogin || onLogin)(req, config);
      }

      await this.cookieApi.setSessionCookie();
    } catch (err) {
      if (!state?.attemptingSilentLogin) {
        this.session = undefined;
        return this.#next(err);
      }
    }

    const redirectTo = state?.returnTo || this.baseURL;
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
      debug('Using insecure backchannel logout mode - DO NOT USE IN PRODUCTION');
      const token = decodeJwt(logoutToken);
      const onToken = this.backchannelLogoutOptions.onLogoutToken || onLogoutToken;
      try {
        await onToken(token, config);
        res.status(204).send();
      } catch (e) {
        debug('req.oidc.backchannelLogout() failed with: %s', e.message);
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

        const jwks = createRemoteJWKSet(new URL(jwksUri));

        const { payload, protectedHeader } = await jwtVerify(logoutToken, jwks, {
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

        debug('Logout token verified successfully');
      } catch (verificationError) {
        debug('Logout token verification failed: %s', verificationError.message);
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
        debug('req.oidc.backchannelLogout() failed with: %s', e.message);
        res.status(400).json({
          error: 'application_error',
          error_description: 'The application failed to invalidate the session.',
        });
      }
    } catch (err) {
      debug('Backchannel logout error', err);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error processing logout token',
      });
    }
  }

  getRedirectUri() {
    const config = this.#config;
    if (config.routes.callback) {
      return new URL(config.routes.callback, this.baseURL).toString();
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
      debug('performing a local only logout, redirecting to %s', returnUrl);
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
