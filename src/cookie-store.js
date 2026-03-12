import { serialize } from 'cookie';

import { COOKIES, SESSION, SET_SESSION_COOKIE, SESSION_ID, REGENERATED_SESSION_ID, MAX_COOKIE_SIZE } from './constants.js';
import { getEncryptionKeyStore, getSigningKeyStore, verifyCookie, signCookie, encrypt, decrypt } from './crypto.js';
import Debug from './debug.js';

const debug = Debug('cookie-store');

export class DefaultCookieStore {
  /** @type {[Buffer, Buffer[]]} */
  #encryptionKeys;
  /** @type {[Buffer, Buffer[]]} */
  #signingKeys;
  /**
   * @param {import('types').ConfigParams} config
   */
  constructor(config) {
    this.config = config;
    this.sessionName = config.session.name;

    const { transient, ...cookieOptions } = (this.cookieConfig = config.session.cookie);

    const emptyCookie = serialize(`${this.sessionName}.0`, '', {
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
   * Store session from request
   * @param {import('express').Request} _req
   * @param {object} _options
   */
  // eslint-disable-next-line no-unused-vars
  set(_req, _options) {
    return Promise.resolve();
  }

  /**
   * Get session cookie from request
   * @param {import('express').Request} req
   * @returns session cookie value, if any
   */
  getCookie(req) {
    const sessionName = this.sessionName;
    const cookies = req[COOKIES];
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
          debug('reading session chunk from %s.%d cookie', sessionName, i);
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
    const sessionName = this.sessionName;
    const { domain, path, sameSite, secure } = this.cookieConfig;
    for (const cookieName of Object.keys(req[COOKIES])) {
      if (cookieName.match(`^${sessionName}(?:\\.\\d)?$`)) {
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
  setCookie(req, res, { uat = epoch(), iat = uat, exp = this.calculateExp(iat, uat) }) {
    const session = req[SESSION];
    const sessionCookieValue = req[SET_SESSION_COOKIE];

    if (!session || !sessionCookieValue) {
      debug('session was deleted or is empty, clearing all matching session cookies');
      return this.clearSessionCookies(req, res);
    }

    const cookies = req[COOKIES];
    const sessionName = this.sessionName;
    const { transient, ...cookieOptions } = this.cookieConfig;
    const options = {
      ...cookieOptions,
      ...(!transient && { expires: new Date(exp * 1000) }),
    };

    debug('found session, creating signed session cookie(s) with name %o(.i)', sessionName);

    const chunkCount = Math.ceil(sessionCookieValue.length / this.cookieChunkSize);

    if (chunkCount === 1) {
      res.cookie(sessionName, sessionCookieValue, options);
      for (const cookieName of Object.keys(cookies)) {
        debug('replacing chunked cookies with non chunked cookies');
        if (cookieName.match(`^${sessionName}\\.\\d$`)) {
          this.clearCookie(cookieName, res);
        }
      }
      return;
    }

    debug('cookie size greater than %d, chunking', this.cookieChunkSize);
    for (let i = 0; i < chunkCount; i++) {
      const chunkValue = sessionCookieValue.slice(i * this.cookieChunkSize, (i + 1) * this.cookieChunkSize);
      res.cookie(`${sessionName}.${i}`, chunkValue, options);
    }
    if (sessionName in cookies) {
      debug('replacing non chunked cookie with chunked cookies');
      this.clearCookie(sessionName, res);
    }
  }

  /**
   * Regenerate session cookie value
   * @param {import('express').Request} req
   * @param {import('express').Response} _res
   * @param {object} options
   * @param {number} [options.uat]
   * @param {number} [options.iat]
   * @param {number} [options.exp]
   */
  async #generateSessionCookie(req, _res, { uat = epoch(), iat = uat, exp = this.calculateExp(iat, uat) }) {
    /** @type {import('./session.js').Session} */
    const session = req[SESSION];
    if (!session) {
      req[SET_SESSION_COOKIE] = undefined;
      return;
    }

    req[SET_SESSION_COOKIE] = await encrypt(this.encryptKey, JSON.stringify(session.getSessionData() || {}), { iat, uat, exp });
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
   * @param {import('express').Response} res
   * @param {number} iat
   */
  api(req, res, iat) {
    const self = this;
    return {
      /**
       * @param {object} [options]
       * @param {number} [options.uat]
       * @param {number} [options.iat]
       * @param {number} [options.exp]
       */
      async setSessionCookie(options) {
        await self.#generateSessionCookie(req, res, { iat, ...options });
      },
    };
  }
}

export class CustomCookieStore extends DefaultCookieStore {
  /**
   * @param {import('types').ConfigParams} config
   */
  constructor(config) {
    super(config);
    this.store = config.session.store;
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
   * @param {object} options
   * @param {number} [options.uat]
   * @param {number} [options.iat]
   * @param {number} [options.exp]
   */
  async set(req, { uat = epoch(), iat = uat, exp = this.calculateExp(iat, uat) }) {
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
   * Get session cookie from request
   * @param {import('express').Request} req
   */
  getCookie(req) {
    const sessionName = this.sessionName;
    return req[COOKIES][sessionName];
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
    const value = regenSessionId || sessionId; //id;
    req[SET_SESSION_COOKIE] = this.config.session.signSessionStoreCookie ? await signCookie(sessionName, value, this.signingKey) : value;
  }

  /**
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @param {number} iat
   */
  api(req, res, iat) {
    const self = this;
    return {
      /**
       * @param {object} [options]
       * @param {number} [options.uat]
       * @param {number} [options.iat]
       * @param {number} [options.exp]
       */
      async setSessionCookie(options) {
        await self.#generateSessionCookie(req, res, { iat, ...options });
      },
    };
  }
}

export function epoch() {
  return (Date.now() / 1000) | 0;
}
