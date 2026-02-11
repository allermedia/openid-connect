import { getClient } from './client.js';
import { SESSION } from './constants.js';
import { OpenIDConnectBadRequest } from './errors.js';
import { TokenSetSession } from './session.js';

export class AccessToken {
  #config;
  #req;
  #res;
  #legacySession;
  /** @type {import('./session.js').Session} */
  #session;
  /**
   * @param {import('types').ConfigParams} config
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   */
  constructor(config, req, res) {
    this.#config = config;
    this.#req = req;
    this.#res = res;
    this.#session = req[SESSION];

    // @ts-ignore
    this.#legacySession = req[config.session.name];
  }

  /**
   * Access token
   */
  get access_token() {
    return this.#session.access_token;
  }

  /**
   * Token type
   */
  get token_type() {
    return this.#session.token_type;
  }

  /**
   * Access token expires in seconds
   */
  get expires_in() {
    const expiresAt = this.#session.expires_at;
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

    if (!session.refresh_token) {
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

    Object.assign(this.#legacySession, session.getSessionData());

    // @ts-ignore
    return new this.constructor(config, this.#req);
  }

  toJSON() {
    return {
      access_token: this.access_token,
      token_type: this.token_type,
      expires_in: this.expires_in,
    };
  }
}
