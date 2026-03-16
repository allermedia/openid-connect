import { strict } from 'node:assert';

import { decodeJwt } from 'jose';

const kClaims = Symbol.for('cached claims');

export class Session {
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
      this[kClaims] = decodeJwt(this.id_token);
    }
    return { sid: this.sid, ...this[kClaims] };
  }

  /**
   * Get session headers
   * @returns {Partial<import('types').SessionHeaders>}
   */
  getSessionHeaders() {
    const updatedAt = this.headers.uat ?? epoch();
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

    const nowEpoch = epoch();
    strict(exp > nowEpoch, 'it is expired based on options when it was established');

    if (rollingDuration) {
      strict(uat + rollingDuration > nowEpoch, 'it is expired based on current rollingDuration rules');
    }
    if (absoluteDuration) {
      strict(iat + absoluteDuration > nowEpoch, 'it is expired based on current absoluteDuration rules');
    }
  }
}

export class StoredSession extends Session {
  /**
   * @param {any} data
   * @param {import('types').SessionHeaders} headers
   */
  constructor(data, headers) {
    super(data, headers);

    if (typeof data.id_token === 'string') {
      // @ts-ignore
      // eslint-disable-next-line no-var
      var claims = (this[kClaims] = decodeJwt(data.id_token));
    } else {
      this.id_token = undefined;
    }

    this.sid = claims?.sid ?? data.sid;
    this.sub = claims?.sub ?? data.sub;
  }
}

export class TokenSetSession extends Session {
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

export function epoch() {
  return (Date.now() / 1000) | 0;
}
