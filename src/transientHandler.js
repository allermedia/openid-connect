import { COOKIES } from './constants.js';
import { signCookie, verifyCookie, getSigningKeyStore } from './crypto.js';

/**
 * Transaction cookie handler to handle cookies between login and callback
 */
export class TransientCookieHandler {
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
