import { COOKIES } from './constants.js';
import { signCookie, verifyCookie, getEncryptionKeyStore } from './crypto.js';

/**
 * Transaction cookie handler to handle cookies between login and callback
 */
export class TransientCookieHandler {
  /**
   * @param {Partial<import('types').ConfigParams>} config
   */
  constructor(config) {
    const [current, keystore] = getEncryptionKeyStore(config.secret);
    this.currentKey = current;
    this.keyStore = keystore;
    /** @type {Partial<import('types').CookieConfigParams>} */
    this.sessionCookieConfig = config.session?.cookie || {};
    this.legacySameSiteCookie = config.legacySameSiteCookie;
  }

  /**
   * Set a cookie with a value or a generated nonce.
   *
   * @param {string} cookieName Cookie name to use.
   * @param {import('express').Response} res Express Response object.
   * @param {string} value Cookie value
   * @param {Object} opts Cookie options
   * @param {"lax"|"none"|"strict"|boolean} [opts.sameSite] SameSite attribute of "none," "lax," or "strict". Default is "none".
   * @param {Boolean} [opts.legacySameSiteCookie] Should a fallback cookie be set? Default is true.
   *
   * @return {string} Cookie value that was set.
   */
  store(res, cookieName, value, opts) {
    const isSameSiteNone = (opts?.sameSite ?? 'none') === 'none';
    const { domain, path, secure } = this.sessionCookieConfig;
    const basicAttr = {
      httpOnly: true,
      secure,
      domain,
      path,
    };

    const cookieValue = signCookie(cookieName, value, this.currentKey);
    // Set the cookie with the SameSite attribute and, if needed, the Secure flag.
    res.cookie(cookieName, cookieValue, {
      ...basicAttr,
      sameSite: opts?.sameSite ?? 'none',
      secure: isSameSiteNone ? true : basicAttr.secure,
    });

    if (isSameSiteNone && this.legacySameSiteCookie) {
      const cookieValue = signCookie(`_${cookieName}`, value, this.currentKey);
      // Set the fallback cookie with no SameSite or Secure attributes.
      res.cookie(`_${cookieName}`, cookieValue, basicAttr);
    }

    return value;
  }

  /**
   * Get a cookie value then delete it.
   *
   * @param {string} key Cookie name to use.
   * @param {import('express').Request} req Express Request object.
   * @param {import('express').Response} res Express Response object.
   *
   * @return {String|undefined} Cookie value or undefined if cookie was not found.
   */
  getOnce(key, req, res) {
    if (!req[COOKIES]) {
      return undefined;
    }

    const { secure, sameSite } = this.sessionCookieConfig;

    let value = verifyCookie(key, req[COOKIES][key], this.keyStore);
    this.deleteCookie(key, res, { secure, sameSite });

    if (this.legacySameSiteCookie) {
      const fallbackKey = `_${key}`;
      if (!value) {
        value = verifyCookie(fallbackKey, req[COOKIES][fallbackKey], this.keyStore);
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
