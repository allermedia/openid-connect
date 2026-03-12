import crypto from 'node:crypto';

import { stringifySetCookie } from 'cookie';

import { getConfig } from '../src/config.js';
import { COOKIES } from '../src/constants.js';
import { getSigningKeyStore } from '../src/crypto.js';
import { TransientCookieHandler } from '../src/transientHandler.js';

import * as legacyCrypto from './helpers/legacy-crypto.js';

const reqWithCookies = (cookies) => ({ [COOKIES]: cookies });
const secret = '__test_session_secret__';
const defaultConfig = getConfig({
  baseURL: 'http://localhost',
  issuerBaseURL: 'http://op.localhost',
  clientID: crypto.randomUUID(),
  secret,
  legacySameSiteCookie: true,
});

describe('transientHandler', () => {
  let res;
  /** @type {TransientCookieHandler} */
  let transientHandler;
  let generateSignature;

  let signingKey;
  before(() => {
    signingKey = getSigningKeyStore(secret)[0];
  });

  beforeEach(() => {
    transientHandler = new TransientCookieHandler(defaultConfig);
    generateSignature = (cookie, value) => {
      return legacyCrypto.generateSignature(cookie, value, signingKey);
    };

    const cookieCalls = [];
    res = {
      cookie(name, value, opts) {
        cookieCalls.push(stringifySetCookie({ name, value, ...opts }));
      },
      clearCookie(name, opts) {
        cookieCalls.push(stringifySetCookie({ name, ...opts }));
      },
      cookieCalls,
    };
  });

  describe('store()', () => {
    it('should use the passed-in value to set the cookie', async () => {
      await transientHandler.setTransactionCookie(res, 'test_nonce');

      expect(res.cookieCalls).to.have.length(2);

      expect(res.cookieCalls[0]).to.include(`${defaultConfig.transactionCookie.name}=test_nonce.`);
      expect(res.cookieCalls[1]).to.include(`_${defaultConfig.transactionCookie.name}=test_nonce.`);
    });

    it('should use the config.secure property to automatically set cookies secure', async () => {
      const transientHandlerHttps = new TransientCookieHandler({
        ...defaultConfig,
        session: { cookie: { secure: true } },
        legacySameSiteCookie: true,
      });
      const transientHandlerHttp = new TransientCookieHandler({
        ...defaultConfig,
        session: { cookie: { secure: false } },
        legacySameSiteCookie: true,
      });

      await transientHandlerHttps.setTransactionCookie(res, 'foo', {
        sameSite: 'Lax',
      });

      await transientHandlerHttp.setTransactionCookie(res, 'foo', {
        sameSite: 'Lax',
      });

      expect(res.cookieCalls).to.have.length(2);

      expect(res.cookieCalls[0]).to.match(/HttpOnly; Secure; SameSite=Lax$/);
      expect(res.cookieCalls[1]).to.match(/HttpOnly; SameSite=Lax$/);
    });

    it('should set SameSite=None, secure, and fallback cookie by default', async () => {
      await transientHandler.setTransactionCookie(res, 'test_nonce');

      expect(res.cookieCalls).to.have.length(2);

      expect(res.cookieCalls[0]).to.match(/HttpOnly; Secure; SameSite=None$/);
      expect(res.cookieCalls[1]).to.match(/HttpOnly$/);
    });

    it('should turn off fallback', async () => {
      transientHandler = new TransientCookieHandler({
        ...defaultConfig,
        secret,
        legacySameSiteCookie: false,
      });
      await transientHandler.setTransactionCookie(res, 'test_key');

      expect(res.cookieCalls).to.have.length(1);

      expect(res.cookieCalls[0]).to.match(/HttpOnly; Secure; SameSite=None$/);
    });

    it('should set custom SameSite with no fallback', async () => {
      await transientHandler.setTransactionCookie(res, 'foo', { sameSite: 'Lax' });

      expect(res.cookieCalls).to.have.length(1);

      expect(res.cookieCalls[0]).to.match(/HttpOnly; SameSite=Lax$/);
    });
  });

  describe('getOnce()', () => {
    it('should return undefined if there are no cookies', async () => {
      expect(await transientHandler.getOnce('test_key', reqWithCookies(), res)).to.be.undefined;
    });

    it('should return main value and delete both cookies by default', async () => {
      const signature = generateSignature(defaultConfig.transactionCookie.name, 'foo');
      const cookies = {
        [defaultConfig.transactionCookie.name]: `foo.${signature}`,
        [`_${defaultConfig.transactionCookie.name}`]: `foo.${signature}`,
      };
      const req = reqWithCookies(cookies);
      const value = await transientHandler.getOnce(defaultConfig.transactionCookie.name, req, res);

      expect(value).to.equal('foo');

      expect(res.cookieCalls).to.have.length(2);

      expect(res.cookieCalls[0]).to.equal(`${defaultConfig.transactionCookie.name}=; SameSite=Lax`);
      expect(res.cookieCalls[1]).to.equal(`_${defaultConfig.transactionCookie.name}=`);
    });

    it('should delete both cookies with a secure iframe config', async () => {
      const transientHandlerHttpsIframe = new TransientCookieHandler({
        ...defaultConfig,
        secret,
        session: { cookie: { secure: true, sameSite: 'None' } },
        transactionCookie: {
          name: 'test_key',
        },
        legacySameSiteCookie: true,
      });
      const signature = generateSignature('test_key', 'foo');
      const cookies = {
        test_key: `foo.${signature}`,
        _test_key: `foo.${signature}`,
      };
      const req = reqWithCookies(cookies);
      const value = await transientHandlerHttpsIframe.getOnce('test_key', req, res);

      expect(value).to.equal('foo');

      expect(res.cookieCalls).to.have.length(2);

      expect(res.cookieCalls[0]).to.include('test_key=;');
      expect(res.cookieCalls[1]).to.equal('_test_key=');
    });

    it('should return fallback value and delete both cookies if main value not present', async () => {
      const cookies = {
        [defaultConfig.transactionCookie.name]: `foo.${generateSignature(defaultConfig.transactionCookie.name, 'foo')}`,
      };
      const req = reqWithCookies(cookies);
      const value = await transientHandler.getOnce(defaultConfig.transactionCookie.name, req, res);

      expect(value).to.equal('foo');

      expect(res.cookieCalls).to.have.length(2);

      expect(res.cookieCalls[0]).to.include(`${defaultConfig.transactionCookie.name}=;`);
    });

    it('should NOT delete fallback cookie if legacy support is off', async () => {
      const signature = generateSignature(defaultConfig.transactionCookie.name, 'foo');
      const cookies = {
        [defaultConfig.transactionCookie.name]: `foo.${signature}`,
        [`_${defaultConfig.transactionCookie.name}`]: `foo.${signature}`,
      };
      const req = reqWithCookies(cookies);
      transientHandler = new TransientCookieHandler({
        ...defaultConfig,
        legacySameSiteCookie: false,
      });
      const value = await transientHandler.getOnce(defaultConfig.transactionCookie.name, req, res);

      expect(value).to.equal('foo');

      expect(res.cookieCalls).to.have.length(1);

      expect(res.cookieCalls[0]).to.include(`${defaultConfig.transactionCookie.name}=;`);
    });

    it("should not throw when it can't verify the signature", async () => {
      const cookies = {
        test_key: 'foo.bar',
        _test_key: 'foo.bar',
      };
      const req = reqWithCookies(cookies);
      const value = await transientHandler.getOnce('test_key', req, res);

      expect(value).to.be.undefined;

      expect(res.cookieCalls).to.have.length(2);
    });
  });
});
