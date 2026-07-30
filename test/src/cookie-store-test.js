import { SESSION } from '../../src/constants.js';
import { DefaultCookieStore, CustomCookieStore } from '../../src/cookie-store.js';
import { CustomStore } from '../helpers/custom-store.js';

describe('cookie store', () => {
  describe('default cookie store', () => {
    it('await set(req) returns undefined', async () => {
      const store = new DefaultCookieStore({ session: { name: 'test', cookie: {} } });

      expect(await store.set(/** @type {any} */ ({}))).to.be.undefined;
    });

    it('set(req) updates uat header when request has a session', async () => {
      const store = new DefaultCookieStore({ session: { name: 'test', cookie: {} } });
      const session = { headers: {} };

      await store.set(/** @type {any} */ ({ [SESSION]: session }));

      expect(session.headers.uat).to.be.a('number');
    });

    it('api(req).replaceSession(session) replaces the request session', async () => {
      const store = new DefaultCookieStore({ session: { name: 'test', cookie: {} } });
      const req = /** @type {any} */ ({});
      const session = /** @type {any} */ ({ headers: {} });

      await store.api(req).replaceSession(session);

      expect(req[SESSION]).to.equal(session);
    });
  });

  describe('custom cookie store', () => {
    it('await set(req) returns undefined', async () => {
      const store = new CustomCookieStore({ session: { name: 'test', store: new CustomStore(), cookie: {} } });

      expect(await store.set(/** @type {any} */ ({}))).to.be.undefined;
    });

    it('getSession(req) rejects an expired stored session', async () => {
      const expiredStore = /** @type {any} */ ({
        get() {
          return { header: { iat: 1, uat: 1, exp: 2 }, data: {} };
        },
      });
      const store = new CustomCookieStore({ session: { name: 'test', store: expiredStore, cookie: {} } });
      const req = /** @type {any} */ ({ get: () => 'test=some-session-id' });

      expect(await store.getSession(req)).to.be.undefined;
    });

    it('getSession(req) returns undefined when the store throws an unexpected error', async () => {
      const brokenStore = /** @type {any} */ ({
        get() {
          throw new Error('store is down');
        },
      });
      const store = new CustomCookieStore({ session: { name: 'test', store: brokenStore, cookie: {} } });
      const req = /** @type {any} */ ({ get: () => 'test=some-session-id' });

      expect(await store.getSession(req)).to.be.undefined;
    });
  });
});
