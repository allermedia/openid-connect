import { DefaultCookieStore, CustomCookieStore } from '../../src/cookie-store.js';
import { CustomStore } from '../helpers/custom-store.js';

describe('cookie store', () => {
  describe('default cookie store', () => {
    it('await set(req) returns undefined', async () => {
      const store = new DefaultCookieStore({ session: { name: 'test', cookie: {} } });

      expect(await store.set({})).to.be.undefined;
    });
  });

  describe('custom cookie store', () => {
    it('await set(req) returns undefined', async () => {
      const store = new CustomCookieStore({ session: { name: 'test', store: new CustomStore(), cookie: {} } });

      expect(await store.set({}, { iat: Date.now() })).to.be.undefined;
    });
  });
});
