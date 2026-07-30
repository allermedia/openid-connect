import { Session } from '../../src/session.js';

function makeUnsignedJwt(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.`;
}

describe('session', () => {
  describe('getClaims()', () => {
    it('lazily decodes claims from id_token when not already cached', () => {
      const session = new Session({ id_token: makeUnsignedJwt({ sub: '__sub__', sid: '__sid__' }) }, { iat: 1 });

      expect(session.getClaims()).to.deep.include({ sub: '__sub__', sid: '__sid__' });
      expect(session.getClaims(), 'second call uses cached claims').to.deep.include({ sub: '__sub__' });
    });

    it('returns sid only when session has no id_token', () => {
      const session = new Session({ sid: '__sid__' }, { iat: 1 });

      expect(session.getClaims()).to.deep.equal({ sid: '__sid__' });
    });
  });

  describe('decorate()', () => {
    it('throws a TypeError on non-object decoration data', () => {
      const session = new Session({}, { iat: 1 });

      expect(() => session.decorate(/** @type {any} */ ('not an object'))).to.throw(TypeError, /must be an object/);
    });
  });
});
