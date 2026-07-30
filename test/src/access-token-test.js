import { AccessToken } from '../../src/access-token.js';
import { SESSION } from '../../src/constants.js';

describe('access token', () => {
  describe('without a session', () => {
    const accessToken = new AccessToken({}, /** @type {any} */ ({}), /** @type {any} */ ({}));

    it('expires_in is undefined', () => {
      expect(accessToken.expires_in).to.be.undefined;
    });

    it('isExpired() returns false', () => {
      expect(accessToken.isExpired()).to.be.false;
    });

    it('toJSON() returns undefined', () => {
      expect(accessToken.toJSON()).to.be.undefined;
    });
  });

  describe('with a session lacking expires_at', () => {
    const req = /** @type {any} */ ({ [SESSION]: { access_token: '__token__', token_type: 'Bearer' } });
    const accessToken = new AccessToken({}, req, /** @type {any} */ ({}));

    it('expires_in is undefined', () => {
      expect(accessToken.expires_in).to.be.undefined;
    });

    it('isExpired() returns false', () => {
      expect(accessToken.isExpired()).to.be.false;
    });

    it('toJSON() returns token without expiry', () => {
      expect(accessToken.toJSON()).to.deep.include({ access_token: '__token__', token_type: 'Bearer' });
    });
  });

  describe('with a session holding expires_at', () => {
    it('expires_in counts down to expires_at and isExpired() switches when passed', () => {
      const nowEpoch = Math.floor(Date.now() / 1000);

      const fresh = new AccessToken({}, /** @type {any} */ ({ [SESSION]: { expires_at: nowEpoch + 100 } }), /** @type {any} */ ({}));
      expect(fresh.expires_in).to.be.within(99, 100);
      expect(fresh.isExpired()).to.be.false;

      const expired = new AccessToken({}, /** @type {any} */ ({ [SESSION]: { expires_at: nowEpoch - 100 } }), /** @type {any} */ ({}));
      expect(expired.expires_in).to.equal(0);
      expect(expired.isExpired()).to.be.true;
    });
  });
});
