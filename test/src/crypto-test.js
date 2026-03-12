import { compactDecrypt } from 'jose';
import { JWE } from 'jose-v2';

import * as freshCrypto from '../../src/crypto.js';
import * as legacyCrypto from '../helpers/legacy-crypto.js';

describe('crypto', () => {
  let encryptionKeyStore;
  let signingKeyStore;
  before(() => {
    encryptionKeyStore = freshCrypto.getEncryptionKeyStore('cookie-secret');
    signingKeyStore = freshCrypto.getSigningKeyStore('cookie-secret');
  });

  describe('signing', () => {
    it('legacy cookie signature should be verifiable by new functionality', async () => {
      const legacySessionCookie = legacyCrypto.signCookie('appSession', 'value', signingKeyStore[0]);

      const freshVerified = await freshCrypto.verifyCookie('appSession', legacySessionCookie, signingKeyStore);

      expect(freshVerified).to.be.ok;
    });
  });

  describe('encrypt', () => {
    it('encrypt return encrypted string that can be decrypted with jose.compactDecrypt', async () => {
      const encrypted = await freshCrypto.encrypt(encryptionKeyStore[0], 'foo');

      const { plaintext } = await compactDecrypt(encrypted, encryptionKeyStore[0]);
      expect(new TextDecoder().decode(plaintext)).to.equal('foo');
    });

    it('jose@2 JWE encrypted cookie can be decrypted with new functionality', async () => {
      const jweEncrypted = JWE.encrypt(JSON.stringify({ sub: 'subject' }), encryptionKeyStore[0], { alg: 'dir', enc: 'A256GCM' });

      const { plaintext } = await compactDecrypt(jweEncrypted, encryptionKeyStore[0]);
      expect(Buffer.from(plaintext).toString(), 'compactDecrypt plaintext').to.equal(JSON.stringify({ sub: 'subject' }));

      const { payload } = await freshCrypto.decrypt(encryptionKeyStore[0], jweEncrypted);
      expect(payload, 'crypto plaintext').to.equal(JSON.stringify({ sub: 'subject' }));
    });

    it('freshly encrypted cookie can be decrypted with jose@2 JWE', async () => {
      const jweEncrypted = await freshCrypto.encrypt(encryptionKeyStore[0], JSON.stringify({ sub: 'subject' }));

      const { plaintext } = await compactDecrypt(jweEncrypted, encryptionKeyStore[0]);
      expect(Buffer.from(plaintext).toString(), 'compactDecrypt plaintext').to.equal(JSON.stringify({ sub: 'subject' }));

      const { cleartext } = JWE.decrypt(jweEncrypted, encryptionKeyStore[0], {
        complete: true,
        contentEncryptionAlgorithms: ['A256GCM'],
        keyManagementAlgorithms: ['dir'],
      });

      expect(cleartext.toString(), 'JWE plaintext').to.equal(JSON.stringify({ sub: 'subject' }));
    });

    it('saved old cookie can be verified with legacy functionality', async () => {
      const appSession =
        'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiaWF0IjoxNzczMTUzNTIyLCJ1YXQiOjE3NzMxNTM1MjIsImV4cCI6MTc3MzE1NzEyMn0..MR1J4CT1_VlKnQyg.peD8N42QGT1QNN5X0hMz779kWr9sIn0dsCwFgYQ8M-6sGKtiT_20pypEGyS3LljS2_GldOrG1LsaGFFTrGq4jHONFDkoP3pU-h090qePIeor4bSxVJSiyuWTx8kWJfrKzTXmCEqdHATY6F0FfsB7oSzSUf2gcNoMwP-GXa8SkHdFpTg6qUEdrXavmCmUOQeO99YYsBZH_XUcA8SPN7VXbgCzZJPWa-OmEQ6C4keTqtj_i_NF7HHAJUuVPTVKyaAdfzhZhJDZplPGOHYZheoIKm-jMTmaYP84Q3XmR9yYlERMzZubTTgrgvYsuqQ7yOKDnkS8utx0lhwqdKXUFHrUXxd-TY46fMC69UAE1_Bj5Jo0AOBmyaMw63c9T5ibrOVb8FXvFwC2n0SIur8W_4kPMAr5aTEv2ncqimTzNA31XPForfpdecCHqH5iLqTa5aWRwASC9t04i8QsdazJa29Qj7S1lqo5VaRERrZqkdzGd9lxeuw3zjsPr8l8RJtp8ErRIltXRrBQMyPWJI1UsjxvzpOC-fEWcN6NNOQpjpqCssC1ACdZBZjPoZjwOEPK582waMNDjbqeKG-nYpDT6_RxKF9SRuHQZpGDVd4wZirKfMtuNQlymrAEYIVqcohkspNdj_KM4hGxIGV8Z9g62ycc183opmsh4R8UXK17RSMdr1FyRkV5ivf2bcD6nCxmWGcGtY3W6J_Vecz6BcNq7tCX5i_m80UW9xSy0mYp8qEZNnfZ4HbEAzA5QbHe3dw5VbgO3R0k9g2PvxRMffUVaujOSnoC1fCIU-E9cfLcnE-Uknnj2k9qAp7eXkcgLM8zPMjIt6jnuSBe4GiLamlhPcPUSSSW-6A8gKvW_kU2LN2SpA21vBhWqpg64VBQkKLNSYEEz-ge08zm7I2YYs46p0_wB05vJqtaxOoQU2Yc1DtdNp7R8e1joNPPqxSNS8qkzCleow594Yu0zvOGKtmwda3Pnt2jkyhPYFNzE_c1hKA7JPptKQ3YmPyok4d0zVWt61UETEj7MGEHdfEDH7YfeDLkQglVq8-xTSG8wOLN-VgIws7CRZy0mxg_Af2CQl9OZd2kHP-j_HlvBKRLCm5_u0ZLi5KVeF9hsKPH2E_eTkCyWIlbsMQSXnhJofCb0wDGb2y_Uaow_pGmotIw9CrOzZieYhZ2_z3STE8oAJU6ctxJF6BruON3b2TTkS15AMvwCNqvvrEV_29zjsLYTbZ0C23j-m1UkIKY9I-GqMtbkGIw9fF7tmEowhuzsTIWC-7HxaEfWLL5Z7SAs9rRORrUMIGUVyMnsgnRtlgO7rQgutkofdJyy6Jdc7wEVf1W-fcRPxOo3Lw3xYFhtgyYIQmXuQrZNR3GE3iQLkUonZh1_awtd5gK8myBCfM3nIOU8_RO1vK-EKCqq10-QSpPQWTyW5tMWS1Et5MOvRT1uXf9_d8NsRe2V2l3CXoDbqwcdHRRMHvzXA64ZnzLe4hKku6McsVNISXcBojxQozWCqIozdPgFdC1mXVdc3BGIEnB55VcRZVmgx6xgbj2XMYyXq9fu727hnMlHbtWWWNZ1YuF96wYLf_IQoqvye_N_D8jzBxqFpGFZOqL5Um9yGXztRuHZvOlN7KVTcu5vWgeQ9B_tTxsP4iLd2AUJ3kC6bhptR_TUcC5TC9SLJV_0ZJlLUhgQE9GT8c3zBwI09IDh4c7xNYDPuGHcug3MC-1iZ7JnfUgN3WbfsaBPk1KrnZS.yzjEFrnMJ12frUz-lS7eKA';

      const { plaintext } = await compactDecrypt(appSession, encryptionKeyStore[0]);
      expect(Buffer.from(plaintext).toString(), 'compactDecrypt plaintext').to.contain('access_token');

      const { cleartext } = JWE.decrypt(appSession, encryptionKeyStore[0], {
        complete: true,
        contentEncryptionAlgorithms: ['A256GCM'],
        keyManagementAlgorithms: ['dir'],
      });

      expect(Buffer.from(cleartext).toString(), 'compactDecrypt plaintext').to.contain('access_token');
    });

    it('saved old cookie can be decrypted with fresh functionality', async () => {
      const appSession =
        'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiaWF0IjoxNzczMTUzNTIyLCJ1YXQiOjE3NzMxNTM1MjIsImV4cCI6MTc3MzE1NzEyMn0..MR1J4CT1_VlKnQyg.peD8N42QGT1QNN5X0hMz779kWr9sIn0dsCwFgYQ8M-6sGKtiT_20pypEGyS3LljS2_GldOrG1LsaGFFTrGq4jHONFDkoP3pU-h090qePIeor4bSxVJSiyuWTx8kWJfrKzTXmCEqdHATY6F0FfsB7oSzSUf2gcNoMwP-GXa8SkHdFpTg6qUEdrXavmCmUOQeO99YYsBZH_XUcA8SPN7VXbgCzZJPWa-OmEQ6C4keTqtj_i_NF7HHAJUuVPTVKyaAdfzhZhJDZplPGOHYZheoIKm-jMTmaYP84Q3XmR9yYlERMzZubTTgrgvYsuqQ7yOKDnkS8utx0lhwqdKXUFHrUXxd-TY46fMC69UAE1_Bj5Jo0AOBmyaMw63c9T5ibrOVb8FXvFwC2n0SIur8W_4kPMAr5aTEv2ncqimTzNA31XPForfpdecCHqH5iLqTa5aWRwASC9t04i8QsdazJa29Qj7S1lqo5VaRERrZqkdzGd9lxeuw3zjsPr8l8RJtp8ErRIltXRrBQMyPWJI1UsjxvzpOC-fEWcN6NNOQpjpqCssC1ACdZBZjPoZjwOEPK582waMNDjbqeKG-nYpDT6_RxKF9SRuHQZpGDVd4wZirKfMtuNQlymrAEYIVqcohkspNdj_KM4hGxIGV8Z9g62ycc183opmsh4R8UXK17RSMdr1FyRkV5ivf2bcD6nCxmWGcGtY3W6J_Vecz6BcNq7tCX5i_m80UW9xSy0mYp8qEZNnfZ4HbEAzA5QbHe3dw5VbgO3R0k9g2PvxRMffUVaujOSnoC1fCIU-E9cfLcnE-Uknnj2k9qAp7eXkcgLM8zPMjIt6jnuSBe4GiLamlhPcPUSSSW-6A8gKvW_kU2LN2SpA21vBhWqpg64VBQkKLNSYEEz-ge08zm7I2YYs46p0_wB05vJqtaxOoQU2Yc1DtdNp7R8e1joNPPqxSNS8qkzCleow594Yu0zvOGKtmwda3Pnt2jkyhPYFNzE_c1hKA7JPptKQ3YmPyok4d0zVWt61UETEj7MGEHdfEDH7YfeDLkQglVq8-xTSG8wOLN-VgIws7CRZy0mxg_Af2CQl9OZd2kHP-j_HlvBKRLCm5_u0ZLi5KVeF9hsKPH2E_eTkCyWIlbsMQSXnhJofCb0wDGb2y_Uaow_pGmotIw9CrOzZieYhZ2_z3STE8oAJU6ctxJF6BruON3b2TTkS15AMvwCNqvvrEV_29zjsLYTbZ0C23j-m1UkIKY9I-GqMtbkGIw9fF7tmEowhuzsTIWC-7HxaEfWLL5Z7SAs9rRORrUMIGUVyMnsgnRtlgO7rQgutkofdJyy6Jdc7wEVf1W-fcRPxOo3Lw3xYFhtgyYIQmXuQrZNR3GE3iQLkUonZh1_awtd5gK8myBCfM3nIOU8_RO1vK-EKCqq10-QSpPQWTyW5tMWS1Et5MOvRT1uXf9_d8NsRe2V2l3CXoDbqwcdHRRMHvzXA64ZnzLe4hKku6McsVNISXcBojxQozWCqIozdPgFdC1mXVdc3BGIEnB55VcRZVmgx6xgbj2XMYyXq9fu727hnMlHbtWWWNZ1YuF96wYLf_IQoqvye_N_D8jzBxqFpGFZOqL5Um9yGXztRuHZvOlN7KVTcu5vWgeQ9B_tTxsP4iLd2AUJ3kC6bhptR_TUcC5TC9SLJV_0ZJlLUhgQE9GT8c3zBwI09IDh4c7xNYDPuGHcug3MC-1iZ7JnfUgN3WbfsaBPk1KrnZS.yzjEFrnMJ12frUz-lS7eKA';

      const freshDecrypted = await freshCrypto.decrypt(encryptionKeyStore[0], appSession);
      expect(freshDecrypted).to.be.ok.and.have.property('payload');
    });
  });
});
