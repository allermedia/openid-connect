import fs from 'node:fs';

import nock from 'nock';

import { getClient } from '../src/client.js';
import { getConfig } from '../src/config.js';

import wellKnown from './fixture/well-known.json' with { type: 'json' };

describe('client initialization', () => {
  describe('default case', () => {
    const config = getConfig({
      secret: '__test_session_secret__',
      clientID: '__test_client_id__',
      clientSecret: '__test_client_secret__',
      issuerBaseURL: 'https://op.example.com',
      baseURL: 'https://example.org',
    });

    before(() => {
      return nock('https://op.example.com/').get('/.well-known/openid-configuration').reply(200, wellKnown);
    });
    after(nock.cleanAll);

    let client;
    beforeEach(async () => {
      ({ client } = await getClient(config));
    });

    it('should save the passed values', () => {
      expect(client.client_id).to.equal('__test_client_id__');
      expect(client.client_secret).to.be.undefined;
    });
  });

  describe('idTokenSigningAlg configuration is not overridden by discovery server', () => {
    const config = getConfig({
      secret: '__test_session_secret__',
      clientID: '__test_client_id__',
      clientSecret: '__test_client_secret__',
      issuerBaseURL: 'https://op.aller.local',
      baseURL: 'https://example.org',
      idTokenSigningAlg: 'RS256',
    });

    it('should prefer user configuration regardless of idP discovery', async () => {
      nock('https://op.aller.local')
        .get('/.well-known/openid-configuration')
        .reply(200, { ...wellKnown, issuer: 'https://op.aller.local', id_token_signing_alg_values_supported: ['none'] });

      const { client } = await getClient(config);
      expect(client.configuration.clientMetadata().id_token_signed_response_alg).to.equal('RS256');
    });
  });

  describe('client respects httpUserAgent configuration', () => {
    before(() => {
      return nock('https://op.example.com/').get('/.well-known/openid-configuration').reply(200, wellKnown).persist();
    });
    after(nock.cleanAll);

    it('should accept httpUserAgent configuration', async () => {
      const config = getConfig({
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        issuerBaseURL: 'https://op.example.com',
        baseURL: 'https://example.org',
        httpUserAgent: 'custom-user-agent',
      });

      const { client } = await getClient(config);
      expect(client).to.be.ok; // Configuration is accepted
    });
  });

  describe('client respects pushedAuthorizationRequests configuration', () => {
    afterEach(() => {
      nock.cleanAll();
    });

    it('should fail if configured with PAR and issuer has no PAR endpoint', async () => {
      const config = getConfig({
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        issuerBaseURL: 'https://op.aller.local',
        baseURL: 'https://example.org',
        pushedAuthorizationRequests: true,
      });

      const { pushed_authorization_request_endpoint, ...rest } = wellKnown;
      nock('https://op.aller.local')
        .persist()
        .get('/.well-known/openid-configuration')
        .reply(200, { ...rest, issuer: config.issuerBaseURL });

      try {
        await getClient(config);
      } catch (err) {
        // eslint-disable-next-line no-var
        var error = err;
      }
      expect(error.message).to.equal(
        `pushed_authorization_request_endpoint must be configured on the issuer to use pushedAuthorizationRequests`
      );
    });

    it('should succeed if configured with PAR and issuer has PAR endpoint', async () => {
      const config = getConfig({
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        clientSecret: '__test_client_secret__',
        issuerBaseURL: 'https://op.aller.local',
        baseURL: 'https://example.org',
        pushedAuthorizationRequests: true,
      });

      nock('https://op.aller.local')
        .persist()
        .get('/.well-known/openid-configuration')
        .reply(200, { ...wellKnown, issuer: config.issuerBaseURL });

      const { client } = await getClient(config);
      expect(client).to.be.ok;
    });
  });

  describe('client respects clientAssertionSigningAlg configuration', () => {
    before(() => {
      return nock('https://op.example.com/').get('/.well-known/openid-configuration').reply(200, wellKnown).persist();
    });
    after(nock.cleanAll);

    it('should accept clientAssertionSigningKey configuration', async () => {
      const config = getConfig({
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        issuerBaseURL: 'https://op.example.com',
        baseURL: 'https://example.org',
        authorizationParams: {
          response_type: 'code',
        },
        clientAssertionSigningKey: fs.readFileSync('./test/fixture/private-key.pem'),
        clientAssertionSigningAlg: 'RS256',
      });

      const { client } = await getClient(config);
      expect(client).to.be.ok;
    });
  });

  describe('client cache behavior', () => {
    before(() => {
      return nock('https://op.example.com/').get('/.well-known/openid-configuration').reply(200, wellKnown).persist();
    });
    after(nock.cleanAll);

    it('should create client successfully', async () => {
      const config = getConfig({
        secret: '__test_session_secret__',
        clientID: '__test_cache_client_id__',
        clientSecret: '__test_client_secret__',
        issuerBaseURL: 'https://op.example.com',
        baseURL: 'https://example.org',
      });

      const { client } = await getClient(config);
      expect(client).to.be.ok;
      expect(client.client_id).to.equal('__test_cache_client_id__');
    });

    it('should handle different configurations', async () => {
      const config1 = getConfig({
        secret: '__test_session_secret__',
        clientID: '__test_client_1__',
        clientSecret: '__test_client_secret__',
        issuerBaseURL: 'https://op.example.com',
        baseURL: 'https://example.org',
      });

      const config2 = getConfig({
        secret: '__test_session_secret__',
        clientID: '__test_client_2__',
        clientSecret: '__test_client_secret__',
        issuerBaseURL: 'https://op.example.com',
        baseURL: 'https://example.org',
      });

      const { client: client1 } = await getClient(config1);
      const { client: client2 } = await getClient(config2);

      expect(client1.client_id).to.equal('__test_client_1__');
      expect(client2.client_id).to.equal('__test_client_2__');
    });

    it('should accept discoveryCacheMaxAge configuration', async () => {
      const config = getConfig({
        secret: '__test_session_secret__',
        clientID: '__test_cache_client_id__',
        clientSecret: '__test_client_secret__',
        issuerBaseURL: 'https://op.example.com',
        baseURL: 'https://example.org',
        discoveryCacheMaxAge: 20 * 60 * 1000, // 20 minutes
      });

      const { client } = await getClient(config);
      expect(client).to.be.ok;
    });
  });
});
