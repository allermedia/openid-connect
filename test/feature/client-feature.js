import { randomUUID, subtle, KeyObject } from 'node:crypto';
import fs from 'node:fs/promises';

import { auth } from '@aller/openid-connect';
import { jwtVerify } from 'jose';
import nock from 'nock';
import request from 'supertest';

import pkg from '../../package.json' with { type: 'json' };
import { makeIdToken } from '../fixture/cert.js';
import { createApp } from '../fixture/server.js';
import { setupDiscovery } from '../helpers/openid-helper.js';

Feature('OpenID client', () => {
  Scenario('default configuration with insecure issuer', () => {
    const issuer = 'http://insecure.local';
    before(() => {
      setupDiscovery(issuer);
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.Agent} */
    let agent;
    Given('an app is setup with minimal configuration', () => {
      app = createApp(
        auth({
          secret: 'supers3cret',
          baseURL: 'http://example.local',
          clientID: 'insecure-client-id',
          issuerBaseURL: issuer,
          allowInsecureRequests: true,
        })
      );
      agent = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    When('user logs in', async () => {
      response = await agent.get('/login');
    });

    Then('user is redirected to issuer with default configuration', () => {
      expect(response.statusCode, response.text).to.equal(302);
      const authUrl = new URL(response.get('location'));

      expect(authUrl.pathname).to.equal('/authorize');

      const qs = Object.fromEntries(authUrl.searchParams);
      expect(qs, 'authentication parameters').to.deep.include({
        response_type: 'code',
        scope: 'openid profile email',
        code_challenge_method: 'S256',
        client_id: 'insecure-client-id',
      });
    });
  });

  Scenario('client is setup with custom headers', () => {
    const issuer = 'https://op.example.com/';
    before(() => {
      nock(issuer)
        .get('/.well-known/openid-configuration')
        .matchHeader('traceparent', '00-traceid-spanid-00')
        .matchHeader('user-agent', `${pkg.name}/v${pkg.version}`)
        .reply(200, {
          issuer,
          authorization_endpoint: new URL('/authorize', issuer),
          token_endpoint: new URL('/oauth/token', issuer),
          userinfo_endpoint: new URL('/userinfo', issuer),
          jwks_uri: new URL('/.well-known/jwks.json', issuer),
          end_session_endpoint: new URL('/session/end', issuer),
          introspection_endpoint: new URL('/introspection', issuer),
          id_token_signing_alg_values_supported: ['RS256', 'HS256'],
          response_types_supported: ['code', 'id_token', 'code id_token'],
          response_modes_supported: ['query', 'fragment', 'form_post'],
          subject_types_supported: ['public'],
          scopes_supported: ['openid', 'profile', 'email'],
        });
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.Agent} */
    let agent;
    Given('an app is setup with custom client fetch method that adds header', () => {
      app = createApp(
        auth({
          secret: ['newsupers3cret', 'supers3cret'],
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: 'https://op.example.com',
          authRequired: false,
          customFetch(uri, options) {
            options.headers = {
              ...options.headers,
              'user-agent': `${pkg.name}/v${pkg.version}`,
              traceparent: '00-traceid-spanid-00',
            };

            return fetch(uri, options);
          },
        })
      );
      agent = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    When('user logs in and callback is called', async () => {
      response = await agent.get('/login');

      expect(response.statusCode, response.text).to.equal(302);
      const authCallUrl = new URL(response.get('location'));

      nock(issuer)
        .post('/oauth/token')
        .matchHeader('traceparent', '00-traceid-spanid-00')
        .matchHeader('user-agent', `${pkg.name}/v${pkg.version}`)
        .reply(200, {
          id_token: await makeIdToken({ iss: issuer, nonce: authCallUrl.searchParams.get('nonce'), sub: randomUUID() }),
          access_token: randomUUID(),
          refresh_token: randomUUID(),
          token_type: 'Bearer',
        });

      response = await agent.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });
    });

    Then('user is redirected back to content', () => {
      expect(response.statusCode, response.text).to.equal(302);
    });

    When('user refresh tokens', async () => {
      nock(issuer)
        .post('/oauth/token')
        .matchHeader('traceparent', '00-traceid-spanid-00')
        .reply(200, {
          id_token: await makeIdToken({}),
          access_token: randomUUID(),
          refresh_token: randomUUID(),
          token_type: 'Bearer',
        });

      response = await agent.get('/refresh');
    });

    Then('user is redirected back to content', () => {
      expect(response.statusCode, response.text).to.equal(307);
    });

    When('user makes POST AJAX call to refresh tokens', async () => {
      nock('https://op.example.com')
        .post('/oauth/token')
        .matchHeader('traceparent', '00-traceid-spanid-00')
        .reply(200, {
          id_token: await makeIdToken({}),
          access_token: randomUUID(),
          refresh_token: randomUUID(),
          token_type: 'Bearer',
        });

      response = await agent.post('/refresh');
    });

    Then('user is redirected with preserved verb', () => {
      expect(response.statusCode, response.text).to.equal(307);
    });
  });

  Scenario('Client JWT authentication with RSA', () => {
    const issuer = 'https://jwtrsaop.example.local';
    before(() => {
      setupDiscovery(issuer);
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.Agent} */
    let agent;
    Given('an app is setup with client authentication matching scenario', async () => {
      app = createApp(
        auth({
          secret: ['supers3cret'],
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: issuer,
          authRequired: false,
          clientAuthMethod: 'private_key_jwt',
          clientAssertionSigningKey: await fs.readFile('./test/fixture/private-key.pem'),
          clientAssertionSigningAlg: 'RS256',
        })
      );
      agent = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    When('user logs in and callback is called', async () => {
      response = await agent.get('/login');

      expect(response.statusCode, response.text).to.equal(302);
      const authCallUrl = new URL(response.get('location'));

      nock(issuer)
        .post('/oauth/token')
        .reply(200, {
          id_token: await makeIdToken({ iss: issuer, nonce: authCallUrl.searchParams.get('nonce'), sub: randomUUID() }),
          access_token: randomUUID(),
          refresh_token: randomUUID(),
          token_type: 'Bearer',
        });

      response = await agent.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });
    });

    Then('user is redirected back to content', () => {
      expect(response.statusCode, response.text).to.equal(302);
    });

    When('user refresh tokens', async () => {
      nock(issuer)
        .post('/oauth/token')
        .reply(200, {
          id_token: await makeIdToken({ iss: issuer }),
          access_token: randomUUID(),
          refresh_token: randomUUID(),
          token_type: 'Bearer',
        });

      response = await agent.get('/refresh');
    });

    Then('user is redirected back to content', () => {
      expect(response.statusCode, response.text).to.equal(307);
    });
  });

  Scenario('Client JWT authentication with elliptic curve client auth method', () => {
    const issuer = 'https://jwtop.example.local';
    before(() => {
      setupDiscovery(issuer);
    });

    /** @type {Awaited<ReturnType<import('node:crypto')['subtle']['generateKey']>>} */
    let keyPair;
    Given('EdDSA key pair exist', async () => {
      keyPair = await subtle.generateKey('Ed25519', true, ['sign', 'verify']);
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.Agent} */
    let agent;
    And('an app is setup with client authentication matching scenario', () => {
      app = createApp(
        auth({
          secret: ['supers3cret'],
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: issuer,
          authRequired: false,
          clientAuthMethod: 'private_key_jwt',
          clientAssertionSigningKey: keyPair.privateKey,
        })
      );
      agent = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    When('user logs in and callback is called', async () => {
      response = await agent.get('/login');

      expect(response.statusCode, response.text).to.equal(302);
      const authCallUrl = new URL(response.get('location'));

      nock(issuer)
        .post('/oauth/token')
        .reply(200, async (_uri, body) => {
          await jwtVerify(new URLSearchParams(body).get('client_assertion'), keyPair.publicKey);

          return {
            id_token: await makeIdToken({ iss: issuer, nonce: authCallUrl.searchParams.get('nonce'), sub: randomUUID() }),
            access_token: randomUUID(),
            refresh_token: randomUUID(),
            token_type: 'Bearer',
          };
        });

      response = await agent.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });
    });

    Then('user is redirected back to content', () => {
      expect(response.statusCode, response.text).to.equal(302);
    });

    When('user refresh tokens', async () => {
      nock(issuer)
        .post('/oauth/token')
        .reply(200, async (_uri, body) => {
          await jwtVerify(new URLSearchParams(body).get('client_assertion'), keyPair.publicKey);

          return {
            id_token: await makeIdToken({ iss: issuer }),
            access_token: randomUUID(),
            refresh_token: randomUUID(),
            token_type: 'Bearer',
          };
        });

      response = await agent.get('/refresh');
    });

    Then('user is redirected back to content', () => {
      expect(response.statusCode, response.text).to.equal(307);
    });
  });

  Scenario('Client JWT authentication with imported elliptic curve', () => {
    const issuer = 'https://jwtop.example.local';
    before(() => {
      setupDiscovery(issuer);
    });

    /** @type {Awaited<ReturnType<import('node:crypto')['subtle']['generateKey']>>} */
    let keyPair;
    Given('EdDSA key pair exist', async () => {
      keyPair = await subtle.generateKey('Ed25519', true, ['sign', 'verify']);
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.Agent} */
    let agent;
    And('an app is setup with client authentication matching scenario', () => {
      app = createApp(
        auth({
          secret: ['supers3cret'],
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: 'https://jwtop.example.local',
          authRequired: false,
          clientAssertionSigningAlg: 'EdDSA',
          clientAuthMethod: 'private_key_jwt',
          clientAssertionSigningKey: KeyObject.from(keyPair.privateKey).export({ format: 'pem', type: 'pkcs8' }).toString(),
        })
      );
      agent = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    When('user logs in and callback is called', async () => {
      response = await agent.get('/login');

      expect(response.statusCode, response.text).to.equal(302);
      const authCallUrl = new URL(response.get('location'));

      nock(issuer)
        .post('/oauth/token')
        .reply(200, async (_uri, body) => {
          await jwtVerify(new URLSearchParams(body).get('client_assertion'), keyPair.publicKey);

          return {
            id_token: await makeIdToken({ iss: issuer, nonce: authCallUrl.searchParams.get('nonce'), sub: randomUUID() }),
            access_token: randomUUID(),
            refresh_token: randomUUID(),
            token_type: 'Bearer',
          };
        });

      response = await agent.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });
    });

    Then('user is redirected back to content', () => {
      expect(response.statusCode, response.text).to.equal(302);
    });

    When('user refresh tokens', async () => {
      nock(issuer)
        .post('/oauth/token')
        .reply(200, async (_uri, body) => {
          await jwtVerify(new URLSearchParams(body).get('client_assertion'), keyPair.publicKey);

          return {
            id_token: await makeIdToken({ iss: issuer }),
            access_token: randomUUID(),
            refresh_token: randomUUID(),
            token_type: 'Bearer',
          };
        });

      response = await agent.get('/refresh');
    });

    Then('user is redirected back to content', () => {
      expect(response.statusCode, response.text).to.equal(307);
    });
  });

  Scenario('Client JWT authentication with unsupported algorithm', () => {
    const issuer = 'https://jwtunsupported.example.local';
    before(() => {
      setupDiscovery(issuer);
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.Agent} */
    let agent;
    And('an app is setup with client authentication matching scenario', async () => {
      app = createApp(
        auth({
          secret: ['supers3cret'],
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: issuer,
          authRequired: false,
          clientAssertionSigningAlg: 'UnSUP',
          clientAuthMethod: 'private_key_jwt',
          clientAssertionSigningKey: await fs.readFile('./test/fixture/private-key.pem'),
        })
      );
      agent = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    When('user attempts to log in', async () => {
      response = await agent.get('/login');
    });

    Then('an error is thrown', () => {
      expect(response.statusCode, response.text).to.equal(500);
      expect(response.body?.err).to.have.property('code', 'ERR_JOSE_NOT_SUPPORTED');
    });
  });

  Scenario('OpenID server lacks end session endpoint but client expects to logout from IdP', () => {
    const issuer = 'https://nosessionend.example.local';
    before(() => {
      setupDiscovery(issuer, { end_session_endpoint: undefined });
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.Agent} */
    let agent;
    Given('an app is setup with enabled IdP logout', () => {
      app = createApp(
        auth({
          secret: ['supers3cret'],
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: issuer,
          authRequired: false,
          idpLogout: true,
        })
      );
      agent = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    And('user is logged in', async () => {
      response = await agent.get('/login');

      expect(response.statusCode, response.text).to.equal(302);
      const authCallUrl = new URL(response.get('location'));

      nock(issuer)
        .post('/oauth/token')
        .reply(200, {
          id_token: await makeIdToken({ iss: issuer, nonce: authCallUrl.searchParams.get('nonce'), sub: randomUUID() }),
          access_token: randomUUID(),
          refresh_token: randomUUID(),
          token_type: 'Bearer',
        });

      return agent
        .get('/callback')
        .query({
          code: randomUUID(),
          state: authCallUrl.searchParams.get('state'),
        })
        .expect(302);
    });

    When('user attempts to log out from IdP', async () => {
      response = await agent.get('/logout');
    });

    Then('internal server error is returned', () => {
      expect(response.statusCode, response.text).to.equal(500);
    });
  });
});
