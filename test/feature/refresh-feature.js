import { randomUUID } from 'node:crypto';
import { mock } from 'node:test';

import { auth, requiresAuth } from '@aller/openid-connect';
import nock from 'nock';
import request from 'supertest';

import { makeIdToken } from '../fixture/cert.js';
import { createApp } from '../fixture/server.js';
import { CustomStore } from '../helpers/custom-store.js';
import { setupDiscovery } from '../helpers/openid-helper.js';

Feature('Refresh', () => {
  afterEachScenario(() => {
    mock.timers.reset();
  });

  Scenario('user tokens expires', () => {
    before(() => {
      mock.timers.enable({ apis: ['Date'], now: Date.now() });
      setupDiscovery();
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.agent} */
    let agent;
    Given('a client server is setup', () => {
      app = createApp(
        auth({
          secret: '__test_session_secret__',
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: 'https://op.example.com',
          authRequired: false,
          authorizationParams: {
            scope: 'openid',
          },
          discoveryCacheMaxAge: 24 * 3600 * 1000,
        }),
        requiresAuth()
      );

      agent = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    When('user navigates to protected content', async () => {
      response = await agent.get('/protected');
    });

    /** @type {URL} */
    let authCallUrl;
    Then('user is redirected to Open ID server', () => {
      expect(response.statusCode, response.text).to.equal(302);

      authCallUrl = new URL(response.get('location'));
    });

    let userSub;
    let accessToken;
    let refreshToken;
    When('auth callback is called with code', async () => {
      userSub = randomUUID();
      accessToken = randomUUID();
      refreshToken = randomUUID();
      const nonce = authCallUrl.searchParams.get('nonce');
      nock('https://op.example.com')
        .post('/oauth/token')
        .query(true)
        .reply(200, {
          id_token: await makeIdToken({ nonce, sub: userSub }),
          access_token: accessToken,
          refresh_token: refreshToken,
          token_type: 'Bearer',
          expires_in: 3600,
        });

      response = await agent.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });
    });

    Then('user is redirected to return url', () => {
      expect(response.statusCode, response.text).to.equal(302);
      expect(response.get('location')).to.equal('/protected');
    });

    let cookies;
    let appSessionCookie;
    And('authentication session cookie is set', () => {
      cookies = agent.jar.getCookies({ domain: '127.0.0.1', path: '/' });
      appSessionCookie = cookies.find((c) => c.name === 'appSession');
      expect(appSessionCookie).to.deep.include({
        noscript: true,
      });
    });

    And('session cookie has access token', async () => {
      response = await agent.get('/session').expect(200);
      expect(response.body).to.deep.include({ access_token: accessToken });
    });

    Given('access token has expired', () => {
      mock.timers.tick(3601 * 1000);
    });

    let newAccessToken;
    let newRefreshToken;
    And('openid server expects refresh token call', async () => {
      newAccessToken = randomUUID();
      newRefreshToken = randomUUID();
      nock('https://op.example.com')
        .post('/oauth/token', (body) => {
          return body.refresh_token === refreshToken;
        })
        .reply(200, {
          id_token: await makeIdToken({ sub: userSub }),
          access_token: newAccessToken,
          refresh_token: newRefreshToken,
          token_type: 'Bearer',
          expires_in: 3600,
        });
    });

    When('user navigates to refresh with return to protected content', async () => {
      response = await agent.get('/refresh').query({ return_to: '/protected' });
    });

    Then('user is redirected back to return to', () => {
      expect(response.statusCode, response.text).to.equal(307);
      expect(response.get('location')).to.equal('/protected');
    });

    And('authentication session cookie is refreshed', () => {
      expect(response.get('set-cookie')).to.have.length(1);
      cookies = agent.jar.getCookies({ domain: '127.0.0.1', path: '/' });
      appSessionCookie = cookies.find((c) => c.name === 'appSession');
      expect(appSessionCookie).to.deep.include({
        noscript: true,
      });
    });

    And('session has new access token', async () => {
      response = await agent.get('/session').expect(200);
      expect(response.body).to.deep.include({ access_token: newAccessToken, refresh_token: newRefreshToken });
    });

    Given('new access token has expired', () => {
      mock.timers.tick(3601 * 1000);
    });

    let newestAccessToken;
    let newestRefreshToken;
    And('openid server expects refresh token call but fails to return id_token', () => {
      newestAccessToken = randomUUID();
      newestRefreshToken = randomUUID();
      nock('https://op.example.com')
        .post('/oauth/token', (body) => {
          return body.refresh_token === newRefreshToken;
        })
        .reply(200, {
          access_token: newestAccessToken,
          refresh_token: newestRefreshToken,
          token_type: 'Bearer',
          expires_in: 3600,
        });
    });

    When('user navigates to refresh without return to', async () => {
      response = await agent.get('/refresh');
    });

    Then('user is redirected to Open ID server', () => {
      expect(response.statusCode, response.text).to.equal(307);
      expect(response.get('location')).to.equal('/');
    });

    And('session has new access token', async () => {
      response = await agent.get('/session').expect(200);
      expect(response.body).to.deep.include({ access_token: newestAccessToken, refresh_token: newestRefreshToken });
    });
  });

  Scenario('refresh without refresh token', () => {
    before(() => {
      mock.timers.enable({ apis: ['Date'], now: Date.now() });
      setupDiscovery();
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.agent} */
    let agent;
    Given('a client server is setup', () => {
      app = createApp(
        auth({
          secret: '__test_session_secret__',
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: 'https://op.example.com',
          authRequired: false,
          authorizationParams: {
            scope: 'openid',
          },
          discoveryCacheMaxAge: 24 * 3600 * 1000,
        }),
        requiresAuth()
      );

      agent = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    let accessToken;
    When('user is authenticated without refresh token', async () => {
      response = await agent.get('/protected');
      expect(response.statusCode, response.text).to.equal(302);

      const authCallUrl = new URL(response.get('location'));

      accessToken = randomUUID();
      const nonce = authCallUrl.searchParams.get('nonce');
      nock('https://op.example.com')
        .post('/oauth/token')
        .query(true)
        .reply(200, {
          id_token: await makeIdToken({ nonce, sub: randomUUID() }),
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
        });

      response = await agent.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });

      expect(response.statusCode, response.text).to.equal(302);

      expect(response.get('location')).to.equal('/protected');
    });

    When('user navigates to refresh', async () => {
      response = await agent.get('/refresh').query({ return_to: '/protected' });
    });

    Then('bad request is returned', () => {
      expect(response.statusCode, response.text).to.equal(400);
    });

    And('session still exists', async () => {
      response = await agent.get('/session').expect(200);
      expect(response.body).to.deep.include({ access_token: accessToken });
    });
  });

  Scenario('refresh when stored session only has refresh_token', () => {
    before(() => {
      setupDiscovery();
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.agent} */
    let agent;
    Given('a client server with custom store is setup', () => {
      app = createApp(
        auth({
          secret: '__test_session_secret__',
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: 'https://op.example.com',
          authRequired: false,
          session: { store: new CustomStore() },
          authorizationParams: {
            scope: 'openid',
          },
          discoveryCacheMaxAge: 24 * 3600 * 1000,
        }),
        requiresAuth()
      );

      agent = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    let refreshToken;
    And('a session with just refresh token exists', () => {
      refreshToken = randomUUID();
      return agent.post('/session').send({ access_token: randomUUID(), refresh_token: refreshToken }).expect(200);
    });

    And('session lacks user subject', async () => {
      response = await agent.get('/session').expect(200);
      expect(response.body).to.have.property('access_token');
      expect(response.body).to.not.have.property('sub');
    });

    let freshRefreshToken;
    let freshAccessToken;
    let userSubject;
    And('issuer expects refresh token call', async () => {
      freshRefreshToken = randomUUID();
      freshAccessToken = randomUUID();
      userSubject = randomUUID();
      nock('https://op.example.com')
        .post('/oauth/token', (body) => body.refresh_token === refreshToken)
        .reply(200, {
          id_token: await makeIdToken({ sub: userSubject }),
          access_token: freshAccessToken,
          refresh_token: freshRefreshToken,
          token_type: 'Bearer',
          expires_in: 3600,
        });
    });

    When('user navigates to refresh', async () => {
      response = await agent.get('/refresh').query({ return_to: '/protected' });
    });

    Then('bad request is returned', () => {
      expect(response.statusCode, response.text).to.equal(307);
    });

    And('session still exists', async () => {
      response = await agent.get('/session').expect(200);
      expect(response.body).to.deep.include({ access_token: freshAccessToken, refresh_token: freshRefreshToken, sub: userSubject });
    });
  });

  Scenario('refresh fails to return token type', () => {
    before(() => {
      setupDiscovery();
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.agent} */
    let agent;
    Given('a client server is setup', () => {
      app = createApp(
        auth({
          secret: '__test_session_secret__',
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: 'https://op.example.com',
          authRequired: false,
          authorizationParams: {
            scope: 'openid',
          },
          discoveryCacheMaxAge: 24 * 3600 * 1000,
        }),
        requiresAuth()
      );

      agent = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    let accessToken;
    When('user is authenticated without refresh token', async () => {
      response = await agent.get('/protected');
      expect(response.statusCode, response.text).to.equal(302);

      const authCallUrl = new URL(response.get('location'));

      accessToken = randomUUID();
      const nonce = authCallUrl.searchParams.get('nonce');
      nock('https://op.example.com')
        .post('/oauth/token')
        .query(true)
        .reply(200, {
          id_token: await makeIdToken({ nonce, sub: randomUUID() }),
          access_token: accessToken,
          refresh_token: randomUUID(),
          token_type: 'Bearer',
          expires_in: 3600,
        });

      response = await agent.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });

      expect(response.statusCode, response.text).to.equal(302);

      expect(response.get('location')).to.equal('/protected');
    });

    When('token type is missing when user attempts to refresh', async () => {
      nock('https://op.example.com').post('/oauth/token').query(true).reply(200, {
        access_token: randomUUID(),
        refresh_token: randomUUID(),
        expires_in: 3600,
      });

      response = await agent.get('/refresh').query({ return_to: '/protected' });
    });

    Then('bad request is returned', () => {
      expect(response.statusCode, response.text).to.equal(400);
      expect(response.body.err).to.have.property('code', 'OAUTH_INVALID_RESPONSE');
    });

    And('session still exists', async () => {
      response = await agent.get('/session').expect(200);
      expect(response.body).to.deep.include({ access_token: accessToken });
    });
  });
});
