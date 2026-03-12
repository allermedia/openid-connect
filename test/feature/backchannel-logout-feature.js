import { randomUUID } from 'node:crypto';
import { mock } from 'node:test';

import { auth, requiresAuth } from '@aller/openid-connect';
import nock from 'nock';
import request from 'supertest';

import { makeIdToken, makeLogoutToken, makeProperLogoutToken } from '../fixture/cert.js';
import { createApp } from '../fixture/server.js';
import { CustomStore } from '../helpers/custom-store.js';
import { setupDiscovery, setupJwks } from '../helpers/openid-helper.js';

Feature('Backchannel logout', () => {
  /** @type {CustomStore} */
  let store;
  /** @type {import('express').Application} */
  let app;
  before('a client server is setup with a custom store', () => {
    store = new CustomStore();

    app = createApp(
      auth({
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'http://example.local',
        issuerBaseURL: 'https://op.example.com',
        authRequired: false,
        session: { store },
        discoveryCacheMaxAge: 24 * 3600 * 1000,
        backchannelLogout: true,
      }),
      requiresAuth()
    );
  });

  beforeEachScenario(() => {
    setupDiscovery();
    setupJwks();
  });

  afterEachScenario(() => {
    mock.timers.reset();
    nock.cleanAll();
  });

  Scenario('multiple logins', () => {
    /** @type {request.agent} */
    let agent1;
    /** @type {request.agent} */
    let agent2;
    Given('user owns two devices', () => {
      agent1 = request.agent(app);
      agent2 = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    let userSubject;
    let accessToken;
    let idToken;
    let sessionId;
    When('user is authenticated on first device', async () => {
      response = await agent1.get('/protected');
      userSubject = randomUUID();
      expect(response.statusCode, response.text).to.equal(302);

      const authCallUrl = new URL(response.get('location'));

      const nonce = authCallUrl.searchParams.get('nonce');

      accessToken = randomUUID();
      sessionId = randomUUID();
      idToken = await makeIdToken({ nonce, sub: userSubject, sid: sessionId });

      nock('https://op.example.com').post('/oauth/token').query(true).reply(200, {
        id_token: idToken,
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
      });

      response = await agent1.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });

      expect(response.statusCode, response.text).to.equal(302);

      expect(response.get('location')).to.equal('/protected');
    });

    And('on another device', async () => {
      response = await agent2.get('/protected');
      expect(response.statusCode, response.text).to.equal(302);

      const authCallUrl = new URL(response.get('location'));

      const nonce = authCallUrl.searchParams.get('nonce');
      nock('https://op.example.com')
        .post('/oauth/token')
        .query(true)
        .reply(200, {
          id_token: await makeIdToken({ nonce, sub: userSubject }),
          access_token: randomUUID(),
          token_type: 'Bearer',
          expires_in: 3600,
        });

      response = await agent2.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });

      expect(response.statusCode, response.text).to.equal(302);

      expect(response.get('location')).to.equal('/protected');
    });

    Then('both sessions are active', async () => {
      response = await agent1.get('/session').expect(200);
      expect(response.body, response.text).to.not.be.empty;

      response = await agent2.get('/session').expect(200);
      expect(response.body, response.text).to.not.be.empty;
    });

    When('openid server calls backchannel logout', async () => {
      response = await request(app)
        .post('/backchannel-logout')
        .set('content-type', 'application/x-www-form-urlencoded')
        .send(new URLSearchParams({ logout_token: await makeLogoutToken({ sid: sessionId, sub: userSubject }) }).toString());

      expect(response.statusCode, response.text).to.equal(204);
    });

    Then('then session is not set on first device', async () => {
      response = await agent1.get('/session').expect(200);
      expect(response.body, response.text).to.be.empty;
    });

    And('then session is not set on second device', async () => {
      response = await agent2.get('/session').expect(200);
      expect(response.body, response.text).to.be.empty;
    });
  });

  Scenario('logout token is of the wrong type', () => {
    /** @type {import('express').Response} */
    let response;
    When('openid server calls backchannel logout without required events', async () => {
      response = await request(app)
        .post('/backchannel-logout')
        .set('content-type', 'application/x-www-form-urlencoded')
        .send(
          new URLSearchParams({
            logout_token: await makeProperLogoutToken({ payload: { sid: randomUUID(), sub: randomUUID() }, headers: { typ: 'JWT' } }),
          }).toString()
        );
    });

    Then('bad request is returned', () => {
      expect(response.statusCode, response.text).to.equal(400);
      expect(response.body).to.have.property('error', 'invalid_token');
    });
  });

  Scenario('post process logout token is used for some reason', () => {
    /** @type {import('express').Application} */
    let anotherApp;
    Given('openid is configured on app', () => {
      setupDiscovery('https://openid.local');

      anotherApp = createApp(
        auth({
          secret: '__test_session_secret__',
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: 'https://openid.local',
          authRequired: false,
          session: { store: new CustomStore() },
          discoveryCacheMaxAge: 24 * 3600 * 1000,
          backchannelLogout: true,
        }),
        requiresAuth()
      );
    });

    /** @type {import('express').Response} */
    let response;
    When('openid server calls backchannel logout without required events', async () => {
      response = await request(anotherApp)
        .post('/backchannel-logout')
        .set('content-type', 'application/x-www-form-urlencoded')
        .send(
          new URLSearchParams({
            logout_token: await makeProperLogoutToken(),
          }).toString()
        );
    });

    Then('bad request is returned', () => {
      expect(response.statusCode, response.text).to.equal(400);
      expect(response.body).to.have.property('error', 'invalid_token');
    });
  });

  Scenario('logout token lacks required events', () => {
    /** @type {import('express').Response} */
    let response;
    When('openid server calls backchannel logout without required events', async () => {
      response = await request(app)
        .post('/backchannel-logout')
        .set('content-type', 'application/x-www-form-urlencoded')
        .send(
          new URLSearchParams({
            logout_token: await makeProperLogoutToken({ payload: { sid: randomUUID(), sub: randomUUID(), events: {} } }),
          }).toString()
        );
    });

    Then('bad request is returned', () => {
      expect(response.statusCode, response.text).to.equal(400);
      expect(response.body).to.have.property('error', 'invalid_token');
    });
  });

  Scenario('logout token lacks sub and sid', () => {
    /** @type {import('express').Response} */
    let response;
    When('openid server calls backchannel logout without required events', async () => {
      response = await request(app)
        .post('/backchannel-logout')
        .set('content-type', 'application/x-www-form-urlencoded')
        .send(
          new URLSearchParams({
            logout_token: await makeProperLogoutToken(),
          }).toString()
        );
    });

    Then('bad request is returned', () => {
      expect(response.statusCode, response.text).to.equal(400);
      expect(response.body).to.have.property('error', 'invalid_token');
    });
  });

  Scenario('issuer lacks jwks uri', () => {
    /** @type {import('express').Application} */
    let anotherApp;
    Given('openid is configured on app', () => {
      setupDiscovery('https://broken.openid.local', { jwks_uri: null });

      anotherApp = createApp(
        auth({
          secret: '__test_session_secret__',
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: 'https://broken.openid.local',
          authRequired: false,
          session: { store: new CustomStore() },
          discoveryCacheMaxAge: 24 * 3600 * 1000,
          backchannelLogout: true,
        }),
        requiresAuth()
      );
    });

    /** @type {import('express').Response} */
    let response;
    When('openid server calls backchannel logout without required events', async () => {
      response = await request(anotherApp)
        .post('/backchannel-logout')
        .set('content-type', 'application/x-www-form-urlencoded')
        .send(
          new URLSearchParams({
            logout_token: await makeProperLogoutToken({ payload: { iss: 'https://broken.openid.local', sid: randomUUID() } }),
          }).toString()
        );
    });

    Then('bad request is returned', () => {
      expect(response.statusCode, response.text).to.equal(400);
      expect(response.body).to.have.property('error', 'invalid_token');
    });
  });
});
