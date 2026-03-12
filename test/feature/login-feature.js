import { randomUUID } from 'node:crypto';

import { auth, requiresAuth } from '@aller/openid-connect';
import { decodeJwt } from 'jose';
import nock from 'nock';
import request from 'supertest';

import { makeIdToken } from '../fixture/cert.js';
import { createApp } from '../fixture/server.js';
import { decryptCookie } from '../helpers/crypto-helper.js';
import { CustomStore } from '../helpers/custom-store.js';
import { setupDiscovery } from '../helpers/openid-helper.js';

Feature('login', () => {
  Scenario('user navigates to protected content', () => {
    before(() => {
      setupDiscovery();
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.agent} */
    let agent;
    Given('a client server is setup with default cookie store', () => {
      app = createApp(
        auth({
          secret: '__test_session_secret__',
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: 'https://op.example.com',
          authRequired: false,
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
      expect(authCallUrl.searchParams.get('prompt'), 'prompt').to.be.null;
    });

    And('cookie is set to indicate authentication attempt', () => {
      expect(agent.jar.getCookies({ domain: '127.0.0.1', path: '/' })[0]).to.deep.include({
        name: 'auth_verification',
        noscript: true,
      });
    });

    let userSub;
    When('auth callback is called with code', async () => {
      userSub = randomUUID();
      const nonce = authCallUrl.searchParams.get('nonce');
      nock('https://op.example.com')
        .post('/oauth/token')
        .query(true)
        .reply(200, {
          id_token: await makeIdToken({ nonce, sub: userSub }),
          access_token: randomUUID(),
          token_type: 'Bearer',
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

    And('session cookie is encrypted', async () => {
      const session = await decryptCookie('__test_session_secret__', appSessionCookie.value);
      expect(JSON.parse(session.plaintext)).to.have.property('sub', userSub);
    });

    And('authentication transaction cookie is removed', () => {
      expect(cookies.find((c) => c.name === 'auth_verification')).to.not.be.ok;
    });

    And('session has first user id', async () => {
      response = await agent.get('/session').expect(200);
      expect(decodeJwt(response.body.id_token)).to.have.property('sub', userSub);
    });

    When('following redirect', async () => {
      response = await agent.get('/protected').expect(200);
    });

    Then('session cookie is regenerated', () => {
      expect(response.get('set-cookie')).to.have.length(1);
      expect(response.get('set-cookie').toString()).to.include('appSession=');
    });
  });

  Scenario('same browser with subsequent logins by different users', () => {
    before(() => {
      setupDiscovery();
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.agent} */
    let agent;
    Given('a client server is setup with custom store', () => {
      app = createApp(
        auth({
          secret: '__test_session_secret__',
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: 'https://op.example.com',
          authRequired: false,
          session: {
            store: new CustomStore(),
          },
        }),
        requiresAuth()
      );

      agent = request.agent(app);
    });

    /** @type {import('supertest').Response} */
    let response;
    /** @type {URL} */
    let authCallUrl;
    When('first user authenticates', async () => {
      response = await agent.get('/login').expect(302);

      authCallUrl = new URL(response.get('location'));
    });

    let firstUserSub;
    And('issuer issues id token and calls callback', async () => {
      firstUserSub = randomUUID();
      const nonce = authCallUrl.searchParams.get('nonce');
      nock('https://op.example.com')
        .post('/oauth/token')
        .query(true)
        .reply(200, {
          id_token: await makeIdToken({ nonce, sub: firstUserSub }),
          access_token: randomUUID(),
          token_type: 'Bearer',
        });

      response = await agent.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });
    });

    Then('first user is redirected to return url', () => {
      expect(response.statusCode, response.text).to.equal(302);

      expect(response.get('location')).to.equal('http://example.local');
    });

    let firstAppSessionCookie;
    And('first user session cookie is set', () => {
      firstAppSessionCookie = agent.jar.getCookies({ domain: '127.0.0.1', path: '/' }).find((c) => c.name === 'appSession');
      expect(firstAppSessionCookie).to.be.ok;
    });

    And('session has first user id', async () => {
      response = await agent.get('/session').expect(200);
      expect(decodeJwt(response.body.id_token)).to.have.property('sub', firstUserSub);
    });

    When('second user authenticates in the same browser', async () => {
      response = await agent.get('/login').expect(302);

      authCallUrl = new URL(response.get('location'));
    });

    let secondUserSub;
    And('issuer issues id token and calls callback', async () => {
      secondUserSub = randomUUID();
      const nonce = authCallUrl.searchParams.get('nonce');
      nock('https://op.example.com')
        .post('/oauth/token')
        .query(true)
        .reply(200, {
          id_token: await makeIdToken({ nonce, sub: secondUserSub }),
          access_token: randomUUID(),
          token_type: 'Bearer',
        });

      response = await agent.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });
    });

    Then('second user is redirected to return url', () => {
      expect(response.statusCode, response.text).to.equal(302);

      expect(response.get('location')).to.equal('http://example.local');
    });

    And('session has second user id', async () => {
      response = await agent.get('/session').expect(200);
      expect(decodeJwt(response.body.id_token)).to.have.property('sub', secondUserSub);
    });

    When('attempting to get session with first user session cookie', async () => {
      response = await request(app).get('/session').set('Cookie', `appSession=${firstAppSessionCookie.value}`);
    });

    Then('first session is invalidated', () => {
      expect(response.statusCode, response.text).to.equal(200);
      expect(response.body).to.not.have.property('id_token');
    });
  });

  Scenario('login without return to', () => {
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
        }),
        requiresAuth()
      );

      agent = request.agent(app);
    });

    /** @type {import('supertest').Response} */
    let response;
    /** @type {URL} */
    let authCallUrl;
    When('user authenticates over the current session', async () => {
      response = await agent.get('/login').query({ return_to: '' }).expect(302);

      authCallUrl = new URL(response.get('location'));
    });

    And('callback is called', async () => {
      const nonce = authCallUrl.searchParams.get('nonce');
      nock('https://op.example.com')
        .post('/oauth/token')
        .query(true)
        .reply(200, {
          id_token: await makeIdToken({ nonce }),
          access_token: randomUUID(),
          token_type: 'Bearer',
        });

      response = await agent.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });
    });

    Then('user is redirected to return url', () => {
      expect(response.statusCode, response.text).to.equal(302);

      expect(response.get('location')).to.equal('http://example.local');
    });

    And('session has subject', async () => {
      response = await agent.get('/session').expect(200);
      expect(response.body).to.have.property('sub').that.is.ok;
    });
  });

  Scenario('stored session lacks user subject', () => {
    before(() => {
      setupDiscovery();
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.agent} */
    let agent;
    /** @type {CustomStore} */
    let store;
    Given('a client server is setup with custom store', () => {
      store = new CustomStore();
      app = createApp(
        auth({
          secret: '__test_session_secret__',
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: 'https://op.example.com',
          session: { store },
          authRequired: false,
        }),
        requiresAuth()
      );

      agent = request.agent(app);
    });

    /** @type {import('supertest').Response} */
    let response;
    let sid;
    And('a session without user subject exists', async () => {
      sid = randomUUID();
      return agent
        .post('/session')
        .send({ id_token: await makeIdToken({ sub: undefined, sid }) })
        .expect(200);
    });

    And('session has id token that lacks user subject', async () => {
      response = await agent.get('/session').expect(200);
      expect(response.body).to.have.property('sid', sid);
      expect(response.body).to.have.property('id_token').that.is.ok;
      expect(response.body).to.not.have.property('sub');
    });

    /** @type {URL} */
    let authCallUrl;
    When('user authenticates over the current session', async () => {
      response = await agent.get('/login').expect(302);

      authCallUrl = new URL(response.get('location'));
    });

    And('issuer issues ID token with subject and calls callback', async () => {
      const nonce = authCallUrl.searchParams.get('nonce');
      nock('https://op.example.com')
        .post('/oauth/token')
        .query(true)
        .reply(200, {
          id_token: await makeIdToken({ nonce, sub: randomUUID(), sid }),
          access_token: randomUUID(),
          token_type: 'Bearer',
        });

      response = await agent.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });
    });

    Then('user is redirected to return url', () => {
      expect(response.statusCode, response.text).to.equal(302);

      expect(response.get('location')).to.equal('http://example.local');
    });

    And('session has subject', async () => {
      response = await agent.get('/session').expect(200);
      expect(response.body).to.have.property('sub').that.is.ok;
      expect(response.body).to.have.property('sid', sid);
    });
  });

  Scenario('login when token endpoint fails to return id token', () => {
    before(() => {
      setupDiscovery();
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.agent} */
    let agent;
    Given('a client server is setup with custom store', () => {
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
        }),
        requiresAuth()
      );

      agent = request.agent(app);
    });

    /** @type {import('supertest').Response} */
    let response;
    /** @type {URL} */
    let authCallUrl;
    When('user authenticates', async () => {
      response = await agent.get('/login').expect(302);

      authCallUrl = new URL(response.get('location'));
    });

    And('issuer issues access token only and calls callback', async () => {
      const nonce = authCallUrl.searchParams.get('nonce');
      nock('https://op.example.com')
        .post('/oauth/token')
        .query(true)
        .reply(200, {
          id_token: await makeIdToken({ nonce, sub: undefined }),
          access_token: randomUUID(),
          token_type: 'Bearer',
        });

      response = await agent.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });
    });

    Then('bad request is returned', () => {
      expect(response.statusCode, response.text).to.equal(400);

      expect(response.body.err).to.have.property('code', 'OAUTH_INVALID_RESPONSE');
    });
  });

  Scenario('login when token endpoint fails to return id token with subject', () => {
    before(() => {
      setupDiscovery();
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.agent} */
    let agent;
    Given('a client server is setup with custom store', () => {
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
        }),
        requiresAuth()
      );

      agent = request.agent(app);
    });

    /** @type {import('supertest').Response} */
    let response;
    /** @type {URL} */
    let authCallUrl;
    When('user authenticates', async () => {
      response = await agent.get('/login').expect(302);

      authCallUrl = new URL(response.get('location'));
    });

    And('issuer issues access token only and calls callback', async () => {
      nock('https://op.example.com').post('/oauth/token').query(true).reply(200, {
        access_token: randomUUID(),
        token_type: 'Bearer',
      });

      response = await agent.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });
    });

    Then('bad request is returned', () => {
      expect(response.statusCode, response.text).to.equal(400);

      expect(response.body.err).to.have.property('code', 'OAUTH_INVALID_RESPONSE');
    });
  });

  Scenario('login when token endpoint fails to return token type', () => {
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
    When('token type is not returned when user logs in', async () => {
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
          expires_in: 3600,
        });

      response = await agent.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });
    });

    Then('bad request is returned', () => {
      expect(response.statusCode, response.text).to.equal(400);
      expect(response.body.err).to.have.property('code', 'OAUTH_INVALID_RESPONSE');
    });

    And('no session exists', async () => {
      response = await agent.get('/session').expect(200);
      expect(response.body).to.be.empty;
    });
  });
});
