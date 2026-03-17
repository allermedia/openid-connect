import { randomUUID } from 'node:crypto';
import { mock } from 'node:test';

import { auth, requiresAuth } from '@aller/openid-connect';
import { compactDecrypt } from 'jose';
import nock from 'nock';
import request from 'supertest';

import { getEncryptionKeyStore } from '../../src/crypto.js';
import { makeIdToken } from '../fixture/cert.js';
import { createApp } from '../fixture/server.js';
import { CustomStore } from '../helpers/custom-store.js';
import { setupDiscovery } from '../helpers/openid-helper.js';

Feature('session', () => {
  Scenario('session secrets are rotated', () => {
    before(() => {
      setupDiscovery();
      setupDiscovery();
      setupDiscovery();
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {import('supertest').Agent} */
    let firstAgent;
    Given('a client server is deployed secrets', () => {
      app = createApp(
        auth({
          secret: ['supers3cret', 'oldsupers3cret'],
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: 'https://op.example.com',
          authRequired: false,
        }),
        requiresAuth()
      );

      firstAgent = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    When('user authenticates', async () => {
      response = await firstAgent.get('/protected');
      expect(response.statusCode, response.text).to.equal(302);

      const authCallUrl = new URL(response.get('location'));
      expect(authCallUrl.searchParams.get('prompt'), 'prompt').to.be.null;

      const nonce = authCallUrl.searchParams.get('nonce');
      nock('https://op.example.com')
        .post('/oauth/token')
        .query(true)
        .reply(200, {
          id_token: await makeIdToken({ nonce, sub: randomUUID() }),
          refresh_token: randomUUID(),
          access_token: randomUUID(),
          token_type: 'Bearer',
        });

      response = await firstAgent.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });

      expect(response.statusCode, response.text).to.equal(302);

      expect(response.get('location')).to.equal('/protected');
    });

    let cookies;
    let appSessionCookie;
    Then('authentication session cookie is set', () => {
      cookies = firstAgent.jar.getCookies({ domain: '127.0.0.1', path: '/' });
      appSessionCookie = cookies.find((c) => c.name === 'appSession');
      expect(appSessionCookie).to.deep.include({ noscript: true });
    });

    And('session cookie can be decrypted using jose', async () => {
      const keyStore = getEncryptionKeyStore(['supers3cret', 'oldsupers3cret']);
      await compactDecrypt(appSessionCookie.value, keyStore[0]);
    });

    /** @type {import('express').Application} */
    let rotatedApp;
    /** @type {import('supertest').Agent} */
    let secondAgent;
    Given('new client server is deployed with rotated secrets', () => {
      rotatedApp = createApp(
        auth({
          secret: ['newsupers3cret', 'supers3cret'],
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: 'https://op.example.com',
          authRequired: false,
        }),
        requiresAuth()
      );

      secondAgent = request.agent(rotatedApp);
      secondAgent.jar = firstAgent.jar;
    });

    When('user requests protected content', async () => {
      response = await secondAgent.get('/protected');
    });

    Then('user is still authenticated', () => {
      expect(response.statusCode, response.text).to.equal(200);
    });

    And('session cookie has been updated', () => {
      const newCookies = secondAgent.jar.getCookies({ domain: '127.0.0.1', path: '/' });
      const oldAppSessionCookie = cookies.find((c) => c.name === 'appSession');
      const newAppSessionCookie = newCookies.find((c) => c.name === 'appSession');
      expect(oldAppSessionCookie.value === newAppSessionCookie.value, 'sessions are equal').to.be.false;
    });

    /** @type {import('supertest').Agent} */
    let thirdAgent;
    Given('client server is deployed with totally new rotated secrets', () => {
      const newestRotatedApp = createApp(
        auth({
          secret: ['recentsupers3cret', 'notsorecents3cret'],
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: 'https://op.example.com',
          authRequired: false,
        }),
        requiresAuth()
      );

      thirdAgent = request.agent(newestRotatedApp);
      thirdAgent.jar = secondAgent.jar;
    });

    When('user requests protected content', async () => {
      response = await thirdAgent.get('/protected');
    });

    Then('user is required to re-authenticate', () => {
      expect(response.statusCode, response.text).to.equal(302);
      expect(new URL(response.get('location')).origin).to.equal('https://op.example.com');
    });

    And('session cookie has been removed', () => {
      const appSessionCookie = thirdAgent.jar.getCookies({ domain: '127.0.0.1', path: '/' }).find((c) => c.name === 'appSession');
      expect(appSessionCookie?.value).to.not.be.ok;
    });
  });

  [undefined, new CustomStore()].forEach((store) => {
    Scenario(`expired session with ${store ? 'custom' : 'cookie'} store rolling duration of 3 days absolute duration 7 days`, () => {
      before(() => {
        setupDiscovery();
        mock.timers.enable({ apis: ['Date'], now: new Date() });
      });
      after(() => {
        mock.timers.reset();
      });

      /** @type {import('express').Application} */
      let app;
      /** @type {import('supertest').Agent} */
      let agent;
      Given('a client server is deployed' + store, () => {
        app = createApp(
          auth({
            secret: ['supers3cret', 'oldsupers3cret'],
            clientID: '__test_client_id__',
            baseURL: 'http://example.local',
            issuerBaseURL: 'https://op.example.com',
            session: {
              store,
              rollingDuration: 3 * 24 * 60 * 60,
              absoluteDuration: 7 * 24 * 60 * 60,
            },
            authRequired: false,
            discoveryCacheMaxAge: 365 * 24 * 60 * 60 * 1000,
          }),
          requiresAuth()
        );

        agent = request.agent(app);
      });

      /** @type {import('express').Response} */
      let response;
      When('user authenticates', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(302);

        const authCallUrl = new URL(response.get('location'));
        expect(authCallUrl.searchParams.get('prompt'), 'prompt').to.be.null;

        const nonce = authCallUrl.searchParams.get('nonce');
        nock('https://op.example.com')
          .post('/oauth/token')
          .query(true)
          .reply(200, {
            id_token: await makeIdToken({ nonce, sub: randomUUID() }),
            refresh_token: randomUUID(),
            access_token: randomUUID(),
            token_type: 'Bearer',
          });

        response = await agent.get('/callback').query({
          code: randomUUID(),
          state: authCallUrl.searchParams.get('state'),
        });

        expect(response.statusCode, response.text).to.equal(302);

        expect(response.get('location')).to.equal('/protected');
      });

      Then('user is authenticated', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(200);
      });

      When('one day has passed', () => {
        mock.timers.tick(24 * 60 * 60 * 1000);
      });

      Then('user is still authenticated', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(200);
      });

      When('seven days has passed from first visit', () => {
        mock.timers.tick(6 * 24 * 60 * 60 * 1000 + 2000);
      });

      Then('user is has to reauthenticate', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(302);
      });
    });

    Scenario(`expired session with ${store ? 'custom' : 'cookie'} store rolling duration of 30 days and infinite absolute duration`, () => {
      before(() => {
        setupDiscovery();
        mock.timers.enable({ apis: ['Date'], now: new Date() });
      });
      after(() => {
        mock.timers.reset();
      });

      /** @type {import('express').Application} */
      let app;
      /** @type {import('supertest').Agent} */
      let agent;
      Given('a client server is deployed' + store, () => {
        app = createApp(
          auth({
            secret: ['supers3cret', 'oldsupers3cret'],
            clientID: '__test_client_id__',
            baseURL: 'http://example.local',
            issuerBaseURL: 'https://op.example.com',
            session: {
              store,
              rollingDuration: 30 * 24 * 60 * 60,
              absoluteDuration: false,
            },
            authRequired: false,
            discoveryCacheMaxAge: 365 * 24 * 60 * 60 * 1000,
          }),
          requiresAuth()
        );

        agent = request.agent(app);
      });

      /** @type {import('express').Response} */
      let response;
      When('user authenticates', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(302);

        const authCallUrl = new URL(response.get('location'));
        expect(authCallUrl.searchParams.get('prompt'), 'prompt').to.be.null;

        const nonce = authCallUrl.searchParams.get('nonce');
        nock('https://op.example.com')
          .post('/oauth/token')
          .query(true)
          .reply(200, {
            id_token: await makeIdToken({ nonce, sub: randomUUID() }),
            refresh_token: randomUUID(),
            access_token: randomUUID(),
            token_type: 'Bearer',
          });

        response = await agent.get('/callback').query({
          code: randomUUID(),
          state: authCallUrl.searchParams.get('state'),
        });

        expect(response.statusCode, response.text).to.equal(302);

        expect(response.get('location')).to.equal('/protected');
      });

      Then('user is authenticated', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(200);
      });

      When('one day has passed', () => {
        mock.timers.tick(24 * 60 * 60 * 1000);
      });

      Then('user is still authenticated', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(200);
      });

      When('seven days has passed from first visit', () => {
        mock.timers.tick(6 * 24 * 60 * 60 * 1000 + 2000);
      });

      Then('user is still authenticated', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(200);
      });

      When('a fortnight has passed from last visit', () => {
        mock.timers.tick(14 * 24 * 60 * 60 * 1000 + 2000);
      });

      Then('user is still authenticated', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(200);
      });

      When('a month has passed from last visit', () => {
        mock.timers.tick(30 * 24 * 60 * 60 * 1000 + 2000);
      });

      Then('user has to reauthenticate', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(302);
      });
    });

    Scenario(`unset session with ${store ? 'custom' : 'cookie'} store rolling duration of 30 days and infinite absolute duration`, () => {
      before(() => {
        setupDiscovery();
        mock.timers.enable({ apis: ['Date'], now: new Date() });
      });
      after(() => {
        mock.timers.reset();
      });

      /** @type {import('express').Application} */
      let app;
      /** @type {import('supertest').Agent} */
      let agent;
      Given('a client server is deployed' + store, () => {
        app = createApp(
          auth({
            secret: ['supers3cret', 'oldsupers3cret'],
            clientID: '__test_client_id__',
            baseURL: 'http://example.local',
            issuerBaseURL: 'https://op.example.com',
            session: {
              store,
              rollingDuration: 30 * 24 * 60 * 60,
              absoluteDuration: false,
            },
            authRequired: false,
            discoveryCacheMaxAge: 365 * 24 * 60 * 60 * 1000,
          }),
          requiresAuth()
        );

        agent = request.agent(app);
      });

      /** @type {import('express').Response} */
      let response;
      When('user authenticates', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(302);

        const authCallUrl = new URL(response.get('location'));
        expect(authCallUrl.searchParams.get('prompt'), 'prompt').to.be.null;

        const nonce = authCallUrl.searchParams.get('nonce');
        nock('https://op.example.com')
          .post('/oauth/token')
          .query(true)
          .reply(200, {
            id_token: await makeIdToken({ nonce, sub: randomUUID() }),
            refresh_token: randomUUID(),
            access_token: randomUUID(),
            token_type: 'Bearer',
          });

        response = await agent.get('/callback').query({
          code: randomUUID(),
          state: authCallUrl.searchParams.get('state'),
        });

        expect(response.statusCode, response.text).to.equal(302);

        expect(response.get('location')).to.equal('/protected');
      });

      Then('user is authenticated', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(200);
      });

      When('one day has passed', () => {
        mock.timers.tick(24 * 60 * 60 * 1000);
      });

      Then('user is still authenticated', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(200);
      });

      When('seven days has passed from first visit', () => {
        mock.timers.tick(6 * 24 * 60 * 60 * 1000 + 2000);
      });

      Then('user is still authenticated', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(200);
      });

      When('a fortnight has passed from last visit', () => {
        mock.timers.tick(14 * 24 * 60 * 60 * 1000 + 2000);
      });

      Then('user is still authenticated', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(200);
      });

      When('a month has passed from last visit', () => {
        mock.timers.tick(30 * 24 * 60 * 60 * 1000 + 2000);
      });

      Then('user has to reauthenticate', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(302);
      });
    });
  });
});
