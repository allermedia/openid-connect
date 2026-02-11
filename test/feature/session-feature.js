import { randomUUID } from 'node:crypto';

import { auth, requiresAuth } from '@aller/openid-connect';
import nock from 'nock';
import request from 'supertest';

import { makeIdToken } from '../fixture/cert.js';
import { createApp } from '../fixture/server.js';
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
    Then('authentication session cookie is set', () => {
      cookies = firstAgent.jar.getCookies({ domain: '127.0.0.1', path: '/' });
      expect(cookies.find((c) => c.name === 'appSession')).to.deep.include({
        noscript: true,
      });
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
      expect(oldAppSessionCookie.value === newAppSessionCookie.value).to.be.false;
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
});
