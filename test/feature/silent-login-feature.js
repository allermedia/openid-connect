import { randomUUID } from 'node:crypto';

import { auth, attemptSilentLogin } from '@aller/openid-connect';
import nock from 'nock';
import request from 'supertest';

import { makeIdToken } from '../fixture/cert.js';
import { createApp } from '../fixture/server.js';
import { setupDiscovery } from '../helpers/openid-helper.js';

Feature('silent login', () => {
  Scenario('user logs in after silent login fails', () => {
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
        attemptSilentLogin()
      );

      agent = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    When('user client attempts to fetch images on protected route', async () => {
      response = await agent.get('/protected').set('accept', 'image/png');
    });

    Then('no attempt was made to login', () => {
      expect(response.statusCode, response.text).to.equal(200);
    });

    And('NO cookie is set to indicate silent login', () => {
      expect(agent.jar.getCookies({ domain: '127.0.0.1', path: '/' }).length).to.equal(0);
    });

    When('user client makes fetch request accepting JSON', async () => {
      response = await agent.get('/protected').set('accept', 'application/json');
    });

    Then('no attempt was made to login', () => {
      expect(response.statusCode, response.text).to.equal(200);
    });

    When('user navigates to protected content', async () => {
      response = await agent.get('/protected');
    });

    Then('user is redirected to Open ID server with prompt none', () => {
      expect(response.statusCode, response.text).to.equal(302);

      const location = new URL(response.get('location'));
      expect(location.searchParams.get('prompt'), 'prompt').to.equal('none');
    });

    And('cookie is set to indicate silent login', () => {
      expect(agent.jar.getCookies({ domain: '127.0.0.1', path: '/' })[0]).to.deep.include({
        name: 'skipSilentLogin',
        value: 'true',
        noscript: true,
      });
    });

    When('user navigates to protected content again', async () => {
      response = await agent.get('/protected');
    });

    Then('no attempt to silent login was made', () => {
      expect(response.statusCode, response.text).to.equal(200);
    });

    /** @type {URL} */
    let authCallUrl;
    When('user authenticates', async () => {
      response = await agent.get('/login').expect(302);

      authCallUrl = new URL(response.get('location'));
    });

    And('callback is called with code', async () => {
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

    let cookies;
    And('authentication session cookie is set', () => {
      cookies = agent.jar.getCookies({ domain: '127.0.0.1', path: '/' });
      expect(cookies.find((c) => c.name === 'appSession')).to.be.ok;
    });

    And('indicate silent login cookie is removed', () => {
      expect(cookies.find((c) => c.name === 'skipSilentLogin')).to.not.be.ok;
    });
  });
});
