import { randomUUID } from 'node:crypto';
import { mock } from 'node:test';

import { auth, requiresAuth } from '@aller/openid-connect';
import { parseSetCookie } from 'cookie';
import nock from 'nock';
import request from 'supertest';

import { makeIdToken } from '../fixture/cert.js';
import { createApp } from '../fixture/server.js';
import { setupDiscovery } from '../helpers/openid-helper.js';

Feature('Configuration', () => {
  Scenario('default configuration', () => {
    const issuer = 'https://auth.local';
    before(() => {
      setupDiscovery(issuer);
      mock.timers.enable({ apis: ['Date'], now: new Date() });
    });
    after(() => {
      mock.timers.reset();
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
          clientID: 'default-client-id',
          clientSecret: 'supers3cret',
          issuerBaseURL: issuer,
        }),
        requiresAuth()
      );
      agent = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    /** @type {URL} */
    let authCallUrl;
    When('user initiates authentication', async () => {
      response = await agent.get('/login');

      expect(response.statusCode, response.text).to.equal(302);
      authCallUrl = new URL(response.get('location'));

      expect(authCallUrl.pathname).to.equal('/authorize');
    });

    Then('default scope is set', () => {
      const qs = Object.fromEntries(authCallUrl.searchParams);
      expect(qs, 'authentication parameters').to.deep.include({
        response_type: 'code',
        scope: 'openid profile email',
        code_challenge_method: 'S256',
        client_id: 'default-client-id',
      });
    });

    When('code is exchanged against tokens with basic auth', async () => {
      const nonce = authCallUrl.searchParams.get('nonce');
      nock(issuer)
        .post('/oauth/token')
        .basicAuth({ user: encodeBasicAuthValue('default-client-id'), pass: encodeBasicAuthValue('supers3cret') })
        .reply(200, {
          id_token: await makeIdToken({ nonce, sub: randomUUID(), iss: issuer, aud: 'default-client-id' }),
          refresh_token: randomUUID(),
          access_token: randomUUID(),
          token_type: 'Bearer',
          scope: 'openid profile email',
          expires_in: 15 * 60 * 60,
        });

      response = await agent.get('/callback').query({
        code: randomUUID(),
        state: authCallUrl.searchParams.get('state'),
      });

      expect(response.statusCode, response.text).to.equal(302);
    });

    Then('session cookie has the expected default properties', () => {
      const setCookies = Object.fromEntries(
        response.get('set-cookie').map((c) => {
          const cookie = parseSetCookie(c);
          return [cookie.name, cookie];
        })
      );

      expect(setCookies.appSession, 'expires in to 24 hrs')
        .to.have.property('expires')
        .that.deep.equal(new Date((Math.floor(Date.now() / 1000) + 24 * 60 * 60) * 1000));

      expect(setCookies.appSession, 'properties').to.deep.include({
        path: '/',
        httpOnly: true,
        sameSite: 'lax',
      });
    });
  });
});

function encodeBasicAuthValue(v) {
  return encodeURIComponent(v).replace(/_/g, '%5F').replace(/-/g, '%2D');
}
