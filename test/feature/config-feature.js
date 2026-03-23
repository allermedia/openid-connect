import { randomUUID } from 'node:crypto';
import { mock } from 'node:test';

import { auth, requiresAuth } from '@aller/openid-connect';
import { parseSetCookie } from 'cookie';
import express from 'express';
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

  Scenario('auto-detect base url without idp logout', () => {
    const issuer = 'https://auth.local';
    const headers = { 'x-forwarded-host': 'example.local', 'x-forwarded-proto': 'https' };
    before(() => {
      setupDiscovery(issuer);
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.Agent} */
    let agent;
    Given('an app is setup with trust proxy', () => {
      app = express();
      app.set('trust proxy', true);
      app.use(
        auth({
          secret: 'supers3cret',
          baseURL: 'autodetect',
          clientID: 'default-client-id',
          clientSecret: 'supers3cret',
          issuerBaseURL: issuer,
        })
      );

      agent = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    /** @type {URL} */
    let authCallUrl;
    When('user initiates authentication', async () => {
      response = await agent.get('/login').set(headers);

      expect(response.statusCode, response.text).to.equal(302);
      authCallUrl = new URL(response.get('location'));

      expect(authCallUrl.pathname).to.equal('/authorize');
    });

    Then('redirect uri is autodetected from headers', () => {
      const qs = Object.fromEntries(authCallUrl.searchParams);
      expect(qs, 'authentication parameters').to.deep.include({
        response_type: 'code',
        scope: 'openid profile email',
        code_challenge_method: 'S256',
        client_id: 'default-client-id',
        redirect_uri: 'https://example.local/callback',
      });
    });

    When('code is exchanged against tokens with basic auth', async () => {
      const nonce = authCallUrl.searchParams.get('nonce');
      nock(issuer)
        .post('/oauth/token')
        .reply(200, {
          id_token: await makeIdToken({ nonce, sub: randomUUID(), iss: issuer, aud: 'default-client-id' }),
          refresh_token: randomUUID(),
          access_token: randomUUID(),
          token_type: 'Bearer',
          scope: 'openid profile email',
          expires_in: 15 * 60 * 60,
        });

      response = await agent
        .get('/callback')
        .set(headers)
        .query({
          code: randomUUID(),
          state: authCallUrl.searchParams.get('state'),
        });
    });

    Then('user is redirected to root', () => {
      expect(response.statusCode, response.text).to.equal(302);
      expect(response.get('location')).to.equal('/');
    });

    When('user signs out', async () => {
      response = await agent.get('/logout').set(headers);
    });

    Then('user is redirected to autodetected base url', () => {
      expect(response.statusCode, response.text).to.equal(302);
      expect(response.get('location')).to.equal('https://example.local/');
    });

    When('user initiates authentication without forwarded headers, only host', async () => {
      response = await agent.get('/login').set({ 'x-forwarded-proto': 'https', host: 'another.example.local' });

      expect(response.statusCode, response.text).to.equal(302);
      authCallUrl = new URL(response.get('location'));

      expect(authCallUrl.pathname).to.equal('/authorize');
    });

    Then('redirect uri is autodetected from host header', () => {
      const qs = Object.fromEntries(authCallUrl.searchParams);
      expect(qs, 'authentication parameters').to.deep.include({
        response_type: 'code',
        scope: 'openid profile email',
        code_challenge_method: 'S256',
        client_id: 'default-client-id',
        redirect_uri: 'https://another.example.local/callback',
      });
    });
  });

  Scenario('auto-detect base url with idp logout', () => {
    const issuer = 'https://endsession.auth.local';
    const headers = { 'x-forwarded-host': 'www.example.local', 'x-forwarded-proto': 'https' };
    before(() => {
      setupDiscovery(issuer);
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.Agent} */
    let agent;
    Given('an app is setup with trust proxy', () => {
      app = express();
      app.set('trust proxy', true);
      app.use(
        auth({
          secret: 'supers3cret',
          baseURL: 'autodetect',
          clientID: 'default-client-id',
          clientSecret: 'supers3cret',
          idpLogout: true,
          issuerBaseURL: issuer,
          routes: {
            postLogoutRedirect: '/logout/callback',
          },
        })
      );

      agent = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    /** @type {URL} */
    let authCallUrl;
    When('user initiates authentication with return to', async () => {
      response = await agent.get('/login').set(headers);

      expect(response.statusCode, response.text).to.equal(302);
      authCallUrl = new URL(response.get('location'));

      expect(authCallUrl.pathname).to.equal('/authorize');
    });

    Then('redirect uri is autodetected from headers', () => {
      const qs = Object.fromEntries(authCallUrl.searchParams);
      expect(qs, 'authentication parameters').to.deep.include({
        response_type: 'code',
        scope: 'openid profile email',
        code_challenge_method: 'S256',
        client_id: 'default-client-id',
        redirect_uri: 'https://www.example.local/callback',
      });
    });

    When('code is exchanged against tokens with basic auth', async () => {
      const nonce = authCallUrl.searchParams.get('nonce');
      nock(issuer)
        .post('/oauth/token')
        .reply(200, {
          id_token: await makeIdToken({ nonce, sub: randomUUID(), iss: issuer, aud: 'default-client-id' }),
          refresh_token: randomUUID(),
          access_token: randomUUID(),
          token_type: 'Bearer',
          scope: 'openid profile email',
          expires_in: 15 * 60 * 60,
        });

      response = await agent
        .get('/callback')
        .set(headers)
        .query({
          code: randomUUID(),
          state: authCallUrl.searchParams.get('state'),
        });
    });

    Then('user is redirected to root', () => {
      expect(response.statusCode, response.text).to.equal(302);
      expect(response.get('location')).to.equal('/');
    });

    When('user signs out', async () => {
      response = await agent.get('/logout').set(headers);
    });

    Then('user is redirected to end session endpoint with expected post logout uri', () => {
      expect(response.statusCode, response.text).to.equal(302);
      const endSessionUrl = new URL(response.get('location'));
      const qs = Object.fromEntries(endSessionUrl.searchParams);
      expect(qs).to.deep.include({
        post_logout_redirect_uri: 'https://www.example.local/logout/callback',
      });
    });
  });

  Scenario("auto-detect base url when we don't trust proxy", () => {
    const issuer = 'https://endsession.auth.local';
    const headers = { 'x-forwarded-host': 'cdn.example.local', 'x-forwarded-proto': 'https', host: 'example.local' };
    before(() => {
      setupDiscovery(issuer);
    });

    /** @type {import('express').Application} */
    let app;
    /** @type {request.Agent} */
    let agent;
    Given('an app is setup with trust proxy', () => {
      app = express();
      app.use(
        auth({
          secret: 'supers3cret',
          baseURL: 'autodetect',
          clientID: 'default-client-id',
          clientSecret: 'supers3cret',
          idpLogout: true,
          issuerBaseURL: issuer,
          routes: {
            postLogoutRedirect: '/logout/callback',
          },
        })
      );

      agent = request.agent(app);
    });

    /** @type {import('express').Response} */
    let response;
    /** @type {URL} */
    let authCallUrl;
    When('user initiates authentication with return to', async () => {
      response = await agent.get('/login').set(headers);

      expect(response.statusCode, response.text).to.equal(302);
      authCallUrl = new URL(response.get('location'));

      expect(authCallUrl.pathname).to.equal('/authorize');
    });

    Then('redirect uri is autodetected from headers', () => {
      const qs = Object.fromEntries(authCallUrl.searchParams);
      expect(qs, 'authentication parameters').to.deep.include({
        response_type: 'code',
        scope: 'openid profile email',
        code_challenge_method: 'S256',
        client_id: 'default-client-id',
        redirect_uri: 'http://example.local/callback',
      });
    });

    When('code is exchanged against tokens with basic auth', async () => {
      const nonce = authCallUrl.searchParams.get('nonce');
      nock(issuer)
        .post('/oauth/token')
        .reply(200, {
          id_token: await makeIdToken({ nonce, sub: randomUUID(), iss: issuer, aud: 'default-client-id' }),
          refresh_token: randomUUID(),
          access_token: randomUUID(),
          token_type: 'Bearer',
          scope: 'openid profile email',
          expires_in: 15 * 60 * 60,
        });

      response = await agent
        .get('/callback')
        .set(headers)
        .query({
          code: randomUUID(),
          state: authCallUrl.searchParams.get('state'),
        });
    });

    Then('user is redirected to root', () => {
      expect(response.statusCode, response.text).to.equal(302);
      expect(response.get('location')).to.equal('/');
    });

    When('user signs out', async () => {
      response = await agent.get('/logout').set(headers);
    });

    Then('user is redirected to end session endpoint with expected post logout uri', () => {
      expect(response.statusCode, response.text).to.equal(302);
      const endSessionUrl = new URL(response.get('location'));
      const qs = Object.fromEntries(endSessionUrl.searchParams);
      expect(qs).to.deep.include({
        post_logout_redirect_uri: 'http://example.local/logout/callback',
      });
    });
  });
});

function encodeBasicAuthValue(v) {
  return encodeURIComponent(v).replace(/_/g, '%5F').replace(/-/g, '%2D');
}
