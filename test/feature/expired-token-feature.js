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
  [undefined, new CustomStore()].forEach((store) => {
    Scenario(`expired token with ${store ? 'custom' : 'cookie'}`, () => {
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
      When('user authenticates and receives access token that expires in 15 minutes and ID token that expires in 14 days', async () => {
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
            expires_in: 15 * 60 * 60,
            scope: 'openid',
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

      And('access token has NOT expired', async () => {
        response = await agent.get('/tokens');
        expect(response.statusCode, response.text).to.equal(200);
        expect(response.body).to.have.property('accessTokenExpired').that.is.false;
      });

      When('14 minutes has passed since tokens where issued', () => {
        mock.timers.tick(14 * 60 * 60 * 1000);
      });

      Then('user is still authenticated', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(200);
      });

      And('access token has NOT expired', async () => {
        response = await agent.get('/tokens');
        expect(response.statusCode, response.text).to.equal(200);
        expect(response.body).to.have.property('accessTokenExpired').that.is.false;
      });

      When('15 minutes has passed since tokens where issued', () => {
        mock.timers.tick(60 * 60 * 1000);
      });

      Then('user is still authenticated', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(200);
      });

      And('access token has expired', async () => {
        response = await agent.get('/tokens');
        expect(response.statusCode, response.text).to.equal(200);
        expect(response.body).to.have.property('accessTokenExpired').that.is.true;
      });

      When('another day has passed since last visit', () => {
        mock.timers.tick(24 * 60 * 60 * 1000);
      });

      Then('user is still authenticated', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(200);
      });

      And('access token has still expired', async () => {
        response = await agent.get('/tokens');
        expect(response.statusCode, response.text).to.equal(200);
        expect(response.body).to.have.property('accessTokenExpired').that.is.true;
      });
    });
  });
});
