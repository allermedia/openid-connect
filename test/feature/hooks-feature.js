import { randomUUID } from 'node:crypto';

import { auth, requiresAuth } from '@aller/openid-connect';
import nock from 'nock';
import request from 'supertest';

import { makeIdToken } from '../fixture/cert.js';
import { createApp } from '../fixture/server.js';
import { CustomStore } from '../helpers/custom-store.js';
import { setupDiscovery } from '../helpers/openid-helper.js';

[undefined, new CustomStore()].forEach((store) => {
  Feature(`hooks with ${store ? 'custom' : 'cookie'} session store`, () => {
    Scenario('after callback hook', () => {
      before(() => {
        setupDiscovery();
      });

      /** @type {import('express').Application} */
      let app;
      /** @type {request.agent} */
      let agent;
      Given('a client server is setup with after callback hook', () => {
        app = createApp(
          auth({
            secret: '__test_session_secret__',
            clientID: '__test_client_id__',
            baseURL: 'http://example.local',
            issuerBaseURL: 'https://op.example.com',
            authRequired: false,
            session: { store },
            afterCallback(req, res, sessionData, state) {
              return Promise.resolve({
                foo: 'bar',
                req: new URL(req.originalUrl, 'http://localhost').pathname,
                res: res.headersSent,
                session: sessionData.sub,
                state: state.returnTo,
              });
            },
          }),
          requiresAuth()
        );

        agent = request.agent(app);
      });

      /** @type {import('express').Response} */
      let response;
      let userSub;
      When('user authenticates', async () => {
        response = await agent.get('/protected');

        expect(response.statusCode, response.text).to.equal(302);

        const authCallUrl = new URL(response.get('location'));
        expect(authCallUrl.searchParams.get('prompt'), 'prompt').to.be.null;

        userSub = randomUUID();
        const nonce = authCallUrl.searchParams.get('nonce');
        nock('https://op.example.com')
          .post('/oauth/token')
          .query(true)
          .reply(200, {
            id_token: await makeIdToken({ nonce, sub: userSub }),
            access_token: randomUUID(),
            refresh_token: randomUUID(),
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

      And('session has user id', async () => {
        response = await agent.get('/session').expect(200);
        expect(response.body).to.have.property('sub', userSub);
      });

      And('and resolved after callback hook data', () => {
        expect(response.body).to.deep.include({
          foo: 'bar',
          req: '/callback',
          res: false,
          session: userSub,
          state: '/protected',
        });
      });

      When('user refresh tokens', async () => {
        nock('https://op.example.com')
          .post('/oauth/token')
          .query(true)
          .reply(200, {
            id_token: await makeIdToken({ sub: userSub }),
            access_token: randomUUID(),
            token_type: 'Bearer',
          });

        response = await agent.get('/refresh').query({ return_to: '/bar' });
      });

      Then('user is redirected to return url', () => {
        expect(response.statusCode, response.text).to.equal(307);

        expect(response.get('location')).to.equal('/bar');
      });

      And('session has user id', async () => {
        response = await agent.get('/session').expect(200);
        expect(response.body).to.have.property('sub', userSub);
      });

      And('and resolved after callback hook data', () => {
        expect(response.body).to.deep.include({
          foo: 'bar',
          req: '/refresh',
          res: false,
          session: userSub,
          state: '/bar',
        });
      });
    });

    Scenario('after callback hook throws', () => {
      before(() => {
        setupDiscovery();
      });

      /** @type {import('express').Application} */
      let app;
      /** @type {request.agent} */
      let agent;
      Given('a client server is setup with broken after callback hook', () => {
        app = createApp(
          auth({
            secret: '__test_session_secret__',
            clientID: '__test_client_id__',
            baseURL: 'http://example.local',
            issuerBaseURL: 'https://op.example.com',
            authRequired: false,
            session: { store },
            afterCallback() {
              return Promise.reject(new Error('foo'));
            },
          }),
          requiresAuth()
        );

        agent = request.agent(app);
      });

      /** @type {import('express').Response} */
      let response;
      let userSub;
      When('user attempts to authenticate', async () => {
        response = await agent.get('/protected');

        expect(response.statusCode, response.text).to.equal(302);

        const authCallUrl = new URL(response.get('location'));
        expect(authCallUrl.searchParams.get('prompt'), 'prompt').to.be.null;

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

      Then('internal server error is returned', () => {
        expect(response.statusCode, response.text).to.equal(500);
      });

      And('no session exists', async () => {
        response = await agent.get('/session').expect(200);
        expect(response.body).to.be.empty;
      });
    });
  });
});
