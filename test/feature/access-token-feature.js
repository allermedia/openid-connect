import { randomUUID } from 'node:crypto';
import { mock } from 'node:test';

import { auth, requiresAuth } from '@aller/openid-connect';
import nock from 'nock';
import request from 'supertest';

import { makeIdToken } from '../fixture/cert.js';
import { createApp } from '../fixture/server.js';
import { CustomStore } from '../helpers/custom-store.js';
import { setupDiscovery } from '../helpers/openid-helper.js';

Feature('Access token', () => {
  [undefined, new CustomStore()].forEach((store) => {
    Scenario(`middleware fiddles around with access token`, () => {
      const issuer = 'https://accesstoken.auth.local';
      before(() => {
        setupDiscovery(issuer);
        mock.timers.enable({ apis: ['Date'], now: new Date() });
      });
      after(() => {
        mock.timers.reset();
      });

      /** @type {import('express').Application} */
      let app;
      /** @type {import('supertest').Agent} */
      let agent;
      Given('a client server is deployed with a middlewares that handles access token', () => {
        const route = auth({
          secret: ['supers3cret', 'oldsupers3cret'],
          clientID: '__test_client_id__',
          baseURL: 'http://example.local',
          issuerBaseURL: issuer,
          session: {
            name: 'mySession',
            store,
          },
          authRequired: false,
          discoveryCacheMaxAge: 365 * 24 * 60 * 60 * 1000,
        });
        route.get('/auth/access-token', (req, res) => {
          res.json(req.oidc.accessToken);
        });
        route.get('/auth/double-refresh', async (req, res) => {
          await req.oidc.accessToken.refresh();
          await req.oidc.accessToken.refresh();
          res.send('OK');
        });
        route.get('/auth/access-token/:prop', (req, res) => {
          res.send({ [req.params.prop]: req.oidc.accessToken[req.params.prop] });
        });
        route.delete('/auth/unset', (req, res) => {
          req.mySession = null;
          res.json();
        });

        app = createApp(route, requiresAuth());

        agent = request.agent(app);
      });

      /** @type {import('express').Response} */
      let response;
      let accessToken;
      let refreshToken;
      When('user authenticates', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(302);

        const authCallUrl = new URL(response.get('location'));
        expect(authCallUrl.searchParams.get('prompt'), 'prompt').to.be.null;

        const nonce = authCallUrl.searchParams.get('nonce');
        accessToken = randomUUID();
        refreshToken = randomUUID();
        nock(issuer)
          .post('/oauth/token')
          .query(true)
          .reply(200, {
            id_token: await makeIdToken({ nonce, sub: randomUUID(), iss: issuer }),
            refresh_token: refreshToken,
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

      Then('user is authenticated', async () => {
        response = await agent.get('/protected');
        expect(response.statusCode, response.text).to.equal(200);
      });

      When('time has passed and access token is fetched', async () => {
        mock.timers.tick(1800 * 1000);
        response = await agent.get('/auth/access-token').expect(200);
      });

      Then('access token expires in is reduced', () => {
        expect(response.body).to.deep.equal({ access_token: accessToken, token_type: 'bearer', expires_in: 1800 });
      });

      When('access token token type is fetched', async () => {
        response = await agent.get('/auth/access-token/token_type').expect(200);
      });

      Then('access token token type has the expected value', () => {
        expect(response.body).to.deep.equal({ token_type: 'bearer' });
      });

      let latestAccessToken;
      When('access token is double refreshed', async () => {
        const intermediateRefreshToken = randomUUID();
        latestAccessToken = randomUUID();

        nock(issuer)
          .post('/oauth/token', (body) => {
            return body.refresh_token === refreshToken;
          })
          .reply(200, {
            id_token: await makeIdToken({ iss: issuer }),
            refresh_token: intermediateRefreshToken,
            access_token: randomUUID(),
            token_type: 'Bearer',
            expires_in: 3600,
          })
          .post('/oauth/token', (body) => {
            return body.refresh_token === intermediateRefreshToken;
          })
          .reply(200, {
            id_token: await makeIdToken({ iss: issuer }),
            refresh_token: intermediateRefreshToken,
            access_token: latestAccessToken,
            token_type: 'Bearer',
            expires_in: 3600,
          });

        response = await agent.get('/auth/double-refresh').expect(200);
      });

      Then('access token is the last refreshed token', async () => {
        response = await agent.get('/auth/access-token/access_token').expect(200);
        expect(response.body).to.deep.equal({ access_token: latestAccessToken });
      });
    });
  });
});
