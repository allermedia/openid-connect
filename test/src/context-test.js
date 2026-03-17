import { randomUUID } from 'node:crypto';

import { auth } from '@aller/openid-connect';
import nock from 'nock';
import request from 'supertest';

import { makeIdToken } from '../fixture/cert.js';
import { createApp } from '../fixture/server.js';
import { setupDiscovery } from '../helpers/openid-helper.js';

const clientID = '__test_client_id__';

const deafultIssuer = 'https://auth.local';
const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: clientID,
  baseURL: 'http://example.local',
  issuerBaseURL: deafultIssuer,
  authRequired: false,
};

describe('context', () => {
  describe('request context', () => {
    let app;
    before(() => {
      setupDiscovery(deafultIssuer);

      const router = auth({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code',
          audience: deafultIssuer,
          scope: 'openid profile email',
        },
      });

      router.get('/user-info', async (req, res) => {
        res.json(await req.oidc.fetchUserInfo());
      });
      router.get('/user', (req, res) => {
        res.json(req.oidc.user);
      });

      app = createApp(router);
    });

    it('throws if accessToken is not present when fetching userinfo', async () => {
      const agent = request.agent(app);
      const { body } = await agent.get('/user-info').expect(400);

      expect(body.err).to.deep.equal({
        message: 'No access token available',
        statusCode: 400,
      });
    });

    it('unauthenticated get user returns nothing', async () => {
      const agent = request.agent(app);

      const { body } = await agent.get('/user').expect(200);

      expect(body).to.not.be.ok;
    });

    it('authenticated get user returns claims', async () => {
      const agent = request.agent(app);

      const response = await agent.get('/login').expect(302);
      const authCallUrl = new URL(response.get('location'));

      const sub = randomUUID();

      nock(deafultIssuer)
        .post('/oauth/token')
        .reply(200, {
          access_token: '__test_access_token__',
          refresh_token: '__test_refresh_token__',
          id_token: await makeIdToken({
            aud: defaultConfig.clientID,
            iss: deafultIssuer,
            sub,
            nonce: authCallUrl.searchParams.get('nonce'),
          }),
          token_type: 'bearer',
          expires_in: 86400,
          scope: 'openid profile email',
        });

      await agent
        .get('/callback')
        .query({
          code: randomUUID(),
          state: authCallUrl.searchParams.get('state'),
        })
        .expect(302);

      const { body } = await agent.get('/user').expect(200);

      expect(body).to.deep.equal({ nickname: '__test_nickname__', sub });
    });

    it('user filters claims if configured', async () => {
      const issuerUri = 'https://filtered.auth.local';
      setupDiscovery(issuerUri);

      const router = auth({
        ...defaultConfig,
        issuerBaseURL: issuerUri,
        clientSecret: '__test_client_secret__',
        identityClaimFilter: ['nickname', 'aud', 'exp', 'iss', 'iat', 'nonce'],
        authorizationParams: {
          response_type: 'code',
          audience: deafultIssuer,
          scope: 'openid profile email',
        },
      });

      router.get('/user', (req, res) => {
        res.json(req.oidc.user);
      });

      const customApp = createApp(router);

      const agent = request.agent(customApp);

      const response = await agent.get('/login').expect(302);
      const authCallUrl = new URL(response.get('location'));

      const sub = randomUUID();

      nock(issuerUri)
        .post('/oauth/token')
        .reply(200, {
          access_token: '__test_access_token__',
          refresh_token: '__test_refresh_token__',
          id_token: await makeIdToken({
            aud: defaultConfig.clientID,
            iss: issuerUri,
            sub,
            nonce: authCallUrl.searchParams.get('nonce'),
          }),
          token_type: 'bearer',
          expires_in: 86400,
          scope: 'openid profile email',
        });

      await agent
        .get('/callback')
        .query({
          code: randomUUID(),
          state: authCallUrl.searchParams.get('state'),
        })
        .expect(302);

      const { body } = await agent.get('/user').expect(200);

      expect(body).to.deep.equal({ sub });
    });
  });
});
