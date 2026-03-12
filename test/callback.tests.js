import { randomUUID } from 'node:crypto';
import { mock } from 'node:test';

import { auth } from '@aller/openid-connect';
import nock from 'nock';
import request from 'supertest';

import { getSigningKeyStore, signCookie } from '../src/crypto.js';
import { encodeState } from '../src/hooks/getLoginState.js';

import { makeIdToken, JWT } from './fixture/cert.js';
import { getPrivatePEM } from './fixture/jwk.js';
import { createApp } from './fixture/server.js';
import { CustomStore } from './helpers/custom-store.js';
import { setupDiscovery, setupJwks } from './helpers/openid-helper.js';

const clientID = '__test_client_id__';
const expectedDefaultState = encodeState({ returnTo: 'https://example.org' });

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: clientID,
  baseURL: 'http://example.local',
  issuerBaseURL: 'https://op.example.com',
  authRequired: false,
};

/**
 * Generate transient transaction cookie value
 * @param {Record<string, string>} value
 * @param {string} [cookieName]
 * @param {string} [secret]
 */
function generateTransactionCookie(value, cookieName = 'auth_verification', secret) {
  const [key] = getSigningKeyStore(secret ?? defaultConfig.secret);
  return signCookie(cookieName, JSON.stringify(value), key);
}

describe('callback response_mode: form_post', () => {
  beforeEach(() => {
    setupDiscovery();
  });
  afterEach(() => {
    mock.timers.reset();
  });

  it('should error when the body is empty', async () => {
    const app = createApp(auth(defaultConfig));

    const response = await request(app).post('/callback');
    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err?.message).to.be.ok;
  });

  it('should error when the state cookie is missing', async () => {
    const app = createApp(auth(defaultConfig));
    const response = await request(app).post('/callback').send({
      state: '__test_state__',
      id_token: '__invalid_token__',
      code: randomUUID(),
    });

    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err?.code).to.equal('OAUTH_INVALID_RESPONSE');
  });

  it("should error when state doesn't match", async () => {
    const app = createApp(auth(defaultConfig));

    const vercookie = await generateTransactionCookie({ state: '__valid_state__', nonce: '__test_nonce__' });

    const response = await request(app).post('/callback').set('Cookie', `auth_verification=${vercookie}`).send({
      state: '__invalid_state__',
      code: randomUUID(),
    });

    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err?.code).to.equal('OAUTH_INVALID_RESPONSE');
  });

  it("should error when id_token can't be parsed (implicit and hybrid unsupported)", async () => {
    const app = createApp(auth(defaultConfig));

    const vercookie = await generateTransactionCookie({ state: '__test_state__', nonce: '__test_nonce__' });

    const response = await request(app).post('/callback').set('Cookie', `auth_verification=${vercookie}`).send({
      state: '__test_state__',
      code: randomUUID(),
      id_token: '__invalid_token__',
    });

    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err.code).to.equal('OAUTH_UNSUPPORTED_OPERATION');
  });

  it('should error when id_token has invalid alg (implicit and hybrid unsupported)', async () => {
    const app = createApp(auth(defaultConfig));

    const vercookie = await generateTransactionCookie({ state: '__test_state__', nonce: '__test_nonce__' });

    const response = await request(app)
      .post('/callback')
      .set('Cookie', `auth_verification=${vercookie}`)
      .send({
        state: '__test_state__',
        code: randomUUID(),
        id_token: JWT.sign({ sub: '__test_sub__' }, 'secret', {
          algorithm: 'HS256',
        }),
      });

    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err.code).to.equal('OAUTH_UNSUPPORTED_OPERATION');
  });

  it('should error when id_token is missing issuer (implicit and hybrid unsupported)', async () => {
    // const { response } = await setup({
    //   cookies: generateCookies({
    //     nonce: '__test_nonce__',
    //     state: '__test_state__',
    //   }),
    //   body: {
    //     state: '__test_state__',
    //     code: randomUUID(),
    //     id_token: await makeIdToken({ iss: undefined }),
    //   },
    // });
    // expect(response.statusCode, response.text).to.equal(400);
    // expect(response.body.err.code).to.equal('OAUTH_UNSUPPORTED_OPERATION');

    const app = createApp(auth(defaultConfig));

    const vercookie = await generateTransactionCookie({ state: '__test_state__', nonce: '__test_nonce__' });

    const response = await request(app)
      .post('/callback')
      .set('Cookie', `auth_verification=${vercookie}`)
      .send({
        state: '__test_state__',
        code: randomUUID(),
        id_token: await makeIdToken({ iss: undefined }),
      });

    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err.code).to.equal('OAUTH_UNSUPPORTED_OPERATION');
  });

  it('should error when nonce is missing from cookies (implicit and hybrid unsupported)', async () => {
    const app = createApp(auth(defaultConfig));

    const vercookie = await generateTransactionCookie({ state: '__test_state__' });

    const response = await request(app)
      .post('/callback')
      .set('Cookie', `auth_verification=${vercookie}`)
      .send({
        state: '__test_state__',
        code: randomUUID(),
        id_token: await makeIdToken(),
      });

    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err.code).to.equal('OAUTH_UNSUPPORTED_OPERATION');

    // const { response } = await setup({
    //   cookies: generateCookies({
    //     state: '__test_state__',
    //   }),
    //   body: {
    //     state: '__test_state__',
    //     code: randomUUID(),
    //     id_token: await makeIdToken(),
    //   },
    // });
    // expect(response.statusCode, response.text).to.equal(400);
    // expect(response.body.err.code).to.equal('OAUTH_UNSUPPORTED_OPERATION');
  });

  it('should error when legacy samesite fallback is off', async () => {
    const app = createApp(auth({ ...defaultConfig, legacySameSiteCookie: false }));

    const vercookie = await generateTransactionCookie({ state: '__test_state__' }, '_auth_verification');

    const response = await request(app)
      .post('/callback')
      .set('Cookie', `_auth_verification=${vercookie}`)
      .send({
        state: '__test_state__',
        code: randomUUID(),
        id_token: await makeIdToken(),
      });

    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err.code).to.equal('OAUTH_INVALID_RESPONSE');
  });

  it('should include oauth error properties in error', async () => {
    const app = createApp(auth(defaultConfig));

    const response = await request(app).post('/callback').send({
      error: 'foo',
      error_description: 'bar',
      code: 'TEST_CODE',
    });

    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err?.error).to.equal('foo');
    expect(response.body.err?.error_description).to.equal('bar');
  });

  it('should use legacy samesite fallback', async () => {
    setupJwks();

    const agent = request.agent(
      createApp(
        auth({
          ...defaultConfig,
          clientSecret: '__test_client_secret__',
          authorizationParams: {
            response_type: 'code id_token',
          },
        })
      )
    );

    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    nock('https://op.example.com/').post('/oauth/token').query(true).reply(200, {
      access_token: '__test_access_token__',
      refresh_token: '__test_refresh_token__',
      id_token: idToken,
      token_type: 'bearer',
      expires_in: 86400,
    });

    const sameSiteVercookie = await generateTransactionCookie(
      { state: expectedDefaultState, nonce: '__test_nonce__' },
      '_auth_verification'
    );

    const response = await agent.post('/callback').set('Cookie', `_auth_verification=${sameSiteVercookie}`).send({
      state: expectedDefaultState,
      code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      id_token: idToken,
    });

    expect(response.statusCode, response.text).to.equal(302);
  });

  it("should expose all tokens when id_token is valid and response_type is 'code id_token'", async () => {
    setupJwks();

    const agent = request.agent(
      createApp(
        auth({
          ...defaultConfig,
          clientSecret: '__test_client_secret__',
          authorizationParams: {
            response_type: 'code id_token',
            audience: 'https://api.example.com/',
            scope: 'openid profile email read:reports offline_access',
          },
        })
      )
    );

    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    nock('https://op.example.com/').post('/oauth/token').query(true).reply(200, {
      access_token: '__test_access_token__',
      refresh_token: '__test_refresh_token__',
      id_token: idToken,
      token_type: 'bearer',
      expires_in: 86400,
    });

    const vercookie = await generateTransactionCookie({ state: expectedDefaultState, nonce: '__test_nonce__' });

    await agent.post('/callback').set('Cookie', `auth_verification=${vercookie}`).send({
      state: expectedDefaultState,
      id_token: idToken,
      code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
    });

    const { body: tokens } = await agent.get('/tokens').expect(200);

    expect(tokens.isAuthenticated).to.equal(true);
    expect(tokens.idToken).to.be.ok;
    expect(tokens.idToken).to.be.a('string');
    expect(tokens.refreshToken).to.equal('__test_refresh_token__');
    expect(tokens.accessToken).to.deep.include({
      access_token: '__test_access_token__',
      token_type: 'bearer',
    });
    expect(tokens.idTokenClaims).to.deep.include({
      sub: '__test_sub__',
    });
  });

  it('should handle access token expiry', async () => {
    setupJwks();

    const agent = request.agent(
      createApp(
        auth({
          ...defaultConfig,
          clientSecret: '__test_client_secret__',
          authorizationParams: {
            response_type: 'code',
          },
        })
      )
    );

    mock.timers.enable({ apis: ['Date'], now: new Date() });

    const hrSecs = 60 * 60;
    const hrMs = hrSecs * 1000;

    nock('https://op.example.com/')
      .post('/oauth/token')
      .reply(200, {
        access_token: '__test_access_token__',
        refresh_token: '__test_refresh_token__',
        id_token: await makeIdToken(),
        token_type: 'bearer',
        expires_in: 86400,
      });

    const vercookie = await generateTransactionCookie({ state: expectedDefaultState, nonce: '__test_nonce__' });

    await agent.post('/callback').set('Cookie', `auth_verification=${vercookie}`).send({
      state: expectedDefaultState,
      code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
    });

    const { body: tokens } = await agent.get('/tokens').expect(200);

    expect(tokens.accessToken.expires_in).to.be.approximately(24 * hrSecs, 5);
    mock.timers.tick(4 * hrMs);
    const tokens2 = await agent
      .get('/tokens')
      .expect(200)
      .then((r) => r.body);
    expect(tokens2.accessToken.expires_in).to.be.approximately(20 * hrSecs, 5);
    expect(tokens2.accessTokenExpired).to.be.false;
    mock.timers.tick(21 * hrMs);
    const tokens3 = await agent
      .get('/tokens')
      .expect(200)
      .then((r) => r.body);
    expect(tokens3.accessTokenExpired).to.be.true;
  });

  it('should refresh an access token', async () => {
    setupJwks();

    const router = auth({
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      clientAuthMethod: 'client_secret_post',
      authorizationParams: {
        response_type: 'code id_token',
        audience: 'https://api.example.com/',
        scope: 'openid profile email read:reports offline_access',
      },
    });
    router.get('/refresh', async (req, res) => {
      const accessToken = await req.oidc.accessToken.refresh();
      res.json({
        accessToken,
        refreshToken: req.oidc.refreshToken,
      });
    });

    const agent = request.agent(createApp(router));

    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    nock('https://op.example.com/').post('/oauth/token').query(true).reply(200, {
      access_token: '__test_access_token__',
      refresh_token: '__test_refresh_token__',
      id_token: idToken,
      token_type: 'bearer',
      expires_in: 86400,
    });

    const vercookie = await generateTransactionCookie({ state: expectedDefaultState, nonce: '__test_nonce__' });

    await agent.post('/callback').set('Cookie', `auth_verification=${vercookie}`).send({
      state: expectedDefaultState,
      id_token: idToken,
      code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
    });

    const { body: tokens } = await agent.get('/tokens').expect(200);

    nock('https://op.example.com/').post('/oauth/token').reply(200, {
      access_token: '__new_access_token__',
      refresh_token: '__new_refresh_token__',
      id_token: tokens.idToken,
      token_type: 'Bearer',
      expires_in: 86400,
    });

    const { body: newTokens } = await agent.get('/refresh').expect(200);

    expect(tokens.accessToken.access_token).to.equal('__test_access_token__');
    expect(tokens.refreshToken).to.equal('__test_refresh_token__');
    expect(newTokens.accessToken.access_token).to.equal('__new_access_token__');
    expect(newTokens.refreshToken).to.equal('__new_refresh_token__');

    const newerTokens = await agent.get('/tokens').then((r) => r.body);

    expect(newerTokens.accessToken.access_token, 'the new access token should be persisted in the session').to.equal(
      '__new_access_token__'
    );
  });

  it('should retain sid after token refresh', async () => {
    setupJwks();

    const router = auth({
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code id_token',
        audience: 'https://api.example.com/',
        scope: 'openid profile email read:reports offline_access',
      },
    });
    router.get('/refresh', async (req, res, next) => {
      try {
        const accessToken = await req.oidc.accessToken.refresh();
        res.json({
          accessToken,
          refreshToken: req.oidc.refreshToken,
        });
      } catch (err) {
        next(err);
      }
    });

    const agent = request.agent(createApp(router));

    const idTokenWithSid = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
      sid: 'foo',
    });
    const idTokenNoSid = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    nock('https://op.example.com/')
      .post('/oauth/token')
      .query(true)
      .reply(200, {
        access_token: '__test_access_token__',
        refresh_token: '__test_refresh_token__',
        id_token: idTokenWithSid,
        token_type: 'bearer',
        expires_in: 86400,
      })
      .post('/oauth/token')
      .query(true)
      .reply(200, {
        access_token: '__new_access_token__',
        refresh_token: '__new_refresh_token__',
        id_token: idTokenNoSid,
        token_type: 'bearer',
        expires_in: 86400,
      });

    const vercookie = await generateTransactionCookie({ state: expectedDefaultState, nonce: '__test_nonce__' });

    await agent.post('/callback').set('Cookie', `auth_verification=${vercookie}`).send({
      state: expectedDefaultState,
      id_token: idTokenWithSid,
      code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
    });

    await agent.get('/refresh');
    const { body: newTokens } = await agent.get('/tokens');

    expect(newTokens.accessToken.access_token).to.equal('__new_access_token__');
    expect(newTokens.idTokenClaims.sid).to.equal('foo');
  });

  it('should remove any stale back-channel logout entries by sub', async () => {
    setupJwks();

    const store = new CustomStore();
    await store.set('https://op.example.com/|bcl-sub', '{}');

    const agent = request.agent(
      createApp(
        auth({
          ...defaultConfig,
          backchannelLogout: { store },
          clientSecret: '__test_client_secret__',
          authorizationParams: {
            response_type: 'code id_token',
          },
        })
      )
    );

    const idToken = await makeIdToken({
      sub: 'bcl-sub',
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    nock('https://op.example.com/').post('/oauth/token').query(true).reply(200, {
      access_token: '__test_access_token__',
      refresh_token: '__test_refresh_token__',
      id_token: idToken,
      token_type: 'bearer',
      expires_in: 86400,
    });

    const vercookie = await generateTransactionCookie({ state: expectedDefaultState, nonce: '__test_nonce__' });

    const response = await agent.post('/callback').set('Cookie', `auth_verification=${vercookie}`).send({
      state: expectedDefaultState,
      code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      id_token: idToken,
    });

    expect(response.statusCode, response.text).to.equal(302);
    const logout = await store.get('https://op.example.com/|bcl-sub');
    expect(logout).to.not.be.ok;
  });

  it('should refresh an access token and keep original refresh token', async () => {
    setupJwks();

    const router = auth({
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      clientAuthMethod: 'client_secret_post',
      authorizationParams: {
        response_type: 'code id_token',
        audience: 'https://api.example.com/',
        scope: 'openid profile email read:reports offline_access',
      },
    });
    router.get('/refresh', async (req, res, next) => {
      try {
        const accessToken = await req.oidc.accessToken.refresh();
        res.json({
          accessToken,
          refreshToken: req.oidc.refreshToken,
        });
      } catch (err) {
        next(err);
      }
    });

    const agent = request.agent(createApp(router));

    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    nock('https://op.example.com/')
      .post('/oauth/token')
      .query(true)
      .reply(200, {
        access_token: '__test_access_token__',
        refresh_token: '__test_refresh_token__',
        id_token: idToken,
        token_type: 'bearer',
        expires_in: 86400,
      })
      .post('/oauth/token')
      .query(true)
      .reply(200, {
        access_token: '__new_access_token__',
        id_token: idToken,
        token_type: 'bearer',
        expires_in: 86400,
      });

    const vercookie = await generateTransactionCookie({ state: expectedDefaultState, nonce: '__test_nonce__' });

    await agent.post('/callback').set('Cookie', `auth_verification=${vercookie}`).send({
      state: expectedDefaultState,
      id_token: idToken,
      code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
    });

    const { body: tokens } = await agent.get('/tokens').expect(200);

    const { body: newTokens } = await agent.get('/refresh').expect(200);

    expect(tokens.accessToken.access_token).to.equal('__test_access_token__');
    expect(tokens.refreshToken).to.equal('__test_refresh_token__');
    expect(newTokens.accessToken.access_token).to.equal('__new_access_token__');
    expect(newTokens.refreshToken).to.equal('__test_refresh_token__');
  });

  it('should refresh an access token and pass tokenEndpointParams and refresh argument params to the request', async () => {
    setupJwks();

    const router = auth({
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code id_token',
        audience: 'https://api.example.com/',
        scope: 'openid profile email read:reports offline_access',
      },
      tokenEndpointParams: {
        longeLiveToken: true,
      },
    });
    router.get('/refresh', async (req, res) => {
      const accessToken = await req.oidc.accessToken.refresh({
        tokenEndpointParams: { force: true },
      });
      res.json({
        accessToken,
        refreshToken: req.oidc.refreshToken,
      });
    });

    const agent = request.agent(createApp(router));

    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    nock('https://op.example.com/')
      .post('/oauth/token')
      .query(true)
      .reply(200, {
        access_token: '__test_access_token__',
        refresh_token: '__test_refresh_token__',
        id_token: idToken,
        token_type: 'bearer',
        expires_in: 86400,
      })
      .post('/oauth/token')
      .query(true)
      .reply(200, {
        access_token: '__new_access_token__',
        refresh_token: '__new_refresh_token__',
        id_token: idToken,
        token_type: 'bearer',
        expires_in: 86400,
      });

    const vercookie = await generateTransactionCookie({ state: expectedDefaultState, nonce: '__test_nonce__' });

    await agent.post('/callback').set('Cookie', `auth_verification=${vercookie}`).send({
      state: expectedDefaultState,
      id_token: idToken,
      code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
    });

    const { body: tokens } = await agent.get('/tokens').expect(200);

    const { body: newTokens } = await agent.get('/refresh').expect(200);

    expect(tokens.accessToken.access_token).to.equal('__test_access_token__');
    expect(tokens.refreshToken).to.equal('__test_refresh_token__');
    expect(newTokens.accessToken.access_token).to.equal('__new_access_token__');
    expect(newTokens.refreshToken).to.equal('__new_refresh_token__');

    const newerTokens = await agent.get('/tokens').then((r) => r.body);

    expect(newerTokens.accessToken.access_token, 'the new access token should be persisted in the session').to.equal(
      '__new_access_token__'
    );
  });

  it('should fetch userinfo', async () => {
    setupJwks();

    const router = auth({
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code id_token',
        audience: 'https://api.example.com/',
        scope: 'openid profile email',
      },
    });
    router.get('/user-info', async (req, res) => {
      res.json(await req.oidc.fetchUserInfo());
    });

    const agent = request.agent(createApp(router));

    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    nock('https://op.example.com/').post('/oauth/token').query(true).reply(200, {
      access_token: '__test_access_token__',
      refresh_token: '__test_refresh_token__',
      id_token: idToken,
      token_type: 'bearer',
      expires_in: 86400,
    });

    const vercookie = await generateTransactionCookie({ state: expectedDefaultState, nonce: '__test_nonce__' });

    await agent.post('/callback').set('Cookie', `auth_verification=${vercookie}`).send({
      state: expectedDefaultState,
      id_token: idToken,
      code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
    });

    nock('https://op.example.com/').get('/userinfo').query(true).reply(200, {
      userInfo: true,
      sub: '__test_sub__',
    });

    const userInfo = await agent.get('/user-info').then((r) => r.body);

    expect(userInfo).to.deep.equal({ userInfo: true, sub: '__test_sub__' });
  });

  it('should use basic auth on token endpoint when using code flow', async () => {
    setupJwks();

    const agent = request.agent(
      createApp(
        auth({
          ...defaultConfig,
          clientSecret: '__test_client_secret__',
          clientAuthMethod: 'client_secret_basic',
          authorizationParams: {
            response_type: 'code id_token',
            audience: 'https://api.example.com/',
            scope: 'openid profile email read:reports offline_access',
          },
        })
      )
    );

    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    nock('https://op.example.com/')
      .post('/oauth/token')
      .basicAuth({ user: encodeBasicAuthValue(defaultConfig.clientID), pass: encodeBasicAuthValue('__test_client_secret__') })
      .reply(200, {
        access_token: '__test_access_token__',
        refresh_token: '__test_refresh_token__',
        id_token: idToken,
        token_type: 'bearer',
        expires_in: 86400,
      });

    const vercookie = await generateTransactionCookie({ state: expectedDefaultState, nonce: '__test_nonce__' });

    await agent.post('/callback').set('Cookie', `auth_verification=${vercookie}`).send({
      state: expectedDefaultState,
      id_token: idToken,
      code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
    });

    const { body: tokens } = await agent.get('/tokens').expect(200);

    expect(tokens).to.exist;
    expect(tokens.isAuthenticated).to.be.true;
  });

  it('should use private key jwt on token endpoint', async () => {
    const privateKey = await getPrivatePEM();

    const agent = request.agent(
      createApp(
        auth({
          ...defaultConfig,
          authorizationParams: {
            response_type: 'code',
          },
          clientAssertionSigningKey: privateKey,
        })
      )
    );

    nock('https://op.example.com/')
      .post('/oauth/token')
      .query(true)
      .reply(200, {
        access_token: '__test_access_token__',
        refresh_token: '__test_refresh_token__',
        id_token: await makeIdToken(),
        token_type: 'bearer',
        expires_in: 86400,
      });

    const vercookie = await generateTransactionCookie({ state: expectedDefaultState, nonce: '__test_nonce__' });

    await agent.post('/callback').set('Cookie', `auth_verification=${vercookie}`).send({
      state: expectedDefaultState,
      code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
    });

    const { body: tokens } = await agent.get('/tokens').expect(200);

    expect(tokens).to.exist;
    expect(tokens.isAuthenticated).to.be.true;
  });

  it('should use client secret jwt on token endpoint', async () => {
    const agent = request.agent(
      createApp(
        auth({
          ...defaultConfig,
          clientSecret: 'foo',
          authorizationParams: {
            response_type: 'code',
          },
          clientAuthMethod: 'client_secret_jwt',
        })
      )
    );

    nock('https://op.example.com/')
      .post('/oauth/token')
      .query(true)
      .reply(200, {
        access_token: '__test_access_token__',
        refresh_token: '__test_refresh_token__',
        id_token: await makeIdToken(),
        token_type: 'bearer',
        expires_in: 86400,
      });

    const vercookie = await generateTransactionCookie({ state: expectedDefaultState, nonce: '__test_nonce__' });

    await agent.post('/callback').set('Cookie', `auth_verification=${vercookie}`).send({
      state: expectedDefaultState,
      code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
    });

    const { body: tokens } = await agent.get('/tokens').expect(200);

    expect(tokens).to.exist;
    expect(tokens.isAuthenticated).to.be.true;
  });

  it('should allow custom callback route', async () => {
    const router = auth({
      ...defaultConfig,
      authorizationParams: {
        response_type: 'code id_token',
      },
      routes: {
        callback: false,
      },
    });

    router.post('/callback', (_req, res) => {
      res.set('foo', 'bar');
      res.oidc.callback({
        redirectUri: 'http://localhost:3000/callback',
      });
    });

    const agent = request.agent(createApp(router));

    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    nock('https://op.example.com/').post('/oauth/token').query(true).reply(200, {
      access_token: '__test_access_token__',
      refresh_token: '__test_refresh_token__',
      id_token: idToken,
      token_type: 'bearer',
      expires_in: 86400,
    });

    const vercookie = await generateTransactionCookie({ state: expectedDefaultState, nonce: '__test_nonce__' });

    const response = await agent.post('/callback').set('Cookie', `auth_verification=${vercookie}`).send({
      state: expectedDefaultState,
      code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      id_token: idToken,
    });

    expect(response.get('foo')).to.equal('bar');
  });
});

function encodeBasicAuthValue(v) {
  return encodeURIComponent(v).replace(/_/g, '%5F');
}
