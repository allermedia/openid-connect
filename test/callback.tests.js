import { randomUUID } from 'node:crypto';
import { mock } from 'node:test';

import { auth } from '@aller/openid-connect';
import nock from 'nock';
import request from 'supertest';

import { encodeState } from '../src/hooks/getLoginState.js';
import { TransientCookieHandler } from '../src/transientHandler.js';

import { makeIdToken, JWT } from './fixture/cert.js';
import { getPrivatePEM } from './fixture/jwk.js';
import { createApp } from './fixture/server.js';
import { CustomStore } from './helpers/custom-store.js';
import { setupDiscovery, setupJwks } from './helpers/openid-helper.js';

const clientID = '__test_client_id__';
const expectedDefaultState = encodeState({ returnTo: 'https://example.org' });

const baseUrl = 'http://localhost:3000';
const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: clientID,
  baseURL: 'http://example.local',
  issuerBaseURL: 'https://op.example.com',
  authRequired: false,
};

function generateCookies(values, customTxnCookieName) {
  return { [customTxnCookieName || 'auth_verification']: JSON.stringify(values) };
}

async function setup(params) {
  // Create appropriate ID token for token endpoint based on test setup
  if (params.cookies && Object.keys(params.cookies).length > 0) {
    // Parse the auth verification cookie to get the nonce
    let authVerification = {};
    const authVerificationCookie = params.cookies.auth_verification || params.cookies[Object.keys(params.cookies)[0]];
    if (authVerificationCookie) {
      try {
        authVerification = JSON.parse(authVerificationCookie);
      } catch {
        // If it's already an object
        authVerification = authVerificationCookie;
      }
    }

    // Create token endpoint ID token with matching nonce (required by oauth4webapi)
    const tokenPayload = { nonce: authVerification.nonce || '__test_nonce__' };
    if (params.body?.id_token) {
      try {
        // Decode the authorization endpoint ID token to get the subject
        const authIdToken = params.body.id_token;
        const payload = JSON.parse(Buffer.from(authIdToken.split('.')[1], 'base64url').toString());
        tokenPayload.sub = payload.sub; // Match the subject from authorization endpoint
      } catch {
        // If decoding fails, use default
      }
    }
  }

  const authOpts = { ...defaultConfig, ...params.authOpts };

  const router = params.router || auth(authOpts);
  const transient = new TransientCookieHandler(authOpts);

  const agent = request.agent(createApp(router));

  Object.keys(params.cookies).forEach((cookieName) => {
    let value;

    transient.store(
      {
        cookie(key, ...args) {
          if (key === cookieName) {
            value = args[0];
          }
        },
      },
      cookieName,
      params.cookies[cookieName]
    );

    agent.jar.setCookie(`${cookieName}=${value}; Max-Age=3600; Path=/; HttpOnly; SameSite=lax`);
  });

  let existingSessionCookie;
  if (params.existingSession) {
    await agent.post('/session').send(params.existingSession);

    const cookies = agent.jar.getCookies({ domain: '127.0.0.1', path: '/' });
    existingSessionCookie = cookies.find(({ name }) => name === 'appSession');
  }

  const response = await agent.post('/callback').send(params.body);

  const currentUser = await agent.get('/user').then((r) => r.body);
  const currentSession = await agent.get('/session').then((r) => r.body);
  const tokens = await agent.get('/tokens').then((r) => r.body);

  return {
    agent,
    baseUrl,
    response,
    currentUser,
    currentSession,
    tokens,
    existingSessionCookie,
  };
}

// For the purpose of this test the fake SERVER returns the error message in the body directly
// production application should have an error middleware.
// http://expressjs.com/en/guide/error-handling.html

describe('callback response_mode: form_post', () => {
  beforeEach(() => {
    setupDiscovery();
  });
  afterEach(() => {
    mock.timers.reset();
  });

  it('should error when the body is empty', async () => {
    const { response } = await setup({
      cookies: generateCookies({
        nonce: '__test_nonce__',
        state: '__test_state__',
      }),
      body: '',
    });
    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err.message).to.be.ok;
  });

  it('should error when the state is missing', async () => {
    const { response } = await setup({
      cookies: {},
      body: {
        state: '__test_state__',
        id_token: '__invalid_token__',
        code: randomUUID(),
      },
    });
    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err?.code).to.equal('OAUTH_INVALID_RESPONSE');
  });

  it("should error when state doesn't match", async () => {
    const { response } = await setup({
      cookies: generateCookies({
        nonce: '__test_nonce__',
        state: '__valid_state__',
      }),
      body: {
        state: '__invalid_state__',
        code: randomUUID(),
      },
    });
    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err?.code).to.equal('OAUTH_INVALID_RESPONSE');
  });

  it("should error when id_token can't be parsed", async () => {
    const { response } = await setup({
      cookies: generateCookies({
        nonce: '__test_nonce__',
        state: '__test_state__',
      }),
      body: {
        state: '__test_state__',
        code: randomUUID(),
        id_token: '__invalid_token__',
      },
    });
    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err.code).to.equal('OAUTH_UNSUPPORTED_OPERATION');
  });

  it('should error when id_token has invalid alg', async () => {
    const { response } = await setup({
      cookies: generateCookies({
        nonce: '__test_nonce__',
        state: '__test_state__',
      }),
      body: {
        state: '__test_state__',
        code: randomUUID(),
        id_token: JWT.sign({ sub: '__test_sub__' }, 'secret', {
          algorithm: 'HS256',
        }),
      },
    });
    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err.code).to.equal('OAUTH_UNSUPPORTED_OPERATION');
  });

  it('should error when id_token is missing issuer', async () => {
    const { response } = await setup({
      cookies: generateCookies({
        nonce: '__test_nonce__',
        state: '__test_state__',
      }),
      body: {
        state: '__test_state__',
        code: randomUUID(),
        id_token: await makeIdToken({ iss: undefined }),
      },
    });
    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err.code).to.equal('OAUTH_UNSUPPORTED_OPERATION');
  });

  it('should error when nonce is missing from cookies', async () => {
    const { response } = await setup({
      cookies: generateCookies({
        state: '__test_state__',
      }),
      body: {
        state: '__test_state__',
        code: randomUUID(),
        id_token: await makeIdToken(),
      },
    });
    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err.code).to.equal('OAUTH_UNSUPPORTED_OPERATION');
  });

  it('should error when legacy samesite fallback is off', async () => {
    const { response } = await setup({
      authOpts: {
        // Do not check the fallback cookie value.
        legacySameSiteCookie: false,
      },
      cookies: {
        ['_auth_verification']: JSON.stringify({
          state: '__test_state__',
        }),
      },
      body: {
        state: '__test_state__',
        code: randomUUID(),
        id_token: '__invalid_token__',
      },
    });
    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err.code).to.equal('OAUTH_INVALID_RESPONSE');
  });

  it('should include oauth error properties in error', async () => {
    const { response } = await setup({
      cookies: {},
      body: {
        error: 'foo',
        error_description: 'bar',
        code: 'TEST_CODE',
      },
    });

    expect(response.statusCode, response.text).to.equal(400);
    expect(response.body.err?.error).to.equal('foo');
    expect(response.body.err?.error_description).to.equal('bar');
  });

  it('should use legacy samesite fallback', async () => {
    setupJwks();

    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ', // Required for hybrid flow
    });

    nock('https://op.example.com/').post('/oauth/token').query(true).reply(200, {
      access_token: '__test_access_token__',
      refresh_token: '__test_refresh_token__',
      id_token: idToken,
      token_type: 'bearer',
      expires_in: 86400,
    });

    const { currentUser } = await setup({
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
        },
      },
      cookies: {
        auth_verification: JSON.stringify({
          state: expectedDefaultState,
          nonce: '__test_nonce__',
        }),
      },
      body: {
        state: expectedDefaultState,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
        id_token: idToken,
      },
    });

    expect(currentUser).to.be.ok;
  });

  it("should expose all tokens when id_token is valid and response_type is 'code id_token'", async () => {
    setupJwks();

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

    const { tokens } = await setup({
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
          audience: 'https://api.example.com/',
          scope: 'openid profile email read:reports offline_access',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: idToken,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });

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

    const { tokens, agent } = await setup({
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });
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

    const authOpts = {
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      clientAuthMethod: 'client_secret_post',
      authorizationParams: {
        response_type: 'code id_token',
        audience: 'https://api.example.com/',
        scope: 'openid profile email read:reports offline_access',
      },
    };
    const router = auth(authOpts);
    router.get('/refresh', async (req, res) => {
      const accessToken = await req.oidc.accessToken.refresh();
      res.json({
        accessToken,
        refreshToken: req.oidc.refreshToken,
      });
    });

    const { tokens, agent } = await setup({
      router,
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
          audience: 'https://api.example.com/',
          scope: 'openid profile email read:reports offline_access',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: idToken,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });

    nock('https://op.example.com/').post('/oauth/token').reply(200, {
      access_token: '__new_access_token__',
      refresh_token: '__new_refresh_token__',
      id_token: tokens.idToken,
      token_type: 'Bearer',
      expires_in: 86400,
    });

    const newTokens = await agent.get('/refresh').then((r) => r.body);

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

    const idTokenWithSid = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
      sid: 'foo',
    });
    const idTokenNoSid = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ',
    });

    const authOpts = {
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code id_token',
        audience: 'https://api.example.com/',
        scope: 'openid profile email read:reports offline_access',
      },
    };
    const router = auth(authOpts);
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

    const { agent } = await setup({
      router,
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
          audience: 'https://api.example.com/',
          scope: 'openid profile email read:reports offline_access',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: idTokenWithSid,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });

    await agent.get('/refresh');
    const { body: newTokens } = await agent.get('/tokens');

    expect(newTokens.accessToken.access_token).to.equal('__new_access_token__');
    expect(newTokens.idTokenClaims.sid).to.equal('foo');
  });

  it('should remove any stale back-channel logout entries by sub', async () => {
    setupJwks();

    const idToken = await makeIdToken({
      sub: 'bcl-sub',
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ', // Required for hybrid flow
    });

    nock('https://op.example.com/').post('/oauth/token').query(true).reply(200, {
      access_token: '__test_access_token__',
      refresh_token: '__test_refresh_token__',
      id_token: idToken,
      token_type: 'bearer',
      expires_in: 86400,
    });

    // const { client, store } = getRedisStore();
    // await client.asyncSet('https://op.example.com/|bcl-sub', '{}');
    const store = new CustomStore();
    await store.set('https://op.example.com/|bcl-sub', '{}');
    const {
      response: { statusCode },
    } = await setup({
      authOpts: {
        backchannelLogout: { store },
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
        id_token: idToken,
      },
    });
    expect(statusCode).to.equal(302);
    // const logout = await client.asyncGet('https://op.example.com/|bcl-sub');
    const logout = await store.get('https://op.example.com/|bcl-sub');
    expect(logout).to.not.be.ok;
  });

  it('should refresh an access token and keep original refresh token', async () => {
    setupJwks();

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

    const authOpts = {
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      clientAuthMethod: 'client_secret_post',
      authorizationParams: {
        response_type: 'code id_token',
        audience: 'https://api.example.com/',
        scope: 'openid profile email read:reports offline_access',
      },
    };
    const router = auth(authOpts);
    router.get('/refresh', async (req, res) => {
      const accessToken = await req.oidc.accessToken.refresh();
      res.json({
        accessToken,
        refreshToken: req.oidc.refreshToken,
      });
    });

    const { tokens, agent } = await setup({
      router,
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
          audience: 'https://api.example.com/',
          scope: 'openid profile email read:reports offline_access',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: idToken,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });

    const newTokens = await agent.get('/refresh').then((r) => r.body);

    expect(tokens.accessToken.access_token).to.equal('__test_access_token__');
    expect(tokens.refreshToken).to.equal('__test_refresh_token__');
    expect(newTokens.accessToken.access_token).to.equal('__new_access_token__');
    expect(newTokens.refreshToken).to.equal('__test_refresh_token__');
  });

  it('should refresh an access token and pass tokenEndpointParams and refresh argument params to the request', async () => {
    setupJwks();

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

    const authOpts = {
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
    };
    const router = auth(authOpts);
    router.get('/refresh', async (req, res) => {
      const accessToken = await req.oidc.accessToken.refresh({
        tokenEndpointParams: { force: true },
      });
      res.json({
        accessToken,
        refreshToken: req.oidc.refreshToken,
      });
    });

    const { tokens, agent } = await setup({
      router,
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
          audience: 'https://api.example.com/',
          scope: 'openid profile email read:reports offline_access',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: idToken,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });

    const newTokens = await agent.get('/refresh').then((r) => r.body);

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

    const authOpts = {
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code id_token',
        audience: 'https://api.example.com/',
        scope: 'openid profile email',
      },
    };
    const router = auth(authOpts);
    router.get('/user-info', async (req, res) => {
      res.json(await req.oidc.fetchUserInfo());
    });

    const { agent } = await setup({
      router,
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
          audience: 'https://api.example.com/',
          scope: 'openid profile email read:reports offline_access',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: idToken,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
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

    nock('https://op.example.com/').post('/userinfo').query(true).reply(200, {
      userInfo: true,
      sub: '__test_sub__',
    });

    const { currentUser, tokens } = await setup({
      authOpts: {
        clientSecret: '__test_client_secret__',
        clientAuthMethod: 'client_secret_basic',
        authorizationParams: {
          response_type: 'code id_token',
          audience: 'https://api.example.com/',
          scope: 'openid profile email read:reports offline_access',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        id_token: idToken,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });

    // Verify the callback succeeded with basic auth
    expect(currentUser).to.exist;
    expect(currentUser.sub).to.equal('__test_sub__');
    expect(tokens).to.exist;
    expect(tokens.isAuthenticated).to.be.true;
  });

  it('should use private key jwt on token endpoint', async () => {
    const privateKey = await getPrivatePEM();

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

    nock('https://op.example.com/').post('/userinfo').query(true).reply(200, {
      userInfo: true,
      sub: '__test_sub__',
    });

    const { currentUser, tokens } = await setup({
      authOpts: {
        authorizationParams: {
          response_type: 'code',
        },
        clientAssertionSigningKey: privateKey,
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });

    // Verify the callback succeeded with private key JWT auth
    expect(currentUser).to.exist;
    expect(currentUser.sub).to.equal('__test_sub__');
    expect(tokens).to.exist;
    expect(tokens.isAuthenticated).to.be.true;
  });

  it('should use client secret jwt on token endpoint', async () => {
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

    nock('https://op.example.com/').post('/userinfo').query(true).reply(200, {
      userInfo: true,
      sub: '__test_sub__',
    });

    const { currentUser, tokens } = await setup({
      authOpts: {
        clientSecret: 'foo',
        authorizationParams: {
          response_type: 'code',
        },
        clientAuthMethod: 'client_secret_jwt',
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
      },
    });

    // Verify the callback succeeded with client secret JWT auth
    expect(currentUser).to.exist;
    expect(currentUser.sub).to.equal('__test_sub__');
    expect(tokens).to.exist;
    expect(tokens.isAuthenticated).to.be.true;
  });

  it('should allow custom callback route', async () => {
    const config = {
      ...defaultConfig,
      routes: {
        callback: false,
      },
    };
    const router = auth(config);

    router.post('/callback', (_req, res) => {
      res.set('foo', 'bar');
      res.oidc.callback({
        redirectUri: 'http://localhost:3000/callback',
      });
    });

    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ', // Required for hybrid flow
    });

    const {
      response: { headers },
    } = await setup({
      router,
      authOpts: {
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
        },
      },
      cookies: generateCookies({
        state: expectedDefaultState,
        nonce: '__test_nonce__',
      }),
      body: {
        state: expectedDefaultState,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y',
        id_token: idToken,
      },
    });
    expect(headers.foo).to.equal('bar');
  });
});
