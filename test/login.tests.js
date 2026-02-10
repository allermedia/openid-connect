import { assert } from 'chai';
import request from 'supertest';

import { auth } from '../index.js';
import { decodeState } from '../src/hooks/getLoginState.js';

import { create as createServer } from './fixture/server.js';

function filterRoute(method, path) {
  return (r) => r.route && r.route.path === path && r.route.methods[method.toLowerCase()];
}

function fetchAuthCookie(res, txnCookieName) {
  txnCookieName = txnCookieName || 'auth_verification';
  const cookieHeaders = res.headers['set-cookie'];
  return cookieHeaders.filter((header) => header.split('=')[0] === txnCookieName)[0];
}

function fetchFromAuthCookie(res, cookieName, txnCookieName) {
  txnCookieName = txnCookieName || 'auth_verification';
  const authCookie = fetchAuthCookie(res, txnCookieName);

  if (!authCookie) {
    return false;
  }

  const decodedAuthCookie = new URLSearchParams(authCookie);
  const cookieValuePart = decodedAuthCookie.get(txnCookieName).split('; ')[0].split('.')[0];
  const authCookieParsed = JSON.parse(cookieValuePart);

  return authCookieParsed[cookieName];
}

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  baseURL: 'https://example.org',
  issuerBaseURL: 'https://op.example.com',
  authRequired: false,
};

describe('auth', () => {
  let server;
  afterEach(() => {
    server?.close();
  });

  it('should contain the default authentication routes', async () => {
    const router = auth(defaultConfig);
    server = await createServer(router);
    assert.ok(router.stack.some(filterRoute('GET', '/login')));
    assert.ok(router.stack.some(filterRoute('GET', '/logout')));
    assert.ok(router.stack.some(filterRoute('POST', '/callback')));
    assert.ok(router.stack.some(filterRoute('GET', '/callback')));
  });

  it('should contain custom authentication routes', async () => {
    const router = auth({
      ...defaultConfig,
      routes: {
        callback: 'custom-callback',
        login: 'custom-login',
        logout: 'custom-logout',
      },
    });
    server = await createServer(router);
    assert.ok(router.stack.some(filterRoute('GET', '/custom-login')));
    assert.ok(router.stack.some(filterRoute('GET', '/custom-logout')));
    assert.ok(router.stack.some(filterRoute('POST', '/custom-callback')));
    assert.ok(router.stack.some(filterRoute('GET', '/custom-callback')));
  });

  // v6: Default response_type is now 'code' with PKCE
  it('should redirect to the authorize url for /login', async () => {
    server = await createServer(auth(defaultConfig));
    const res = await request(server).get('/login');
    assert.equal(res.statusCode, 302);

    const parsed = new URL(res.headers.location);
    assert.equal(parsed.hostname, 'op.example.com');
    assert.equal(parsed.pathname, '/authorize');
    assert.equal(parsed.searchParams.get('client_id'), '__test_client_id__');
    assert.equal(parsed.searchParams.get('scope'), 'openid profile email');
    assert.equal(parsed.searchParams.get('response_type'), 'code');
    assert.equal(parsed.searchParams.get('redirect_uri'), 'https://example.org/callback');
    assert.isTrue(parsed.searchParams.has('nonce'));
    assert.isTrue(parsed.searchParams.has('state'));
    // v6: PKCE is always used with code flow
    assert.isTrue(parsed.searchParams.has('code_challenge'));
    assert.equal(parsed.searchParams.get('code_challenge_method'), 'S256');

    assert.equal(fetchFromAuthCookie(res, 'nonce'), parsed.searchParams.get('nonce'));
    assert.equal(fetchFromAuthCookie(res, 'state'), parsed.searchParams.get('state'));
  });

  // v6: Default response_type is now 'code' with PKCE
  it('should redirect to the authorize url for /login when txn cookie name is custom', async () => {
    const customTxnCookieName = 'CustomTxnCookie';

    server = await createServer(
      auth({
        ...defaultConfig,
        transactionCookie: { name: customTxnCookieName },
      })
    );
    const res = await request(server).get('/login');
    assert.equal(res.statusCode, 302);

    const parsed = new URL(res.headers.location);
    assert.equal(parsed.hostname, 'op.example.com');
    assert.equal(parsed.pathname, '/authorize');
    assert.equal(parsed.searchParams.get('client_id'), '__test_client_id__');
    assert.equal(parsed.searchParams.get('scope'), 'openid profile email');
    assert.equal(parsed.searchParams.get('response_type'), 'code');
    assert.equal(parsed.searchParams.get('redirect_uri'), 'https://example.org/callback');
    assert.isTrue(parsed.searchParams.has('nonce'));
    assert.isTrue(parsed.searchParams.has('state'));
    // v6: PKCE is always used with code flow
    assert.isTrue(parsed.searchParams.has('code_challenge'));
    assert.equal(parsed.searchParams.get('code_challenge_method'), 'S256');

    assert.equal(fetchFromAuthCookie(res, 'nonce', customTxnCookieName), parsed.searchParams.get('nonce'));
    assert.equal(fetchFromAuthCookie(res, 'state', customTxnCookieName), parsed.searchParams.get('state'));
  });

  it('should redirect to the authorize url for any route if authRequired', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: true,
      })
    );
    const res = await request(server).get('/session');
    assert.equal(res.statusCode, 302);
  });

  it('should redirect to the authorize url for any route if attemptSilentLogin', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        attemptSilentLogin: true,
      })
    );
    const res = await request(server).get('/session');
    assert.equal(res.statusCode, 302);
  });

  it('should redirect to the authorize url for any route with custom txn name if attemptSilentLogin ', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        attemptSilentLogin: true,
        transactionCookie: { name: 'CustomTxnCookie' },
      })
    );
    const res = await request(server).get('/session');
    assert.equal(res.statusCode, 302);
  });

  it('should redirect to the authorize url for /login in code flow', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code',
        },
      })
    );
    const res = await request(server).get('/login');
    assert.equal(res.statusCode, 302);

    const parsed = new URL(res.headers.location);

    assert.equal(parsed.hostname, 'op.example.com');
    assert.equal(parsed.pathname, '/authorize');
    assert.equal(parsed.searchParams.get('client_id'), '__test_client_id__');
    assert.equal(parsed.searchParams.get('scope'), 'openid profile email');
    assert.equal(parsed.searchParams.get('response_type'), 'code');
    assert.equal(parsed.searchParams.get('response_mode'), undefined);
    assert.equal(parsed.searchParams.get('redirect_uri'), 'https://example.org/callback');
    assert.isTrue(parsed.searchParams.has('nonce'));
    assert.isTrue(parsed.searchParams.has('state'));
    assert.property(res.headers, 'set-cookie');

    assert.equal(fetchFromAuthCookie(res, 'nonce'), parsed.searchParams.get('nonce'));
    assert.equal(fetchFromAuthCookie(res, 'state'), parsed.searchParams.get('state'));
  });

  it('should redirect to the authorize url for /login in code flow with custom txn cookie', async () => {
    const customTxnCookieName = 'CustomTxnCookie';
    server = await createServer(
      auth({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code',
        },
        transactionCookie: { name: customTxnCookieName },
      })
    );
    const res = await request(server).get('/login');
    assert.equal(res.statusCode, 302);

    const parsed = new URL(res.headers.location);

    assert.equal(parsed.hostname, 'op.example.com');
    assert.equal(parsed.pathname, '/authorize');
    assert.equal(parsed.searchParams.get('client_id'), '__test_client_id__');
    assert.equal(parsed.searchParams.get('scope'), 'openid profile email');
    assert.equal(parsed.searchParams.get('response_type'), 'code');
    assert.equal(parsed.searchParams.get('response_mode'), undefined);
    assert.equal(parsed.searchParams.get('redirect_uri'), 'https://example.org/callback');
    assert.isTrue(parsed.searchParams.has('nonce'));
    assert.isTrue(parsed.searchParams.has('state'));
    assert.property(res.headers, 'set-cookie');

    assert.equal(fetchFromAuthCookie(res, 'nonce', customTxnCookieName), parsed.searchParams.get('nonce'));
    assert.equal(fetchFromAuthCookie(res, 'state', customTxnCookieName), parsed.searchParams.get('state'));
  });

  // v6: Implicit flow (id_token response_type) is no longer supported
  // The id_token flow test has been removed as openid-client v6 only supports authorization code flow
  it('should redirect to the authorize url for /login in hybrid flow', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
        },
      })
    );
    const res = await request(server).get('/login');
    assert.equal(res.statusCode, 302);

    const parsed = new URL(res.headers.location);

    assert.equal(parsed.hostname, 'op.example.com');
    assert.equal(parsed.pathname, '/authorize');
    assert.equal(parsed.searchParams.get('client_id'), '__test_client_id__');
    assert.equal(parsed.searchParams.get('scope'), 'openid profile email');
    assert.equal(parsed.searchParams.get('response_type'), 'code id_token');
    assert.equal(parsed.searchParams.get('response_mode'), 'form_post');
    assert.equal(parsed.searchParams.get('redirect_uri'), 'https://example.org/callback');
    assert.isTrue(parsed.searchParams.has('nonce'));
    assert.isTrue(parsed.searchParams.has('state'));
  });

  it('should redirect to the authorize url for custom login route', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        routes: {
          callback: 'custom-callback',
          login: 'custom-login',
          logout: 'custom-logout',
        },
      })
    );
    const res = await request(server).get('/custom-login');
    assert.equal(res.statusCode, 302);

    const parsed = new URL(res.headers.location);
    assert.equal(parsed.hostname, 'op.example.com');
    assert.equal(parsed.pathname, '/authorize');
    assert.equal(parsed.searchParams.get('redirect_uri'), 'https://example.org/custom-callback');
  });

  it('should allow custom login route with additional login params', async () => {
    const router = auth({
      ...defaultConfig,
      routes: { login: false },
    });
    router.get('/login', (req, res) => {
      res.oidc.login({
        returnTo: 'https://example.org/custom-redirect',
        authorizationParams: {
          response_type: 'code',
          response_mode: 'query',
          scope: 'openid email',
        },
      });
    });
    server = await createServer(router);

    const res = await request(server).get('/login');
    assert.equal(res.statusCode, 302);

    const parsed = new URL(res.headers.location);

    assert.equal(parsed.hostname, 'op.example.com');
    assert.equal(parsed.pathname, '/authorize');
    assert.equal(parsed.searchParams.get('scope'), 'openid email');
    assert.equal(parsed.searchParams.get('response_type'), 'code');
    assert.equal(parsed.searchParams.get('response_mode'), 'query');
    assert.equal(parsed.searchParams.get('redirect_uri'), 'https://example.org/callback');
    assert.isTrue(parsed.searchParams.has('nonce'));

    const decodedState = decodeState(parsed.searchParams.get('state'));

    assert.equal(decodedState.returnTo, 'https://example.org/custom-redirect');
  });

  it('should not allow removing openid from scope', async () => {
    const router = auth({ ...defaultConfig, routes: { login: false } });
    router.get('/login', (_req, res) => {
      res.oidc.login({
        authorizationParams: {
          scope: 'email',
        },
      });
    });
    server = await createServer(router);

    const res = await request(server).get('/login');
    assert.equal(res.statusCode, 500);
    assert.equal(res.body.err.message, 'scope should contain "openid"');
  });

  it('should not allow an invalid response_type', async () => {
    const router = auth({
      ...defaultConfig,
      routes: { login: false },
    });
    router.get('/login', (_req, res) => {
      res.oidc.login({
        authorizationParams: {
          response_type: 'invalid',
        },
      });
    });
    server = await createServer(router);

    const res = await request(server).get('/login');
    assert.equal(res.statusCode, 500);
    assert.equal(res.body.err.message, 'response_type should be one of id_token, code id_token, code');
  });

  it('should not allow an invalid response_type when txn cookie name custom', async () => {
    const router = auth({
      ...defaultConfig,
      routes: { login: false },
      transactionCookie: { name: 'CustomTxnCookie' },
    });
    router.get('/login', (req, res) => {
      res.oidc.login({
        authorizationParams: {
          response_type: 'invalid',
        },
      });
    });
    server = await createServer(router);

    const res = await request(server).get('/login');
    assert.equal(res.statusCode, 500);
    assert.equal(res.body.err.message, 'response_type should be one of id_token, code id_token, code');
  });

  it('should use a custom state builder', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        getLoginState: (req, opts) => {
          return {
            returnTo: opts.returnTo + '/custom-page',
            customProp: '__test_custom_prop__',
          };
        },
      })
    );
    const res = await request(server).get('/login');
    assert.equal(res.statusCode, 302);

    const parsed = new URL(res.headers.location);
    const decodedState = decodeState(parsed.searchParams.get('state'));

    assert.equal(decodedState.returnTo, 'https://example.org/custom-page');
    assert.equal(decodedState.customProp, '__test_custom_prop__');
  });

  it('should use PKCE when response_type includes code', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
        },
      })
    );
    const res = await request(server).get('/login');
    assert.equal(res.statusCode, 302);

    const parsed = new URL(res.headers.location);

    assert.isDefined(parsed.searchParams.get('code_challenge'));
    assert.equal(parsed.searchParams.get('code_challenge_method'), 'S256');

    assert.isDefined(fetchFromAuthCookie(res, 'code_verifier'));
  });

  it('should respect session.cookie.sameSite when transaction.sameSite is not set and response_mode is not form_post', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_mode: 'query',
          response_type: 'code',
        },
        session: {
          cookie: {
            sameSite: 'Strict',
          },
        },
      })
    );
    const res = await request(server).get('/login');
    assert.equal(res.statusCode, 302);

    assert.include(fetchAuthCookie(res), 'SameSite=Strict');
  });

  it('should respect transactionCookie.sameSite when response_mode is not form_post', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        transactionCookie: {
          sameSite: 'Strict',
        },
        authorizationParams: {
          response_mode: 'query',
          response_type: 'code',
        },
      })
    );
    const res = await request(server).get('/login');
    assert.equal(res.statusCode, 302);

    assert.include(fetchAuthCookie(res), 'SameSite=Strict');
  });

  // v6: Must explicitly set response_mode to form_post since default response_type is now 'code'
  it('should overwrite SameSite to None when response_mode is form_post', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authorizationParams: {
          response_type: 'code',
          response_mode: 'form_post',
        },
        transactionCookie: {
          sameSite: 'Strict',
        },
      })
    );
    const res = await request(server).get('/login');
    assert.equal(res.statusCode, 302);

    assert.include(fetchAuthCookie(res), 'SameSite=None');
  });

  it('should pass discovery errors to the express mw', async () => {
    // Disable global mock discovery for this test
    const originalMockDiscovery = global.__testMockDiscovery;
    delete global.__testMockDiscovery;

    // Use undici MockAgent to mock the error response (works with native fetch in Node 20+)
    const { MockAgent, setGlobalDispatcher, getGlobalDispatcher } = await import('undici');
    const originalDispatcher = getGlobalDispatcher();
    const mockAgent = new MockAgent();
    mockAgent.disableNetConnect();
    setGlobalDispatcher(mockAgent);

    const pool = mockAgent.get('https://example.com');
    pool.intercept({ path: '/.well-known/openid-configuration', method: 'GET' }).reply(500, 'Internal Server Error');
    pool
      .intercept({
        path: '/.well-known/oauth-authorization-server',
        method: 'GET',
      })
      .reply(500, 'Internal Server Error');

    try {
      server = await createServer(
        auth({
          ...defaultConfig,
          issuerBaseURL: 'https://example.com',
        })
      );
      const res = await request(server).get('/login');
      assert.equal(res.statusCode, 500);
      assert.match(
        res.body.err.message,
        /^(Issuer\.discover\(\) failed|fetch failed|Discovery failed|"response" is not conforming|unexpected HTTP response status code)/,
        'Should get error json from server error middleware'
      );
    } finally {
      // Restore mock discovery and dispatcher
      global.__testMockDiscovery = originalMockDiscovery;
      setGlobalDispatcher(originalDispatcher);
      await mockAgent.close();
    }
  });
});
