import { join } from 'node:path/posix';

import { auth } from '@aller/openid-connect';
import nock from 'nock';
import request from 'supertest';

import { decodeState } from '../src/hooks/getLoginState.js';

import { createApp } from './fixture/server.js';
import { setupDiscovery } from './helpers/openid-helper.js';

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  baseURL: 'https://example.org',
  issuerBaseURL: 'https://op.example.com',
  authRequired: false,
};

describe('auth', () => {
  before(() => {
    setupDiscovery().persist();
  });
  after(nock.cleanAll);

  it('should contain the default authentication routes', () => {
    const router = auth(defaultConfig);
    createApp(router);
    expect(router.stack.some(filterRoute('GET', '/login'))).to.be.ok;
    expect(router.stack.some(filterRoute('GET', '/logout'))).to.be.ok;
    expect(router.stack.some(filterRoute('POST', '/callback'))).to.be.ok;
    expect(router.stack.some(filterRoute('GET', '/callback'))).to.be.ok;
  });

  it('should contain custom authentication routes', () => {
    const router = auth({
      ...defaultConfig,
      routes: {
        callback: 'custom-callback',
        login: 'custom-login',
        logout: 'custom-logout',
      },
    });
    createApp(router);
    expect(router.stack.some(filterRoute('GET', '/custom-login'))).to.be.ok;
    expect(router.stack.some(filterRoute('GET', '/custom-logout'))).to.be.ok;
    expect(router.stack.some(filterRoute('POST', '/custom-callback'))).to.be.ok;
    expect(router.stack.some(filterRoute('GET', '/custom-callback'))).to.be.ok;
  });

  it('should redirect to the authorize url for /login', async () => {
    const server = createApp(auth(defaultConfig));
    const res = await request(server).get('/login');
    expect(res.statusCode, res.text).to.equal(302);

    const parsed = new URL(res.headers.location);
    expect(parsed.hostname).to.equal('op.example.com');
    expect(parsed.pathname).to.equal('/authorize');
    expect(parsed.searchParams.get('client_id')).to.equal('__test_client_id__');
    expect(parsed.searchParams.get('scope')).to.equal('openid profile email');
    expect(parsed.searchParams.get('response_type')).to.equal('code');
    expect(parsed.searchParams.get('redirect_uri')).to.equal('https://example.org/callback');
    expect(parsed.searchParams.has('nonce')).to.be.true;
    expect(parsed.searchParams.has('state')).to.be.true;
    expect(parsed.searchParams.has('code_challenge')).to.be.true;
    expect(parsed.searchParams.get('code_challenge_method')).to.equal('S256');

    expect(fetchFromAuthCookie(res, 'nonce')).to.equal(parsed.searchParams.get('nonce'));
    expect(fetchFromAuthCookie(res, 'state')).to.equal(parsed.searchParams.get('state'));
  });

  it('should redirect to the authorize url for /login when txn cookie name is custom', async () => {
    const customTxnCookieName = 'CustomTxnCookie';

    const server = createApp(
      auth({
        ...defaultConfig,
        transactionCookie: { name: customTxnCookieName },
      })
    );
    const res = await request(server).get('/login');
    expect(res.statusCode, res.text).to.equal(302);

    const parsed = new URL(res.headers.location);
    expect(parsed.hostname).to.equal('op.example.com');
    expect(parsed.pathname).to.equal('/authorize');
    expect(parsed.searchParams.get('client_id')).to.equal('__test_client_id__');
    expect(parsed.searchParams.get('scope')).to.equal('openid profile email');
    expect(parsed.searchParams.get('response_type')).to.equal('code');
    expect(parsed.searchParams.get('redirect_uri')).to.equal('https://example.org/callback');
    expect(parsed.searchParams.has('nonce')).to.be.true;
    expect(parsed.searchParams.has('state')).to.be.true;
    expect(parsed.searchParams.has('code_challenge')).to.be.true;
    expect(parsed.searchParams.get('code_challenge_method')).to.equal('S256');

    expect(fetchFromAuthCookie(res, 'nonce', customTxnCookieName)).to.equal(parsed.searchParams.get('nonce'));
    expect(fetchFromAuthCookie(res, 'state', customTxnCookieName)).to.equal(parsed.searchParams.get('state'));
  });

  it('should redirect to the authorize url for any route if authRequired', async () => {
    const server = createApp(
      auth({
        ...defaultConfig,
        authRequired: true,
      })
    );
    const res = await request(server).get('/session');
    expect(res.statusCode, res.text).to.equal(302);
  });

  it('should redirect to the authorize url for any route if attemptSilentLogin', async () => {
    const server = createApp(
      auth({
        ...defaultConfig,
        authRequired: false,
        attemptSilentLogin: true,
      })
    );
    const res = await request(server).get('/session');
    expect(res.statusCode, res.text).to.equal(302);
  });

  it('should redirect to the authorize url for any route with custom txn name if attemptSilentLogin ', async () => {
    const server = createApp(
      auth({
        ...defaultConfig,
        authRequired: false,
        attemptSilentLogin: true,
        transactionCookie: { name: 'CustomTxnCookie' },
      })
    );
    const res = await request(server).get('/session');
    expect(res.statusCode, res.text).to.equal(302);
  });

  it('should redirect to the authorize url for /login in code flow', async () => {
    const server = createApp(
      auth({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code',
        },
      })
    );
    const res = await request(server).get('/login');
    expect(res.statusCode, res.text).to.equal(302);

    const parsed = new URL(res.headers.location);

    expect(parsed.hostname).to.equal('op.example.com');
    expect(parsed.pathname).to.equal('/authorize');
    expect(parsed.searchParams.get('client_id')).to.equal('__test_client_id__');
    expect(parsed.searchParams.get('scope')).to.equal('openid profile email');
    expect(parsed.searchParams.get('response_type')).to.equal('code');
    expect(parsed.searchParams.has('response_mode')).to.be.false;
    expect(parsed.searchParams.get('redirect_uri')).to.equal('https://example.org/callback');
    expect(parsed.searchParams.has('nonce')).to.be.true;
    expect(parsed.searchParams.has('state')).to.be.true;
    expect(res.headers).to.have.property('set-cookie');

    expect(fetchFromAuthCookie(res, 'nonce')).to.equal(parsed.searchParams.get('nonce'));
    expect(fetchFromAuthCookie(res, 'state')).to.equal(parsed.searchParams.get('state'));
  });

  it('should redirect to the authorize url for /login in code flow with custom txn cookie', async () => {
    const customTxnCookieName = 'CustomTxnCookie';
    const server = createApp(
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
    expect(res.statusCode, res.text).to.equal(302);

    const parsed = new URL(res.headers.location);

    expect(parsed.hostname).to.equal('op.example.com');
    expect(parsed.pathname).to.equal('/authorize');
    expect(parsed.searchParams.get('client_id')).to.equal('__test_client_id__');
    expect(parsed.searchParams.get('scope')).to.equal('openid profile email');
    expect(parsed.searchParams.get('response_type')).to.equal('code');
    expect(parsed.searchParams.has('response_mode')).to.be.false;
    expect(parsed.searchParams.get('redirect_uri')).to.equal('https://example.org/callback');
    expect(parsed.searchParams.has('nonce')).to.be.true;
    expect(parsed.searchParams.has('state')).to.be.true;
    expect(res.headers).to.have.property('set-cookie');

    expect(fetchFromAuthCookie(res, 'nonce', customTxnCookieName)).to.equal(parsed.searchParams.get('nonce'));
    expect(fetchFromAuthCookie(res, 'state', customTxnCookieName)).to.equal(parsed.searchParams.get('state'));
  });

  it('should redirect to the authorize url for /login in hybrid flow', async () => {
    const server = createApp(
      auth({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
        },
      })
    );
    const res = await request(server).get('/login');
    expect(res.statusCode, res.text).to.equal(302);

    const parsed = new URL(res.headers.location);

    expect(parsed.hostname).to.equal('op.example.com');
    expect(parsed.pathname).to.equal('/authorize');
    expect(parsed.searchParams.get('client_id')).to.equal('__test_client_id__');
    expect(parsed.searchParams.get('scope')).to.equal('openid profile email');
    expect(parsed.searchParams.get('response_type')).to.equal('code id_token');
    expect(parsed.searchParams.get('response_mode')).to.equal('form_post');
    expect(parsed.searchParams.get('redirect_uri')).to.equal('https://example.org/callback');
    expect(parsed.searchParams.has('nonce')).to.be.true;
    expect(parsed.searchParams.has('state')).to.be.true;
  });

  it('should redirect to the authorize url for custom login route', async () => {
    const server = createApp(
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
    expect(res.statusCode, res.text).to.equal(302);

    const parsed = new URL(res.headers.location);
    expect(parsed.hostname).to.equal('op.example.com');
    expect(parsed.pathname).to.equal('/authorize');
    expect(parsed.searchParams.get('redirect_uri')).to.equal('https://example.org/custom-callback');
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
    const server = createApp(router);

    const res = await request(server).get('/login');
    expect(res.statusCode, res.text).to.equal(302);

    const parsed = new URL(res.headers.location);

    expect(parsed.hostname).to.equal('op.example.com');
    expect(parsed.pathname).to.equal('/authorize');
    expect(parsed.searchParams.get('scope')).to.equal('openid email');
    expect(parsed.searchParams.get('response_type')).to.equal('code');
    expect(parsed.searchParams.get('response_mode')).to.equal('query');
    expect(parsed.searchParams.get('redirect_uri')).to.equal('https://example.org/callback');
    expect(parsed.searchParams.has('nonce')).to.be.true;

    const decodedState = decodeState(parsed.searchParams.get('state'));

    expect(decodedState.returnTo).to.equal('https://example.org/custom-redirect');
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
    const server = createApp(router);

    const res = await request(server).get('/login');
    expect(res.statusCode, res.text).to.equal(500);
    expect(res.body.err.message).to.equal('scope should contain "openid"');
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
    const server = createApp(router);

    const res = await request(server).get('/login');
    expect(res.statusCode, res.text).to.equal(500);
    expect(res.body.err.message).to.equal('response_type should be one of id_token, code id_token, code');
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
    const server = createApp(router);

    const res = await request(server).get('/login');
    expect(res.statusCode, res.text).to.equal(500);
    expect(res.body.err.message).to.equal('response_type should be one of id_token, code id_token, code');
  });

  it('should use a custom state builder', async () => {
    const server = createApp(
      auth({
        ...defaultConfig,
        getLoginState(_req, opts) {
          return {
            returnTo: join(opts.returnTo, '/custom-page'),
            customProp: '__test_custom_prop__',
          };
        },
      })
    );
    const res = await request(server).get('/login');
    expect(res.statusCode, res.text).to.equal(302);

    const parsed = new URL(res.headers.location);
    const decodedState = decodeState(parsed.searchParams.get('state'));

    expect(decodedState.returnTo).to.equal('/custom-page');
    expect(decodedState.customProp).to.equal('__test_custom_prop__');
  });

  it('should use PKCE when response_type includes code', async () => {
    const server = createApp(
      auth({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code id_token',
        },
      })
    );
    const res = await request(server).get('/login');
    expect(res.statusCode, res.text).to.equal(302);

    const parsed = new URL(res.headers.location);

    expect(parsed.searchParams.get('code_challenge')).to.be.ok;
    expect(parsed.searchParams.get('code_challenge_method')).to.equal('S256');

    expect(fetchFromAuthCookie(res, 'code_verifier')).to.be.ok;
  });

  it('should respect session.cookie.sameSite when transaction.sameSite is not set and response_mode is not form_post', async () => {
    const server = createApp(
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
    expect(res.statusCode, res.text).to.equal(302);

    expect(fetchAuthCookie(res)).to.include('SameSite=Strict');
  });

  it('should respect transactionCookie.sameSite when response_mode is not form_post', async () => {
    const server = createApp(
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
    expect(res.statusCode, res.text).to.equal(302);

    expect(fetchAuthCookie(res)).to.include('SameSite=Strict');
  });

  it('should overwrite SameSite to None when response_mode is form_post', async () => {
    const server = createApp(
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
    expect(res.statusCode, res.text).to.equal(302);

    expect(fetchAuthCookie(res)).to.include('SameSite=None');
  });

  it('should pass discovery errors to the express mw', async () => {
    nock('https://example.com').get('/.well-known/openid-configuration').reply(500, 'Internal Server Error');

    const server = createApp(
      auth({
        ...defaultConfig,
        issuerBaseURL: 'https://example.com',
      })
    );
    const res = await request(server).get('/login');
    expect(res.statusCode, res.text).to.equal(500);
    expect(res.body.err.message, 'Should get error json from server error middleware').to.match(
      /^(Issuer\.discover\(\) failed|fetch failed|Discovery failed|"response" is not conforming|unexpected HTTP response status code)/
    );
  });
});

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
