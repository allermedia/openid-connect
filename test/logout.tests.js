import { join } from 'node:path/posix';

import request from 'supertest';

import { auth } from '../index.js';

import { makeIdToken } from './fixture/cert.js';
import { create as createServer } from './fixture/server.js';

const defaultConfig = {
  clientID: '__test_client_id__',
  baseURL: 'http://example.org',
  issuerBaseURL: 'https://op.example.com',
  secret: '__test_session_secret__',
  authRequired: false,
};

async function login(agent, idToken, prefixPath = '') {
  const endpoint = join(prefixPath, '/session');
  await agent.post(endpoint).send({
    id_token: idToken || (await makeIdToken()),
  });

  const session = (await agent.get(endpoint)).body;
  return { session };
}

async function logout(agent, prefixPath = '') {
  const response = await agent.get(join(prefixPath, '/logout'));
  const session = (await agent.get(join(prefixPath, '/session'))).body;
  return { response, session };
}

describe('logout route', () => {
  let server;

  afterEach(() => {
    server?.close();
  });

  it('should perform a local logout', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        idpLogout: false,
      })
    );

    const agent = request.agent(server);
    const { session: loggedInSession } = await login(agent);
    expect(loggedInSession.id_token).to.be.ok;
    const { response, session: loggedOutSession } = await logout(agent);
    expect(loggedOutSession.id_token).to.not.be.ok;
    expect(response.statusCode, response.text).to.equal(302);
    expect(response.headers, 'should redirect to the base url').to.deep.include({
      location: 'http://example.org/',
    });
  });

  it('should perform a distributed logout', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        idpLogout: true,
      })
    );

    const idToken = await makeIdToken();
    const agent = request.agent(server);
    await login(agent, idToken);
    const { response, session: loggedOutSession } = await logout(agent);
    expect(loggedOutSession.id_token).to.not.be.ok;
    expect(response.statusCode, response.text).to.equal(302);
    expect(response.headers, 'should redirect to the identity provider').to.deep.include({
      location: `https://op.example.com/session/end?id_token_hint=${idToken}&post_logout_redirect_uri=http%3A%2F%2Fexample.org%2F`,
    });
  });

  it('should perform an auth0 logout', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        issuerBaseURL: 'https://test.eu.auth0.com',
        idpLogout: true,
        auth0Logout: true,
      })
    );

    const agent = request.agent(server);
    await login(agent);
    const { response, session: loggedOutSession } = await logout(agent);
    expect(loggedOutSession.id_token).to.not.be.ok;
    expect(response.statusCode, response.text).to.equal(302);
    expect(response.headers, 'should redirect to the identity provider').to.deep.include({
      location: 'https://test.eu.auth0.com/v2/logout?returnTo=http%3A%2F%2Fexample.org%2F&client_id=__test_client_id__',
    });
  });

  it('should redirect to postLogoutRedirect', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        routes: {
          postLogoutRedirect: '/after-logout-in-auth-config',
        },
      })
    );

    const agent = request.agent(server);
    await login(agent);
    const { response, session: loggedOutSession } = await logout(agent);
    expect(loggedOutSession.id_token).to.not.be.ok;
    expect(response.statusCode, response.text).to.equal(302);

    expect(response.headers, 'should redirect to postLogoutRedirect').to.deep.include({
      location: 'http://example.org/after-logout-in-auth-config',
    });
  });

  it('should redirect to the specified returnTo', async () => {
    const router = auth({
      ...defaultConfig,
      routes: {
        logout: false,
        postLogoutRedirect: '/after-logout-in-auth-config',
      },
    });
    server = await createServer(router);
    router.get('/logout', (req, res) => res.oidc.logout({ returnTo: 'http://www.another-example.org/logout' }));

    const agent = request.agent(server);
    await login(agent);
    const { response, session: loggedOutSession } = await logout(agent);
    expect(loggedOutSession.id_token).to.not.be.ok;
    expect(response.statusCode, response.text).to.equal(302);
    expect(response.headers, 'should redirect to params.returnTo').to.deep.include({
      location: 'http://www.another-example.org/logout',
    });
  });

  it('should logout when scoped to a sub path', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        session: {
          cookie: {
            path: '/foo',
          },
        },
      }),
      null,
      '/foo'
    );

    const agent = request.agent(server);
    const { session: loggedInSession } = await login(agent, undefined, '/foo');
    expect(loggedInSession.id_token).to.be.ok;
    const sessionCookie = agent.jar.getCookies({ domain: '127.0.0.1', path: '/foo' }).find(({ name }) => name === 'appSession');
    expect(sessionCookie.path).to.equal('/foo');
    const { session: loggedOutSession } = await logout(agent, '/foo');
    expect(loggedOutSession.id_token).to.not.be.ok;
  });

  it('should cancel silent logins when user logs out', async () => {
    server = await createServer(auth(defaultConfig));

    const agent = request.agent(server);
    await login(agent);

    expect(agent.jar.getCookies({ domain: '127.0.0.1', path: '/' }).find(({ name }) => name === 'skipSilentLogin')).to.not.be.ok;
    await logout(agent);
    expect(agent.jar.getCookies({ domain: '127.0.0.1', path: '/' }).find(({ name }) => name === 'skipSilentLogin')).to.be.ok;
  });

  it('should pass logout params to end session url', async () => {
    server = await createServer(auth({ ...defaultConfig, idpLogout: true, logoutParams: { foo: 'bar' } }));

    const agent = request.agent(server);
    await login(agent);
    const {
      response: {
        headers: { location },
      },
    } = await logout(agent);

    expect(new URL(location).searchParams.get('foo')).to.equal('bar');
  });

  it('should override logout params per request', async () => {
    const router = auth({
      ...defaultConfig,
      idpLogout: true,
      logoutParams: { foo: 'bar' },
      routes: { logout: false },
    });
    server = await createServer(router);
    router.get('/logout', (_req, res) => res.oidc.logout({ logoutParams: { foo: 'baz' } }));

    const agent = request.agent(server);
    await login(agent);
    const {
      response: {
        headers: { location },
      },
    } = await logout(agent);

    expect(new URL(location).searchParams.get('foo')).to.equal('baz');
  });

  it('should pass logout params to auth0 logout url', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        issuerBaseURL: 'https://test.eu.auth0.com',
        idpLogout: true,
        auth0Logout: true,
        logoutParams: { foo: 'bar' },
      })
    );

    const agent = request.agent(server);
    await login(agent);
    const {
      response: {
        headers: { location },
      },
    } = await logout(agent);
    const url = new URL(location);
    expect(url.pathname).to.equal('/v2/logout');
    expect(url.searchParams.get('foo')).to.equal('bar');
  });

  it('should honor logout url config over logout params', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        routes: { postLogoutRedirect: 'http://foo.com' },
        idpLogout: true,
        logoutParams: {
          foo: 'bar',
          post_logout_redirect_uri: 'http://bar.com',
        },
      })
    );

    const agent = request.agent(server);
    await login(agent);
    const {
      response: {
        headers: { location },
      },
    } = await logout(agent);
    const url = new URL(new URL(location).searchParams.get('post_logout_redirect_uri'));
    expect(url.hostname).to.equal('foo.com');
  });

  it('should honor logout url arguments over logout params', async () => {
    const router = auth({
      ...defaultConfig,
      idpLogout: true,
      routes: { logout: false },
    });
    server = await createServer(router);
    router.get('/logout', (req, res) =>
      res.oidc.logout({
        logoutParams: { post_logout_redirect_uri: 'http://bar.com' },
      })
    );

    const agent = request.agent(server);
    await login(agent);
    const {
      response: {
        headers: { location },
      },
    } = await logout(agent);
    const url = new URL(new URL(location).searchParams.get('post_logout_redirect_uri'));
    expect(url.hostname).to.equal('bar.com');
  });

  it('should honor logout id_token_hint arguments over default', async () => {
    const router = auth({
      ...defaultConfig,
      idpLogout: true,
      routes: { logout: false },
    });
    server = await createServer(router);
    router.get('/logout', (req, res) =>
      res.oidc.logout({
        logoutParams: { id_token_hint: null },
      })
    );

    const agent = request.agent(server);
    await login(agent);
    const {
      response: {
        headers: { location },
      },
    } = await logout(agent);
    expect(new URL(location).searchParams.get('id_token_hint')).to.not.be.ok;
  });

  it('should ignore undefined or null logout params', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        issuerBaseURL: 'https://test.eu.auth0.com',
        idpLogout: true,
        auth0Logout: true,
        logoutParams: { foo: 'bar', bar: undefined, baz: null, qux: '' },
      })
    );

    const agent = request.agent(server);
    await login(agent);
    const {
      response: {
        headers: { location },
      },
    } = await logout(agent);
    const url = new URL(location);
    expect(url.pathname).to.equal('/v2/logout');
    expect(url.searchParams.get('foo')).to.equal('bar');
    expect(url.searchParams.has('bar')).to.be.false;
    expect(url.searchParams.has('baz')).to.be.false;
    expect(url.searchParams.get('qux')).to.equal('');
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

      const res = await request(server).get('/logout');
      expect(res.statusCode, res.text).to.equal(500);
      expect(res.body.err.message, 'Should get error json from server error middleware').to.match(
        /^(Issuer\.discover\(\) failed|fetch failed|Discovery failed|"response" is not conforming|unexpected HTTP response status code)/
      );
    } finally {
      // Restore global mock discovery and dispatcher
      if (originalMockDiscovery) {
        global.__testMockDiscovery = originalMockDiscovery;
      }
      setGlobalDispatcher(originalDispatcher);
      await mockAgent.close();
    }
  });
});
