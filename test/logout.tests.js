import { join } from 'node:path/posix';

import { auth } from '@aller/openid-connect';
import nock from 'nock';
import request from 'supertest';

import { makeIdToken } from './fixture/cert.js';
import { createApp } from './fixture/server.js';
import { setupDiscovery } from './helpers/openid-helper.js';

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
  before(() => {
    setupDiscovery().persist();
  });
  after(nock.cleanAll);

  it('should perform a local logout', async () => {
    const server = createApp(
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
    const server = createApp(
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

  it('should redirect to postLogoutRedirect', async () => {
    const server = createApp(
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
    const server = createApp(router);
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
    const server = createApp(
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
    const server = createApp(auth(defaultConfig));

    const agent = request.agent(server);
    await login(agent);

    expect(agent.jar.getCookies({ domain: '127.0.0.1', path: '/' }).find(({ name }) => name === 'skipSilentLogin')).to.not.be.ok;
    await logout(agent);
    expect(agent.jar.getCookies({ domain: '127.0.0.1', path: '/' }).find(({ name }) => name === 'skipSilentLogin')).to.be.ok;
  });

  it('should pass logout params to end session url', async () => {
    const server = createApp(auth({ ...defaultConfig, idpLogout: true, logoutParams: { foo: 'bar' } }));

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
    const server = createApp(router);
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

  it('should honor logout url config over logout params', async () => {
    const server = createApp(
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
    const server = createApp(router);
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
    const server = createApp(router);
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

  it('should pass discovery errors to the express mw', async () => {
    nock('https://example.com').get('/.well-known/openid-configuration').reply(500, 'Internal Server Error');

    const server = createApp(
      auth({
        ...defaultConfig,
        issuerBaseURL: 'https://example.com',
        idpLogout: true,
      })
    );

    const res = await request(server).get('/logout');
    expect(res.statusCode, res.text).to.equal(500);
    expect(res.body.err.message, 'Should get error json from server error middleware').to.match(
      /^(Issuer\.discover\(\) failed|fetch failed|Discovery failed|"response" is not conforming|unexpected HTTP response status code)/
    );
  });
});
