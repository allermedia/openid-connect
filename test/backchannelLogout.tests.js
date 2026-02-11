import { auth } from '@aller/openid-connect';
import nock from 'nock';
import request from 'supertest';

import { getConfig } from '../src/config.js';
import onLogin from '../src/hooks/backchannelLogout/onLogIn.js';

import { makeIdToken, makeLogoutToken } from './fixture/cert.js';
import { createApp } from './fixture/server.js';
import { CustomStore } from './helpers/custom-store.js';
import { setupDiscovery } from './helpers/openid-helper.js';

/**
 * Login and get session with id_token
 * @param {import('supertest').Agent} agent
 * @param {Record<string, any>} [idToken]
 */
async function login(agent, idToken) {
  return agent.post('/session').send({
    id_token: idToken || (await makeIdToken()),
  });
}

describe('back-channel logout', () => {
  before(() => {
    setupDiscovery().persist();
  });
  after(nock.cleanAll);

  let client;
  let store;
  let config;
  beforeEach(() => {
    // ({ client, store } = getRedisStore());
    store = new CustomStore();
    config = {
      clientID: '__test_client_id__',
      baseURL: 'http://example.org',
      issuerBaseURL: 'https://op.example.com',
      secret: '__test_session_secret__',
      authRequired: false,
      backchannelLogout: {
        store,
        isInsecure: true,
      },
    };
  });

  afterEach(async () => {
    if (client) {
      await new Promise((resolve) => client.flushall(resolve));
      await new Promise((resolve) => client.quit(resolve));
    }
  });

  it('should only handle post requests', async () => {
    const server = createApp(auth(config));

    for (const method of ['get', 'put', 'patch', 'delete']) {
      const res = await request(server)[method]('/backchannel-logout', {
        method,
      });
      expect(res.statusCode, res.text).to.equal(404);
    }
  });

  it('should require a logout token', async () => {
    const server = createApp(auth(config));

    const res = await request(server).post('/backchannel-logout');
    expect(res.statusCode, res.text).to.equal(400);
    expect(res.body).to.deep.equal({
      error: 'invalid_request',
      error_description: 'Missing logout_token',
    });
  });

  it('should not cache the response', async () => {
    const server = createApp(auth(config));

    const res = await request(server).post('/backchannel-logout');
    expect(res.get('cache-control')).to.equal('no-store');
  });

  it('should accept and store a valid logout_token', async () => {
    const server = createApp(auth(config));

    const res = await request(server)
      .post('/backchannel-logout')
      .set('content-type', 'application/x-www-form-urlencoded')
      .send(
        new URLSearchParams({
          logout_token: await makeLogoutToken({ sid: 'foo' }),
        }).toString()
      );

    expect(res.statusCode, res.text).to.equal(204);
    const payload = await store.get('https://op.example.com/|foo');
    expect(payload).to.be.ok;
  });

  it('should accept and store a valid logout_token signed with HS256', async () => {
    const server = createApp(auth(config));

    const res = await request(server)
      .post('/backchannel-logout')
      .set('content-type', 'application/x-www-form-urlencoded')
      .send(
        new URLSearchParams({
          logout_token: await makeLogoutToken({
            sid: 'foo',
            secret: config.clientSecret,
          }),
        }).toString()
      );

    expect(res.statusCode, res.text).to.equal(204);
    const payload = await store.get('https://op.example.com/|foo');
    expect(payload).to.be.ok;
  });

  it('should require a sid or a sub', async () => {
    const server = createApp(auth(config));

    const res = await request(server)
      .post('/backchannel-logout')
      .set('content-type', 'application/x-www-form-urlencoded')
      .send(new URLSearchParams({ logout_token: await makeLogoutToken() }).toString());

    expect(res.statusCode, res.text).to.equal(400);
  });

  it('should set a maxAge based on rolling expiry', async () => {
    const server = createApp(auth({ ...config, session: { rollingDuration: 999 } }));

    const res = await request(server)
      .post('/backchannel-logout')
      .set('content-type', 'application/x-www-form-urlencoded')
      .send(new URLSearchParams({ logout_token: await makeLogoutToken({ sid: 'foo' }) }).toString());

    expect(res.statusCode, res.text).to.equal(204);
    const { cookie } = await store.get('https://op.example.com/|foo');
    expect(cookie.maxAge).to.equal(999 * 1000);
    const ttl = await store.ttl('https://op.example.com/|foo');
    expect(ttl).to.be.approximately(999, 5);
  });

  it('should set a maxAge based on absolute expiry', async () => {
    const server = createApp(auth({ ...config, session: { absoluteDuration: 999, rolling: false } }));

    const res = await request(server)
      .post('/backchannel-logout')
      .set('content-type', 'application/x-www-form-urlencoded')
      .send(
        new URLSearchParams({
          logout_token: await makeLogoutToken({ sid: 'foo' }),
        }).toString()
      );

    expect(res.statusCode, res.text).to.equal(204);
    const { cookie } = await store.get('https://op.example.com/|foo');
    expect(cookie.maxAge).to.equal(999 * 1000);
    const ttl = await store.ttl('https://op.example.com/|foo');
    expect(ttl).to.be.approximately(999, 5);
  });

  it('should fail if storing the token fails', async () => {
    const server = createApp(
      auth({
        ...config,
        backchannelLogout: {
          ...config.backchannelLogout,
          onLogoutToken() {
            throw new Error('storage failure');
          },
        },
      })
    );

    const res = await request(server)
      .post('/backchannel-logout')
      .set('content-type', 'application/x-www-form-urlencoded')
      .send(new URLSearchParams({ logout_token: await makeLogoutToken({ sid: 'foo' }) }).toString());

    expect(res.statusCode, res.text).to.equal(400);
    expect(res.body.error).to.equal('application_error');
  });

  it('should log sid out on subsequent requests', async () => {
    const server = createApp(auth(config));

    const agent = request.agent(server);

    await login(agent, await makeIdToken({ sid: '__foo_sid__' }));

    let res = await agent.get('/session');

    expect(res.body).to.not.be.empty;
    expect(agent.jar.getCookies({ domain: '127.0.0.1', path: '/' })).to.not.be.empty;

    res = await agent
      .post('/backchannel-logout')
      .set('content-type', 'application/x-www-form-urlencoded')
      .send(
        new URLSearchParams({
          logout_token: await makeLogoutToken({ sid: '__foo_sid__' }),
        }).toString()
      );

    expect(res.statusCode, res.text).to.equal(204);
    const payload = await store.get('https://op.example.com/|__foo_sid__');
    expect(payload).to.be.ok;

    const { body } = await agent.get('/session');

    expect(body).to.be.be.empty;
    expect(agent.jar.getCookies({ domain: '127.0.0.1', path: '/' })).to.be.empty;
  });

  it('should log sub out on subsequent requests', async () => {
    const server = createApp(auth(config));

    const agent = request.agent(server);

    await login(agent, await makeIdToken({ sub: '__foo_sub__' }));
    let res = await agent.get('/session');

    expect(res.body).to.not.be.empty;
    expect(agent.jar.getCookies({ domain: '127.0.0.1', path: '/' })).to.not.be.empty;

    res = await agent
      .post('/backchannel-logout')
      .set('content-type', 'application/x-www-form-urlencoded')
      .send(
        new URLSearchParams({
          logout_token: await makeLogoutToken({ sid: '__foo_sub__' }),
        }).toString()
      );

    expect(res.statusCode, res.text).to.equal(204);
    const payload = await store.get('https://op.example.com/|__foo_sub__');
    expect(payload).to.be.ok;

    res = await agent.get('/session');

    expect(agent.jar.getCookies({ domain: '127.0.0.1', path: '/' })).to.be.empty;
    expect(res.body).to.be.empty;
  });

  it('should not log sub out if login is after back-channel logout', async () => {
    const server = createApp(auth(config));

    const agent = request.agent(server);

    await login(agent, await makeIdToken({ sub: '__foo_sub__' }));

    const res = await agent
      .post('/backchannel-logout')
      .set('content-type', 'application/x-www-form-urlencoded')
      .send(
        new URLSearchParams({
          logout_token: await makeLogoutToken({ sid: '__foo_sub__' }),
        }).toString()
      );

    expect(res.statusCode, res.text).to.equal(204);
    let payload = await store.get('https://op.example.com/|__foo_sub__');
    expect(payload).to.be.ok;

    await onLogin({ oidc: { idTokenClaims: { sub: '__foo_sub__' } } }, getConfig(config));
    payload = await store.get('https://op.example.com/|__foo_sub__');
    expect(payload).to.not.be.ok;

    const { body } = await agent.get('/session');

    expect(agent.jar.getCookies({ domain: '127.0.0.1', path: '/' })).to.not.be.empty;
    expect(body).to.not.be.empty;
  });

  it('should handle failures to get logout token', async () => {
    const server = createApp(
      auth({
        ...config,
        backchannelLogout: {
          ...config.backchannelLogout,
          isLoggedOut() {
            throw new Error('storage failure');
          },
        },
      })
    );

    const agent = request.agent(server);

    await login(agent, await makeIdToken({ sid: '__foo_sid__' }));
    const { body } = await agent.get('/session');

    expect(body).to.deep.equal({ err: { message: 'storage failure' } });
  });
});
