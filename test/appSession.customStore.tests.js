import express from 'express';
import request from 'supertest';

import { getConfig } from '../src/config.js';
import { SESSION } from '../src/constants.js';
import { getSigningKeyStore, signCookie } from '../src/crypto.js';
import appSession from '../src/middleware/appSession.js';

import { createApp } from './fixture/server.js';
import { CustomStore } from './helpers/custom-store.js';

const defaultConfig = {
  clientID: '__test_client_id__',
  clientSecret: '__test_client_secret__',
  issuerBaseURL: 'https://op.example.com',
  baseURL: 'http://example.org',
  secret: '__test_secret__',
  errorOnRequiredAuth: true,
  session: {
    signSessionStoreCookie: true,
  },
};

function sessionData() {
  const epoch = () => (Date.now() / 1000) | 0;
  const epochNow = epoch();
  const weekInSeconds = 7 * 24 * 60 * 60;

  return JSON.stringify({
    header: {
      uat: epochNow,
      iat: epochNow,
      exp: epochNow + weekInSeconds,
    },
    data: { sub: '__test_sub__' },
  });
}

const baseUrl = 'http://localhost:3000';

/**
 * Login with claims
 * @param {import('supertest').Agent} agent
 * @param {Record<string, any>} claims
 */
function login(agent, claims) {
  return agent.post('/session').send(claims);
}

describe('appSession custom store', () => {
  let signedCookieValue;
  let middlewareConfig;

  async function setup(config) {
    middlewareConfig = getConfig({
      ...defaultConfig,
      ...config,
      session: {
        ...defaultConfig.session,
        ...config?.session,
        store: new CustomStore(),
      },
    });

    const [key] = getSigningKeyStore(middlewareConfig.secret);
    signedCookieValue = await signCookie('appSession', 'foo', key);

    return createApp(appSession(middlewareConfig));
  }

  it('should not create a session when there are no cookies', async () => {
    const server = await setup();
    const res = await request(server).get('/session');
    expect(res.body).to.be.empty;
  });

  it('should not error for non existent sessions', async () => {
    const server = await setup();
    const res = await request(server).get('/session', {
      baseUrl,
      json: true,
      headers: {
        cookie: 'appSession=__invalid_identity__',
      },
    });
    expect(res.statusCode, res.text).to.equal(200);
    expect(res.body).to.be.empty;
  });

  it('should not error for non existent signed sessions', async () => {
    const server = await setup();
    const conf = getConfig(defaultConfig);
    const [key] = getSigningKeyStore(conf.secret);
    const res = await request(server)
      .get('/session')
      .set('cookie', 'appSession=' + (await signCookie('appSession', 'foo', key)));
    expect(res.statusCode, res.text).to.equal(200);
    expect(res.body).to.be.empty;
  });

  it('should get an existing session', async () => {
    const server = await setup();
    await middlewareConfig.session.store.set('foo', sessionData());

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=${signedCookieValue}`);

    expect(res.statusCode, res.text).to.equal(200);
    expect(res.body).to.deep.equal({ sub: '__test_sub__' });
    const [cookie] = agent.jar.getCookies({ domain: '127.0.0.1', path: '/' });

    expect(cookie).to.deep.include({
      name: 'appSession',
      value: signedCookieValue,
    });
  });

  it('should set ttl for compatible session stores', async () => {
    const twoDays = 172800;
    const server = await setup({ session: { rolling: false, absoluteDuration: twoDays } });
    await middlewareConfig.session.store.set('foo', sessionData());

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=${signedCookieValue}`);

    expect(res.statusCode, res.text).to.equal(200);
    expect(res.body).to.deep.equal({ sub: '__test_sub__' });
    expect(res.statusCode, res.text).to.equal(200);
    const ttl = await middlewareConfig.session.store.ttl('foo');
    expect(ttl).to.be.approximately(twoDays, 10 * 1000);
  });

  it('should not populate the store when there is no session', async () => {
    const server = await setup();
    await request(server).get('/session');
    expect(await middlewareConfig.session.store.dbSize()).to.equal(0);
  });

  it('should get a new session', async () => {
    const server = await setup();

    const agent = request.agent(server);

    await login(agent, { sub: '__foo_user__' });

    const res = await agent.get('/session');
    expect(res.statusCode, res.text).to.equal(200);
    expect(res.body).to.deep.equal({ sub: '__foo_user__' });
    expect(await middlewareConfig.session.store.dbSize()).to.equal(1);
  });

  it('should destroy an existing session', async () => {
    const server = await setup({ idpLogout: false });
    await middlewareConfig.session.store.set('foo', sessionData());

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=${signedCookieValue}`);

    expect(res.body).to.deep.equal({ sub: '__test_sub__' });
    await agent.post('/session');
    const loggedOutRes = await agent.get('/session');
    expect(loggedOutRes.body).to.be.empty;
    expect(agent.jar.getCookies({ domain: '127.0.0.1', path: '/' })).to.be.empty;
    expect(await middlewareConfig.session.store.dbSize()).to.equal(0);
  });

  it('uses custom session id generator when provided', async () => {
    const immId = 'apple';
    const server = await setup({
      session: { genid: () => Promise.resolve(immId) },
    });

    const agent = request.agent(server);

    await login(agent, {
      sub: '__foo_user__',
      role: 'test',
      userid: immId,
    });

    const res = await request(server).get('/session');
    expect(res.statusCode, res.text).to.equal(200);
    const { data: sessionValues } = await middlewareConfig.session.store.get(immId);
    expect(sessionValues).to.deep.equal({
      sub: '__foo_user__',
      role: 'test',
      userid: immId,
    });
    expect(await middlewareConfig.session.store.dbSize()).to.equal(1);
  });

  it('should handle storage errors', async () => {
    const store = {
      get() {
        return new Promise((resolve) => process.nextTick(() => resolve(JSON.parse(sessionData()))));
      },
      set() {
        return Promise.reject(new Error('storage error'));
      },
      destroy() {
        return new Promise((resolve) => process.nextTick(resolve));
      },
    };

    const conf = getConfig({
      ...defaultConfig,
      session: { store },
    });

    const server = createApp(appSession(conf));

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=${signedCookieValue}`);
    expect(res.statusCode, res.text).to.equal(500);
    expect(res.body.err.message).to.equal('storage error');
  });

  it('should not throw if another mw writes the header', async () => {
    const app = express();

    await middlewareConfig.session.store.set('foo', sessionData());

    const conf = getConfig({
      ...defaultConfig,
      session: { ...defaultConfig.session, store: middlewareConfig.session.store },
    });
    app.use(appSession(conf));

    const [key] = getSigningKeyStore(conf.secret);
    const cookieValue = await signCookie('appSession', 'foo', key);

    app.get('/', (req, res, next) => {
      res.json(req[SESSION]?.getSessionData());
      next();
    });

    app.use((_req, res, next) => {
      if (!res.headersSent) {
        res.writeHead(200);
      }
      next();
    });

    await request(app).get('/').set('cookie', `appSession=${cookieValue}`).expect(200).expect({ sub: '__test_sub__' });
  });

  it('should not sign the session cookie if signSessionStoreCookie is false', async () => {
    const server = await setup({ session: { signSessionStoreCookie: false } });
    await middlewareConfig.session.store.set('foo', sessionData());

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=foo`);
    expect(res.statusCode, res.text).to.equal(200);
    expect(res.body).to.deep.equal({ sub: '__test_sub__' });
    const [cookie] = agent.jar.getCookies({ domain: '127.0.0.1', path: '/' });
    expect(cookie).to.deep.include({
      name: 'appSession',
      value: 'foo',
    });
  });

  it('should allow migration by signing the session cookie but not requiring it to be signed', async () => {
    const server = await setup({
      session: {
        signSessionStoreCookie: true,
        requireSignedSessionStoreCookie: false,
      },
    });
    await middlewareConfig.session.store.set('foo', sessionData());

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=foo`);
    expect(res.statusCode, res.text).to.equal(200);
    expect(res.body).to.deep.equal({ sub: '__test_sub__' });

    const [cookie] = agent.jar.getCookies({ domain: '127.0.0.1', path: '/' });
    expect(cookie).to.deep.include({
      name: 'appSession',
      value: signedCookieValue,
    });
  });

  it('should allow signed session cookies when not requiring it to be signed', async () => {
    const server = await setup({
      session: {
        signSessionStoreCookie: true,
        requireSignedSessionStoreCookie: false,
      },
    });
    await middlewareConfig.session.store.set('foo', sessionData());

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=${signedCookieValue}`);
    expect(res.statusCode, res.text).to.equal(200);
    expect(res.body).to.deep.equal({ sub: '__test_sub__' });

    const [cookie] = agent.jar.getCookies({ domain: '127.0.0.1', path: '/' });
    expect(cookie).to.deep.include({
      name: 'appSession',
      value: signedCookieValue,
    });
  });

  it('should handle null/undefined session data gracefully', async () => {
    // This test simulates the scenario where store.get() returns null/undefined
    // due to Redis replication lag or race conditions in multi-instance deployments
    const store = {
      get() {
        // Simulate store.get() returning null/undefined due to replication lag
        return new Promise((resolve) => process.nextTick(resolve.bind(null, null)));
      },
      set() {
        return new Promise((resolve) => process.nextTick(resolve));
      },
      destroy() {
        return new Promise((resolve) => process.nextTick(resolve));
      },
    };

    const conf = getConfig({
      ...defaultConfig,
      session: { ...defaultConfig.session, store },
    });

    const server = createApp(appSession(conf));

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=${signedCookieValue}`);

    // Should not crash with destructuring error, should create new empty session
    expect(res.statusCode, res.text).to.equal(200);
    expect(res.body).to.be.empty;
  });
});
