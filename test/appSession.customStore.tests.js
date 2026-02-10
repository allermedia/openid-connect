import * as chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
import express from 'express';
import request from 'supertest';

import appSession from '../src/appSession.js';
import { get as getConfig } from '../src/config.js';
import { getKeyStore, signCookie } from '../src/crypto.js';

import { create as createServer } from './fixture/server.js';
import getRedisStore from './fixture/store.js';

const { assert } = chai.use(chaiAsPromised);

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
  /** @type {import('http').Server} */
  let server;
  let redisClient;
  let signedCookieValue;

  async function setup(config) {
    const { client, store } = getRedisStore();
    redisClient = client;

    const conf = getConfig({
      ...defaultConfig,
      ...config,
      session: {
        ...defaultConfig.session,
        ...(config && config.session),
        store,
      },
    });

    const [key] = getKeyStore(conf.secret);
    signedCookieValue = signCookie('appSession', 'foo', key);

    server = await createServer(appSession(conf));
  }

  afterEach(async () => {
    server?.close();
    if (redisClient) {
      await new Promise((resolve) => redisClient.flushall(resolve));
      await new Promise((resolve) => redisClient.quit(resolve));
    }
  });

  it('should not create a session when there are no cookies', async () => {
    await setup();
    const res = await request(server).get('/session');
    assert.isEmpty(res.body);
  });

  it('should not error for non existent sessions', async () => {
    await setup();
    const res = await request(server).get('/session', {
      baseUrl,
      json: true,
      headers: {
        cookie: 'appSession=__invalid_identity__',
      },
    });
    assert.equal(res.statusCode, 200);
    assert.isEmpty(res.body);
  });

  it('should not error for non existent signed sessions', async () => {
    await setup();
    const conf = getConfig(defaultConfig);
    const [key] = getKeyStore(conf.secret);
    const res = await request(server)
      .get('/session')
      .set('cookie', 'appSession=' + signCookie('appSession', 'foo', key));
    assert.equal(res.statusCode, 200);
    assert.isEmpty(res.body);
  });

  it('should get an existing session', async () => {
    await setup();
    await redisClient.asyncSet('foo', sessionData());

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=${signedCookieValue}`);

    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body, { sub: '__test_sub__' });
    const [cookie] = agent.jar.getCookies({ domain: '127.0.0.1', path: '/' });

    assert.deepInclude(cookie, {
      name: 'appSession',
      value: signedCookieValue,
    });
  });

  it('should set ttl for compatible session stores', async () => {
    const twoDays = 172800;
    await setup({ session: { rolling: false, absoluteDuration: twoDays } });
    await redisClient.asyncSet('foo', sessionData());

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=${signedCookieValue}`);

    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body, { sub: '__test_sub__' });
    assert.equal(res.statusCode, 200);
    const ttl = await redisClient.asyncTtl('foo');
    assert.closeTo(ttl, twoDays, 10 * 1000);
  });

  it('should not populate the store when there is no session', async () => {
    await setup();
    await request(server).get('/session');
    assert.equal(await redisClient.asyncDbsize(), 0);
  });

  it('should get a new session', async () => {
    await setup();

    const agent = request.agent(server);

    await login(agent, { sub: '__foo_user__' });

    const res = await agent.get('/session');
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body, { sub: '__foo_user__' });
    assert.equal(await redisClient.asyncDbsize(), 1);
  });

  it('should destroy an existing session', async () => {
    await setup({ idpLogout: false });
    await redisClient.asyncSet('foo', sessionData());

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=${signedCookieValue}`);

    assert.deepEqual(res.body, { sub: '__test_sub__' });
    await agent.post('/session');
    const loggedOutRes = await agent.get('/session');
    assert.isEmpty(loggedOutRes.body);
    assert.isEmpty(agent.jar.getCookies({ domain: '127.0.0.1', path: '/' }));
    assert.equal(await redisClient.asyncDbsize(), 0);
  });

  it('uses custom session id generator when provided', async () => {
    const immId = 'apple';
    await setup({
      session: { genid: () => Promise.resolve(immId) },
    });

    const agent = request.agent(server);

    await login(agent, {
      sub: '__foo_user__',
      role: 'test',
      userid: immId,
    });

    const res = await request(server).get('/session');
    assert.equal(res.statusCode, 200);
    const { data: sessionValues } = await redisClient.asyncGet(immId);
    assert.deepEqual(sessionValues, {
      sub: '__foo_user__',
      role: 'test',
      userid: immId,
    });
    assert.equal(await redisClient.asyncDbsize(), 1);
  });

  it('should handle storage errors', async () => {
    const store = {
      get(_id, cb) {
        process.nextTick(() => cb(null, JSON.parse(sessionData())));
      },
      set() {
        return Promise.reject(new Error('storage error'));
      },
      destroy(_id, cb) {
        process.nextTick(() => cb());
      },
    };

    const conf = getConfig({
      ...defaultConfig,
      session: { store },
    });

    server = await createServer(appSession(conf));

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=${signedCookieValue}`);
    assert.equal(res.statusCode, 500);
    assert.equal(res.body.err.message, 'storage error');
  });

  it('should not throw if another mw writes the header', async () => {
    const app = express();

    const { client, store } = getRedisStore();
    redisClient = client;
    await redisClient.set('foo', sessionData());

    const conf = getConfig({
      ...defaultConfig,
      session: { ...defaultConfig.session, store },
    });
    app.use(appSession(conf));

    const [key] = getKeyStore(conf.secret);
    const cookieValue = signCookie('appSession', 'foo', key);

    app.get('/', (req, res, next) => {
      res.json(req.appSession);
      next();
    });

    app.use((_req, res, next) => {
      if (!res.headersSent) {
        res.writeHead(200);
      }
      next();
    });

    server = await new Promise((resolve) => {
      const server = app.listen(3000, () => resolve(server));
    });

    await request(server).get('/').set('cookie', `appSession=${cookieValue}`).expect(200).expect({ sub: '__test_sub__' });
  });

  it('should not sign the session cookie if signSessionStoreCookie is false', async () => {
    await setup({ session: { signSessionStoreCookie: false } });
    await redisClient.asyncSet('foo', sessionData());

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=foo`);
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body, { sub: '__test_sub__' });
    const [cookie] = agent.jar.getCookies({ domain: '127.0.0.1', path: '/' });
    assert.deepInclude(cookie, {
      name: 'appSession',
      value: 'foo',
    });
  });

  it('should allow migration by signing the session cookie but not requiring it to be signed', async () => {
    await setup({
      session: {
        signSessionStoreCookie: true,
        requireSignedSessionStoreCookie: false,
      },
    });
    await redisClient.asyncSet('foo', sessionData());

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=foo`);
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body, { sub: '__test_sub__' });

    const [cookie] = agent.jar.getCookies({ domain: '127.0.0.1', path: '/' });
    assert.deepInclude(cookie, {
      name: 'appSession',
      value: signedCookieValue,
    });
  });

  it('should allow signed session cookies when not requiring it to be signed', async () => {
    await setup({
      session: {
        signSessionStoreCookie: true,
        requireSignedSessionStoreCookie: false,
      },
    });
    await redisClient.asyncSet('foo', sessionData());

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=${signedCookieValue}`);
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body, { sub: '__test_sub__' });

    const [cookie] = agent.jar.getCookies({ domain: '127.0.0.1', path: '/' });
    assert.deepInclude(cookie, {
      name: 'appSession',
      value: signedCookieValue,
    });
  });

  it('should handle null/undefined session data gracefully', async () => {
    // This test simulates the scenario where store.get() returns null/undefined
    // due to Redis replication lag or race conditions in multi-instance deployments
    const store = {
      get(_id, cb) {
        // Simulate store.get() returning null/undefined due to replication lag
        process.nextTick(() => cb(null, null));
      },
      set(_id, _val, cb) {
        process.nextTick(() => cb());
      },
      destroy(_id, cb) {
        process.nextTick(() => cb());
      },
    };

    const conf = getConfig({
      ...defaultConfig,
      session: { ...defaultConfig.session, store },
    });

    server = await createServer(appSession(conf));

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=${signedCookieValue}`);

    // Should not crash with destructuring error, should create new empty session
    assert.equal(res.statusCode, 200);
    assert.isEmpty(res.body);
  });

  describe('safePromisify backward compatibility', () => {
    it('should work with callback-based stores (legacy)', async () => {
      const store = new Map();
      const callbackStore = {
        get(id, cb) {
          process.nextTick(() => {
            const data = store.get(id);
            cb(null, data ? JSON.parse(data) : null);
          });
        },
        set(id, val, cb) {
          process.nextTick(() => {
            store.set(id, JSON.stringify(val));
            cb(null);
          });
        },
        destroy(id, cb) {
          process.nextTick(() => {
            store.delete(id);
            cb(null);
          });
        },
      };

      const conf = getConfig({
        ...defaultConfig,
        session: { store: callbackStore },
      });

      server = await createServer(appSession(conf));

      const agent = request.agent(server);

      await login(agent, { sub: '__callback_user__' });

      const res = await agent.get('/session');

      assert.equal(res.statusCode, 200);
      assert.deepEqual(res.body, { sub: '__callback_user__' });
    });

    it('should work with Promise-based stores (modern)', async () => {
      const store = new Map();
      const promiseStore = {
        get(id) {
          const data = store.get(id);
          return Promise.resolve(data ? JSON.parse(data) : null);
        },
        set(id, val) {
          store.set(id, JSON.stringify(val));
          return Promise.resolve();
        },
        destroy(id) {
          store.delete(id);
          return Promise.resolve();
        },
      };

      const conf = getConfig({
        ...defaultConfig,
        session: { store: promiseStore },
      });

      server = await createServer(appSession(conf));

      const agent = request.agent(server);

      await login(agent, { sub: '__promise_user__' });

      const res = await agent.get('/session');

      assert.equal(res.statusCode, 200);
      assert.deepEqual(res.body, { sub: '__promise_user__' });
    });

    it('should work with stores that return Promises directly', async () => {
      const store = new Map();
      const directPromiseStore = {
        get(id) {
          const data = store.get(id);
          return Promise.resolve(data ? JSON.parse(data) : null);
        },
        set(id, val) {
          store.set(id, JSON.stringify(val));
          return Promise.resolve();
        },
        destroy(id) {
          store.delete(id);
          return Promise.resolve();
        },
      };

      const conf = getConfig({
        ...defaultConfig,
        session: { store: directPromiseStore },
      });

      server = await createServer(appSession(conf));

      const agent = request.agent(server);

      await login(agent, { sub: '__direct_promise_user__' });

      const res = await agent.get('/session');

      assert.equal(res.statusCode, 200);
      assert.deepEqual(res.body, { sub: '__direct_promise_user__' });
    });

    it('should work with mixed callback/Promise stores', async () => {
      const store = new Map();
      const mixedStore = {
        // Async method
        get(id) {
          const data = store.get(id);
          return Promise.resolve(data ? JSON.parse(data) : null);
        },
        // Callback method
        set(id, val, cb) {
          process.nextTick(() => {
            store.set(id, JSON.stringify(val));
            cb(null);
          });
        },
        // Promise-returning method
        destroy(id) {
          store.delete(id);
          return Promise.resolve();
        },
      };

      const conf = getConfig({
        ...defaultConfig,
        session: { store: mixedStore },
      });

      server = await createServer(appSession(conf));

      const agent = request.agent(server);

      await login(agent, { sub: '__mixed_user__' });

      const res = await agent.get('/session');

      assert.equal(res.statusCode, 200);
      assert.deepEqual(res.body, { sub: '__mixed_user__' });
    });

    it('should not cause Node.js deprecation warnings', async () => {
      // This test ensures our solution doesn't trigger deprecation warnings
      // by using a store that would previously cause issues with util.promisify
      const store = new Map();
      const modernRedisLikeStore = {
        get(key) {
          const data = store.get(key);
          return Promise.resolve(data ? JSON.parse(data) : null);
        },
        set(key, value) {
          store.set(key, JSON.stringify(value));
          return Promise.resolve('OK');
        },
        del(key) {
          const existed = store.has(key);
          store.delete(key);
          return Promise.resolve(existed ? 1 : 0);
        },
        // Alias destroy to del (common in Redis clients)
        destroy(key) {
          return this.del(key);
        },
      };

      const conf = getConfig({
        ...defaultConfig,
        session: { store: modernRedisLikeStore },
      });

      // This should not trigger any deprecation warnings in Node.js v21.6.0+
      server = await createServer(appSession(conf));

      const agent = request.agent(server);

      await login(agent, { sub: '__modern_redis_user__' });

      const res = await agent.get('/session');

      assert.equal(res.statusCode, 200);
      assert.deepEqual(res.body, { sub: '__modern_redis_user__' });
    });
  });
});
