import crypto from 'node:crypto';
import { mock } from 'node:test';

import request from 'supertest';

import { getConfig } from '../src/config.js';
import appSession from '../src/middleware/appSession.js';

import { makeIdToken } from './fixture/cert.js';
import { createApp } from './fixture/server.js';
import { encrypted } from './fixture/sessionEncryption.js';

const defaultConfig = {
  clientID: '__test_client_id__',
  clientSecret: '__test_client_secret__',
  issuerBaseURL: 'https://op.example.com',
  baseURL: 'http://example.org',
  secret: '__test_secret__',
  errorOnRequiredAuth: true,
};

const baseUrl = 'http://localhost:3000';

/**
 * Login with id_token claims
 * @param {import('supertest').Agent} agent
 * @param {Record<string, any>} claims
 */
async function login(agent, claims) {
  return agent.post('/session').send({ id_token: await makeIdToken(claims) });
}

const HR_MS = 60 * 60 * 1000;

describe('appSession', () => {
  afterEach(() => {
    mock.timers.reset();
  });

  it('should not create a session when there are no cookies', async () => {
    const server = createApp(appSession(getConfig(defaultConfig)));
    const res = await request(server).get('/session');
    expect(res.body, res.text).to.be.empty;
  });

  it('should not error for malformed sessions', async () => {
    const server = createApp(appSession(getConfig(defaultConfig)));
    const res = await request(server).get('/session').set('cookie', 'appSession=__invalid_identity__');
    expect(res.statusCode, res.text).to.equal(200);
    expect(res.body, res.text).to.be.empty;
  });

  it('should not error with JWEDecryptionFailed when using old secrets', async () => {
    const server = createApp(
      appSession(
        getConfig({
          ...defaultConfig,
          secret: 'another secret',
        })
      )
    );
    const res = await request(server).get('/session').set('cookie', `appSession=${encrypted}`);

    expect(res.statusCode, res.text).to.equal(200);
    expect(res.body, res.text).to.be.empty;
  });

  it('should get an existing session', async () => {
    const server = createApp(appSession(getConfig(defaultConfig)));
    const res = await request(server).get('/session').set('cookie', `appSession=${encrypted}`);
    expect(res.statusCode, res.text).to.equal(200);
    expect(res.body.sub).to.equal('__test_sub__');
  });

  it('should chunk and accept chunked cookies over 4kb', async () => {
    const server = createApp(appSession(getConfig(defaultConfig)));
    const agent = request.agent(server);

    const random = crypto.randomBytes(4000).toString('base64');
    await agent.post('/session').send({
      sub: '__test_sub__',
      random,
    });

    expect(agent.jar.getCookies({ domain: '127.0.0.1', path: '/' }).map(({ name }) => name)).to.deep.equal([
      'appSession.0',
      'appSession.1',
    ]);
    const res = await agent.get('/session');
    expect(res.statusCode, res.text).to.equal(200);
    expect(res.body).to.deep.equal({
      sub: '__test_sub__',
      random,
    });
  });

  it('should limit total cookie size to 4096 Bytes', async () => {
    const server = createApp(appSession(getConfig(defaultConfig)));
    const agent = request.agent(server);

    const res = await agent.post('/session').send({
      sub: '__test_sub__',
      random: crypto.randomBytes(8000).toString('base64'),
    });

    const setCookies = res.get('set-cookie');

    expect(setCookies.length).to.equal(4);
    expect(setCookies[0].length).to.equal(4096);
    expect(setCookies[1].length).to.equal(4096);
    expect(setCookies[2].length).to.equal(4096);
    expect(setCookies[3].length).to.be.below(4096);
  });

  it('should limit total cookie size to 4096 Bytes with custom path', async () => {
    const path = '/some-really-really-really-really-really-really-really-really-really-really-really-really-really-long-path';
    const server = createApp(appSession(getConfig({ ...defaultConfig, session: { cookie: { path } } })));

    const res = await request(server)
      .post('/session')
      .send({
        sub: '__test_sub__',
        random: crypto.randomBytes(8000).toString('base64'),
      });

    const setCookies = res.get('set-cookie');

    expect(setCookies.length).to.equal(4);
    expect(setCookies[0].length).to.equal(4096);
    expect(setCookies[1].length).to.equal(4096);
    expect(setCookies[2].length).to.equal(4096);
    expect(setCookies[3].length).to.be.below(4096);
  });

  it('should clean up single cookie when switching to chunked', async () => {
    const server = createApp(appSession(getConfig(defaultConfig)));

    const agent = request.agent(server);

    agent.jar.setCookie(`appSession=foo; Path=/; HttpOnly; SameSite=Lax`);

    const firstCookies = agent.jar
      .getCookies({ domain: '127.0.0.1', path: '/' })
      .reduce((obj, value) => Object.assign(obj, { [value.name]: value + '' }), {});

    expect(firstCookies).to.have.property('appSession');

    await agent.post('/session').send({
      sub: '__test_sub__',
      random: crypto.randomBytes(8000).toString('base64'),
    });

    const cookies = agent.jar
      .getCookies({ domain: '127.0.0.1', path: '/' })
      .reduce((obj, value) => Object.assign(obj, { [value.name]: value + '' }), {});

    expect(cookies).to.have.property('appSession.0');
    expect(cookies).to.not.have.property('appSession');
  });

  it('should clean up chunked cookies when switching to single cookie', async () => {
    const server = createApp(appSession(getConfig(defaultConfig)));

    const agent = request.agent(server);

    agent.jar.setCookie(`appSession.0=foo; Path=/; HttpOnly; SameSite=Lax`);
    agent.jar.setCookie(`appSession.1=foo; Path=/; HttpOnly; SameSite=Lax`);

    const firstCookies = agent.jar
      .getCookies({ domain: '127.0.0.1', path: '/' })
      .reduce((obj, value) => Object.assign(obj, { [value.name]: value + '' }), {});
    expect(firstCookies).to.have.property('appSession.0');
    expect(firstCookies).to.have.property('appSession.1');

    await agent.post('/session').send({
      sub: '__test_sub__',
    });

    const cookies = agent.jar
      .getCookies({ domain: '127.0.0.1', path: '/' })
      .reduce((obj, value) => Object.assign(obj, { [value.name]: value + '' }), {});

    expect(cookies).to.have.property('appSession');
    expect(cookies).to.not.have.property('appSession.0');
  });

  it('should handle unordered chunked cookies', async () => {
    const server = createApp(appSession(getConfig(defaultConfig)));

    const agent1 = request.agent(server);

    const random = crypto.randomBytes(4000).toString('base64');
    const res1 = await agent1.post('/session').send({
      sub: '__test_sub__',
      random,
    });

    const agent2 = request.agent(server);

    for (const c of res1.get('Set-Cookie').reverse()) {
      agent2.jar.setCookie(c);
    }

    expect(agent2.jar.getCookies({ domain: '127.0.0.1', path: '/' }).map(({ name }) => name)).to.deep.equal([
      'appSession.1',
      'appSession.0',
    ]);

    const res2 = await agent2.get('/session');

    expect(res2.statusCode, res2.text).to.equal(200);
    expect(res2.body).to.deep.equal({
      sub: '__test_sub__',
      random,
    });
  });

  it('should not throw for malformed cookie chunks', async () => {
    const server = createApp(appSession(getConfig(defaultConfig)));

    const agent = request.agent(server);

    agent.jar.setCookie('appSession.0=foo; SameSite=lax');
    agent.jar.setCookie('appSession.1=bar; SameSite=lax');

    const res = await agent.get('/session');

    expect(res.statusCode, res.text).to.equal(200);

    expect(res.get('Set-Cookie'), 'unset cookie headers').to.have.length(2);
  });

  it('should set the default cookie options over http', async () => {
    mock.timers.enable({ apis: ['Date'], now: new Date() });

    const server = createApp(appSession(getConfig({ ...defaultConfig, baseURL: 'http://example.org' })));

    const agent = request.agent(server);

    await agent.get('/session').set('cookie', `appSession=${encrypted}`);

    const [cookie] = agent.jar.getCookies({ domain: '127.0.0.1', path: '/' });

    expect(cookie).to.deep.include({
      name: 'appSession',
      domain: '127.0.0.1',
      path: '/',
      noscript: true,
      explicit_domain: false,
    });

    const expDate = new Date(cookie.expiration_date);
    expect(expDate - Date.now()).to.be.approximately(86400000, 5000);
  });

  it('should set the default cookie options over https', async () => {
    const server = createApp(appSession(getConfig({ ...defaultConfig, baseURL: 'https://example.org' })));

    const agent = request.agent(server);

    await agent.get('/session').set('cookie', `appSession=${encrypted}`);
    // Secure cookies not set over http
    expect(agent.jar.getCookies({ domain: '127.0.0.1', path: '/' })).to.be.empty;
  });

  it('should set the custom cookie options', async () => {
    const server = createApp(
      appSession(
        getConfig({
          ...defaultConfig,
          session: {
            cookie: {
              httpOnly: false,
              sameSite: 'Strict',
            },
          },
        })
      )
    );

    const agent = request.agent(server);

    await agent.get('/session').set('cookie', `appSession=${encrypted}`);

    const [cookie] = agent.jar.getCookies({ domain: '127.0.0.1', path: '/' });

    expect(cookie).to.deep.include({
      name: 'appSession',
      noscript: false,
      explicit_domain: false,
    });
  });

  it('should disregard custom id generation without a custom store', async () => {
    const server = createApp(
      appSession(
        getConfig({
          ...defaultConfig,
          session: {
            genid: () => {
              throw 'this should not be called';
            }, //consider using chai-spies
          },
        })
      )
    );

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=${encrypted}`);

    expect(res.statusCode, res.text).to.equal(200);
    expect(res.body.sub).to.equal('__test_sub__');
  });

  it('should use a custom cookie name', async () => {
    const server = createApp(
      appSession(
        getConfig({
          ...defaultConfig,
          session: { name: 'customName' },
        })
      )
    );

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `customName=${encrypted}`);

    const [cookie] = agent.jar.getCookies({ domain: '127.0.0.1', path: '/' });
    expect(res.statusCode, res.text).to.equal(200);
    expect(cookie.name).to.equal('customName');
  });

  it('should set an ephemeral cookie', async () => {
    const server = createApp(
      appSession(
        getConfig({
          ...defaultConfig,
          session: { cookie: { transient: true } },
        })
      )
    );

    const agent = request.agent(server);

    const res = await agent.get('/session').set('cookie', `appSession=${encrypted}`);

    const [cookie] = agent.jar.getCookies({ domain: '127.0.0.1', path: '/' });
    expect(res.statusCode, res.text).to.equal(200);
    expect(cookie.expiration_date).to.equal(Infinity);
  });

  it('should not throw for expired cookies', async () => {
    const twoWeeks = 2 * 7 * 24 * 60 * 60 * 1000;

    mock.timers.enable({ apis: ['Date'], now: new Date() });

    const server = createApp(appSession(getConfig(defaultConfig)));

    const agent = request.agent(server);

    mock.timers.tick(twoWeeks);

    const res = await agent.get('/session').set('cookie', `appSession=${encrypted}`);

    expect(res.statusCode, res.text).to.equal(200);

    expect(res.get('Set-Cookie')).to.have.length(1);
  });

  it('should throw for duplicate mw', async () => {
    const server = createApp((req, res, next) => {
      req.appSession = {};
      appSession(getConfig(defaultConfig))(req, res, next);
    });
    const res = await request(server).get('/session');
    expect(res.statusCode, res.text).to.equal(500);
    expect(res.body.err).to.have.property('message', 'req[appSession] is already set, did you run this middleware twice?');
  });

  it('should throw for reassigning session', async () => {
    const server = createApp((req, res, next) => {
      appSession(getConfig(defaultConfig))(req, res, () => {
        try {
          req.appSession = {};
          next();
        } catch (e) {
          next(e);
        }
      });
    });
    const res = await request(server).get('/session', { baseUrl, json: true });

    expect(res.statusCode, res.text).to.equal(500);
    expect(res.body.err.message).to.equal('session object cannot be reassigned');
  });

  it('should not throw for reassigining session to empty', async () => {
    const server = createApp((req, res, next) => {
      appSession(getConfig(defaultConfig))(req, res, () => {
        req.appSession = null;
        req.appSession = undefined;
        next();
      });
    });
    const res = await request(server).get('/session');
    expect(res.statusCode, res.text).to.equal(200);
  });

  it('should expire after 24hrs of inactivity by default', async () => {
    mock.timers.enable({ apis: ['Date'], now: new Date() });

    const server = createApp(appSession(getConfig(defaultConfig)));

    const agent = request.agent(server);

    await login(agent, { sub: '__test_sub__' });

    let res = await agent.get('/session');
    expect(res.body, res.text).to.not.be.empty;

    mock.timers.tick(23 * HR_MS);
    res = await agent.get('/session');
    expect(res.body, res.text).to.not.be.empty;

    mock.timers.tick(25 * HR_MS);
    res = await agent.get('/session');
    expect(res.body, res.text).to.be.empty;
  });

  it('should expire after 7days regardless of activity by default', async () => {
    mock.timers.enable({ apis: ['Date'], now: new Date() });

    const server = createApp(appSession(getConfig(defaultConfig)));

    const agent = request.agent(server);

    await login(agent, { sub: '__test_sub__' });

    let days = 7;
    while (days--) {
      mock.timers.tick(23 * HR_MS);
      const res = await agent.get('/session');
      expect(res.body, res.text).to.not.be.empty;
    }

    mock.timers.tick(8 * HR_MS);
    const res = await agent.get('/session');
    expect(res.body, res.text).to.be.empty;
  });

  it('should expire only after defined absoluteDuration', async () => {
    mock.timers.enable({ apis: ['Date'], now: new Date() });

    const server = createApp(
      appSession(
        getConfig({
          ...defaultConfig,
          session: {
            rolling: false,
            absoluteDuration: 10 * 60 * 60,
          },
        })
      )
    );

    const agent = request.agent(server);

    await login(agent, { sub: '__test_sub__' });

    mock.timers.tick(9 * HR_MS);
    let res = await agent.get('/session');

    expect(res.body, res.text).to.not.be.empty;

    mock.timers.tick(2 * HR_MS);
    res = await agent.get('/session');
    expect(res.body, res.text).to.be.empty;
  });

  it('should expire only after defined rollingDuration period of inactivty', async () => {
    mock.timers.enable({ apis: ['Date'], now: new Date() });

    const server = createApp(
      appSession(
        getConfig({
          ...defaultConfig,
          session: {
            rolling: true,
            rollingDuration: 24 * 60 * 60,
            absoluteDuration: false,
          },
        })
      )
    );

    const agent = request.agent(server);

    await login(agent, { sub: '__test_sub__' });

    let days = 30;
    while (days--) {
      mock.timers.tick(23 * HR_MS);
      const res = await agent.get('/session');
      expect(res.body, `after ${days}: ${res.text}`).to.not.be.empty;
    }

    mock.timers.tick(25 * HR_MS);
    const res = await agent.get('/session');
    expect(res.body, res.text).to.be.empty;
  });
});
