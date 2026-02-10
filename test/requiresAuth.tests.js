import sinon from 'sinon';
import request from 'supertest';

import { auth, requiresAuth, claimEquals, claimIncludes, claimCheck } from '../index.js';

import { makeIdToken } from './fixture/cert.js';
import { create as createServer } from './fixture/server.js';

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  baseURL: 'http://example.org',
  issuerBaseURL: 'https://op.example.com',
};

async function login(agent, claims) {
  return agent.post('/session').send({
    id_token: await makeIdToken(claims),
  });
}

describe('requiresAuth', () => {
  /** @type {import('http').Server} */
  let server;

  afterEach(() => {
    server?.close();
  });

  it('should allow logged in users to visit a protected route', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      requiresAuth()
    );
    const agent = request.agent(server);
    await login(agent);
    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(200);
  });

  it('should ask anonymous user to login when visiting a protected route', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      requiresAuth()
    );
    const agent = request.agent(server);
    const response = await agent.get('/protected');
    const state = new URL(response.headers.location).searchParams.get('state');
    const decoded = Buffer.from(state, 'base64');
    const parsed = JSON.parse(decoded);

    expect(response.statusCode, response.text).to.equal(302);
    expect(response.get('location')).to.include('https://op.example.com');
    expect(parsed.returnTo).to.equal('/protected');
  });

  it("should 401 for anonymous users who don't accept html", async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      requiresAuth()
    );
    const agent = request.agent(server);

    const response = await agent.get('/protected').set('accept', 'application/json');
    expect(response.statusCode, response.text).to.equal(401);
  });

  it('should return 401 when anonymous user visits a protected route', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      requiresAuth()
    );
    const agent = request.agent(server);

    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(401);
  });

  it("should throw when there's no auth middleware", async () => {
    server = await createServer(null, requiresAuth());
    const agent = request.agent(server);
    const {
      body: { err },
    } = await agent.get('/protected').set('accept', 'application/json');
    expect(err.message).to.equal('req.oidc is not found, did you include the auth middleware?');
  });

  it('should allow logged in users with the right claim', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimEquals('foo', 'bar')
    );
    const agent = request.agent(server);

    await login(agent, { foo: 'bar' });
    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(200);
  });

  it("should return 401 when logged in user doesn't have the right value for claim", async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimEquals('foo', 'bar')
    );
    const agent = request.agent(server);

    await login(agent, { foo: 'baz' });
    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(401);
  });

  it("should return 401 when logged in user doesn't have the claim", async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimEquals('baz', 'bar')
    );
    const agent = request.agent(server);

    await login(agent, { foo: 'bar' });
    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(401);
  });

  it("should return 401 when anonymous user doesn't have the right claim", async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimEquals('foo', 'bar')
    );
    const agent = request.agent(server);

    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(401);
  });

  it('should throw when claim is not a string', () => {
    expect(() => claimEquals(true, 'bar')).to.throw(TypeError, '"claim" must be a string');
  });

  it('should throw when claim value is a non primitive', () => {
    expect(() => claimEquals('foo', { bar: 1 })).to.throw(TypeError, '"expected" must be a string, number, boolean or null');
  });

  it('should allow logged in users with all of the requested claims', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimIncludes('foo', 'bar', 'baz')
    );
    const agent = request.agent(server);

    await login(agent, { foo: ['baz', 'bar'] });
    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(200);
  });

  it('should return 401 for logged with some of the requested claims', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimIncludes('foo', 'bar', 'baz', 'qux')
    );
    const agent = request.agent(server);

    await login(agent, { foo: 'baz bar' });
    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(401);
  });

  it('should accept claim values as a space separated list', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimIncludes('foo', 'bar', 'baz')
    );
    const agent = request.agent(server);

    await login(agent, { foo: 'baz bar' });
    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(200);
  });

  it("should not accept claim values that aren't a string or array", async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimIncludes('foo', 'bar', 'baz')
    );
    const agent = request.agent(server);

    await login(agent, { foo: { bar: 'baz' } });
    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(401);
  });

  it('should throw when claim value for checking many claims is a non primitive', () => {
    expect(() => claimIncludes(false, 'bar')).to.throw(TypeError, '"claim" must be a string');
  });

  it("should return 401 when checking multiple claims and the user doesn't have the claim", async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimIncludes('foo', 'bar', 'baz')
    );
    const agent = request.agent(server);

    await login(agent, { bar: 'bar baz' });
    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(401);
  });

  it('should return 401 when checking many claims with anonymous user', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimIncludes('foo', 'bar', 'baz')
    );
    const agent = request.agent(server);

    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(401);
  });

  it("should throw when custom claim check doesn't get a function", () => {
    expect(() => claimCheck(null)).to.throw(TypeError, '"claimCheck" expects a function');
  });

  it('should allow user when custom claim check returns truthy', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimCheck(() => true)
    );
    const agent = request.agent(server);
    await login(agent);
    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(200);
  });

  it('should not allow user when custom claim check returns falsey', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimCheck(() => false)
    );
    const agent = request.agent(server);
    await login(agent);
    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(401);
  });

  it('should make the token claims available to custom check', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimCheck((_req, claims) => claims.foo === 'some_claim')
    );
    const agent = request.agent(server);

    await login(agent, { foo: 'some_claim' });
    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(200);
  });

  it('should not allow anonymous users to check custom claims', async () => {
    const checkSpy = sinon.spy();
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimCheck(checkSpy)
    );
    const agent = request.agent(server);

    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(401);
    sinon.assert.notCalled(checkSpy);
  });

  it('should collapse leading slashes on returnTo', async () => {
    server = await createServer(auth(defaultConfig));
    const agent = request.agent(server);

    const payloads = ['//google.com', '///google.com', '//google.com'];
    for (const payload of payloads) {
      const response = await agent.get(payload);

      const state = new URL(response.headers.location).searchParams.get('state');
      const decoded = Buffer.from(state, 'base64');
      const parsed = JSON.parse(decoded);

      expect(response.statusCode, response.text).to.equal(302);
      expect(response.headers.location).to.include('https://op.example.com');
      expect(parsed.returnTo).to.equal('/google.com');
    }
  });
});
