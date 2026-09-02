import { auth, requiresAuth, claimEquals, claimIncludes, claimIncludesAny, claimCheck, ForbiddenError } from '@aller/openid-connect';
import nock from 'nock';
import request from 'supertest';

import { makeIdToken } from './fixture/cert.js';
import { createApp } from './fixture/server.js';
import { setupDiscovery } from './helpers/openid-helper.js';

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
  before(() => {
    setupDiscovery().persist();
  });
  after(nock.cleanAll);

  it('should allow logged in users to visit a protected route', async () => {
    const server = createApp(
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
    const server = createApp(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      requiresAuth()
    );
    const agent = request.agent(server);
    const response = await agent.get('/protected').expect(302);
    const state = new URL(response.get('location')).searchParams.get('state');
    const decoded = Buffer.from(state, 'base64');
    const parsed = JSON.parse(decoded.toString());

    expect(response.statusCode, response.text).to.equal(302);
    expect(response.get('location')).to.include('https://op.example.com');
    expect(parsed.returnTo).to.equal('/protected');
  });

  it("should 401 for anonymous users who don't accept html", async () => {
    const server = createApp(
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
    const server = createApp(
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
    const server = createApp(null, requiresAuth());
    const agent = request.agent(server);
    const {
      body: { err },
    } = await agent.get('/protected').set('accept', 'application/json');
    expect(err.message).to.equal('req.oidc is not found, did you include the auth middleware?');
  });

  it('should allow logged in users with the right claim', async () => {
    const server = createApp(
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

  it("should return 403 when logged in user doesn't have the right value for claim", async () => {
    const server = createApp(
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

    expect(response.statusCode, response.text).to.equal(403);
    expect(response.get('location')).to.be.undefined;
    expect(response.body.err.message).to.equal('Insufficient claim "foo"');
    expect(response.body.err.reason).to.deep.equal({ claim: 'foo', expected: 'bar', actual: 'baz' });
  });

  it("should return 403 when logged in user doesn't have the claim", async () => {
    const server = createApp(
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

    expect(response.statusCode, response.text).to.equal(403);
    expect(response.get('location')).to.be.undefined;
    expect(response.body.err.message).to.equal('Missing claim "baz"');
    expect(response.body.err.reason).to.deep.equal({ claim: 'baz', expected: 'bar' });
  });

  it("should return 401 when anonymous user doesn't have the right claim", async () => {
    const server = createApp(
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
    expect(() => claimEquals(/** @type {any} */ (true), 'bar')).to.throw(TypeError, '"claim" must be a string');
  });

  it('should throw when claim value is a non primitive', () => {
    expect(() => claimEquals('foo', /** @type {any} */ ({ bar: 1 }))).to.throw(
      TypeError,
      '"expected" must be a string, number, boolean or null'
    );
  });

  it('should allow logged in users with all of the requested claims', async () => {
    const server = createApp(
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

  it('should return 403 for logged with some of the requested claims', async () => {
    const server = createApp(
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

    expect(response.statusCode, response.text).to.equal(403);
    expect(response.body.err.reason).to.deep.equal({ claim: 'foo', expected: ['bar', 'baz', 'qux'], actual: 'baz bar' });
  });

  it('should accept claim values as a space separated list', async () => {
    const server = createApp(
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
    const server = createApp(
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

    expect(response.statusCode, response.text).to.equal(403);
    expect(response.body.err.reason).to.deep.equal({ claim: 'foo', expected: ['bar', 'baz'], actual: { bar: 'baz' } });
  });

  it('should throw when claim value for checking many claims is a non primitive', () => {
    expect(() => claimIncludes(/** @type {any} */ (false), 'bar')).to.throw(TypeError, '"claim" must be a string');
  });

  it("should return 403 when checking multiple claims and the user doesn't have the claim", async () => {
    const server = createApp(
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

    expect(response.statusCode, response.text).to.equal(403);
  });

  it('should return 401 when checking many claims with anonymous user', async () => {
    const server = createApp(
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
    const server = createApp(
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
    const server = createApp(
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

    expect(response.statusCode, response.text).to.equal(403);
    expect(response.body.err.message).to.equal('Insufficient claims');
  });

  it('should make the token claims available to custom check', async () => {
    const server = createApp(
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
    let claimChecksCounter = 0;

    const server = createApp(
      auth({
        ...defaultConfig,
        authRequired: false,
        errorOnRequiredAuth: true,
      }),
      claimCheck(() => {
        claimChecksCounter++;
      })
    );
    const agent = request.agent(server);

    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(401);
    expect(claimChecksCounter).to.equal(0);
  });

  it('should pass the error returned by a custom claim check to next', async () => {
    const server = createApp(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      claimCheck((_req, claims) => {
        if (Array.isArray(claims.roles) && claims.roles.includes('Support')) return true;
        return new ForbiddenError('Support role required', { claim: 'roles', expected: ['Support'], actual: claims.roles });
      })
    );
    const agent = request.agent(server);

    await login(agent, { roles: ['User'] });
    const response = await agent.get('/protected');

    expect(response.statusCode, response.text).to.equal(403);
    expect(response.body.err.message).to.equal('Support role required');
    expect(response.body.err.reason).to.deep.equal({ claim: 'roles', expected: ['Support'], actual: ['User'] });
  });

  describe('authenticated user failing a claim check', () => {
    it('is answered with 403 and no redirect even if the request accepts html', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimIncludes('roles', 'Admin')
      );
      const agent = request.agent(server);

      await login(agent);
      const response = await agent.get('/protected').set('accept', 'text/html');

      expect(response.statusCode, response.text).to.equal(403);
      expect(response.get('location')).to.be.undefined;
      expect(response.body.err.message).to.equal('Missing claim "roles"');
    });

    it('is answered with 403 when the claim is present but wrong', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimIncludes('roles', 'Admin')
      );
      const agent = request.agent(server);

      await login(agent, { roles: ['User'] });
      const response = await agent.get('/protected').set('accept', 'text/html');

      expect(response.statusCode, response.text).to.equal(403);
      expect(response.get('location')).to.be.undefined;
      expect(response.body.err.reason).to.deep.equal({ claim: 'roles', expected: ['Admin'], actual: ['User'] });
    });

    it('is answered with 403 for claimEquals and claimCheck as well', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimEquals('foo', 'bar')
      );
      const agent = request.agent(server);

      await login(agent, { foo: 'baz' });
      expect((await agent.get('/protected').set('accept', 'text/html')).statusCode).to.equal(403);

      const customServer = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimCheck(() => false)
      );
      const customAgent = request.agent(customServer);
      await login(customAgent);
      expect((await customAgent.get('/protected').set('accept', 'text/html')).statusCode).to.equal(403);
    });

    it('still redirects anonymous users to login', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimIncludes('roles', 'Admin')
      );
      const agent = request.agent(server);

      const response = await agent.get('/protected').set('accept', 'text/html');

      expect(response.statusCode, response.text).to.equal(302);
      expect(response.get('location')).to.include('https://op.example.com');
    });
  });

  describe('per-middleware errorOnRequiredAuth', () => {
    it('requiresAuth({ errorOnRequiredAuth: true }) answers anonymous users with 401 instead of redirecting', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        requiresAuth({ errorOnRequiredAuth: true })
      );
      const agent = request.agent(server);

      const response = await agent.get('/protected').set('accept', 'text/html');

      expect(response.statusCode, response.text).to.equal(401);
      expect(response.get('location')).to.be.undefined;
    });

    it('requiresAuth(check, { errorOnRequiredAuth: true }) combines a custom check with options', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        requiresAuth(() => true, { errorOnRequiredAuth: true })
      );
      const agent = request.agent(server);

      await login(agent);
      const response = await agent.get('/protected').set('accept', 'text/html');

      expect(response.statusCode, response.text).to.equal(401);
    });

    it('requiresAuth({ errorOnRequiredAuth: false }) redirects even when the global option is true', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
          errorOnRequiredAuth: true,
        }),
        requiresAuth({ errorOnRequiredAuth: false })
      );
      const agent = request.agent(server);

      const response = await agent.get('/protected').set('accept', 'text/html');

      expect(response.statusCode, response.text).to.equal(302);
    });

    it('claimEquals accepts options as third argument', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimEquals('foo', 'bar', { errorOnRequiredAuth: true })
      );
      const agent = request.agent(server);

      const response = await agent.get('/protected').set('accept', 'text/html');

      expect(response.statusCode, response.text).to.equal(401);
    });

    it('claimIncludes accepts options as last argument', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimIncludes('roles', 'Support', { errorOnRequiredAuth: true })
      );
      const agent = request.agent(server);

      const anonymous = await agent.get('/protected').set('accept', 'text/html');
      expect(anonymous.statusCode, anonymous.text).to.equal(401);

      await login(agent, { roles: ['Support'] });
      const authorized = await agent.get('/protected');
      expect(authorized.statusCode, authorized.text).to.equal(200);
    });

    it('claimCheck accepts options as second argument', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimCheck(() => true, { errorOnRequiredAuth: true })
      );
      const agent = request.agent(server);

      const response = await agent.get('/protected').set('accept', 'text/html');

      expect(response.statusCode, response.text).to.equal(401);
    });
  });

  describe('ignoreCase and trim', () => {
    it('claimEquals matches string values case insensitively', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimEquals('email', 'jane@example.org', { ignoreCase: true })
      );
      const agent = request.agent(server);

      await login(agent, { email: 'Jane@Example.org' });
      const response = await agent.get('/protected');

      expect(response.statusCode, response.text).to.equal(200);
    });

    it('claimEquals is case sensitive by default', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimEquals('email', 'jane@example.org')
      );
      const agent = request.agent(server);

      await login(agent, { email: 'Jane@Example.org' });
      const response = await agent.get('/protected');

      expect(response.statusCode, response.text).to.equal(403);
    });

    it('claimEquals keeps non-string values strict', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimEquals('level', 1, { ignoreCase: true })
      );
      const agent = request.agent(server);

      await login(agent, { level: '1' });
      const response = await agent.get('/protected');

      expect(response.statusCode, response.text).to.equal(403);
      expect(response.body.err.reason).to.deep.equal({ claim: 'level', expected: 1, actual: '1' });
    });

    it('claimIncludes matches array and space separated values case insensitively', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimIncludes('roles', 'admin', 'auditor', { ignoreCase: true })
      );
      const agent = request.agent(server);

      await login(agent, { roles: ['Admin', 'AUDITOR'] });
      expect((await agent.get('/protected')).statusCode).to.equal(200);

      await login(agent, { roles: 'Admin AUDITOR' });
      expect((await agent.get('/protected')).statusCode).to.equal(200);
    });

    it('claimEquals trims string values with trim', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimEquals('email', ' jane@example.org', { trim: true })
      );
      const agent = request.agent(server);

      await login(agent, { email: 'jane@example.org  ' });
      const response = await agent.get('/protected');

      expect(response.statusCode, response.text).to.equal(200);
    });

    it('claimEquals does not trim by default', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimEquals('email', 'jane@example.org')
      );
      const agent = request.agent(server);

      await login(agent, { email: 'jane@example.org ' });
      const response = await agent.get('/protected');

      expect(response.statusCode, response.text).to.equal(403);
    });

    it('claimIncludes trims values and splits on runs of whitespace with trim', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimIncludes('roles', 'admin ', ' auditor', { trim: true })
      );
      const agent = request.agent(server);

      await login(agent, { roles: '  admin \t auditor ' });
      expect((await agent.get('/protected')).statusCode).to.equal(200);

      await login(agent, { roles: [' admin', 'auditor '] });
      expect((await agent.get('/protected')).statusCode).to.equal(200);
    });

    it('trim and ignoreCase compose', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimIncludes('roles', 'admin', { trim: true, ignoreCase: true })
      );
      const agent = request.agent(server);

      await login(agent, { roles: ' ADMIN ' });
      expect((await agent.get('/protected')).statusCode).to.equal(200);
    });

    it('claimIncludes reports the original values when the check still fails', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimIncludes('roles', 'admin', 'finance', { ignoreCase: true })
      );
      const agent = request.agent(server);

      await login(agent, { roles: ['Admin'] });
      const response = await agent.get('/protected');

      expect(response.statusCode, response.text).to.equal(403);
      expect(response.body.err.reason).to.deep.equal({ claim: 'roles', expected: ['admin', 'finance'], actual: ['Admin'] });
    });
  });

  describe('claimIncludesAny', () => {
    it('allows a user holding at least one of the values', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimIncludesAny('roles', 'Admin', 'Finance')
      );
      const agent = request.agent(server);

      await login(agent, { roles: ['Finance', 'User'] });
      expect((await agent.get('/protected')).statusCode).to.equal(200);

      await login(agent, { roles: 'User Admin' });
      expect((await agent.get('/protected')).statusCode).to.equal(200);
    });

    it('rejects a user holding none of the values with 403', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimIncludesAny('roles', 'Admin', 'Finance')
      );
      const agent = request.agent(server);

      await login(agent, { roles: ['User'] });
      const response = await agent.get('/protected').set('accept', 'text/html');

      expect(response.statusCode, response.text).to.equal(403);
      expect(response.get('location')).to.be.undefined;
      expect(response.body.err.message).to.equal('Insufficient claim "roles"');
      expect(response.body.err.reason).to.deep.equal({ claim: 'roles', expected: ['Admin', 'Finance'], actual: ['User'] });
    });

    it('rejects a missing claim with 403', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimIncludesAny('roles', 'Admin')
      );
      const agent = request.agent(server);

      await login(agent);
      const response = await agent.get('/protected');

      expect(response.statusCode, response.text).to.equal(403);
      expect(response.body.err.message).to.equal('Missing claim "roles"');
    });

    it('rejects a claim that is neither string nor array', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimIncludesAny('roles', 'Admin')
      );
      const agent = request.agent(server);

      await login(agent, { roles: 42 });
      const response = await agent.get('/protected');

      expect(response.statusCode, response.text).to.equal(403);
      expect(response.body.err.reason).to.deep.equal({ claim: 'roles', expected: ['Admin'], actual: 42 });
    });

    it('supports ignoreCase and trim', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimIncludesAny('roles', 'admin', 'finance', { ignoreCase: true, trim: true })
      );
      const agent = request.agent(server);

      await login(agent, { roles: '  user   FINANCE ' });
      expect((await agent.get('/protected')).statusCode).to.equal(200);
    });

    it('treats anonymous users as requiresAuth does', async () => {
      const server = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimIncludesAny('roles', 'Admin')
      );
      const agent = request.agent(server);

      const redirect = await agent.get('/protected').set('accept', 'text/html');
      expect(redirect.statusCode).to.equal(302);

      const errorServer = createApp(
        auth({
          ...defaultConfig,
          authRequired: false,
        }),
        claimIncludesAny('roles', 'Admin', { errorOnRequiredAuth: true })
      );
      const unauthorized = await request.agent(errorServer).get('/protected').set('accept', 'text/html');
      expect(unauthorized.statusCode).to.equal(401);
    });

    it('validates arguments like claimIncludes', () => {
      expect(() => claimIncludesAny(/** @type {any} */ (1), 'x')).to.throw(TypeError, '"claim" must be a string');
      expect(() => claimIncludesAny('roles', /** @type {any} */ ([]))).to.throw(TypeError, '"expected" must be');
    });
  });
});
