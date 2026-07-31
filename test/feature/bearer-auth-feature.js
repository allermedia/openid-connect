import { claimCheck, claimEquals, claimIncludes, requiresAuth, requiresBearerAuth } from '@aller/openid-connect';
import express from 'express';
import nock from 'nock';
import request from 'supertest';

import { makeIdToken } from '../fixture/cert.js';
import { setupDiscovery, setupJwks } from '../helpers/openid-helper.js';

const ISSUER = 'https://op.example.com';
const AUDIENCE = '__test_api__';

const errorHandler = /** @type {import('express').ErrorRequestHandler} */ (
  (err, _req, res, next) => {
    if (res.headersSent) return next(err);
    res
      .set(err.headers)
      .status(err.statusCode || 500)
      .json({ message: err.message });
  }
);

/**
 * Minimal JSON API protected by the middleware under test
 * @param {Partial<Parameters<typeof requiresBearerAuth>[0]>} [params]
 */
function createApi(params) {
  const app = express();
  app.get('/api', requiresBearerAuth({ issuerBaseURL: ISSUER, audience: AUDIENCE, ...params }), (req, res) => {
    res.json({ sub: req.bearerAuth?.payload.sub ?? null });
  });
  app.use(errorHandler);
  return app;
}

Feature('Bearer authentication', () => {
  Scenario('a JSON API protected by bearer tokens', () => {
    before(() => {
      setupDiscovery().persist();
      setupJwks();
    });
    after(nock.cleanAll);

    /** @type {import('express').Application} */
    let app;
    Given('an API protected by requiresBearerAuth', () => {
      app = createApi();
    });

    /** @type {import('supertest').Response} */
    let response;
    When('a request is made without an authorization header', async () => {
      response = await request(app).get('/api');
    });

    Then('it is rejected with 401 and a WWW-Authenticate challenge', () => {
      expect(response.status).to.equal(401);
      expect(response.headers['www-authenticate']).to.equal('Bearer');
    });

    When('a request presents a valid bearer token', async () => {
      const token = await makeIdToken({ aud: AUDIENCE });
      response = await request(app).get('/api').set('authorization', `Bearer ${token}`);
    });

    Then('it succeeds and the verified payload is exposed as req.bearerAuth', () => {
      expect(response.status).to.equal(200);
      expect(response.body).to.deep.equal({ sub: '__test_sub__' });
    });

    When('a request presents a token minted for another audience', async () => {
      const token = await makeIdToken();
      response = await request(app).get('/api').set('authorization', `Bearer ${token}`);
    });

    Then('it is rejected with 401', () => {
      expect(response.status).to.equal(401);
    });

    When('a request presents a token from another issuer', async () => {
      const token = await makeIdToken({ aud: AUDIENCE, iss: 'https://other.example.com/' });
      response = await request(app).get('/api').set('authorization', `Bearer ${token}`);
    });

    Then('it is also rejected with 401', () => {
      expect(response.status).to.equal(401);
    });

    When('a request presents an expired token', async () => {
      const epoch = Math.floor(Date.now() / 1000);
      const token = await makeIdToken({ aud: AUDIENCE, iat: epoch - 7200, exp: epoch - 3600 });
      response = await request(app).get('/api').set('authorization', `Bearer ${token}`);
    });

    Then('it is rejected with 401 as well', () => {
      expect(response.status).to.equal(401);
    });

    When('a request presents a malformed token', async () => {
      response = await request(app).get('/api').set('authorization', 'Bearer not-a-jwt');
    });

    Then('it is rejected with 401 and an invalid_token challenge', () => {
      expect(response.status).to.equal(401);
      expect(response.headers['www-authenticate']).to.equal('Bearer error="invalid_token"');
    });
  });

  Scenario('an API configured with a clock tolerance', () => {
    before(() => {
      setupDiscovery().persist();
      setupJwks();
    });
    after(nock.cleanAll);

    /** @type {import('express').Application} */
    let app;
    Given('an API protected by requiresBearerAuth with a clockTolerance of 3660 seconds', () => {
      app = createApi({ clockTolerance: 3660 });
    });

    /** @type {import('supertest').Response} */
    let response;
    When('a request presents a token that expired an hour ago', async () => {
      const epoch = Math.floor(Date.now() / 1000);
      const token = await makeIdToken({ aud: AUDIENCE, iat: epoch - 7200, exp: epoch - 3600 });
      response = await request(app).get('/api').set('authorization', `Bearer ${token}`);
    });

    Then('it is accepted since the expiry is within the tolerance', () => {
      expect(response.status).to.equal(200);
    });
  });

  Scenario('issuer discovery fails on the first request', () => {
    after(nock.cleanAll);

    /** @type {import('express').Application} */
    let app;
    /** @type {string} */
    let token;
    Given('an API whose issuer discovery endpoint is unreachable', () => {
      app = createApi();
    });

    /** @type {import('supertest').Response} */
    let response;
    When('a request presents a valid bearer token', async () => {
      token = await makeIdToken({ aud: AUDIENCE });
      response = await request(app).get('/api').set('authorization', `Bearer ${token}`);
    });

    Then('it is rejected with 401', () => {
      expect(response.status).to.equal(401);
    });

    When('the issuer becomes reachable and the request is retried', async () => {
      setupDiscovery();
      setupJwks();
      response = await request(app).get('/api').set('authorization', `Bearer ${token}`);
    });

    Then('the failed discovery was not cached and the retry succeeds', () => {
      expect(response.status).to.equal(200);
    });
  });

  Scenario('an issuer with a tenant path component', () => {
    const issuer = 'https://op.example.com/tenant';
    after(nock.cleanAll);

    /** @type {import('express').Application} */
    let app;
    Given('an API configured with a tenanted issuerBaseURL', () => {
      setupDiscovery(issuer);
      setupJwks(issuer);
      app = createApi({ issuerBaseURL: issuer });
    });

    /** @type {import('supertest').Response} */
    let response;
    When('a request presents a token from the tenanted issuer', async () => {
      const token = await makeIdToken({ aud: AUDIENCE, iss: issuer });
      response = await request(app).get('/api').set('authorization', `Bearer ${token}`);
    });

    Then('discovery resolves under the tenant path and the request succeeds', () => {
      expect(response.status).to.equal(200);
    });
  });

  Scenario('an issuerBaseURL with a trailing slash', () => {
    after(nock.cleanAll);

    /** @type {import('express').Application} */
    let app;
    Given('an API configured with a trailing-slash issuerBaseURL', () => {
      setupDiscovery();
      setupJwks();
      app = createApi({ issuerBaseURL: `${ISSUER}/` });
    });

    /** @type {import('supertest').Response} */
    let response;
    When('a request presents a valid bearer token', async () => {
      const token = await makeIdToken({ aud: AUDIENCE });
      response = await request(app).get('/api').set('authorization', `Bearer ${token}`);
    });

    Then('the request succeeds', () => {
      expect(response.status).to.equal(200);
    });
  });

  Scenario('the issuer serves invalid discovery documents', () => {
    after(nock.cleanAll);

    /** @type {import('supertest').Response} */
    let response;
    When('discovery responds with an error status', async () => {
      nock(ISSUER).get('/.well-known/openid-configuration').reply(500);
      const token = await makeIdToken({ aud: AUDIENCE });
      response = await request(createApi()).get('/api').set('authorization', `Bearer ${token}`);
    });

    Then('the request is rejected with 401', () => {
      expect(response.status).to.equal(401);
    });

    When('the discovery document lacks an issuer', async () => {
      setupDiscovery(undefined, { issuer: undefined });
      const token = await makeIdToken({ aud: AUDIENCE });
      response = await request(createApi()).get('/api').set('authorization', `Bearer ${token}`);
    });

    Then('the request is also rejected with 401', () => {
      expect(response.status).to.equal(401);
    });

    When('the discovery document lacks a JWKS URI', async () => {
      setupDiscovery(undefined, { jwks_uri: undefined });
      const token = await makeIdToken({ aud: AUDIENCE });
      response = await request(createApi()).get('/api').set('authorization', `Bearer ${token}`);
    });

    Then('the request is rejected with 401 as well', () => {
      expect(response.status).to.equal(401);
    });
  });

  Scenario('chaining auth methods with fallthrough', () => {
    before(() => {
      setupDiscovery().persist();
      setupJwks();
    });
    after(nock.cleanAll);

    /** @type {import('express').Application} */
    let app;
    Given('an API protected by requiresBearerAuth with fallthrough enabled', () => {
      app = createApi({ fallthrough: true });
    });

    /** @type {import('supertest').Response} */
    let response;
    When('a request is made without a bearer token', async () => {
      response = await request(app).get('/api');
    });

    Then('it continues unauthenticated to the next handler', () => {
      expect(response.status).to.equal(200);
      expect(response.body).to.deep.equal({ sub: null });
    });

    When('a request presents an invalid bearer token', async () => {
      response = await request(app).get('/api').set('authorization', 'Bearer not-a-jwt');
    });

    Then('it is still rejected with 401', () => {
      expect(response.status).to.equal(401);
    });

    When('a request presents a valid bearer token', async () => {
      const token = await makeIdToken({ aud: AUDIENCE });
      response = await request(app).get('/api').set('authorization', `Bearer ${token}`);
    });

    Then('it is still verified and exposed as req.bearerAuth', () => {
      expect(response.status).to.equal(200);
      expect(response.body).to.deep.equal({ sub: '__test_sub__' });
    });
  });

  Scenario('chaining claim checks after bearer auth', () => {
    before(() => {
      setupDiscovery().persist();
      setupJwks();
    });
    after(nock.cleanAll);

    /** @type {import('express').Application} */
    let app;
    Given('an API with requiresAuth and claim checks chained after requiresBearerAuth', () => {
      const bearer = requiresBearerAuth({ issuerBaseURL: ISSUER, audience: AUDIENCE });
      app = express();
      app.get('/api/user', bearer, requiresAuth(), (req, res) => {
        res.json({ sub: req.bearerAuth?.payload.sub });
      });
      app.get('/api/admin', bearer, claimEquals('role', 'admin'), (_req, res) => {
        res.json({ ok: true });
      });
      app.get('/api/read', bearer, claimIncludes('permissions', 'read'), (_req, res) => {
        res.json({ ok: true });
      });
      app.get(
        '/api/custom',
        bearer,
        claimCheck((_req, claims) => claims.sub === '__test_sub__'),
        (_req, res) => {
          res.json({ ok: true });
        }
      );
      app.use(errorHandler);
    });

    /** @type {import('supertest').Response} */
    let response;
    When('a valid bearer token requests a route guarded by requiresAuth', async () => {
      const token = await makeIdToken({ aud: AUDIENCE });
      response = await request(app).get('/api/user').set('authorization', `Bearer ${token}`);
    });

    Then('the bearer identity satisfies requiresAuth', () => {
      expect(response.status).to.equal(200);
      expect(response.body).to.deep.equal({ sub: '__test_sub__' });
    });

    When('a token carrying role admin requests the claimEquals route', async () => {
      const token = await makeIdToken({ aud: AUDIENCE, role: 'admin' });
      response = await request(app).get('/api/admin').set('authorization', `Bearer ${token}`);
    });

    Then('the token claim satisfies the check', () => {
      expect(response.status).to.equal(200);
    });

    When('a token without the admin role requests the claimEquals route', async () => {
      const token = await makeIdToken({ aud: AUDIENCE });
      response = await request(app).get('/api/admin').set('authorization', `Bearer ${token}`);
    });

    Then('it is rejected with 401', () => {
      expect(response.status).to.equal(401);
    });

    When('a token whose space-delimited permissions include read requests the claimIncludes route', async () => {
      const token = await makeIdToken({ aud: AUDIENCE, permissions: 'read write' });
      response = await request(app).get('/api/read').set('authorization', `Bearer ${token}`);
    });

    Then('the included claim satisfies the check', () => {
      expect(response.status).to.equal(200);
    });

    When('a token failing a custom claimCheck requests its route', async () => {
      const token = await makeIdToken({ aud: AUDIENCE, sub: 'someone-else' });
      response = await request(app).get('/api/custom').set('authorization', `Bearer ${token}`);
    });

    Then('it is rejected with 401 by the custom check', () => {
      expect(response.status).to.equal(401);
    });
  });

  Scenario('invalid configuration', () => {
    Then('requiresBearerAuth throws when called without params', () => {
      // @ts-ignore
      expect(() => requiresBearerAuth()).to.throw(TypeError, 'issuerBaseURL');
    });

    And('it throws without an issuerBaseURL', () => {
      // @ts-ignore
      expect(() => requiresBearerAuth({ audience: AUDIENCE })).to.throw(TypeError, 'issuerBaseURL');
    });

    And('it throws without an audience', () => {
      // @ts-ignore
      expect(() => requiresBearerAuth({ issuerBaseURL: ISSUER })).to.throw(TypeError, 'audience');
    });

    And('it throws on a malformed issuerBaseURL', () => {
      expect(() => requiresBearerAuth({ issuerBaseURL: 'not a url', audience: AUDIENCE })).to.throw(TypeError);
    });
  });
});
