import { auth, attemptSilentLogin } from '@aller/openid-connect';
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

describe('attemptSilentLogin', () => {
  before(() => {
    setupDiscovery().persist();
  });
  after(nock.cleanAll);

  it("should attempt silent login on user's first route", async () => {
    const server = createApp(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      attemptSilentLogin()
    );
    const agent = request.agent(server);

    const response = await agent.get('/protected');
    expect(response.statusCode, response.text).to.equal(302);

    const uri = new URL(response.headers.location);

    expect(uri.searchParams.get('prompt'), 'prompt').to.equal('none');

    expect(agent.jar.getCookies({ domain: '127.0.0.1', path: '/' })[0]).to.deep.include({
      name: 'skipSilentLogin',
      value: 'true',
      noscript: true,
    });
  });

  it('should not attempt silent login for non html requests', async () => {
    const server = createApp(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      attemptSilentLogin()
    );
    const agent = request.agent(server);
    const response = await agent.get('/protected').set('accept', 'application/json');

    expect(response.statusCode, response.text).to.equal(200);
  });

  it("should not attempt silent login on user's subsequent routes", async () => {
    const server = createApp(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      attemptSilentLogin()
    );
    const agent = request.agent(server);

    const response = await agent.get('/protected');
    expect(response.statusCode, response.text).to.equal(302);
    const response2 = await agent.get('/protected');
    expect(response2.statusCode, response2.text).to.equal(200);
    const response3 = await agent.get('/protected');
    expect(response3.statusCode, response3.text).to.equal(200);
  });

  it('should not attempt silent login for authenticated user', async () => {
    const server = createApp(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      attemptSilentLogin()
    );

    const agent = request.agent(server);
    await login(agent);
    const response = await agent.get('/protected');
    expect(response.statusCode, response.text).to.equal(200);
  });

  it('should not attempt silent login after first anonymous request after logout', async () => {
    const server = createApp(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      attemptSilentLogin()
    );
    const agent = request.agent(server);
    await login(agent);
    await agent.get('/protected');
    await agent.get('/logout');
    const response = await agent.get('/protected');
    expect(response.statusCode, response.text).to.equal(200);
  });

  it('should not attempt silent login after first request is to logout', async () => {
    const server = createApp(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      attemptSilentLogin()
    );
    const agent = request.agent(server);
    await login(agent);
    await agent.get('/logout');
    const response = await agent.get('/protected');
    expect(response.statusCode, response.text).to.equal(200);
  });

  it("should throw when there's no auth middleware", async () => {
    const server = createApp(attemptSilentLogin());
    const {
      body: { err },
    } = await request(server).get('/protected').set('accept', 'application/json');

    expect(err.message).to.equal('req.oidc is not found, did you include the auth middleware?');
  });
});
