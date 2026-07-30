import fs from 'node:fs/promises';

import { getClient } from '../../src/client.js';
import { setupDiscovery } from '../helpers/openid-helper.js';

describe('client', () => {
  it('defaults to JWT private_key_jwt if signing key is configured', async () => {
    setupDiscovery();
    return getClient({
      issuerBaseURL: 'https://op.example.com',
      clientID: 'test-client',
      authorizationParams: { response_type: 'code' },
      clientAssertionSigningKey: await fs.readFile('./test/fixture/private-key.pem'),
    });
  });

  it('defaults to client_secret_post if client secret is configured', () => {
    setupDiscovery();
    return getClient({
      issuerBaseURL: 'https://op.example.com',
      clientID: 'test-client',
      clientSecret: 'test-client-secret',
      authorizationParams: { response_type: 'code' },
    });
  });

  it('defaults to none if neither client secret nor signing key is configured', () => {
    setupDiscovery();
    return getClient({
      issuerBaseURL: 'https://op.example.com',
      clientID: 'test-client',
      authorizationParams: { response_type: 'code' },
    });
  });

  it('tolerates issuer not supporting the configured response type and mode', () => {
    setupDiscovery('https://op.example.com/', {
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
    });
    return getClient({
      issuerBaseURL: 'https://op.example.com',
      clientID: 'test-client',
      clientSecret: 'test-client-secret',
      authorizationParams: { response_type: 'code id_token', response_mode: 'form_post' },
    });
  });

  it('tolerates issuer metadata without response type and mode lists', () => {
    setupDiscovery('https://op.example.com/', {
      response_types_supported: null,
      response_modes_supported: null,
    });
    return getClient({
      issuerBaseURL: 'https://op.example.com',
      clientID: 'test-client',
      clientSecret: 'test-client-secret',
      authorizationParams: { response_type: 'code', response_mode: 'form_post' },
    });
  });
});
