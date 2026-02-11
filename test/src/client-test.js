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
});
