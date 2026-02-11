import nock from 'nock';

import { jwks } from '../fixture/cert.js';

/**
 * Nock /.well-known/openid-configuration
 * @param {string} [issuer] issuer base url
 * @param {Record<string, any>} [override] override /.well-known/openid-configuration fields
 */
export function setupDiscovery(issuer = 'https://op.example.com/', override) {
  return nock(issuer)
    .get('/.well-known/openid-configuration')
    .reply(200, {
      issuer,
      authorization_endpoint: new URL('/authorize', issuer),
      token_endpoint: new URL('/oauth/token', issuer),
      userinfo_endpoint: new URL('/userinfo', issuer),
      jwks_uri: new URL('/.well-known/jwks.json', issuer),
      end_session_endpoint: new URL('/session/end', issuer),
      introspection_endpoint: new URL('/introspection', issuer),
      id_token_signing_alg_values_supported: ['RS256', 'HS256'],
      response_types_supported: ['code', 'id_token', 'code id_token'],
      response_modes_supported: ['query', 'fragment', 'form_post'],
      subject_types_supported: ['public'],
      scopes_supported: ['openid', 'profile', 'email'],
      ...override,
    });
}

/**
 * Nock /.well-known/jwks
 * @param {string} [issuer]
 */
export function setupJwks(issuer = 'https://op.example.com/') {
  return nock(issuer).get('/.well-known/jwks.json').optionally().reply(200, jwks);
}
