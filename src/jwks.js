import { createRemoteJWKSet } from 'jose';

const cache = new Map();

/**
 * Get a remote JWKS resolver for a JWKS URI, shared across callers. jose's
 * remote JWK set caches fetched keys internally and only refetches when it
 * encounters an unknown `kid` (subject to a cooldown), so reusing one instance
 * per URI avoids refetching the JWKS on every verification.
 * @param {string | URL} jwksUri
 * @returns {ReturnType<typeof createRemoteJWKSet>}
 */
export function getRemoteJWKSet(jwksUri) {
  const key = jwksUri.toString();
  let jwks = cache.get(key);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(jwksUri));
    cache.set(key, jwks);
  }
  return jwks;
}
