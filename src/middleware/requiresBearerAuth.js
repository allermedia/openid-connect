import { jwtVerify } from 'jose';

import { Debug } from '../debug.js';
import { UnauthorizedError } from '../errors.js';
import { getRemoteJWKSet } from '../jwks.js';

const debug = Debug('requiresBearerAuth');

/**
 * Returns a middleware that authenticates requests carrying an OAuth2 bearer
 * access token (a JWT), for JSON APIs consumed outside the cookie session the
 * `auth()` router maintains — e.g. cross-origin AJAX callers or other services.
 *
 * The token is verified against the issuer's JWKS. The JWKS location is
 * resolved from OIDC discovery on first use and cached for the lifetime of the
 * middleware instance (a failed discovery is not cached — the next request
 * retries). The token must be signed by the issuer, addressed to `audience`,
 * and within its validity window.
 *
 * On success the verified token is exposed as
 * `req.bearerAuth = { payload, protectedHeader, token }` and the request
 * proceeds. The `requiresAuth` family (`requiresAuth`, `claimEquals`,
 * `claimIncludes`, `claimCheck`) recognizes `req.bearerAuth`, so claim checks
 * can be chained after this middleware to authorize on the token claims.
 * On failure the middleware calls `next()` with an `UnauthorizedError`
 * (`statusCode: 401`) whose `headers` carry an RFC 6750 `WWW-Authenticate`
 * challenge — pair it with a JSON error handler that applies `err.headers`
 * to the response.
 *
 * With `fallthrough: true` a request without a bearer token continues to the
 * next handler unauthenticated (`req.bearerAuth` unset) instead of failing, so
 * other auth methods can be chained after this one. A presented-but-invalid
 * token is still rejected.
 *
 * @param {import('types').BearerAuthParams} params
 * @returns {import('express').RequestHandler}
 */
export function requiresBearerAuth(params) {
  const { issuerBaseURL, audience, clockTolerance = 60, fallthrough = false } = params || {};
  if (!issuerBaseURL) throw new TypeError('"issuerBaseURL" is required');
  if (!audience) throw new TypeError('"audience" is required');

  // the base must end with a slash, or relative resolution drops its last path segment
  const discoveryUrl = new URL('.well-known/openid-configuration', issuerBaseURL.endsWith('/') ? issuerBaseURL : `${issuerBaseURL}/`);

  /** @type {ReturnType<typeof discoverIssuer> | undefined} */
  let verifier;

  return async function bearerAuthMiddleware(req, _res, next) {
    const match = /^Bearer +(\S+)$/i.exec(req.get('authorization') || '');
    if (!match) {
      if (fallthrough) {
        debug('no bearer token presented, falling through to the next handler');
        return next();
      }
      debug('no bearer token presented');
      return next(new UnauthorizedError('A bearer token is required for this route.', { 'WWW-Authenticate': 'Bearer' }));
    }
    const token = match[1];

    try {
      verifier = verifier || discoverIssuer(discoveryUrl);
      const { issuer, jwks } = await verifier.catch((err) => {
        verifier = undefined;
        throw err;
      });
      const { payload, protectedHeader } = await jwtVerify(token, jwks, { issuer, audience, clockTolerance });
      req.bearerAuth = { payload, protectedHeader, token };
    } catch (/** @type {any} */ err) {
      debug('bearer token rejected: %s', err.message);
      return next(new UnauthorizedError('Invalid bearer token.', { 'WWW-Authenticate': 'Bearer error="invalid_token"' }));
    }
    next();
  };
}

/**
 * Resolve the issuer identifier and JWKS from the OIDC discovery document. The
 * discovered `issuer` value (not the configured URL) is what tokens are
 * verified against, so trailing-slash differences never cause a mismatch.
 * @param {URL} discoveryUrl
 */
async function discoverIssuer(discoveryUrl) {
  const response = await fetch(discoveryUrl);
  if (!response.ok) {
    throw new Error(`Discovery request to ${discoveryUrl} failed with status ${response.status}`);
  }
  const metadata = /** @type {{issuer?: string, jwks_uri?: string}} */ (await response.json());
  if (!metadata.issuer || !metadata.jwks_uri) {
    throw new Error('No issuer or JWKS URI found in issuer metadata');
  }
  return { issuer: metadata.issuer, jwks: getRemoteJWKSet(metadata.jwks_uri) };
}
