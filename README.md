# @aller/openid-connect

Express middleware for apps using OpenID connect.

[![Build](https://github.com/allermedia/openid-connect/actions/workflows/build.yaml/badge.svg)](https://github.com/allermedia/openid-connect/actions/workflows/build.yaml)

Inspired and borrowed from [express-openid-connect](https://www.npmjs.com/package/express-openid-connect).

## Usage

```javascript
import express from 'express';

import { auth, requiresAuth } from '@aller/openid-connect';

const app = express();

app.use(
  auth({
    baseURL: 'autodetect',
    secret: 'supers3cret',
    clientID: 'insecure-client-id',
    issuerBaseURL: 'https://op.example.com',
    authorizationParams: {
      scope: 'openid email offline_access profile',
      response_type: 'code',
    },
    discoveryCacheMaxAge: 24 * 3600 * 1000,
    attemptSilentLogin: false,
    authRequired: false,
  })
);

app.get('/protected', requiresAuth, (req, res) => {
  res.send('plus content');
});
```

## Protecting APIs with bearer tokens

`requiresBearerAuth` guards JSON API routes with an OAuth2 bearer access token (JWT), independent of the cookie session `auth()` maintains — for cross-origin AJAX callers or other services. Tokens are verified against the issuer's JWKS (resolved via OIDC discovery on first use and cached) and must match the configured audience. The verified token is exposed as `req.bearerAuth = { payload, protectedHeader, token }`; failures call `next()` with an `UnauthorizedError` (`statusCode: 401`) whose `headers` carry an RFC 6750 `WWW-Authenticate` challenge, so pair it with a JSON error handler that applies `err.headers`. With `fallthrough: true` a request without a bearer token continues to the next handler unauthenticated (`req.bearerAuth` unset) instead of failing, so other auth methods can be chained after this one — a presented-but-invalid token is still rejected.

The `requiresAuth` family (`requiresAuth`, `claimEquals`, `claimIncludes`, `claimCheck`) recognizes a bearer-authenticated request, so claim checks can be chained after `requiresBearerAuth` — they then operate on the verified token claims, which take precedence over a session identity when both are present.

```javascript
import express from 'express';

import { claimEquals, requiresBearerAuth } from '@aller/openid-connect';

const api = express();

api.get('/api/things', requiresBearerAuth({ issuerBaseURL: 'https://op.example.com', audience: 'api://my-api' }), (req, res) => {
  res.json({ sub: req.bearerAuth.payload.sub });
});

api.get(
  '/api/admin/things',
  requiresBearerAuth({ issuerBaseURL: 'https://op.example.com', audience: 'api://my-api' }),
  claimEquals('role', 'admin'),
  (req, res) => {
    res.json({ role: req.bearerAuth.payload.role });
  }
);

api.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  res
    .set(err.headers)
    .status(err.statusCode || 500)
    .json({ message: err.message });
});
```

## Differences from `express-openid-connect`

Compared against `express-openid-connect` v3, which is built on the same `openid-client` v6 / `jose` v6 stack:

- ESM only (upstream is CommonJS). Express 5 compatible, Node ≥ 22.
- `baseURL: 'autodetect'` resolves from the request at runtime — no need to hard-code the public URL or set a `BASE_URL` env var.
- `session.store` accepts promise based stores in addition to callback based express-session compatible stores (instantiated with `auth`, e.g. `memorystore(auth)`).
- `requiresBearerAuth` protects JSON APIs with issuer/JWKS-verified bearer access tokens (the [express-oauth2-jwt-bearer](https://www.npmjs.com/package/express-oauth2-jwt-bearer) use case) without a second package — and the `requiresAuth` family recognizes bearer-authenticated requests, so cookie and bearer auth compose on the same routes.
- No Auth0-specific defaults, env vars, or helpers — generic OIDC only.
