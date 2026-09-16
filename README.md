# @aller/openid-connect

Express middleware for apps using OpenID connect.

[![Build](https://github.com/allermedia/openid-connect/actions/workflows/build.yaml/badge.svg)](https://github.com/allermedia/openid-connect/actions/workflows/build.yaml)
[![Build Windows](https://github.com/allermedia/openid-connect/actions/workflows/build-windows.yaml/badge.svg)](https://github.com/allermedia/openid-connect/actions/workflows/build-windows.yaml)

Inspired and borrowed from [express-openid-connect](https://www.npmjs.com/package/express-openid-connect).

<!-- toc -->

- [Usage](#usage)
- [Default routes](#default-routes)
- [API](#api)
  - [`auth(params)`](#authparams)
  - [`requiresAuth([requiresLoginCheck], [options])`](#requiresauthrequireslogincheck-options)
  - [`claimEquals(claim, value, [options])`](#claimequalsclaim-value-options)
  - [`claimIncludes(claim, ...values, [options])`](#claimincludesclaim-values-options)
  - [`claimIncludesAny(claim, ...values, [options])`](#claimincludesanyclaim-values-options)
  - [`claimCheck(fn, [options])`](#claimcheckfn-options)
  - [`requiresBearerAuth(params)`](#requiresbearerauthparams)
  - [`attemptSilentLogin()`](#attemptsilentlogin)
  - [`UnauthorizedError`](#unauthorizederror)
  - [`ForbiddenError`](#forbiddenerror)
  - [`Store`](#store)
- [Protecting APIs with bearer tokens](#protecting-apis-with-bearer-tokens)
- [Authorization with claim checks](#authorization-with-claim-checks)
- [Differences from `express-openid-connect`](#differences-from-express-openid-connect)

<!-- /toc -->

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

## Default routes

`auth()` mounts these routes, relative to wherever the router is applied. Override the paths with `routes`, or set `login`, `logout` or `callback` to `false` to skip mounting that route.

| `routes` option      | Default               | Method    | Behaviour                                                                              |
| -------------------- | --------------------- | --------- | -------------------------------------------------------------------------------------- |
| `login`              | `/login`              | GET       | Redirects to the issuer, returns to `/` after login                                    |
| `logout`             | `/logout`             | GET       | Clears the session and redirects to the issuer end-session endpoint                    |
| `callback`           | `/callback`           | GET, POST | Completes the login. POST serves `response_mode: 'form_post'`                          |
| `backchannelLogout`  | `/backchannel-logout` | POST      | Receives issuer logout tokens. Only mounted when `backchannelLogout` is configured     |
| `postLogoutRedirect` | `''`                  |           | Not a route. The `post_logout_redirect_uri` sent on logout unless `returnTo` is passed |

```javascript
import express from 'express';

import { auth } from '@aller/openid-connect';

const app = express();

app.use(
  auth({
    baseURL: 'https://app.example.com',
    secret: 'supers3cret',
    clientID: 'insecure-client-id',
    issuerBaseURL: 'https://op.example.com',
    routes: {
      login: '/auth/login',
      logout: '/auth/logout',
      callback: '/auth/callback',
      postLogoutRedirect: '/bye',
    },
  })
);
```

## API

All named exports of `@aller/openid-connect`.

### `auth(params)`

Returns an `express.Router` that loads the session, attaches `req.oidc` and `res.oidc`, mounts the [default routes](#default-routes) and, unless `authRequired` is `false`, protects every route mounted after it.

All options are validated with a schema when `auth()` is called; an invalid or missing option throws a `TypeError` at startup. Defaults are the effective values from that schema. The list mirrors the shape of `params`.

- `secret` **required**: string, `Buffer`, or array of either, at least 8 bytes. Derives the session cookie encryption key and signs transient cookies. With an array the first entry signs and encrypts, all entries verify and decrypt, which allows key rotation
- `baseURL` **required**: public root URL of the app, e.g. `https://app.example.com/some/path`. When mounted under a path, mount `auth()` under the same path. `'autodetect'` builds it per request from `req.protocol` and `req.host`, so enable `trust proxy` behind a proxy
- `clientID` **required**: the OIDC client id
- `issuerBaseURL` **required**: issuer URL without trailing slash. Discovery is fetched from `<issuerBaseURL>/.well-known/openid-configuration`
- `clientSecret`: required for the `client_secret_*` auth methods and for `HS*` id token algorithms
- `clientAuthMethod`: `private_key_jwt` when `clientAssertionSigningKey` is set, else `client_secret_basic` when `clientSecret` is set, else `none`. Also accepts `client_secret_post` and `client_secret_jwt`. `none` is not allowed with pushed authorization requests
- `clientAssertionSigningKey`: private key for `private_key_jwt`: PEM string or `Buffer`, JWK object, `KeyObject`, or `CryptoKey`
- `clientAssertionSigningAlg`: algorithm for the client assertion JWT, sent as `token_endpoint_auth_signing_alg`. Defaults to `RS256` when `clientAssertionSigningKey` is a PEM string or `Buffer`, otherwise `openid-client` derives it from the key, or uses `HS256` for `client_secret_jwt`
- `idTokenSigningAlg`: expected id token algorithm, default `RS256`. `none` is rejected
- `clockTolerance`: clock skew tolerance in seconds for token verification, default `60`
- `pushedAuthorizationRequests`: send a pushed authorization request to the issuer before redirecting the user, default `false`
- `authRequired`: apply `requiresAuth()` to every route after `auth()`, default `true`. Set to `false` and protect routes individually
- `errorOnRequiredAuth`: answer an anonymous request with a 401 `UnauthorizedError` instead of redirecting to login, default `false`. Can be overridden per `requiresAuth` middleware
- `attemptSilentLogin`: try a `prompt=none` login on the first unauthenticated HTML request, default `false`
- `authorizationParams`: parameters for the authorization request, default `{ response_type: 'code', scope: 'openid profile email' }`. Extra keys such as `audience` or `acr_values` pass through
  - `response_type`: `code` or `code id_token`
  - `scope`: must contain `openid`
  - `response_mode`: `query` or `form_post`, forced to `form_post` for `code id_token`
- `tokenEndpointParams`: extra body parameters for the token endpoint on code exchange and refresh
- `logoutParams`: extra query parameters for the issuer end-session endpoint
- `idpLogout`: also log the user out at the issuer on `/logout`, default `false`
- `identityClaimFilter`: claims stripped from the id token before it is exposed as `req.oidc.user`, default `['aud', 'iss', 'iat', 'exp', 'nbf', 'nonce', 'azp', 'auth_time', 's_hash', 'at_hash', 'c_hash']`
- `legacySameSiteCookie`: set a fallback transaction cookie without `SameSite` when `response_mode` is `form_post`, for browsers that reject `SameSite=None`, default `true`
- `routes`: paths relative to where the router is mounted, see [Default routes](#default-routes)
  - `login`: default `/login`, `false` skips mounting it
  - `logout`: default `/logout`, `false` skips mounting it
  - `callback`: default `/callback`, `false` skips mounting it
  - `backchannelLogout`: default `/backchannel-logout`, only mounted when `backchannelLogout` is configured
  - `postLogoutRedirect`: the `post_logout_redirect_uri` sent on logout unless `returnTo` is passed, default `''`
- `getLoginState`: `(req, options) => object` hook returning the state object encoded into the `state` parameter. The default returns `{ returnTo }`. May be async
- `afterCallback`: `(req, res, session, decodedState) => session` hook run after the id token is validated and before the redirect. Return the session object to store, so token storage, userinfo calls or extra claim validation can happen here. May be async
- `session`: the session is stored in an encrypted cookie unless `store` is set
  - `name`: cookie name, also the property on `req` that exposes the session data, default `appSession`. Letters, digits, `_`, `.` and `-` only
  - `rolling`: extend the session on every request, default `true`. `false` gives an absolute session that ends a fixed time after login
  - `rollingDuration`: idle time in seconds before the user is logged out, default `86400` (1 day). Must be `false` when `rolling` is `false`
  - `absoluteDuration`: seconds after login when the user is logged out regardless of activity, default `604800` (7 days). `false` disables it, but only when `rolling` is `true`
  - `store`: custom session store with `get`, `set` and `destroy`. Callback based express-session stores and promise based stores both work. The cookie then only holds the session id
  - `genid`: `(req) => string` generating the session id for a custom store, default 16 random bytes as hex. Use a cryptographically strong value or enable `signSessionStoreCookie`
  - `signSessionStoreCookie`: HMAC sign the session id cookie used with a custom store, default `false`
  - `requireSignedSessionStoreCookie`: reject unsigned session id cookies, defaults to `signSessionStoreCookie`. Set to `false` temporarily when turning on signing, so existing sessions can roll over
  - `cookie`: attributes passed to `res.cookie()`
    - `domain`: cookie domain
    - `path`: cookie path, relative
    - `transient`: omit the cookie expiry so the browser drops it when closed, default `false`
    - `httpOnly`: hide the cookie from client side scripts, default `true`
    - `sameSite`: `lax`, `strict` or `none`, default `Lax`. With `none` you need your own CSRF protection
    - `secure`: default `true` for an `https` `baseURL`. Must be `false` for an `http` `baseURL`, since secure cookies are not sent over plain http. Setting it to `false` over https logs a warning
- `transactionCookie`: the short lived cookie that carries `state`, `nonce` and the PKCE verifier between the login redirect and the callback
  - `name`: cookie name, default `auth_verification`
  - `sameSite`: `Lax`, `Strict` or `None`, defaults to `session.cookie.sameSite`. `response_mode: 'form_post'` forces `None` on this cookie
- `backchannelLogout`: default `false`. `true` enables the `POST /backchannel-logout` route with the default hooks, an object configures them. Enabling it requires a `backchannelLogout.store`, or a `session.store` to reuse, or custom `isLoggedOut` and `onLogoutToken` hooks
  - `store`: store for logout entries with `get`, `set` and `destroy`. Falls back to `session.store`
  - `onLogoutToken`: `(decodedToken, config) => void`. Default stores an entry per `sid` and per `sub` from the logout token
  - `isLoggedOut`: `(req, config) => boolean`, checked on every authenticated request. Default looks up the session's `sid` and `sub` in the store. `false` disables the check
  - `onLogin`: `(req, config) => void`. Default removes stale logout entries for the `sub` on successful login. `false` disables it
  - `isInsecure`: skip logout token signature verification. Tests only
- `discoveryCacheMaxAge`: milliseconds to cache the issuer discovery document, default `600000` (10 min)
- `httpTimeout`: timeout in milliseconds for requests to the issuer, default `5000`, at least `500`
- `httpUserAgent`: `User-Agent` header for requests to the issuer
- `allowInsecureRequests`: allow an `http` issuer, for local development, default `false`
- `customFetch`: custom `fetch` implementation handed to `openid-client`, e.g. for a proxy or for testing, default `globalThis.fetch`

### `requiresAuth([requiresLoginCheck], [options])`

Returns a middleware that triggers a login redirect for anonymous HTML requests, or calls `next()` with a 401 `UnauthorizedError` when the request does not accept HTML or `errorOnRequiredAuth` is set. Mounted automatically by `auth()` when `authRequired` is `true`. The optional `requiresLoginCheck`, `(req) => boolean`, returns `true` when the request must log in; the default is `!req.oidc.isAuthenticated()`, satisfied by a bearer authenticated request as well.

- `errorOnRequiredAuth`: answer anonymous requests with 401 instead of a login redirect, defaults to the `auth()` option

### `claimEquals(claim, value, [options])`

Returns a middleware that requires authentication as `requiresAuth` does, then requires the id token claim to strictly equal `value`, a string, number, boolean or `null`. A failing check calls `next()` with a 403 `ForbiddenError`, see [Authorization with claim checks](#authorization-with-claim-checks).

- `errorOnRequiredAuth`: answer anonymous requests with 401 instead of a login redirect, defaults to the `auth()` option
- `ignoreCase`: compare string claim values case insensitively, default `false`
- `trim`: trim string values and split space separated claims on whitespace, default `false`

### `claimIncludes(claim, ...values, [options])`

As `claimEquals`, but every listed value must be present in the claim, which may be an array or a space separated string. Takes the same options as `claimEquals`.

### `claimIncludesAny(claim, ...values, [options])`

As `claimIncludes`, but at least one listed value must be present. Takes the same options as `claimEquals`.

### `claimCheck(fn, [options])`

As `claimEquals`, but with a custom predicate `(req, claims) => unknown`, only called for authenticated requests. Return a truthy value to allow the request, a falsy value to reject it with a generic `ForbiddenError`, or an `Error` to reject it with that error. Takes the `errorOnRequiredAuth` option only.

### `requiresBearerAuth(params)`

Returns a middleware that verifies an OAuth2 bearer access token against the issuer JWKS and exposes it as `req.bearerAuth`, see [Protecting APIs with bearer tokens](#protecting-apis-with-bearer-tokens).

- `issuerBaseURL` **required**: issuer that signs the access tokens; JWKS is resolved through discovery
- `audience` **required**: expected `aud` claim, a string or an array where any match is accepted
- `clockTolerance`: clock skew tolerance in seconds, default `60`
- `fallthrough`: let requests without a bearer token continue unauthenticated, default `false`. Invalid tokens are still rejected

### `attemptSilentLogin()`

Returns a middleware that runs `res.oidc.silentLogin()` for unauthenticated requests, i.e. the same behaviour the `attemptSilentLogin` option of `auth()` mounts at the end of the router, for use on individual routes when the global option is off. Takes no options.

### `UnauthorizedError`

Error with `statusCode: 401` passed to `next()` when authentication is required and missing. `headers` holds response headers the error handler should apply, e.g. the `WWW-Authenticate` challenge set by `requiresBearerAuth`.

### `ForbiddenError`

Error with `statusCode: 403` passed to `next()` when an authenticated request fails a claim check. `reason` describes what failed, `{ claim, expected, actual }` for the built in checks. Construct it yourself in a `claimCheck` predicate to reject with a custom reason.

### `Store`

Base class for express-session compatible, callback based, session stores. Store factories that expect the express-session module can be instantiated with `auth`, which exposes this class as `auth.Store`, e.g. `memorystore(auth)`. Stores extending `Store` are promisified internally; other stores are assumed to be promise based.

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

## Authorization with claim checks

`claimEquals`, `claimIncludes` and `claimCheck` separate authentication from authorization. An anonymous request is handled as by `requiresAuth` — a login redirect, or a 401 `UnauthorizedError` with `errorOnRequiredAuth`. An authenticated request that fails the claim check calls `next()` with a `ForbiddenError` (`statusCode: 403`) — never a login redirect, since the identity provider would just send the user straight back with the same claims. `err.reason` carries what failed as `{ claim, expected, actual }`, where `actual` is `undefined` when the claim is missing altogether, so a "no role assigned" page can be told apart from a "wrong role" one.

`claimIncludes(claim, ...values)` has AND semantics: every listed value must be present in the claim, which may be an array or a space separated string. `claimIncludesAny(claim, ...values)` is the OR variant: at least one listed value must be present. Anything more involved goes in a `claimCheck` predicate.

Claim values are matched exactly, including case, since scopes and roles are opaque strings to the identity provider. For claims where case does not matter, e.g. email addresses, pass `{ ignoreCase: true }` to `claimEquals`, `claimIncludes` or `claimIncludesAny` — string values are then compared case insensitively. `{ trim: true }` strips surrounding whitespace from string values and splits a space separated claim on runs of whitespace. Both flags leave numbers, booleans and null strict, and `err.reason` still reports the original values.

A `claimCheck` predicate is only called for authenticated requests. It returns a truthy value to allow the request, a falsy value to reject it with a generic `ForbiddenError`, or an `Error` — e.g. a `ForbiddenError` with a custom `reason` — to reject it with that error.

`errorOnRequiredAuth` can also be set per middleware, so a single route can answer 401 instead of redirecting without flipping the global option for `requiresAuth`.

```javascript
import express from 'express';

import { auth, requiresAuth, claimIncludes, claimIncludesAny, claimCheck, ForbiddenError } from '@aller/openid-connect';

const app = express();

app.use(
  auth({
    baseURL: 'autodetect',
    secret: 'supers3cret',
    clientID: 'insecure-client-id',
    issuerBaseURL: 'https://op.example.com',
    authRequired: false,
  })
);

app.use(requiresAuth()); // anonymous → login redirect

app.get('/admin', claimIncludes('roles', 'Admin'), (req, res) => {
  res.send('admin content'); // signed in without the role → 403
});

app.get('/audit', claimIncludes('roles', 'Admin', 'Auditor'), (req, res) => {
  res.send('audit content'); // AND: both roles are required
});

app.get('/billing', claimIncludesAny('roles', 'Admin', 'Finance'), (req, res) => {
  res.send('billing content'); // OR: either role is enough
});

app.get(
  '/support',
  claimCheck((req, claims) => {
    if (Array.isArray(claims.roles) && claims.roles.includes('Support')) return true;
    return new ForbiddenError('Support role required', { claim: 'roles', expected: ['Support'], actual: claims.roles });
  }),
  (req, res) => {
    res.send('support content');
  }
);

app.get('/staff', claimIncludes('email', 'jane@example.org', { ignoreCase: true, trim: true }), (req, res) => {
  res.send('staff content'); // " Jane@Example.org " is fine too
});

app.get('/api/me', requiresAuth({ errorOnRequiredAuth: true }), (req, res) => {
  res.json(req.oidc.user); // anonymous → 401 instead of a redirect
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err.statusCode === 403) return res.status(403).send(`Forbidden: ${err.message} ${JSON.stringify(err.reason)}`);
  res.status(err.statusCode || 500).send(err.message);
});
```

## Differences from `express-openid-connect`

Compared against `express-openid-connect` v3, which is built on the same `openid-client` v6 / `jose` v6 stack:

- ESM only (upstream is CommonJS). Express 5 compatible, Node ≥ 22.
- `baseURL: 'autodetect'` resolves from the request at runtime — no need to hard-code the public URL or set a `BASE_URL` env var.
- `session.store` accepts promise based stores in addition to callback based express-session compatible stores (instantiated with `auth`, e.g. `memorystore(auth)`).
- `requiresBearerAuth` protects JSON APIs with issuer/JWKS-verified bearer access tokens (the [express-oauth2-jwt-bearer](https://www.npmjs.com/package/express-oauth2-jwt-bearer) use case) without a second package — and the `requiresAuth` family recognizes bearer-authenticated requests, so cookie and bearer auth compose on the same routes.
- No Auth0-specific defaults, env vars, or helpers — generic OIDC only.
