# Change Log

## v0.3.1 (2026-09-02)

### Additions

- `claimIncludesAny(claim, ...values, options?)` — the OR counterpart of `claimIncludes`: at least one of the values must be present in the claim. Same 403 behaviour, `err.reason` and `ignoreCase`/`trim` options

## v0.3.0 (2026-09-02)

### Breaking

- `claimEquals`, `claimIncludes` and `claimCheck` now separate authentication from authorization: an anonymous request is still redirected to login (or answered 401 with `errorOnRequiredAuth`), but an authenticated request that fails the claim check calls `next()` with a `ForbiddenError` (403) instead of triggering login — the old behaviour looped between the app and the identity provider for signed-in users lacking the claim, e.g. Entra users without an app role. Apps that mapped these failures to 401 should handle 403 as well

### Additions

- `ForbiddenError` (`statusCode: 403`) is exported. Its `reason` holds `{ claim, expected, actual }` for the built-in claim checks, with `actual: undefined` when the claim is missing, so a missing claim can be told apart from a wrong value
- a `claimCheck` predicate may return an `Error` (e.g. a `ForbiddenError` with a custom `reason`) to reject the request with that error
- `errorOnRequiredAuth` can be overridden per middleware: `requiresAuth({ errorOnRequiredAuth: true })`, `requiresAuth(check, options)`, `claimEquals(claim, value, options)`, `claimIncludes(claim, ...values, options)` and `claimCheck(fn, options)`
- `{ ignoreCase: true }` makes `claimEquals` and `claimIncludes` compare string values case insensitively, `{ trim: true }` strips surrounding whitespace and splits space separated claims on runs of whitespace; other types stay strict and `err.reason` reports the original values
- `UnauthorizedError` is exported

## v0.2.0 (2026-07-31)

### Additions

- `requiresBearerAuth({ issuerBaseURL, audience, clockTolerance?, fallthrough? })` middleware protects JSON API routes with an issuer/JWKS-verified OAuth2 bearer access token (JWT), independent of the `auth()` cookie session. Verified claims land on `req.bearerAuth`; failures raise `UnauthorizedError` (401) carrying an RFC 6750 `WWW-Authenticate` challenge in `err.headers`. `fallthrough: true` lets requests without a bearer token continue unauthenticated so other auth methods can be chained
- `requiresAuth`, `claimEquals`, `claimIncludes` and `claimCheck` recognize bearer-authenticated requests, so claim checks can be chained after `requiresBearerAuth` — bearer token claims take precedence over session id_token claims when both are present

## v0.1.0 (2026-07-30)

### Breaking
- require node >= 22
- drop CJS build, package is now ESM only
- upgrade [cookie](https://www.npmjs.com/package/cookie) to v2

### Additions
- callback based express-session compatible session stores, e.g. [memorystore](https://www.npmjs.com/package/memorystore), now work via `auth.Store`

### Fixes
- close test coverage gaps and remove dead code

## v0.0.4 (2026-03-17)

### Breaking
- default `clientAuthMethod` to `client_secret_basic` if client secret is configured

### Additions
- configured `baseURL` accepts the string `autodetect` that will build `baseURL` from `req.protocol` and `req.host`. Simplifies caching of OpenID Clients since they are cached with configuration object ref as key

## v0.0.3 (2026-03-16)

Refactor cookie handling that unfortunately breaks v0.0.1-2 created cookies. Latest [jose](https://www.npmjs.com/package/jose) uses nodejs builtin [Web Crypto API](https://nodejs.org/docs/latest-v22.x/api/webcrypto.html) ([mdn](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)).

### Breaking
- use [jose](https://www.npmjs.com/package/jose) all over to encrypt session cookie, it's async so heavy refactoring was needed
- use [jose](https://www.npmjs.com/package/jose) to sign and verify custom store cookies

### Fixes
- refactor appSession middleware

## ~~v0.0.2 (2026-03-10)~~

- provenance pedigree release

## ~~v0.0.1 (2026-03-10)~~

- intial commit
