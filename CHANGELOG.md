# Change Log

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
