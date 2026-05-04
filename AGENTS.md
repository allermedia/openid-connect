# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`@aller/openid-connect` — Express middleware providing OpenID Connect auth. Inspired by `express-openid-connect`, rebuilt on top of the current `openid-client` (v6) and `jose` (v6). Published as dual ESM (`src/index.js`) / CJS (`lib/index.cjs` via Rollup) with generated `.d.ts` from JSDoc.

Node >= 20 required (`.nvmrc` pins 22). Type: `module`.

## Commands

- `npm test` — Mocha test suite (extension `js`, recursive, BDD Gherkin-style via `mocha-cakes-2`). Posttest runs `lint` + `build`.
- **Always lint after running tests.** `npm test` already chains `posttest` → `npm run lint && npm run build`, so it's covered. If you run Mocha directly (e.g. `npx mocha test/foo.tests.js`), follow up with `npm run lint` before declaring a task done.
- `npm run lint` — ESLint (`eslint . --cache`) + Prettier check + `texample` (executes README fenced code blocks).
- `npm run build` — Rollup CJS bundle, then `dts-buddy` to emit `types/index.d.ts` from JSDoc in `src/`.
- `npm run cov:html` / `npm run test:lcov` — Coverage via `c8` over `src`.
- Single test file: `npx mocha test/login.tests.js`. Grep by scenario: `npx mocha --grep "default configuration"`.
- Scenario globals (`Feature`, `Scenario`, `Given`, `When`, `Then`, `And`, `But`, `expect`) are provided by `mocha-cakes-2` + `chai/register-expect.js` — see `.mocharc.json` and `eslint.config.js`.
- `test/helpers/setup.js` calls `nock.disableNetConnect()` with localhost allowed — all issuer/discovery HTTP must be mocked via `nock` (see `test/helpers/openid-helper.js`).

## Architecture

Entry point `src/index.js` exports three things: `auth` (the middleware router factory), `attemptSilentLogin`, and the `requiresAuth` family (`requiresAuth`, `claimEquals`, `claimIncludes`, `claimCheck`).

`auth(params)` returns an `express.Router` that, in order, mounts: `appSession` (session load/save) → a middleware attaching `req.oidc: RequestContext` and `res.oidc: ResponseContext` → the configured `routes.login`/`logout`/`callback`/`backchannelLogout` handlers → optionally `requiresAuth()` (when `authRequired`, default `true`) → optionally `attemptSilentLogin()`. Handler bodies live on `ResponseContext` (`src/context.js`) — the routes are one-liners delegating to `res.oidc.login()` etc.

### Config (`src/config.js`)

Joi schema validates every option and fills defaults. Returning the validated config object is what the rest of the code holds onto — it is also used as the **cache key** for the OpenID client (`getClient` in `src/client.js` keys its `Map` cache by config reference), so mutating or recreating the config invalidates discovery. `baseURL: 'autodetect'` defers to `req.protocol + req.host` at request time (see `ResponseContext#baseURL`). `clientAuthMethod` defaults: `private_key_jwt` if `clientAssertionSigningKey` is set, else `client_secret_basic` if `clientSecret` is set, else `none`.

### Session lifecycle (`src/session.js`, `src/cookie-store.js`, `src/middleware/appSession.js`)

Session data lives under `Symbol('session')` on the request (`SESSION` in `constants.js`); `req[config.session.name]` (default `appSession`) is a getter-only alias returning `.getSessionData()`. Assigning `null`/`undefined` clears it; any other assignment throws. Three `Session` subclasses:

- `Session` — base, in-memory
- `StoredSession` — reconstructed from persisted data; re-decodes claims from `id_token`
- `TokenSetSession` — built from a fresh `openid-client` token set after callback

Two cookie stores in `cookie-store.js`:

- `DefaultCookieStore` — encrypts the full session payload into the `appSession` cookie using `jose` (key store derived from `config.secret`). Large payloads are chunked across `appSession.0`, `appSession.1`, … up to `MAX_COOKIE_SIZE = 4096` bytes per cookie.
- `CustomCookieStore` — activated when `config.session.store` is supplied. Cookie holds only the session id (optionally HMAC-signed when `signSessionStoreCookie: true`); data is read/written via the user store. Uses `res.end` override + `onHeaders` to persist on response end, and `REGENERATED_SESSION_ID` on identity change.

`replaceSession()` behavior differs between the two stores — default replaces in place, custom store also regenerates the id. Callback flow in `ResponseContext#callback` handles three cases: new sub ≠ current sub (replace), current session had no sub yet (merge via `session.update()`), or first-time (assign).

### Backchannel logout (`src/hooks/backchannelLogout/*`, `ResponseContext#backchannelLogout`)

Enabled when `config.backchannelLogout` is truthy. Adds `POST /backchannel-logout` which verifies the `logout_token` JWT against the issuer JWKS (via `jose.createRemoteJWKSet` + `jwtVerify`), checking `typ === 'logout+jwt'`, the backchannel-logout event claim, and presence of `sid` or `sub`. `onLogoutToken` is the default hook (overridable) that marks the session as logged out in the configured `backchannelLogout.store`; `isLoggedOut` is invoked on every authenticated request to consult that store. `isInsecure: true` skips signature verification — only for tests.

Config requires one of: `backchannelLogout.store`, reuse of `session.store`, or custom `isLoggedOut`+`onLogoutToken` hooks (enforced in the Joi schema).

### Transient cookies (`src/transientHandler.js`)

`auth_verification` cookie (configurable via `transactionCookie.name`) carries `nonce`, encoded `state`, optional `max_age`, and PKCE `code_verifier` across the authorize→callback round trip. `response_mode: 'form_post'` forces `SameSite=None` on that cookie.

### Types

JSDoc in `src/` drives types. `types/types.d.ts` declares `Express.Request#oidc` / `Express.Response#oidc` globally and exposes config/option interfaces. `tsconfig.json` has `checkJs: true` + `strict` (but `strictNullChecks: false`). `dts-buddy` bundles the emitted declarations into `types/index.d.ts` during `build`.

## Testing conventions

- Feature files live in `test/feature/`, unit-ish tests at `test/*.tests.js`. Both styles use Gherkin blocks from `mocha-cakes-2`.
- Use `nock` for issuer discovery and token endpoints — see `test/helpers/openid-helper.js` (`setupDiscovery`) and `test/fixture/` for shared certs, JWKS, and app builders.
- `node:test`'s `mock.timers` is used to freeze `Date` inside scenarios that assert cookie expiry or token timing.
- Fenced code blocks in `README.md` are executed by `texample` during lint — keep them runnable.

## Code style

ESLint config in `eslint.config.js` is strict: `no-console: error`, `eqeqeq`, `prefer-const`, `require-await`, mandatory semicolons, alphabetized `import/order` with `newlines-between: 'always'`. Prettier enforces formatting; `.prettierrc` sets the repo style. `lib/` is generated — never edit by hand.
