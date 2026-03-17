# Change Log

## v0.0.4 (2026-03-17)

### Breaking
- default `clientAuthMethod` to `client_secret_basic` if client secret is configured

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
