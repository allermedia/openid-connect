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

## Differences from `express-openid-connect`

- Dual ESM/CJS, built on `openid-client` v6 and `jose` v6 (peer dep). Express 5 compatible, Node ≥ 20.
- `baseURL: 'autodetect'` resolves from the request at runtime — no need to hard-code the public URL.
- `clientAuthMethod` defaults from what you provide: `private_key_jwt` if `clientAssertionSigningKey`, else `client_secret_basic` if `clientSecret`, else `none`.
- `customFetch` hook plumbed through discovery and token/refresh/userinfo calls.
- Configurable transient cookie via `transactionCookie` (name, `sameSite`).
- Stateful session store via `session.store` with optional HMAC-signed id cookie (`signSessionStoreCookie` / `requireSignedSessionStoreCookie`).
- Backchannel logout (`POST /backchannel-logout`) is first-class, with a `backchannelLogout.store` or custom `isLoggedOut` / `onLogoutToken` hooks.
- No Auth0-specific defaults, env vars, or helpers — generic OIDC only.
