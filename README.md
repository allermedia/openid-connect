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
