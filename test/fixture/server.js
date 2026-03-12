import bodyParser from 'body-parser';
import express from 'express';
import { ClientError } from 'openid-client';

import { SESSION, SESSION_STORE } from '../../src/constants.js';
import Debug from '../../src/debug.js';
import { Session } from '../../src/session.js';

const debug = Debug('test');

/**
 * @param {import('express').Router} router
 * @param {import('express').RequestHandler} protect
 * @param {string} path
 */
export function createApp(router, protect, path) {
  const app = express();

  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(bodyParser.json());

  if (router) {
    app.use(router);
  }

  app.get('/session', (req, res) => {
    res.json(req[SESSION]?.getSessionData());
  });

  app.post('/session', async (req, res) => {
    Object.keys(req.appSession).forEach((prop) => {
      delete req.appSession[prop];
    });
    Object.assign(req.appSession, req.body);

    if (Number(req.get('content-length'))) {
      req[SESSION] = new Session(req.body, {});
    } else {
      req[SESSION] = undefined;
    }

    await req[SESSION_STORE].setSessionCookie();

    res.json();
  });

  app.get('/user', (req, res) => {
    res.json(req.oidc.user);
  });

  app.get('/tokens', (req, res) => {
    // Return token information without exposing internal structure
    const response = {
      isAuthenticated: req.oidc.isAuthenticated(),
      // Only expose behavior-relevant properties
      hasIdToken: !!req.oidc.idToken,
      hasAccessToken: !!req.oidc.accessToken,
      hasRefreshToken: !!req.oidc.refreshToken,
      idTokenClaims: req.oidc.idTokenClaims,
    };

    // Include token details for compatibility, but abstract the structure
    if (req.oidc.idToken) {
      response.idToken = req.oidc.idToken;
    }

    if (req.oidc.accessToken) {
      response.accessToken = req.oidc.accessToken;
      response.accessTokenExpired = req.oidc.accessToken.isExpired ? req.oidc.accessToken.isExpired() : false;
    }

    if (req.oidc.refreshToken) {
      response.refreshToken = req.oidc.refreshToken;
    }

    res.json(response);
  });

  app.use('/refresh', async (req, res) => {
    await req.oidc?.accessToken.refresh();
    return res.redirect(307, req.query.return_to ?? '/');
  });

  if (protect) {
    app.use('/protected', protect, (_req, res) => {
      res.json({});
    });
  }

  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    debug(err.message, { err });
    if (err.statusCode || err.cause?.status) {
      return res.status(err.statusCode || err.cause?.status).send({ err: { ...err, message: err.message } });
    }
    if (err instanceof ClientError) {
      return res.status(400).send({ err: { message: err.message, code: err.code } });
    }

    res.status(err.status || 500).json({
      err: {
        message: err.message,
        error: err.error,
        error_description: err.error_description,
        code: err.code,
      },
    });
  });

  let mainApp;
  if (path) {
    mainApp = express();
    mainApp.use(path, app);
  } else {
    mainApp = app;
  }

  return mainApp;
}

export function create(router, protect, path) {
  const app = createApp(router, protect, path);
  return new Promise((resolve) => {
    const server = app.listen(3000, () => resolve(server));
  });
}
