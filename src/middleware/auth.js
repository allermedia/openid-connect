import express from 'express';

import { getConfig } from '../config.js';
import { SESSION } from '../constants.js';
import { RequestContext, ResponseContext } from '../context.js';
import Debug from '../debug.js';
import isLoggedOut from '../hooks/backchannelLogout/isLoggedOut.js';
import { TransientCookieHandler } from '../transientHandler.js';

import appSession, { replaceSession } from './appSession.js';
import attemptSilentLogin from './attemptSilentLogin.js';
import { requiresAuth } from './requiresAuth.js';

const debug = Debug('');

/**
 * Returns a router with two routes /login and /callback
 *
 * @param {Partial<import('types').ConfigParams>} [params] The parameters object; see index.d.ts for types and descriptions.
 *
 * @returns {express.Router} the router
 */
export default function auth(params) {
  const config = getConfig(params);
  debug('configuration object processed, resulting configuration: %O', config);
  const router = express.Router();
  const transient = new TransientCookieHandler(config);

  router.use(appSession(config));

  // Express context and OpenID Issuer discovery.
  router.use((req, res, next) => {
    req.oidc = new RequestContext(config, req, res);
    res.oidc = new ResponseContext(config, req, res, next, transient);
    next();
  });

  // Login route, configurable with routes.login
  if (config.routes.login) {
    const path = enforceLeadingSlash(config.routes.login);
    debug(`adding GET ${path} route`);
    router.get(path, express.urlencoded({ extended: false }), (_req, res) => res.oidc.login({ returnTo: config.baseURL }));
  } else {
    debug('login handling route not applied');
  }

  // Logout route, configurable with routes.logout
  if (config.routes.logout) {
    const path = enforceLeadingSlash(config.routes.logout);
    debug(`adding GET ${path} route`);
    router.get(path, (_req, res) => res.oidc.logout());
  } else {
    debug('logout handling route not applied');
  }

  // Callback route, configured with routes.callback.
  if (config.routes.callback) {
    const path = enforceLeadingSlash(config.routes.callback);
    debug(`adding GET ${path} route`);
    router.get(path, (_req, res) => res.oidc.callback());
    debug(`adding POST ${path} route`);
    router.post(path, express.urlencoded({ extended: false }), (_req, res) => res.oidc.callback());
  } else {
    debug('callback handling route not applied');
  }

  if (config.backchannelLogout) {
    backchannelLogoutRoute(config, router);
  }

  if (config.authRequired) {
    debug('authentication is required for all routes this middleware is applied to');
    router.use(requiresAuth());
  } else {
    debug(
      'authentication is not required for any of the routes this middleware is applied to ' +
        'see and apply `requiresAuth` middlewares to your protected resources'
    );
  }
  if (config.attemptSilentLogin) {
    debug("silent login will be attempted on end-user's initial HTML request");
    router.use(attemptSilentLogin());
  }

  return router;
}

/**
 * Apply backchannel logout route
 * @param {import('types').ConfigParams} config
 * @param {import('express').Router} router
 */
function backchannelLogoutRoute(config, router) {
  const path = enforceLeadingSlash(config.routes.backchannelLogout);
  debug(`adding POST ${path} route`);
  router.post(path, express.urlencoded({ extended: false }), (_req, res) => res.oidc.backchannelLogout());

  // @ts-ignore
  if (config.backchannelLogout.isLoggedOut !== false) {
    backchannelIsLoggedOutMiddleware(config, router);
  }
}

/**
 * Backchannel is logged out middleware
 * @param {import('types').ConfigParams} config
 * @param {import('express').Router} router
 */
function backchannelIsLoggedOutMiddleware(config, router) {
  // @ts-ignore
  const isLoggedOutFn = config.backchannelLogout.isLoggedOut || isLoggedOut;
  router.use(async (req, _res, next) => {
    if (!req.oidc.isAuthenticated()) {
      return next();
    }

    const loggedOut = await isLoggedOutFn(req, config);

    if (loggedOut) {
      // @ts-ignore
      const session = req[config.session.name];
      // If using external store, try to destroy the session first
      if (config.session.store && typeof session?.destroy === 'function') {
        try {
          session.destroy();
        } catch {
          // Ignore errors during session destruction
        }
      }

      // Clear the session using replaceSession like it was originally
      req[SESSION] = undefined;
      replaceSession(req, undefined, config);
    }
    next();
  });
}

/**
 * Used for instantiating a custom session store. eg
 *
 * ```js
 * const { auth } = import('express-openid-connect');
 * const MemoryStore = import('memorystore');
 * const store = MemoryStore(auth);
 * ```
 *
 * @constructor
 */
auth.Store = function Store() {};

/**
 * @param {string} path endpoint path
 * @returns {string} endpoint path with leading slash
 */
function enforceLeadingSlash(path) {
  return path.split('')[0] === '/' ? path : '/' + path;
}
