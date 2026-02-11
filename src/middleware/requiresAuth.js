import Debug from '../debug.js';
import { UnauthorizedError } from '../errors.js';

const debug = Debug('requiresAuth');

/**
 * Returns a middleware that checks whether an end-user is authenticated.
 * If end-user is not authenticated `res.oidc.login()` is triggered for an HTTP
 * request that can perform a redirect.
 * @param {CallableFunction} requiresLoginCheck
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function requiresLoginMiddleware(requiresLoginCheck, req, res, next) {
  if (!req.oidc) {
    next(new Error('req.oidc is not found, did you include the auth middleware?'));
    return;
  }

  if (requiresLoginCheck(req)) {
    if (!res.oidc.errorOnRequiredAuth && req.accepts('html')) {
      debug('authentication requirements not met with errorOnRequiredAuth() returning false, calling res.oidc.login()');
      return res.oidc.login();
    }
    debug('authentication requirements not met with errorOnRequiredAuth() returning true, calling next() with an Unauthorized error');
    next(new UnauthorizedError('Authentication is required for this route.'));
    return;
  }

  debug('authentication requirements met, calling next()');

  next();
}

export function requiresAuth(requiresLoginCheck = defaultRequiresLogin) {
  return requiresLoginMiddleware.bind(undefined, requiresLoginCheck);
}

/**
 * ID token calim equals
 * @param {*} claim
 * @param {string|number|boolean|null} expected
 */
export function claimEquals(claim, expected) {
  // check that claim is a string value
  if (typeof claim !== 'string') {
    throw new TypeError('"claim" must be a string');
  }
  // check that expected is a JSON supported primitive
  checkJSONprimitive(expected);

  /**
   * @param {import('express').Request} req
   */
  function authenticationCheck(req) {
    if (defaultRequiresLogin(req)) {
      return true;
    }
    const { idTokenClaims } = req.oidc;
    if (!(claim in idTokenClaims)) {
      return true;
    }
    const actual = idTokenClaims[claim];
    if (actual !== expected) {
      return true;
    }

    return false;
  }
  return requiresLoginMiddleware.bind(undefined, authenticationCheck);
}

/**
 * ID token claim includes
 * @param {string} claim
 * @param  {...(string|number|boolean|null)} expected
 */
export function claimIncludes(claim, ...expected) {
  // check that claim is a string value
  if (typeof claim !== 'string') {
    throw new TypeError('"claim" must be a string');
  }
  // check that all expected are JSON supported primitives
  expected.forEach(checkJSONprimitive);

  /**
   * @param {import('express').Request} req
   */
  function authenticationCheck(req) {
    if (defaultRequiresLogin(req)) {
      return true;
    }

    const { idTokenClaims } = req.oidc;
    if (!(claim in idTokenClaims)) {
      return true;
    }

    const actual = idTokenClaims[claim];
    let expectedList;
    if (typeof actual === 'string') {
      expectedList = new Set(actual.split(' '));
    } else if (Array.isArray(actual)) {
      expectedList = new Set(actual);
    } else if (!Array.isArray(actual)) {
      debug('unexpected claim type. expected array or string, got %o', typeof actual);
      return true;
    }

    return !expected.every(Set.prototype.has.bind(expectedList));
  }

  return requiresLoginMiddleware.bind(undefined, authenticationCheck);
}

/**
 * @param {CallableFunction} func
 */
export function claimCheck(func) {
  // check that func is a function
  if (typeof func !== 'function' || func.constructor.name !== 'Function') {
    throw new TypeError('"claimCheck" expects a function');
  }

  /**
   * @param {import('express').Request} req
   */
  function authenticationCheck(req) {
    if (defaultRequiresLogin(req)) {
      return true;
    }

    const { idTokenClaims } = req.oidc;

    return !func(req, idTokenClaims);
  }

  return requiresLoginMiddleware.bind(undefined, authenticationCheck);
}

/**
 * @param {import('express').Request} req
 */
function defaultRequiresLogin(req) {
  return !req.oidc.isAuthenticated();
}

/**
 * Check primitive value
 * @param {string|number|boolean|null} value
 */
function checkJSONprimitive(value) {
  if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean' && value !== null) {
    throw new TypeError('"expected" must be a string, number, boolean or null');
  }
}
