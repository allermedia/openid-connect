import { Debug } from '../debug.js';
import { ForbiddenError, UnauthorizedError } from '../errors.js';

const debug = Debug('requiresAuth');

/**
 * Returns a middleware that first checks whether an end-user is authenticated
 * and then, optionally, whether the authenticated identity is authorized.
 *
 * If end-user is not authenticated `res.oidc.login()` is triggered for an HTTP
 * request that can perform a redirect, otherwise `next()` is called with an
 * `UnauthorizedError` (401). A request authenticated by `requiresBearerAuth()`
 * (`req.bearerAuth`) also satisfies the authentication check, so claim checks
 * can be chained after that middleware.
 *
 * If the end-user is authenticated but `authorize` returns a `ForbiddenError`
 * `next()` is called with that error (403) - never a login redirect, since
 * logging in again would not change the outcome.
 * @param {(req: import('express').Request) => boolean} requiresLoginCheck returns `true` when the request is not authenticated
 * @param {((req: import('express').Request) => ForbiddenError | void) | undefined} authorize returns a `ForbiddenError` when the authenticated request is not authorized
 * @param {import('types').RequiresAuthOptions} options
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function requiresLoginMiddleware(requiresLoginCheck, authorize, options, req, res, next) {
  if (!req.oidc && !req.bearerAuth) {
    next(new Error('req.oidc is not found, did you include the auth middleware?'));
    return;
  }

  if (requiresLoginCheck(req)) {
    const errorOnRequiredAuth = options.errorOnRequiredAuth ?? res.oidc?.errorOnRequiredAuth;
    if (res.oidc && !errorOnRequiredAuth && req.accepts('html')) {
      debug('authentication requirements not met with errorOnRequiredAuth() returning false, calling res.oidc.login()');
      return res.oidc.login();
    }
    debug('authentication requirements not met, calling next() with an Unauthorized error');
    next(new UnauthorizedError('Authentication is required for this route.'));
    return;
  }

  if (authorize) {
    const forbidden = authorize(req);
    if (forbidden) {
      debug('authorization requirements not met, calling next() with a Forbidden error: %s', forbidden.message);
      next(forbidden);
      return;
    }
  }

  debug('authentication requirements met, calling next()');

  next();
}

/**
 * Require an authenticated end-user
 * @param {((req: import('express').Request) => boolean) | import('types').RequiresAuthOptions} [requiresLoginCheck] custom check returning `true` when login is required, or options
 * @param {import('types').RequiresAuthOptions} [options]
 */
export function requiresAuth(requiresLoginCheck = defaultRequiresLogin, options) {
  if (typeof requiresLoginCheck !== 'function') {
    options = requiresLoginCheck;
    requiresLoginCheck = defaultRequiresLogin;
  }
  return requiresLoginMiddleware.bind(undefined, requiresLoginCheck, undefined, options ?? {});
}

/**
 * ID token claim equals. Comparison is strict unless `options.ignoreCase`
 * and/or `options.trim` are set, which normalize string values on both sides.
 * @param {string} claim
 * @param {string|number|boolean|null} expected
 * @param {import('types').RequiresAuthOptions} [options]
 */
export function claimEquals(claim, expected, options) {
  // check that claim is a string value
  if (typeof claim !== 'string') {
    throw new TypeError('"claim" must be a string');
  }
  // check that expected is a JSON supported primitive
  checkJSONprimitive(expected);

  /**
   * @param {import('express').Request} req
   */
  function authorize(req) {
    const claims = authenticatedClaims(req);
    if (!(claim in claims)) {
      return new ForbiddenError(`Missing claim "${claim}"`, { claim, expected, actual: undefined });
    }
    const actual = claims[claim];
    if (fold(actual, options) !== fold(expected, options)) {
      return new ForbiddenError(`Insufficient claim "${claim}"`, { claim, expected, actual });
    }
  }

  return requiresLoginMiddleware.bind(undefined, defaultRequiresLogin, authorize, options ?? {});
}

/**
 * ID token claim includes — every expected value must be present in the
 * claim (an array or a space separated string). Comparison is strict unless
 * `options.ignoreCase` and/or `options.trim` are set. Pass an options object
 * as the last argument.
 * @param {string} claim
 * @param  {...(string|number|boolean|null|import('types').RequiresAuthOptions)} args
 */
export function claimIncludes(claim, ...args) {
  // check that claim is a string value
  if (typeof claim !== 'string') {
    throw new TypeError('"claim" must be a string');
  }
  /** @type {import('types').RequiresAuthOptions} */
  let options = {};
  const last = args[args.length - 1];
  if (typeof last === 'object' && last !== null) {
    options = last;
    args = args.slice(0, -1);
  }
  const expected = /** @type {(string|number|boolean|null)[]} */ (args);
  // check that all expected are JSON supported primitives
  expected.forEach(checkJSONprimitive);

  /**
   * @param {import('express').Request} req
   */
  function authorize(req) {
    const claims = authenticatedClaims(req);
    if (!(claim in claims)) {
      return new ForbiddenError(`Missing claim "${claim}"`, { claim, expected, actual: undefined });
    }

    const actual = claims[claim];
    let actualList;
    if (typeof actual === 'string') {
      actualList = options.trim ? actual.trim().split(/\s+/) : actual.split(' ');
    } else if (Array.isArray(actual)) {
      actualList = actual;
    } else {
      debug('unexpected claim type. expected array or string, got %o', typeof actual);
      return new ForbiddenError(`Insufficient claim "${claim}"`, { claim, expected, actual });
    }

    const actualSet = new Set(actualList.map((value) => fold(value, options)));
    if (!expected.every((value) => actualSet.has(fold(value, options)))) {
      return new ForbiddenError(`Insufficient claim "${claim}"`, { claim, expected, actual });
    }
  }

  return requiresLoginMiddleware.bind(undefined, defaultRequiresLogin, authorize, options);
}

/**
 * Custom claim check. The check function is only called for an authenticated
 * request. Return a truthy value to allow the request, a falsy value to reject
 * it with a `ForbiddenError`, or an `Error` (e.g. a `ForbiddenError` carrying a
 * reason) to reject it with that error.
 * @param {(req: import('express').Request, claims: import('types').IdTokenClaims) => unknown} func
 * @param {import('types').RequiresAuthOptions} [options]
 */
export function claimCheck(func, options) {
  // check that func is a function
  if (typeof func !== 'function' || func.constructor.name !== 'Function') {
    throw new TypeError('"claimCheck" expects a function');
  }

  /**
   * @param {import('express').Request} req
   */
  function authorize(req) {
    const result = func(req, authenticatedClaims(req));
    if (result instanceof Error) {
      return /** @type {ForbiddenError} */ (result);
    }
    if (!result) {
      return new ForbiddenError('Insufficient claims');
    }
  }

  return requiresLoginMiddleware.bind(undefined, defaultRequiresLogin, authorize, options ?? {});
}

/**
 * @param {import('express').Request} req
 */
function defaultRequiresLogin(req) {
  if (req.bearerAuth) {
    return false;
  }
  return !req.oidc.isAuthenticated();
}

/**
 * Claims for the authenticated identity — the verified bearer token payload
 * when `requiresBearerAuth()` authenticated the request (which takes
 * precedence), else the session's id_token claims.
 * @param {import('express').Request} req
 */
function authenticatedClaims(req) {
  return req.bearerAuth ? req.bearerAuth.payload : req.oidc.idTokenClaims;
}

/**
 * Normalize a string value for comparison according to `trim` and
 * `ignoreCase`, leave other types as is
 * @param {unknown} value
 * @param {import('types').RequiresAuthOptions} [options]
 */
function fold(value, options) {
  if (typeof value !== 'string') return value;
  let result = value;
  if (options?.trim) result = result.trim();
  if (options?.ignoreCase) result = result.toLowerCase();
  return result;
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
