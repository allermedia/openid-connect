import onHeaders from 'on-headers';

import { SESSION, SESSION_STORE } from '../constants.js';
import { DefaultCookieStore, CustomCookieStore } from '../cookie-store.js';
import Debug from '../debug.js';

const debug = Debug('session');

/**
 * Create appSession middleware
 * @param {import('types').ConfigParams} config
 * @returns {import('express').RequestHandler}
 */
export default function appSession(config) {
  const sessionName = config.session.name;

  const hasCustomStore = !!config.session.store;
  const store = hasCustomStore ? new CustomCookieStore(config) : new DefaultCookieStore(config);

  return async function appSessionHandler(req, res, next) {
    if (sessionName in req) {
      debug('request object (req) already has %o property, this is indicative of a middleware setup problem', sessionName);
      return next(new Error(`req[${sessionName}] is already set, did you run this middleware twice?`));
    }

    await store.getSession(req);

    attachSessionObject(req, sessionName);

    const cookieApi = (req[SESSION_STORE] = store.api(req));

    await cookieApi.setSessionCookie();

    onHeaders(res, () => {
      store.setCookie(req, res);
    });

    if (hasCustomStore) {
      res.end = customStoreEnd(store, req, res, next);
    }

    return next();
  };
}

/**
 * @param {import('express').Request} req
 * @param {string} sessionName
 */
function attachSessionObject(req, sessionName) {
  Object.defineProperty(req, sessionName, {
    enumerable: true,
    get() {
      return this[SESSION]?.getSessionData();
    },
    set(arg) {
      if (arg === null || arg === undefined) {
        this[SESSION] = undefined;
      } else {
        throw new TypeError('session object cannot be reassigned');
      }
    },
  });
}

/**
 * Response.end override function to store session
 * @param {CustomCookieStore|DefaultCookieStore} store cookie store
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 * @returns {import('express').Response['end']}
 */
function customStoreEnd(store, req, res, next) {
  const endFn = res.end;

  // @ts-ignore
  return async function customEnd(...args) {
    try {
      await store.set(req);
      // @ts-ignore
      endFn.call(res, ...args);
    } catch (err) {
      // need to restore the original `end` so that it gets
      // called after `next(e)` calls the express error handling mw
      res.end = endFn;
      process.nextTick(() => next(err));
    }
  };
}
