import { AssertionError } from 'node:assert';

import { parse } from 'cookie';
import onHeaders from 'on-headers';

import { SESSION, COOKIES, SESSION_ID, REGENERATED_SESSION_ID, REASSIGN } from '../constants.js';
import { DefaultCookieStore, CustomCookieStore } from '../cookie-store.js';
import Debug from '../debug.js';
import { StoredSession } from '../session.js';

const debug = Debug('session');

/**
 * Create appSession middleware
 * @param {import('types').ConfigParams} config
 * @returns {import('express').RequestHandler}
 */
export default function appSession(config) {
  const sessionName = config.session.name;
  const { genid: generateId, absoluteDuration, rollingDuration } = config.session;

  const hasCustomStore = !!config.session.store;
  const store = hasCustomStore ? new CustomCookieStore(config) : new DefaultCookieStore(config);

  return async function appSessionHandler(req, res, next) {
    if (sessionName in req) {
      debug('request object (req) already has %o property, this is indicative of a middleware setup problem', sessionName);
      return next(new Error(`req[${sessionName}] is already set, did you run this middleware twice?`));
    }

    req[COOKIES] = parse(req.get('cookie') || '');

    const session = store.getCookie(req);

    /** @type {number} */
    let iat;
    if (session) {
      try {
        const sessionData = await store.get(session);

        const storedSession = new StoredSession(sessionData.data, sessionData.header);
        storedSession.assertExpired(rollingDuration, Number(absoluteDuration));

        iat = sessionData.header.iat;

        req[SESSION] = storedSession;

        attachSessionObject(req, sessionName, storedSession.getSessionData());
      } catch (err) {
        if (err instanceof AssertionError) {
          debug('existing session was rejected because', err.message);
        } else {
          debug('unexpected error handling session', err);
        }
      }
    }

    // @ts-ignore
    if (!(sessionName in req) || !req[sessionName]) {
      attachSessionObject(req, sessionName, {});
    }

    req[SESSION_ID] = session || (await generateId(req));

    onHeaders(res, () => {
      try {
        store.setCookie(req, res, { iat });
      } catch (err) {
        debug('Error setting cookie in onHeaders:', err);
      }
    });

    if (hasCustomStore) {
      res.end = customStoreEnd(store, iat, req, res, next);
    }

    return next();
  };
}

/**
 * Regenerate session store id
 * @param {import('express').Request} req
 * @param {import('types').ConfigParams} config
 */
export async function regenerateSessionStoreId(req, config) {
  if (config.session.store) {
    req[REGENERATED_SESSION_ID] = await config.session.genid(req);
  }
}

/**
 * Replace session
 * @param {import('express').Request} req
 * @param {Partial<import('types').Session>} session
 * @param {import('types').ConfigParams} config
 */
export function replaceSession(req, session, config) {
  if (session !== null && session !== undefined) {
    session[REASSIGN] = true;
  }
  // @ts-ignore
  req[config.session.name] = session;
}

/**
 * @param {import('express').Request} req
 * @param {string} sessionName
 * @param {any} value
 */
function attachSessionObject(req, sessionName, value) {
  Object.defineProperty(req, sessionName, {
    enumerable: true,
    get() {
      return value;
    },
    set(arg) {
      if (arg === null || arg === undefined || arg[REASSIGN]) {
        value = arg;
      } else {
        throw new TypeError('session object cannot be reassigned');
      }
      return;
    },
  });
}

/**
 * Response.end override function to store session
 * @param {CustomCookieStore|DefaultCookieStore} store cookie store
 * @param {number} iat session issued at
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 * @returns {import('express').Response['end']}
 */
function customStoreEnd(store, iat, req, res, next) {
  const endFn = res.end;

  // @ts-ignore
  return async function customEnd(...args) {
    try {
      await store.set(req, { iat });
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
