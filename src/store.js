import { promisify } from 'node:util';

/**
 * Express-session compatible session store base class.
 *
 * Session store factories that expect the express-session module can be instantiated
 * with `auth`, which exposes this class as `auth.Store`. Stores extending this class
 * are considered callback based and are promisified by `getConfig`.
 * @constructor
 */
export function Store() {}

/**
 * Promisify an express-session compatible, callback based, session store.
 * Stores that don't extend `Store` are assumed to be promise based and returned as-is.
 * @param {any} store
 * @returns {any} promise based session store
 */
export function promisifyStore(store) {
  if (!(store instanceof Store)) return store;
  const callbackStore = /** @type {any} */ (store);
  return {
    get: promisify(callbackStore.get.bind(callbackStore)),
    set: promisify(callbackStore.set.bind(callbackStore)),
    destroy: promisify(callbackStore.destroy.bind(callbackStore)),
  };
}
