import Debug from '../debug.js';

const debug = Debug('getLoginState');

/**
 * Generate the state value for use during login transactions. It is used to store the intended
 * return URL after the user authenticates. State is not used to carry unique PRNG values here
 * because the library utilizes either nonce or PKCE for CSRF protection.
 *
 * @param {import('express').Request} req
 * @param {any} options
 * @returns {Record<string, any>}
 */
export function defaultState(req, options) {
  const state = { returnTo: options.returnTo || req.originalUrl };
  debug('adding default state %O', state);
  return state;
}

/**
 * Prepare a state object to send.
 * Filters out nonce, code_verifier, and max_age from the state object so that the values are
 * only stored in its dedicated transient cookie
 * @param {any} stateObject
 */
export function encodeState(stateObject = {}) {
  const { nonce, code_verifier, max_age, ...filteredState } = stateObject;
  return Buffer.from(JSON.stringify(filteredState)).toString('base64url');
}

/**
 * Decode a state value.
 *
 * @param {string} stateValue
 */
export function decodeState(stateValue) {
  try {
    // @ts-ignore
    return JSON.parse(Buffer.from(stateValue, 'base64'));
  } catch {
    return false;
  }
}
