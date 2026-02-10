import debug from '../debug.js';

const debugGetLoginState = debug('getLoginState');

/**
 * Generate the state value for use during login transactions. It is used to store the intended
 * return URL after the user authenticates. State is not used to carry unique PRNG values here
 * because the library utilizes either nonce or PKCE for CSRF protection.
 *
 * @param {RequestHandler} req
 * @param {object} options
 *
 * @return {object}
 */
export function defaultState(req, options) {
  const state = { returnTo: options.returnTo || req.originalUrl };
  debugGetLoginState('adding default state %O', state);
  return state;
}

/**
 * Prepare a state object to send.
 *
 * @param {object} stateObject
 *
 * @return {string}
 */
export function encodeState(stateObject = {}) {
  // this filters out nonce, code_verifier, and max_age from the state object so that the values are
  // only stored in its dedicated transient cookie
  const { nonce, code_verifier, max_age, ...filteredState } = stateObject;
  return Buffer.from(JSON.stringify(filteredState)).toString('base64url');
}

/**
 * Decode a state value.
 *
 * @param {string} stateValue
 *
 * @return {object}
 */
export function decodeState(stateValue) {
  try {
    return JSON.parse(Buffer.from(stateValue, 'base64'));
  } catch {
    return false;
  }
}
