import crypto from 'crypto';

import { JWKS, JWK, JWS } from 'jose-v2';

const BYTE_LENGTH = 32;
const ENCRYPTION_INFO = 'JWE CEK';
const SIGNING_INFO = 'JWS Cookie Signing';
const DIGEST = 'sha256';
const ALG = 'HS256';
const CRITICAL_HEADER_PARAMS = ['b64'];

const header = { alg: ALG, b64: false, crit: CRITICAL_HEADER_PARAMS };

/**
 *
 * Derives appropriate sized keys from the end-user provided secret random string/passphrase using
 * HKDF (HMAC-based Extract-and-Expand Key Derivation Function) defined in RFC 8569.
 *
 * @see https://tools.ietf.org/html/rfc5869
 *
 */
export const encryption = (secret) => Buffer.from(crypto.hkdfSync(DIGEST, secret, Buffer.alloc(0), ENCRYPTION_INFO, BYTE_LENGTH));
export const signing = (secret) => Buffer.from(crypto.hkdfSync(DIGEST, secret, Buffer.alloc(0), SIGNING_INFO, BYTE_LENGTH));

export function getKeyStore(secret, forEncryption) {
  let current;
  const secrets = Array.isArray(secret) ? secret : [secret];
  const keystore = new JWKS.KeyStore();
  secrets.forEach((secretString, i) => {
    const key = JWK.asKey(forEncryption ? encryption(secretString) : signing(secretString));
    if (i === 0) {
      current = key;
    }
    keystore.add(key);
  });
  return [current, keystore];
}

function getPayload(cookie, value) {
  return Buffer.from(`${cookie}=${value}`);
}

function flattenedJWSFromCookie(cookie, value, signature) {
  return {
    protected: Buffer.from(JSON.stringify(header)).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'),
    payload: getPayload(cookie, value),
    signature,
  };
}

/**
 * @param {string} cookie cookie name
 * @param {string} value  cookie value
 * @param {Buffer} key signing key
 */
export function generateSignature(cookie, value, key) {
  const payload = getPayload(cookie, value);
  return JWS.sign.flattened(payload, key, header).signature;
}

export function verifySignature(cookie, value, signature, keystore) {
  try {
    return !!JWS.verify(flattenedJWSFromCookie(cookie, value, signature), keystore, { algorithms: [ALG], crit: CRITICAL_HEADER_PARAMS });
    // eslint-disable-next-line no-unused-vars
  } catch (err) {
    return false;
  }
}

export function verifyCookie(cookie, value, keystore) {
  if (!value) {
    return undefined;
  }
  let signature;
  [value, signature] = value.split('.');
  if (verifySignature(cookie, value, signature, keystore)) {
    return value;
  }

  return undefined;
}

export function signCookie(cookie, value, key) {
  const signature = generateSignature(cookie, value, key);
  return `${value}.${signature}`;
}
