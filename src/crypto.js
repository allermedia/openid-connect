import { hkdfSync, randomBytes, createCipheriv, createDecipheriv, createHmac, timingSafeEqual } from 'node:crypto';

const BYTE_LENGTH = 32;
const ENCRYPTION_INFO = 'JWE CEK';
const SIGNING_INFO = 'JWS Cookie Signing';
const DIGEST = 'sha256';
const ENCRYPTION_ALG = 'aes-256-gcm';

/**
 * Get current HKDF encryption keys
 * @param {string|string[]} secret secret or secrets
 * @returns {[Buffer, Buffer[]]} tuple with secrets [current, [current, ...]]
 */
export function getEncryptionKeyStore(secret) {
  const secrets = Array.isArray(secret) ? secret : [secret];
  const keystore = secrets.map((s) => encryption(s));
  return [keystore[0], keystore];
}

/**
 * Get current HKDF encryption keys
 * @param {string|string[]} secret secret or secrets
 * @returns {[Buffer, Buffer[]]} tuple with secrets [current, [current, ...]]
 */
export function getSigningKeyStore(secret) {
  const secrets = Array.isArray(secret) ? secret : [secret];
  const keystore = secrets.map((s) => signing(s));
  return [keystore[0], keystore];
}

/**
 * Verify cookie signature
 * @param {string} cookie
 * @param {string} value
 * @param {Buffer[]} keystore
 */
export function verifyCookie(cookie, value, keystore) {
  if (!value) return;

  const [part, signature] = value.split('.');
  if (verifySignature(cookie, part, signature, keystore)) {
    return part;
  }
}

/**
 * Sign cookie
 * @param {string} cookie cookie name
 * @param {string} value cookie valur
 * @param {Buffer} key signing key
 */
export function signCookie(cookie, value, key) {
  const signature = generateSignature(cookie, value, key);
  return `${value}.${signature}`;
}

/**
 * Encrypt cookie
 * @param {Buffer} key encryption key
 * @param {string} payload encrypt payload
 * @param {Record<string, any>} [headers] extra headers
 */
export function encrypt(key, payload, headers) {
  const iv = randomBytes(12);

  const cipher = createCipheriv(ENCRYPTION_ALG, key, iv);

  let encrypted = cipher.update(payload, 'utf8', 'base64url');
  encrypted += cipher.final('base64url');
  const tag = cipher.getAuthTag();

  // Create JWE-like compact format with headers
  const protectedHeader = Buffer.from(
    JSON.stringify({
      alg: 'dir',
      enc: 'A256GCM',
      ...headers,
    })
  ).toString('base64url');

  return `${protectedHeader}..${iv.toString('base64url')}.${encrypted}.${tag.toString('base64url')}`;
}

/**
 * Decrypt cookie
 * @param {Buffer|Buffer[]} keystore
 * @param {string} jweCompact
 */
export function decrypt(keystore, jweCompact) {
  const [protectedHeader, , iv, ciphertext, tag] = jweCompact.split('.');

  // Try each key in keystore (for key rotation support)
  const keysToTry = Array.isArray(keystore) ? keystore : [keystore];

  for (const key of keysToTry) {
    try {
      return decryptAttempt(key, protectedHeader, iv, ciphertext, tag);
    } catch (error) {
      // eslint-disable-next-line no-var
      var lastError = error;
    }
  }

  // If all keys failed, throw the last error
  throw lastError;
}

/**
 * Attempt to decrypt cipher with key
 * @param {Buffer} key decrypt key
 * @param {string} protectedHeader
 * @param {string} iv
 * @param {string} ciphertext
 * @param {string} tag
 * @returns decrypted value payload and cipher headers
 */
function decryptAttempt(key, protectedHeader, iv, ciphertext, tag) {
  const decipher = createDecipheriv(ENCRYPTION_ALG, key, Buffer.from(iv, 'base64url'));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));

  let decrypted = decipher.update(ciphertext, 'base64url', 'utf8');
  decrypted += decipher.final('utf8');

  return {
    payload: decrypted,
    header: JSON.parse(Buffer.from(protectedHeader, 'base64url').toString()),
  };
}

/**
 * @param {string} cookie cookie name
 * @param {string} value cookie value
 * @param {Buffer} key signature key
 */
function generateSignature(cookie, value, key) {
  return createHmac('sha256', key)
    .update(Buffer.from(`${cookie}=${value}`))
    .digest('base64url');
}

/**
 * Verify cookie signature
 * @param {string} cookie cookie name
 * @param {string} value cookie value
 * @param {string} signature cookie signature
 * @param {Buffer[]} keystore signature secrets key store
 */
function verifySignature(cookie, value, signature, keystore) {
  try {
    for (const key of keystore) {
      const expectedSignature = generateSignature(cookie, value, key);
      if (timingSafeEqual(Buffer.from(signature, 'base64url'), Buffer.from(expectedSignature, 'base64url'))) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

/**
 *
 * Derives appropriate sized keys from the end-user provided secret random string/passphrase using
 * HKDF (HMAC-based Extract-and-Expand Key Derivation Function) defined in RFC 8569.
 *
 * @see https://tools.ietf.org/html/rfc5869
 * @param {string} secret
 */
function encryption(secret) {
  return Buffer.from(hkdfSync(DIGEST, secret, Buffer.alloc(0), ENCRYPTION_INFO, BYTE_LENGTH));
}

/**
 * @param {string} secret
 */
function signing(secret) {
  return Buffer.from(hkdfSync(DIGEST, secret, Buffer.alloc(0), SIGNING_INFO, BYTE_LENGTH));
}
