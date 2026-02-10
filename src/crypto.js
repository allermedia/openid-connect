import crypto from 'node:crypto';

const BYTE_LENGTH = 32;
const ENCRYPTION_INFO = 'JWE CEK';
const SIGNING_INFO = 'JWS Cookie Signing';
const DIGEST = 'sha256';

/**
 *
 * Derives appropriate sized keys from the end-user provided secret random string/passphrase using
 * HKDF (HMAC-based Extract-and-Expand Key Derivation Function) defined in RFC 8569.
 *
 * @see https://tools.ietf.org/html/rfc5869
 *
 */
export function encryption(secret) {
  return Buffer.from(crypto.hkdfSync(DIGEST, secret, Buffer.alloc(0), ENCRYPTION_INFO, BYTE_LENGTH));
}

export function signing(secret) {
  return Buffer.from(crypto.hkdfSync(DIGEST, secret, Buffer.alloc(0), SIGNING_INFO, BYTE_LENGTH));
}

export function getKeyStore(secret, forEncryption) {
  let current;
  const secrets = Array.isArray(secret) ? secret : [secret];
  const keystore = [];
  secrets.forEach((secretString, i) => {
    const key = forEncryption ? encryption(secretString) : signing(secretString);
    if (i === 0) {
      current = key;
    }
    keystore.push(key);
  });
  return [current, keystore];
}

function getPayload(cookie, value) {
  return Buffer.from(`${cookie}=${value}`);
}

function generateSignature(cookie, value, key) {
  const payload = getPayload(cookie, value);
  const hmac = crypto.createHmac('sha256', key);
  hmac.update(payload);
  return hmac.digest('base64url');
}

function verifySignature(cookie, value, signature, keystore) {
  try {
    for (const key of keystore) {
      const expectedSignature = generateSignature(cookie, value, key);
      if (crypto.timingSafeEqual(Buffer.from(signature, 'base64url'), Buffer.from(expectedSignature, 'base64url'))) {
        return true;
      }
    }
    return false;
  } catch {
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

export function encrypt(keystore, payload, headers) {
  const algorithm = 'aes-256-gcm';
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(algorithm, keystore, iv);

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

export function decrypt(keystore, jweCompact) {
  // Parse compact serialization
  const parts = jweCompact.split('.');
  const protectedHeader = parts[0];
  const iv = parts[2];
  const ciphertext = parts[3];
  const tag = parts[4];

  // Try each key in keystore (for key rotation support)
  const keysToTry = Array.isArray(keystore) ? keystore : [keystore];

  let lastError;
  for (const key of keysToTry) {
    try {
      const algorithm = 'aes-256-gcm';
      const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(iv, 'base64url'));
      decipher.setAuthTag(Buffer.from(tag, 'base64url'));

      let decrypted = decipher.update(ciphertext, 'base64url', 'utf8');
      decrypted += decipher.final('utf8');

      return {
        payload: decrypted,
        protected: JSON.parse(Buffer.from(protectedHeader, 'base64url').toString()),
      };
    } catch (error) {
      lastError = error;
      // Continue to next key
    }
  }

  // If all keys failed, throw the last error
  throw lastError;
}
