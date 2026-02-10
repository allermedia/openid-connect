import * as jose from 'jose';

// Cache for generated keys
const keysPromise = generateKeys();

// Generate key pair asynchronously
async function generateKeys() {
  const { publicKey, privateKey } = await jose.generateKeyPair('RS256', {
    extractable: true,
  });

  const privateJWK = await jose.exportJWK(privateKey);
  const publicJWK = await jose.exportJWK(publicKey);

  // Add required fields
  privateJWK.alg = 'RS256';
  privateJWK.kid = 'key-1';
  privateJWK.use = 'sig';

  publicJWK.alg = 'RS256';
  publicJWK.kid = 'key-1';
  publicJWK.use = 'sig';

  const privatePEM = await jose.exportPKCS8(privateKey);
  const publicPEM = await jose.exportSPKI(publicKey);

  return { privateJWK, publicJWK, privatePEM, publicPEM };
}

// Export getters that generate keys on first access
export async function getPrivateJWK() {
  const keys = await keysPromise;
  return keys.privateJWK;
}

export async function getPublicJWK() {
  const keys = await keysPromise;
  return keys.publicJWK;
}

export async function getPrivatePEM() {
  const keys = await keysPromise;
  return keys.privatePEM;
}

export async function getPublicPEM() {
  const keys = await keysPromise;
  return keys.publicPEM;
}

// For backward compatibility, also export direct references
// These will be undefined initially but can be set after calling generate
export let privateJWK, publicJWK, privatePEM, publicPEM;
