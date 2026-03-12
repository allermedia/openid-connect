import { compactDecrypt } from 'jose';

import { getEncryptionKeyStore } from '../../src/crypto.js';

export async function decryptCookie(secret, value) {
  const { plaintext, protectedHeader } = await compactDecrypt(value, getEncryptionKeyStore(secret)[0]);
  return {
    plaintext: new TextDecoder().decode(plaintext),
    protectedHeader,
  };
}
