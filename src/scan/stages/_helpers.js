import { q, q1, run, getSetting, setSetting } from '../../db.js';
import { decryptSecret } from '../../security/crypto.js';

export { q, q1, run, getSetting, setSetting };

/** Decrypt a stored secret, returning null instead of throwing. */
export function decryptSecretSafe(enc) {
  try {
    return decryptSecret(enc);
  } catch {
    return null;
  }
}
