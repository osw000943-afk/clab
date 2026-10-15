import crypto from 'node:crypto';
import { config, encryptionReady, decodeKey } from '../config.js';

/**
 * AES-256-GCM encryption for stored secrets (AI API keys, DB credentials).
 * The key comes ONLY from the environment (ENCRYPTION_KEY) — it is never
 * stored in the database alongside the ciphertext.
 */
export function encryptSecret(plaintext) {
  if (!encryptionReady()) {
    const e = new Error('encryption_key_not_configured');
    e.code = 'ENC_KEY_MISSING';
    throw e;
  }
  const key = decodeKey(config.encryptionKey);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1.${iv.toString('base64')}.${tag.toString('base64')}.${ct.toString('base64')}`;
}

export function decryptSecret(payload) {
  if (!encryptionReady()) {
    const e = new Error('encryption_key_not_configured');
    e.code = 'ENC_KEY_MISSING';
    throw e;
  }
  const parts = String(payload).split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') throw new Error('bad_ciphertext');
  const key = decodeKey(config.encryptionKey);
  const iv = Buffer.from(parts[1], 'base64');
  const tag = Buffer.from(parts[2], 'base64');
  const ct = Buffer.from(parts[3], 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

/** Non-reversible hint like "sk-…abcd" so the UI can show which key is active. */
export function keyHint(secret) {
  const s = String(secret);
  if (s.length <= 8) return '••••';
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}
