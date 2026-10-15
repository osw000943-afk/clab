import crypto from 'node:crypto';

const SCRYPT_N = 16384, r = 8, p = 1, KEYLEN = 64;

/**
 * Hash a password with scrypt (memory-hard, built into Node — no native deps).
 * Format: scrypt$N$r$p$salt_b64$hash_b64
 */
export function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 8) {
    throw new Error('password must be at least 8 characters');
  }
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, KEYLEN, { N: SCRYPT_N, r, p, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${SCRYPT_N}$${r}$${p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

export function verifyPassword(password, stored) {
  try {
    const [scheme, n, rr, pp, saltB64, hashB64] = String(stored).split('$');
    if (scheme !== 'scrypt') return false;
    const salt = Buffer.from(saltB64, 'base64');
    const expected = Buffer.from(hashB64, 'base64');
    const actual = crypto.scryptSync(password, salt, expected.length, {
      N: Number(n), r: Number(rr), p: Number(pp), maxmem: 64 * 1024 * 1024,
    });
    return crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}
