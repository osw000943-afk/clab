import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, verifyPassword } from '../src/security/password.js';
import { encryptSecret, decryptSecret } from '../src/security/crypto.js';
import { config } from '../src/config.js';
import { classifyIp, isBlockedIp, allowPrivateTargets } from '../src/security/scope.js';

describe('password hashing (scrypt, memory-hard equivalent of argon2id)', () => {
  const pw = hashPassword('S3cure!Passw0rd');
  assert.match(pw, /^scrypt/);
  assert.equal(verifyPassword('S3cure!Passw0rd', pw), true);
  assert.equal(verifyPassword('wrong-pass', pw), false);
  assert.throws(() => hashPassword('short'), /at least 8 characters/);
});

describe('AES-GCM stored secret encryption', () => {
  const key = 'VGVzdC1rZXktZGFuaWlsLWJ1aWxkZXJzIHRoZXJlIGZvciBjb250ZW50';
  process.env.ENCRYPTION_KEY = key;
  const plain = 'sk-abc123super-secret-long-token-xyz';
  const enc = encryptSecret(plain);
  assert.ok(enc.startsWith('v1.') && enc.includes('.'), 'format v1.iv.tag.ct');
  assert.equal(decryptSecret(enc), plain);
  assert.throws(() => decryptSecret('garbage'), { message: 'bad_ciphertext' });
});

describe('IP classification (SSRF protection)', () => {
  const publicIps = ['93.184.216.34', '1.1.1.1', '2001:4860:4860::8888'];
  const blockedIps = ['127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.1.1', '169.254.169.254', '::1'];
  for (const ip of publicIps) assert.equal(isBlockedIp(ip), false, ip);
  for (const ip of blockedIps) assert.equal(isBlockedIp(ip), true, ip);
  assert.equal(classifyIp('172.16.5.4'), '172.16.0.0/12');
  assert.equal(classifyIp('fe80::1'), 'link-local');
  assert.equal(classifyIp('2001:4860:4860::8888'), 'public');
});

describe('allow-private toggle respects design default', () => {
  assert.equal(typeof allowPrivateTargets, 'boolean');
});
