#!/usr/bin/env node
/** Set/change the lab owner password. Writes a scrypt hash into .env. */
import readline from 'node:readline/promises';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { hashPassword } from '../src/security/password.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const envPath = path.join(ROOT, '.env');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const p1 = await rl.question('New password (min 8 chars): ');
const p2 = await rl.question('Repeat password: ');
rl.close();

if (p1 !== p2) { console.error('Passwords do not match.'); process.exit(1); }
if (p1.length < 8) { console.error('Password must be at least 8 characters.'); process.exit(1); }

const hash = hashPassword(p1);
let content = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';
if (/^LAB_PASSWORD_HASH=/m.test(content)) {
  content = content.replace(/^LAB_PASSWORD_HASH=.*$/m, 'LAB_PASSWORD_HASH=' + hash);
} else {
  content += (content && !content.endsWith('\n') ? '\n' : '') + 'LAB_PASSWORD_HASH=' + hash + '\n';
}
if (!fs.existsSync(path.join(ROOT, '.gitignore')) || !fs.readFileSync(path.join(ROOT, '.gitignore'), 'utf8').includes('.env')) {
  console.warn('WARNING: make sure .env is gitignored!');
}
fs.writeFileSync(envPath, content, { mode: 0o600 });
console.log('Password hash written to .env (LAB_PASSWORD_HASH). The plaintext password is not stored anywhere.');
console.log('Restart clab to apply.');
