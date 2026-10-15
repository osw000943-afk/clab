#!/usr/bin/env node
/** Generate SESSION_SECRET and ENCRYPTION_KEY into .env (never printed to stdout logs). */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const envPath = path.join(ROOT, '.env');
const sessionSecret = crypto.randomBytes(32).toString('base64url');
const encryptionKey = crypto.randomBytes(32).toString('base64');

let content = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';
const set = (k, v) => {
  if (new RegExp('^' + k + '=', 'm').test(content)) content = content.replace(new RegExp('^' + k + '.*$', 'm'), k + '=' + v);
  else content += (content && !content.endsWith('\n') ? '\n' : '') + k + '=' + v + '\n';
};
set('SESSION_SECRET', sessionSecret);
set('ENCRYPTION_KEY', encryptionKey);
fs.writeFileSync(envPath, content, { mode: 0o600 });
console.log('Generated SESSION_SECRET and ENCRYPTION_KEY into .env (file mode 600).');
console.log('The encryption key is NOT stored in the database.');
