#!/usr/bin/env node
/** Backup the SQLite database (WAL checkpointed) into ./backups with timestamp. */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dbPath = path.resolve(ROOT, process.env.DB_PATH || './data/clab.db');
const outDir = path.join(ROOT, 'backups');
fs.mkdirSync(outDir, { recursive: true });
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const out = path.join(outDir, 'clab-' + stamp + '.db');

const db = new DatabaseSync(dbPath);
db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
db.close();
fs.copyFileSync(dbPath, out);
console.log('Backup written:', out, '(' + Math.round(fs.statSync(out).size / 1024) + ' KB)');
