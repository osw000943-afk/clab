import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** Minimal .env loader. Existing shell env vars win for secrets ONLY when they
 * look like a real scrypt hash. A stale/invalid shell export (e.g.
 * LAB_PASSWORD_HASH=testserver) must never shadow the real hash in .env. */
const SECRET_KEYS = new Set(['LAB_PASSWORD_HASH', 'SESSION_SECRET', 'ENCRYPTION_KEY']);
function looksLikeScryptHash(v) { return typeof v === 'string' && v.startsWith('scrypt$'); }
function loadEnvFile(file) {
  if (!fs.existsSync(file)) return;
  const txt = fs.readFileSync(file, 'utf8');
  for (const rawLine of txt.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (SECRET_KEYS.has(key) && !looksLikeScryptHash(process.env[key])) {
      // shell value is missing or invalid -> load real secret from file
      if (val) process.env[key] = val;
    } else if (!(key in process.env)) {
      process.env[key] = val;
    }
  }
}

loadEnvFile(process.env.ENV_FILE || path.join(ROOT, '.env'));

const num = (v, d) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
};

export const config = {
  root: ROOT,
  nodeEnv: process.env.NODE_ENV || 'production',
  isDev: process.env.NODE_ENV === 'development',
  port: num(process.env.PORT, 3000),
  host: process.env.HOST || '127.0.0.1',

  dataDir: path.resolve(ROOT, process.env.DATA_DIR || './data'),
  dbPath: path.resolve(ROOT, process.env.DB_PATH || './data/clab.db'),
  logDir: path.resolve(ROOT, process.env.LOG_DIR || './logs'),
  logMaxKB: num(process.env.LOG_MAX_KB, 512),
  logKeep: num(process.env.LOG_KEEP, 3),

  labPasswordHash: process.env.LAB_PASSWORD_HASH || '',
  sessionSecret: process.env.SESSION_SECRET || '',
  encryptionKey: process.env.ENCRYPTION_KEY || '',

  sessionIdleMin: num(process.env.SESSION_IDLE_MIN, 30),
  sessionAbsoluteH: num(process.env.SESSION_ABSOLUTE_H, 8),

  limits: {
    maxScanDurationMin: num(process.env.MAX_SCAN_DURATION_MIN, 45),
    toolTimeoutMs: num(process.env.TOOL_TIMEOUT_MS, 300_000),
    maxPortCount: num(process.env.MAX_PORT_COUNT, 64),
    maxProbePaths: num(process.env.MAX_PROBE_PATHS, 60),
    maxBodyBytes: 2 * 1024 * 1024,
    sseHeartbeatMs: 15_000,
  },
};

export function ensureDirs() {
  fs.mkdirSync(config.dataDir, { recursive: true });
  fs.mkdirSync(config.logDir, { recursive: true });
}

export function sessionSecretBuffer() {
  if (!config.sessionSecret) return null;
  return crypto.createHash('sha256').update(config.sessionSecret).digest();
}

/** True when the encryption key is configured and well-formed (32 bytes base64/hex). */
export function encryptionReady() {
  if (!config.encryptionKey) return false;
  try {
    return decodeKey(config.encryptionKey).length === 32;
  } catch {
    return false;
  }
}

export function decodeKey(key) {
  const k = key.trim();
  const b64 = Buffer.from(k, 'base64');
  if (b64.length === 32) return b64;
  const hex = Buffer.from(k, 'hex');
  if (hex.length === 32) return hex;
  // fall back to sha256 of the provided string so arbitrary passphrases still work deterministically
  return crypto.createHash('sha256').update(k).digest();
}
