import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import { config } from './config.js';

let db = null;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  csrf TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ip TEXT, ua TEXT
);
CREATE TABLE IF NOT EXISTS login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  username TEXT NOT NULL,
  ts INTEGER NOT NULL,
  success INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(ip, username, ts);
CREATE TABLE IF NOT EXISTS ai_providers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  api_key_enc TEXT,
  api_key_hint TEXT,
  timeout_ms INTEGER NOT NULL DEFAULT 30000,
  max_tokens INTEGER NOT NULL DEFAULT 2048,
  max_retries INTEGER NOT NULL DEFAULT 2,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_models (
  provider_id TEXT NOT NULL,
  model_id TEXT NOT NULL,
  fetched_at INTEGER NOT NULL,
  PRIMARY KEY (provider_id, model_id)
);
CREATE TABLE IF NOT EXISTS ai_active (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  provider_id TEXT,
  model_id TEXT
);
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  target_url TEXT NOT NULL,
  target_host TEXT NOT NULL,
  resolved_ip TEXT,
  scope TEXT NOT NULL,
  mode TEXT NOT NULL,
  modules TEXT NOT NULL,
  options TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  finished_at INTEGER,
  error TEXT,
  progress REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE TABLE IF NOT EXISTS scan_stages (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  stage_id TEXT NOT NULL,
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at INTEGER,
  finished_at INTEGER,
  error TEXT,
  summary TEXT
);
CREATE INDEX IF NOT EXISTS idx_stages_scan ON scan_stages(scan_id);
CREATE TABLE IF NOT EXISTS stage_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  stage_id TEXT,
  ts INTEGER NOT NULL,
  level TEXT NOT NULL,
  message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_logs_scan ON stage_logs(scan_id, id);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  asset TEXT NOT NULL,
  stage_id TEXT,
  tool TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new',
  description TEXT NOT NULL DEFAULT '',
  evidence TEXT NOT NULL DEFAULT '',
  component TEXT,
  recommendation TEXT,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  verification TEXT,
  ai_status TEXT NOT NULL DEFAULT 'pending',
  ai_analysis TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
CREATE TABLE IF NOT EXISTS tool_runs (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  tool_id TEXT NOT NULL,
  version TEXT,
  status TEXT NOT NULL,
  exit_code INTEGER,
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  stderr_excerpt TEXT
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS db_targets (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  db_type TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  username TEXT,
  secret_enc TEXT,
  tls_mode TEXT NOT NULL DEFAULT 'prefer',
  scope_confirmed INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS test_accounts (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  role TEXT NOT NULL,
  base_url TEXT NOT NULL,
  username TEXT,
  secret_enc TEXT,
  headers TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);
`;

export function openDb(dbPathOverride) {
  if (db) return db;
  const p = dbPathOverride || config.dbPath;
  fs.mkdirSync(path.dirname(p), { recursive: true });
  db = new DatabaseSync(p);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA busy_timeout = 5000');
  db.exec('PRAGMA foreign_keys = ON');
  db.exec(SCHEMA);
  for (const col of ['ai_status', 'ai_analysis']) {
    const has = db.prepare("SELECT COUNT(*) AS n FROM pragma_table_info('findings') WHERE name = ?").get(col).n;
    if (!has) db.exec('ALTER TABLE findings ADD COLUMN ' + col + (col === 'ai_status' ? " TEXT NOT NULL DEFAULT 'pending'" : ' TEXT'));
  }
  return db;
}

export function getDb() {
  return db || openDb();
}

export function closeDb() {
  if (db) {
    try {
      db.close();
    } catch {}
    db = null;
  }
}

/* ---------- small helpers ---------- */

export function q(sql, params = []) {
  return getDb().prepare(sql).all(...params).map((r) => ({ ...r }));
}

export function q1(sql, params = []) {
  const r = getDb().prepare(sql).get(...params);
  return r ? { ...r } : null;
}

export function run(sql, params = []) {
  return getDb().prepare(sql).run(...params);
}

export function getSetting(key, fallback = null) {
  const r = q1('SELECT value FROM settings WHERE key = ?', [key]);
  if (!r) return fallback;
  try {
    return JSON.parse(r.value);
  } catch {
    return fallback;
  }
}

export function setSetting(key, value) {
  run(
    `INSERT INTO settings(key, value) VALUES(?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
    [key, JSON.stringify(value)]
  );
}

export const DEFAULT_LIMITS = {
  heavyModulesEnabled: true, // ZAP, sqlmap, dalfox, load simulation
  availabilityEnabled: false, // DDoS & availability assessment must be explicitly enabled
  maxPortCount: 64,
  maxProbePaths: 60,
  toolTimeoutMs: 300_000,
  scanTimeoutMin: 45,
  aiBatchSize: 5,
  retainLogsDays: 30,
};

export function resourceLimits() {
  return { ...DEFAULT_LIMITS, ...(getSetting('resource_limits', {}) || {}) };
}
