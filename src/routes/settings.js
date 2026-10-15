import { Router } from 'express';
import os from 'node:os';
import fs from 'node:fs';
import { getSetting, setSetting, resourceLimits, DEFAULT_LIMITS, q1 } from '../db.js';
import { config, encryptionReady } from '../config.js';
import { sessionConfigured, purgeExpiredSessions } from '../security/session.js';
import { workerState } from '../scan/orchestrator.js';
import { getToolStatuses } from '../scan/tools-registry.js';

const r = Router();

r.get('/system', (req, res) => {
  res.json({
    limits: resourceLimits(),
    defaults: DEFAULT_LIMITS,
    env: {
      node: process.version,
      nodeEnv: config.nodeEnv,
      port: config.port,
      host: config.host,
      dataDir: config.dataDir,
      dbPath: config.dbPath,
      logDir: config.logDir,
      sessionIdleMin: config.sessionIdleMin,
      sessionAbsoluteH: config.sessionAbsoluteH,
      passwordConfigured: !!config.labPasswordHash,
      sessionSecretConfigured: sessionConfigured(),
      encryptionKeyConfigured: encryptionReady(),
    },
    externalKeys: { gsb: !!getSetting('gsb_api_key'), sucuri: !!getSetting('sucuri_api_key') },
  });
});

r.put('/system', (req, res) => {
  const b = req.body || {};
  const cur = resourceLimits();
  const next = {
    heavyModulesEnabled: b.heavyModulesEnabled !== undefined ? !!b.heavyModulesEnabled : cur.heavyModulesEnabled,
    availabilityEnabled: b.availabilityEnabled !== undefined ? !!b.availabilityEnabled : cur.availabilityEnabled,
    maxPortCount: clamp(b.maxPortCount, 1, 128, cur.maxPortCount),
    maxProbePaths: clamp(b.maxProbePaths, 5, 60, cur.maxProbePaths),
    toolTimeoutMs: clamp(b.toolTimeoutMs, 10000, 600000, cur.toolTimeoutMs),
    scanTimeoutMin: clamp(b.scanTimeoutMin, 1, 180, cur.scanTimeoutMin),
    aiBatchSize: clamp(b.aiBatchSize, 1, 20, cur.aiBatchSize),
    retainLogsDays: clamp(b.retainLogsDays, 1, 365, cur.retainLogsDays),
  };
  setSetting('resource_limits', next);
  res.json({ limits: next });
});

function clamp(v, min, max, dflt) {
  const n = Number(v);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(Math.max(Math.round(n), min), max);
}

/** Health check — no secrets, safe to poll. */
export function healthHandler(req, res) {
  purgeExpiredSessions();
  let dbOk = true;
  try { q1('SELECT 1 AS x'); } catch { dbOk = false; }
  let diskFree = null;
  try {
    const st = fs.statfsSync(config.dataDir);
    diskFree = Math.round((st.bavail * st.bsize) / 1024 / 1024);
  } catch { /* statfs may be unavailable */ }
  const mem = process.memoryUsage();
  const rssMB = Math.round(mem.rss / 1024 / 1024);
  res.json({
    status: dbOk ? 'ok' : 'degraded',
    uptimeSec: Math.round(process.uptime()),
    memory: { rssMB, heapMB: Math.round(mem.heapUsed / 1024 / 1024), totalSystemMB: Math.round(os.totalmem() / 1024 / 1024) },
    diskFreeMB: diskFree,
    database: dbOk ? 'ok' : 'error',
    worker: workerState(),
    tools: { total: Object.keys(getToolStatuses()).length },
    auth: { passwordConfigured: !!config.labPasswordHash, sessionSecretConfigured: sessionConfigured(), encryptionKeyConfigured: encryptionReady() },
    ai: { configured: !!q1('SELECT provider_id FROM ai_active WHERE provider_id IS NOT NULL') },
    timestamp: new Date().toISOString(),
  });
}

r.get('/health', healthHandler);

export default r;
