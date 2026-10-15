import { Router } from 'express';
import { q, q1 } from '../db.js';
import { workerState } from '../scan/orchestrator.js';
import { getToolStatuses } from '../scan/tools-registry.js';

const r = Router();

/** Real dashboard stats — every number comes from the database. */
r.get('/stats', (req, res) => {
  const totalScans = q1('SELECT COUNT(*) AS n FROM scans').n;
  const byStatus = {};
  for (const row of q('SELECT status, COUNT(*) AS n FROM scans GROUP BY status')) byStatus[row.status] = row.n;
  const uniqueAssets = q1('SELECT COUNT(DISTINCT target_host) AS n FROM scans').n;
  const severity = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const row of q('SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity')) severity[row.severity] = row.n;

  const recentScans = q(
    'SELECT id, target_url, target_host, mode, status, created_at, started_at, finished_at, progress FROM scans ORDER BY created_at DESC LIMIT 8'
  );
  const recentFindings = q(
    `SELECT id, scan_id, title, severity, status, asset, tool, last_seen FROM findings
     WHERE severity IN ('critical','high','medium') ORDER BY last_seen DESC LIMIT 8`
  );

  // tool success rate from real tool_runs
  const tr = q('SELECT tool_id, status, COUNT(*) AS n FROM tool_runs GROUP BY tool_id, status');
  const toolRates = {};
  for (const row of tr) {
    toolRates[row.tool_id] = toolRates[row.tool_id] || { completed: 0, failed: 0 };
    if (row.status === 'completed') toolRates[row.tool_id].completed += row.n;
    else if (row.status === 'failed') toolRates[row.tool_id].failed += row.n;
  }
  for (const k of Object.keys(toolRates)) {
    const t = toolRates[k];
    t.rate = t.completed + t.failed ? Math.round((t.completed / (t.completed + t.failed)) * 100) : null;
  }

  // trend: findings per completed scan (last 12)
  const trend = q(
    `SELECT s.id, s.created_at, s.target_host,
       (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS total,
       (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.severity IN ('critical','high')) AS serious
     FROM scans s WHERE s.status='completed' ORDER BY s.created_at DESC LIMIT 12`
  ).reverse();

  const activity = [
    ...recentScans.map((s) => ({ kind: 'scan', at: s.created_at, text: s.mode + ' · ' + s.target_host, status: s.status, id: s.id })),
    ...recentFindings.map((f) => ({ kind: 'finding', at: f.last_seen, text: f.title.slice(0, 120), severity: f.severity, id: f.scan_id })),
  ].sort((a, b) => b.at - a.at).slice(0, 14);

  const tools = getToolStatuses();
  const toolSummary = { available: 0, missing: 0, disabled: 0, 'needs-config': 0, failed: 0, unsupported: 0 };
  for (const t of Object.values(tools)) {
    if (toolSummary[t.status] !== undefined) toolSummary[t.status]++;
  }

  res.json({
    totalScans, uniqueAssets, byStatus, severity,
    openCritical: severity.critical + severity.high,
    worker: workerState(),
    recentScans, recentFindings, toolRates, trend, activity, toolSummary,
    aiConfigured: !!(q1('SELECT provider_id FROM ai_active WHERE provider_id IS NOT NULL')),
  });
});

export default r;
