import { nowMs } from '../util/ids.js';
import { q, q1, run } from '../db.js';
import { redactSecrets } from './tools-registry.js';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
export const STATUSES = ['new', 'confirmed', 'needs-verification', 'false-positive', 'fixed', 'accepted-risk'];

const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, informational: 1 };

export function normalizeSeverity(s) {
  const v = String(s || '').toLowerCase();
  if (SEVERITIES.includes(v)) return v;
  const map = { crit: 'critical', warn: 'low', note: 'informational', info: 'informational', error: 'high', moderate: 'medium' };
  return map[v] || 'informational';
}

/** Insert a finding with validation + secret redaction. Returns row id. */
export function addFinding(f) {
  const id = f.id || `f_${nowMs()}_${Math.random().toString(36).slice(2, 9)}`;
  const now = nowMs();
  const row = {
    scan_id: f.scanId,
    asset: String(f.asset || '').slice(0, 500),
    stage_id: f.stageId || null,
    tool: String(f.tool || 'unknown').slice(0, 60),
    title: String(f.title || '').slice(0, 300),
    severity: normalizeSeverity(f.severity),
    confidence: ['high', 'medium', 'low'].includes(f.confidence) ? f.confidence : 'medium',
    status: STATUSES.includes(f.status) ? f.status : 'new',
    description: redactSecrets(String(f.description || '')).slice(0, 4000),
    evidence: redactSecrets(String(f.evidence || '')).slice(0, 8000),
    component: f.component ? String(f.component).slice(0, 300) : null,
    recommendation: redactSecrets(String(f.recommendation || '')).slice(0, 2000),
    verification: f.verification ? String(f.verification).slice(0, 400) : null,
  };
  if (!row.scan_id || !row.title || !row.asset) throw new Error('finding_missing_required_fields');

  // dedupe within the same scan: same asset+title → bump last_seen + merge evidence
  const dup = q1('SELECT id, evidence FROM findings WHERE scan_id=? AND asset=? AND title=?',
    [row.scan_id, row.asset, row.title]);
  if (dup) {
    const merged = (dup.evidence + '\n---\n' + row.evidence).slice(-8000);
    run('UPDATE findings SET last_seen=?, evidence=?, severity=? WHERE id=?',
      [now, merged, rankHigher(row.severity, q1('SELECT severity FROM findings WHERE id=?', [dup.id]).severity), dup.id]);
    return dup.id;
  }
  run(
    `INSERT INTO findings(id, scan_id, asset, stage_id, tool, title, severity, confidence, status,
       description, evidence, component, recommendation, first_seen, last_seen, verification)
     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [id, row.scan_id, row.asset, row.stage_id, row.tool, row.title, row.severity, row.confidence, row.status,
      row.description, row.evidence, row.component, row.recommendation, now, now, row.verification]
  );
  return id;
}

function rankHigher(a, b) {
  return (SEV_RANK[a] || 0) >= (SEV_RANK[b] || 0) ? a : b;
}

export function findingCounts(scanId) {
  const rows = q('SELECT severity, COUNT(*) AS n FROM findings WHERE scan_id=? GROUP BY severity', [scanId]);
  const out = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const r of rows) out[r.severity] = r.n;
  return out;
}
