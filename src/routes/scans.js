import { Router } from 'express';
import { q, q1, run, resourceLimits } from '../db.js';
import { nowMs, newId } from '../util/ids.js';
import { assertUrlAllowed } from '../security/scope.js';
import { createScan, cancelScan, MODES, resolveStageIds } from '../scan/orchestrator.js';
import { STAGES } from '../scan/stages/index.js';
import { findingCounts } from '../scan/normalize.js';

const r = Router();

/** Create a scan — scope confirmation is mandatory; SSRF validation happens here AND in s01. */
r.post('/', async (req, res) => {
  try {
    const { targetUrl, mode = 'standard', modules = [], options = {}, scopeConfirmed, authorizedTesting } = req.body || {};
    if (!targetUrl) return res.status(400).json({ error: 'target_required' });
    if (scopeConfirmed !== true || authorizedTesting !== true) {
      return res.status(400).json({
        error: 'scope_confirmation_required',
        message: 'Bạn phải xác nhận có phạm vi và quyền kiểm thử trước khi quét.',
      });
    }
    if (!MODES[mode]) return res.status(400).json({ error: 'invalid_mode' });
    let v;
    try {
      v = await assertUrlAllowed(targetUrl);
    } catch (e) {
      return res.status(400).json({ error: e.code || 'scope_rejected', message: e.message });
    }
    const limits = resourceLimits();
    const cleanOpts = sanitizeOptions(options, limits);
    const scanId = createScan({
      targetUrl: v.url.toString(), mode, modules, options: cleanOpts,
      scope: {
        host: v.host, port: v.port, ips: v.ips, scheme: v.scheme,
        confirmedAt: nowMs(), confirmedBy: 'owner',
        authorizationStatement: String(req.body.authorizationStatement || '').slice(0, 500),
      },
    });
    run('UPDATE scans SET target_host=? WHERE id=?', [v.host, scanId]);
    res.status(201).json({ id: scanId, mode, stages: resolveStageIds(mode, modules) });
  } catch (e) {
    res.status(500).json({ error: 'create_failed', message: e.message });
  }
});

function sanitizeOptions(o, limits) {
  const out = {};
  if (o.ssllabs) out.ssllabs = true;
  if (o.zap) out.zap = !!limits.heavyModulesEnabled;
  if (o.availability) out.availability = !!limits.availabilityEnabled;
  out.loadRps = Math.min(Math.max(Number(o.loadRps) || 5, 1), 20);
  out.loadSeconds = Math.min(Math.max(Number(o.loadSeconds) || 10, 3), 60);
  if (typeof o.localPath === 'string') out.localPath = o.localPath.slice(0, 400);
  if (typeof o.captureFile === 'string') out.captureFile = o.captureFile.slice(0, 400);
  if (typeof o.loginPath === 'string') out.loginPath = o.loginPath.slice(0, 120);
  if (Array.isArray(o.dbTargetIds)) out.dbTargetIds = o.dbTargetIds.map(String).slice(0, 20);
  if (Array.isArray(o.testAccountIds)) out.testAccountIds = o.testAccountIds.map(String).slice(0, 20);
  if (Array.isArray(o.authzEndpoints)) out.authzEndpoints = o.authzEndpoints.map(String).slice(0, 20);
  if (Array.isArray(o.idorPairs)) out.idorPairs = o.idorPairs.slice(0, 5);
  if (typeof o.wpscanToken === 'string') out.wpscanToken = o.wpscanToken.slice(0, 200);
  return out;
}

/** List scans with search/filter/pagination/sort. */
r.get('/', (req, res) => {
  const page = Math.max(1, Number(req.query.page) || 1);
  const pageSize = Math.min(50, Math.max(1, Number(req.query.pageSize) || 20));
  const where = [];
  const params = [];
  if (req.query.status) { where.push('s.status = ?'); params.push(String(req.query.status)); }
  if (req.query.mode) { where.push('s.mode = ?'); params.push(String(req.query.mode)); }
  if (req.query.q) {
    where.push('(s.target_url LIKE ? OR s.target_host LIKE ? OR s.id LIKE ?)');
    const like = '%' + String(req.query.q).slice(0, 100) + '%';
    params.push(like, like, like);
  }
  const sortMap = { created_desc: 's.created_at DESC', created_asc: 's.created_at ASC', status: 's.status ASC' };
  const order = sortMap[req.query.sort] || 's.created_at DESC';
  const clause = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const total = q1('SELECT COUNT(*) AS n FROM scans s ' + clause, params).n;
  const rows = q(
    'SELECT s.* FROM scans s ' + clause + ' ORDER BY ' + order + ' LIMIT ? OFFSET ?',
    [...params, pageSize, (page - 1) * pageSize]
  ).map((s) => ({
    ...s, scope: safeParse(s.scope), modules: safeParse(s.modules), options: maskOptions(safeParse(s.options)),
    findings: findingCounts(s.id),
  }));
  res.json({ items: rows, total, page, pageSize });
});

/** Full detail: scan + stages + logs tail + findings. */
r.get('/:id', (req, res) => {
  const s = q1('SELECT * FROM scans WHERE id=?', [req.params.id]);
  if (!s) return res.status(404).json({ error: 'not_found' });
  const stages = q('SELECT * FROM scan_stages WHERE scan_id=? ORDER BY rowid', [s.id]);
  const logs = q('SELECT * FROM stage_logs WHERE scan_id=? ORDER BY id DESC LIMIT 300', [s.id]).reverse();
  const findings = q(`SELECT * FROM findings WHERE scan_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, last_seen DESC`, [s.id]);
  const toolRuns = q('SELECT * FROM tool_runs WHERE scan_id=? ORDER BY started_at', [s.id]);
  res.json({
    ...s, scope: safeParse(s.scope), modules: safeParse(s.modules), options: maskOptions(safeParse(s.options)),
    stages, logs, findings, toolRuns, counts: findingCounts(s.id),
  });
});

r.get('/:id/logs', (req, res) => {
  const after = Number(req.query.after) || 0;
  const limit = Math.min(1000, Number(req.query.limit) || 300);
  const rows = q('SELECT * FROM stage_logs WHERE scan_id=? AND id>? ORDER BY id LIMIT ?', [req.params.id, after, limit]);
  res.json({ items: rows });
});

r.post('/:id/cancel', (req, res) => {
  const ok = cancelScan(req.params.id);
  res.json({ ok, message: ok ? 'Đang hủy…' : 'Lượt quét không ở trạng thái có thể hủy' });
});

/** Re-run (fresh confirmation required on the request). */
r.post('/:id/rerun', async (req, res) => {
  const s = q1('SELECT * FROM scans WHERE id=?', [req.params.id]);
  if (!s) return res.status(404).json({ error: 'not_found' });
  if (req.body?.scopeConfirmed !== true || req.body?.authorizedTesting !== true) {
    return res.status(400).json({ error: 'scope_confirmation_required' });
  }
  try {
    const v = await assertUrlAllowed(s.target_url);
    const scanId = createScan({
      targetUrl: s.target_url, mode: s.mode, modules: safeParse(s.modules),
      options: safeParse(s.options), scope: safeParse(s.scope),
    });
    run('UPDATE scans SET target_host=? WHERE id=?', [v.host, scanId]);
    res.status(201).json({ id: scanId });
  } catch (e) {
    res.status(400).json({ error: e.code || 'rerun_failed', message: e.message });
  }
});

/** Delete with explicit confirmation. */
r.delete('/:id', (req, res) => {
  if (req.query.confirm !== 'yes') return res.status(400).json({ error: 'confirm_required' });
  const s = q1('SELECT status FROM scans WHERE id=?', [req.params.id]);
  if (!s) return res.status(404).json({ error: 'not_found' });
  if (s.status === 'running' || s.status === 'cancelling') return res.status(409).json({ error: 'scan_running' });
  run('DELETE FROM findings WHERE scan_id=?', [req.params.id]);
  run('DELETE FROM stage_logs WHERE scan_id=?', [req.params.id]);
  run('DELETE FROM scan_stages WHERE scan_id=?', [req.params.id]);
  run('DELETE FROM tool_runs WHERE scan_id=?', [req.params.id]);
  run('DELETE FROM scans WHERE id=?', [req.params.id]);
  res.json({ ok: true });
});

/** Compare two scans (new/resolved findings). */
r.get('/:a/compare/:b', (req, res) => {
  const a = q1('SELECT * FROM scans WHERE id=?', [req.params.a]);
  const b = q1('SELECT * FROM scans WHERE id=?', [req.params.b]);
  if (!a || !b) return res.status(404).json({ error: 'not_found' });
  const fa = q('SELECT asset, title, severity, status FROM findings WHERE scan_id=?', [a.id]);
  const fb = q('SELECT asset, title, severity, status FROM findings WHERE scan_id=?', [b.id]);
  const ka = new Map(fa.map((f) => [f.asset + '|' + f.title, f]));
  const kb = new Map(fb.map((f) => [f.asset + '|' + f.title, f]));
  const onlyInA = [...ka.keys()].filter((k) => !kb.has(k)).map((k) => ka.get(k));
  const onlyInB = [...kb.keys()].filter((k) => !ka.has(k)).map((k) => kb.get(k));
  const shared = [...ka.keys()].filter((k) => kb.has(k)).map((k) => ({ a: ka.get(k), b: kb.get(k) }));
  res.json({
    a: { id: a.id, url: a.target_url, createdAt: a.created_at, counts: findingCounts(a.id) },
    b: { id: b.id, url: b.target_url, createdAt: b.created_at, counts: findingCounts(b.id) },
    newInB: onlyInB, resolvedSinceA: onlyInA, shared: shared.length, sharedItems: shared.slice(0, 50),
  });
});

/** Export JSON / CSV / HTML — no secrets, always stamped with scan id + time. */
r.get('/:id/export', (req, res) => {
  const format = req.query.format || 'json';
  const s = q1('SELECT * FROM scans WHERE id=?', [req.params.id]);
  if (!s) return res.status(404).json({ error: 'not_found' });
  const findings = q('SELECT * FROM findings WHERE scan_id=? ORDER BY severity, last_seen DESC', [s.id]);
  const stages = q('SELECT * FROM scan_stages WHERE scan_id=?', [s.id]);
  const stamp = { scanId: s.id, generatedAt: new Date().toISOString(), target: s.target_url, mode: s.mode, status: s.status };

  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="clab-' + s.id + '.csv"');
    const esc = (v) => '"' + String(v ?? '').replace(/"/g, '""').replace(/\r?\n/g, ' ') + '"';
    const lines = ['# scan,' + esc(s.id) + ',generated,' + stamp.generatedAt,
      ['finding_id', 'severity', 'confidence', 'status', 'tool', 'stage', 'title', 'asset', 'recommendation', 'ai_status'].join(',')];
    for (const f of findings) {
      lines.push([f.id, f.severity, f.confidence, f.status, f.tool, f.stage_id, f.title, f.asset, f.recommendation, f.ai_status]
        .map(esc).join(','));
    }
    return res.send(lines.join('\n'));
  }
  if (format === 'html') {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="clab-' + s.id + '.html"');
    return res.send(renderHtml(stamp, s, stages, findings));
  }
  res.setHeader('Content-Disposition', 'attachment; filename="clab-' + s.id + '.json"');
  res.json({ ...stamp, scan: { ...s, scope: safeParse(s.scope), options: maskOptions(safeParse(s.options)) }, stages, findings });
});

function maskOptions(o) {
  const c = { ...o };
  delete c.wpscanToken;
  return c;
}
function safeParse(s) { try { return JSON.parse(s); } catch { return null; } }
function esc(s) { return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

function renderHtml(stamp, s, stages, findings) {
  const sevColor = { critical: '#7f1d1d', high: '#b91c1c', medium: '#b45309', low: '#a16207', informational: '#0369a1' };
  return '<!doctype html><html lang="vi"><head><meta charset="utf-8"><title>clab report ' + esc(stamp.scanId) + '</title>' +
    '<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#0f172a}table{border-collapse:collapse;width:100%;margin:1rem0}th,td{border:1px solid #cbd5e1;padding:.4rem.6rem;font-size:.85rem;text-align:left}th{background:#f1f5f9}.sev{font-weight:700}code{background:#f1f5f9;padding:0.1rem 0.3rem}</style></head><body>' +
    '<h1>clab — WhiteHat Lab report</h1>' +
    '<p><b>Scan ID:</b> ' + esc(stamp.scanId) + '<br><b>Generated:</b> ' + esc(stamp.generatedAt) +
    '<br><b>Target:</b> ' + esc(stamp.target) + '<br><b>Mode:</b> ' + esc(stamp.mode) + ' · <b>Status:</b> ' + esc(stamp.status) + '</p>' +
    '<h2>Stages</h2><table><tr><th>Stage</th><th>Name</th><th>Status</th><th>Error</th></tr>' +
    stages.map((st) => '<tr><td>' + esc(st.stage_id) + '</td><td>' + esc(st.name) + '</td><td>' + esc(st.status) + '</td><td>' + esc(st.error || '') + '</td></tr>').join('') +
    '</table><h2>Findings (' + findings.length + ')</h2><table><tr><th>Severity</th><th>Title</th><th>Asset</th><th>Tool</th><th>Confidence</th><th>Status</th><th>Recommendation</th></tr>' +
    findings.map((f) => '<tr><td class="sev" style="color:' + (sevColor[f.severity] || '#334155') + '">' + esc(f.severity) + '</td><td>' + esc(f.title) + '</td><td>' + esc(f.asset) + '</td><td>' + esc(f.tool) + '</td><td>' + esc(f.confidence) + '</td><td>' + esc(f.status) + '</td><td>' + esc(f.recommendation || '') + '</td></tr>').join('') +
    '</table><footer><p>Báo cáo này tách bạch evidence (dữ liệu thô từ công cụ) với diễn giải AI. Mọi secrets đã bị cắt.</p></footer></body></html>';
}

export default r;
