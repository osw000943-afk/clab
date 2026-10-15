import { Router } from 'express';
import { q, q1, run } from '../db.js';
import { STATUSES } from '../scan/normalize.js';
import { nowMs } from '../util/ids.js';

const r = Router();

/** Global findings list — filter by severity/status/scan/tool, paginated. */
r.get('/', (req, res) => {
  const page = Math.max(1, Number(req.query.page) || 1);
  const pageSize = Math.min(100, Math.max(1, Number(req.query.pageSize) || 25));
  const where = [];
  const params = [];
  for (const col of ['severity', 'status', 'scan_id', 'tool', 'confidence']) {
    const v = req.query[col.replace('_', '')] ?? req.query[col];
    if (v) { where.push('f.' + col + ' = ?'); params.push(String(v)); }
  }
  if (req.query.q) {
    where.push('(f.title LIKE ? OR f.asset LIKE ? OR f.description LIKE ?)');
    const like = '%' + String(req.query.q).slice(0, 120) + '%';
    params.push(like, like, like);
  }
  const clause = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const total = q1('SELECT COUNT(*) AS n FROM findings f ' + clause, params).n;
  const items = q(
    `SELECT f.*, s.target_url, s.target_host FROM findings f JOIN scans s ON s.id = f.scan_id ` + clause +
    ` ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.last_seen DESC LIMIT ? OFFSET ?`,
    [...params, pageSize, (page - 1) * pageSize]
  );
  res.json({ items, total, page, pageSize });
});

/** Update triage status with validation. */
r.patch('/:id', (req, res) => {
  const { status, verification } = req.body || {};
  const f = q1('SELECT * FROM findings WHERE id=?', [req.params.id]);
  if (!f) return res.status(404).json({ error: 'not_found' });
  const updates = [];
  const params = [];
  if (status) {
    if (!STATUSES.includes(status)) return res.status(400).json({ error: 'invalid_status', allowed: STATUSES });
    updates.push('status = ?');
    params.push(status);
  }
  if (verification) {
    updates.push('verification = ?');
    params.push(String(verification).slice(0, 400));
  }
  if (!updates.length) return res.status(400).json({ error: 'nothing_to_update' });
  run('UPDATE findings SET ' + updates.join(', ') + ' WHERE id = ?', [...params, req.params.id]);
  res.json({ ...q1('SELECT * FROM findings WHERE id=?', [req.params.id]) });
});

r.get('/:id', (req, res) => {
  const f = q1('SELECT * FROM findings WHERE id=?', [req.params.id]);
  if (!f) return res.status(404).json({ error: 'not_found' });
  res.json(f);
});

export default r;
