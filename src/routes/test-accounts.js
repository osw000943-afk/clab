import { Router } from 'express';
import { q, q1, run } from '../db.js';
import { encryptSecret } from '../security/crypto.js';
import { encryptionReady } from '../config.js';
import { newId, nowMs } from '../util/ids.js';
import { assertUrlAllowed } from '../security/scope.js';

const r = Router();

r.get('/', (req, res) => {
  const rows = q('SELECT id, label, role, base_url, username, headers, created_at FROM test_accounts ORDER BY created_at');
  res.json({ items: rows.map((x) => ({ ...x, hasSecret: !!q1('SELECT secret_enc FROM test_accounts WHERE id=?', [x.id])?.secret_enc })) });
});

r.post('/', async (req, res) => {
  const { label, role, baseUrl, username, secret, headers } = req.body || {};
  if (!label || !role || !baseUrl) return res.status(400).json({ error: 'label_role_baseurl_required' });
  try {
    await assertUrlAllowed(baseUrl);
  } catch (e) {
    return res.status(400).json({ error: e.code || 'blocked', message: e.message });
  }
  let enc = null;
  if (secret) {
    if (!encryptionReady()) return res.status(503).json({ error: 'encryption_key_missing' });
    enc = encryptSecret(String(secret));
  }
  let hdrs = '{}';
  try {
    const parsed = JSON.parse(headers || '{}');
    if (typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('bad');
    hdrs = JSON.stringify(parsed).slice(0, 2000);
  } catch {
    return res.status(400).json({ error: 'invalid_headers_json' });
  }
  const id = newId('acc');
  run(
    `INSERT INTO test_accounts(id, label, role, base_url, username, secret_enc, headers, created_at) VALUES(?,?,?,?,?,?,?,?)`,
    [id, String(label).slice(0, 80), String(role).slice(0, 40), String(baseUrl).slice(0, 300),
      username ? String(username).slice(0, 120) : null, enc, hdrs, nowMs()]
  );
  res.status(201).json({ id });
});

r.delete('/:id', (req, res) => {
  run('DELETE FROM test_accounts WHERE id=?', [req.params.id]);
  res.json({ ok: true });
});

export default r;
