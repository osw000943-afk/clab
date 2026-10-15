import { Router } from 'express';
import { q, q1, run } from '../db.js';
import { encryptSecret, decryptSecret } from '../security/crypto.js';
import { encryptionReady } from '../config.js';
import { newId, nowMs } from '../util/ids.js';
import { assertHostPortAllowed, resolveHost, isBlockedIp } from '../security/scope.js';

const r = Router();
const TYPES = ['postgres', 'mysql', 'mongodb', 'sqlite'];
const DEFAULT_PORTS = { postgres: 5432, mysql: 3306, mongodb: 27017, sqlite: 0 };

/** List — secrets never leave the server (hint only via username presence). */
r.get('/', (req, res) => {
  const rows = q('SELECT id, name, db_type, host, port, username, tls_mode, scope_confirmed, created_at FROM db_targets ORDER BY created_at DESC');
  res.json({ items: rows.map((x) => ({ ...x, hasCredentials: !!q1('SELECT secret_enc FROM db_targets WHERE id=?', [x.id])?.secret_enc })) });
});

r.post('/', async (req, res) => {
  const { name, dbType, host, port, username, secret, tlsMode = 'prefer', scopeConfirmed } = req.body || {};
  if (!name || !dbType || !TYPES.includes(dbType)) return res.status(400).json({ error: 'invalid_db_type' });
  if (scopeConfirmed !== true) return res.status(400).json({ error: 'scope_confirmation_required' });
  if (dbType !== 'sqlite') {
    if (!host) return res.status(400).json({ error: 'host_required' });
    try {
      await assertHostPortAllowed(host, Number(port) || DEFAULT_PORTS[dbType]);
    } catch (e) {
      return res.status(400).json({ error: e.code || 'blocked', message: e.message });
    }
  } else if (!host || !String(host).startsWith('/')) {
    return res.status(400).json({ error: 'sqlite_path_required', message: 'sqlite cần đường dẫn file tuyệt đối' });
  }
  let enc = null;
  if (secret) {
    if (!encryptionReady()) return res.status(503).json({ error: 'encryption_key_missing', message: 'Cần ENCRYPTION_KEY trước khi lưu credential' });
    enc = encryptSecret(String(secret));
  }
  const id = newId('dbt');
  run(
    `INSERT INTO db_targets(id, name, db_type, host, port, username, secret_enc, tls_mode, scope_confirmed, created_at)
     VALUES(?,?,?,?,?,?,?,?,?,?)`,
    [id, String(name).slice(0, 80), dbType, String(host).slice(0, 300), Number(port) || DEFAULT_PORTS[dbType],
      username ? String(username).slice(0, 80) : null, enc, ['prefer', 'require', 'disable'].includes(tlsMode) ? tlsMode : 'prefer', 1, nowMs()]
  );
  res.status(201).json({ id });
});

r.delete('/:id', (req, res) => {
  run('DELETE FROM db_targets WHERE id=?', [req.params.id]);
  res.json({ ok: true });
});

/** Test connectivity only (TCP), no queries. */
r.post('/:id/probe', async (req, res) => {
  const t = q1('SELECT * FROM db_targets WHERE id=?', [req.params.id]);
  if (!t) return res.status(404).json({ error: 'not_found' });
  if (t.db_type === 'sqlite') {
    const fs = await import('node:fs');
    return res.json({ reachable: fs.existsSync(t.host) });
  }
  try {
    const { tcpProbe } = await import('../security/scope.js');
    const p = await tcpProbe(t.host, t.port, 5000);
    res.json({ reachable: p.open, error: p.error || null });
  } catch (e) {
    res.json({ reachable: false, error: e.message });
  }
});

export default r;
