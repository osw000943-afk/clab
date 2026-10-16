import { Router } from 'express';
import { TOOLS, refreshToolStatuses, getToolStatuses, setToolDisabled, getTool } from '../scan/tools-registry.js';
import { getSetting, setSetting } from '../db.js';

const r = Router();

r.get('/', (req, res) => {
  const statuses = getToolStatuses();
  res.json(TOOLS.map((t) => ({
    id: t.id, name: t.name, category: t.category, mode: t.mode, license: t.license,
    heavy: !!t.heavy, manual: !!t.manual, builtin: !!t.builtin, stages: t.stages, desc: t.desc,
    needsOptIn: !!t.needsOptIn,
    status: statuses[t.id]?.status || 'missing',
    version: statuses[t.id]?.version || null,
    detail: statuses[t.id]?.detail || 'Chưa kiểm tra',
    checkedAt: statuses[t.id]?.checkedAt || null,
    userDisabled: !!statuses[t.id]?.userDisabled,
  })));
});

r.post('/refresh', async (req, res) => {
  const map = await refreshToolStatuses();
  res.json({ ok: true, count: Object.keys(map).length });
});

r.post('/:id/enable', (req, res) => {
  if (!getTool(req.params.id)) return res.status(404).json({ error: 'not_found' });
  setToolDisabled(req.params.id, false);
  refreshToolStatuses().then(() => res.json({ ok: true }));
});

r.post('/:id/disable', (req, res) => {
  if (!getTool(req.params.id)) return res.status(404).json({ error: 'not_found' });
  setToolDisabled(req.params.id, true);
  res.json({ ok: true });
});

/** External-service keys (write-only, masked) used by reputation tools. */
const EXT_KEYS = ['gsb_api_key', 'sucuri_api_key', 'virustotal_api_key', 'urlscan_api_key', 'builtwith_api_key', 'wazuh_api'];
r.get('/external-keys', (req, res) => {
  res.json({
    gsb_api_key: !!getSetting('gsb_api_key'),
    sucuri_api_key: !!getSetting('sucuri_api_key'),
    virustotal_api_key: !!getSetting('virustotal_api_key'),
    urlscan_api_key: !!getSetting('urlscan_api_key'),
    builtwith_api_key: !!getSetting('builtwith_api_key'),
    wazuh_api: !!getSetting('wazuh_api'),
    sucuri_monitor_domain: getSetting('sucuri_monitor_domain') || null,
  });
});

r.post('/external-keys', (req, res) => {
  const b = req.body || {};
  for (const k of EXT_KEYS) {
    if (typeof b[k] === 'string' && b[k].length) setSetting(k, b[k].slice(0, 300));
  }
  if (typeof b.sucuri_monitor_domain === 'string') setSetting('sucuri_monitor_domain', b.sucuri_monitor_domain.slice(0, 120));
  refreshToolStatuses().then(() => res.json({ ok: true }));
});

r.delete('/external-keys', (req, res) => {
  for (const k of EXT_KEYS) setSetting(k, '');
  refreshToolStatuses().then(() => res.json({ ok: true }));
});

export default r;
