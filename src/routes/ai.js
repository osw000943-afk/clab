import { Router } from 'express';
import { encryptionReady } from '../config.js';
import {
  listProviders, getProvider, saveProvider, deleteProvider, setActive, clearActive,
  getActive, testConnection, testModel, listModels, cachedModels, updateProviderKey, deleteProviderKey,
} from '../ai/provider.js';
import { analyzeScan } from '../ai/ai-analyze.js';
import { q1 } from '../db.js';

const r = Router();

r.get('/', (req, res) => {
  const active = q1('SELECT provider_id, model_id FROM ai_active WHERE singleton=1');
  res.json({
    encryptionReady: encryptionReady(),
    providers: listProviders(), // api_key_hint only — never the key
    active: active || { provider_id: null, model_id: null },
  });
});

r.post('/providers', (req, res) => {
  if (!encryptionReady()) {
    return res.status(503).json({
      error: 'encryption_key_missing',
      message: 'Chưa cấu hình ENCRYPTION_KEY — không thể lưu API key. Tạo key: npm run gen-key, thêm vào .env và khởi động lại.',
    });
  }
  const { id, name, baseUrl, apiKey, timeoutMs, maxTokens, maxRetries } = req.body || {};
  if (!name || !baseUrl) return res.status(400).json({ error: 'name_baseurl_required' });
  try {
    const u = new URL(baseUrl);
    if (!['http:', 'https:'].includes(u.protocol)) throw new Error('bad protocol');
  } catch {
    return res.status(400).json({ error: 'invalid_base_url' });
  }
  try {
    const pid = saveProvider({
      id: id || null, name: String(name).slice(0, 80), baseUrl: String(baseUrl).slice(0, 300),
      apiKey: apiKey ? String(apiKey).slice(0, 400) : null,
      timeoutMs: Math.min(Math.max(Number(timeoutMs) || 30000, 3000), 300000),
      maxTokens: Math.min(Math.max(Number(maxTokens) || 2048, 64), 32768),
      maxRetries: Math.min(Math.max(Number(maxRetries) || 2, 0), 5),
    });
    res.status(201).json({ id: pid, providers: listProviders() });
  } catch (e) {
    res.status(500).json({ error: 'save_failed', message: e.message });
  }
});

r.post('/:id/test-connection', async (req, res) => {
  const r2 = await testConnection(req.params.id);
  res.json(r2);
});

r.post('/:id/test-model', async (req, res) => {
  const modelId = req.body?.modelId;
  const r2 = await testModel(req.params.id, modelId);
  res.json(r2);
});

r.get('/:id/models', async (req, res) => {
  const r2 = await listModels(req.params.id);
  if (r2.ok) return res.json(r2);
  // fall back to cache so the UI still works offline
  const cached = cachedModels(req.params.id);
  res.status(200).json({ ok: false, status: r2.status, error: r2.error, cached: cached.map((m) => m.model_id) });
});

r.post('/activate', (req, res) => {
  const { providerId, modelId } = req.body || {};
  if (!providerId || !modelId) return res.status(400).json({ error: 'provider_and_model_required' });
  if (!getProvider(providerId)) return res.status(404).json({ error: 'provider_not_found' });
  setActive(providerId, String(modelId).slice(0, 120));
  res.json({ ok: true });
});

r.post('/deactivate', (req, res) => {
  clearActive();
  res.json({ ok: true });
});

r.delete('/providers/:id', (req, res) => {
  deleteProvider(req.params.id);
  res.json({ ok: true, providers: listProviders() });
});

r.post('/:id/rotate-key', (req, res) => {
  if (!encryptionReady()) return res.status(503).json({ error: 'encryption_key_missing' });
  const { apiKey } = req.body || {};
  if (!apiKey) return res.status(400).json({ error: 'api_key_required' });
  try {
    updateProviderKey(req.params.id, String(apiKey).slice(0, 400));
  } catch (e) { return res.status(e.message === 'provider_not_found' ? 404 : 500).json({ error: e.message }); }
  res.json({ ok: true, providers: listProviders() });
});

/** Delete the stored API key (keep the provider entry). */
r.delete('/:id/key', (req, res) => {
  try {
    deleteProviderKey(req.params.id);
  } catch (e) { return res.status(e.message === 'provider_not_found' ? 404 : 500).json({ error: e.message }); }
  res.json({ ok: true, providers: listProviders() });
});

/** Manual trigger: analyze pending findings of a scan (owner action). */
r.post('/analyze/:scanId', async (req, res) => {
  const result = await analyzeScan(req.params.scanId);
  res.json(result);
});

export default r;
