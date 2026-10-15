import { q, q1, run } from '../db.js';
import { encryptSecret, decryptSecret, keyHint } from '../security/crypto.js';
import { newId, nowMs } from '../util/ids.js';

/**
 * OpenAI-compatible provider adapter (works with OpenAI, Nemotron/NVIDIA NIM,
 * Groq, Together, Ollama, vLLM — anything speaking /chat/completions).
 * The API key is AES-256-GCM encrypted at rest and NEVER leaves the backend.
 */

export function listProviders() {
  return q('SELECT id, name, base_url, api_key_hint, timeout_ms, max_tokens, max_retries, created_at, updated_at FROM ai_providers ORDER BY created_at');
}

export function getProvider(id) {
  return q1('SELECT id, name, base_url, api_key_hint, timeout_ms, max_tokens, max_retries FROM ai_providers WHERE id = ?', [id]);
}

/** Full provider row including decrypted key — backend use only, never serialized to clients. */
export function getProviderWithSecret(id) {
  const row = q1('SELECT * FROM ai_providers WHERE id = ?', [id]);
  if (!row) return null;
  let apiKey = null;
  if (row.api_key_enc) {
    try { apiKey = decryptSecret(row.api_key_enc); } catch { apiKey = null; }
  }
  return { ...row, apiKey };
}

export function getActive() {
  const a = q1('SELECT * FROM ai_active WHERE singleton = 1');
  if (!a || !a.provider_id) return null;
  const p = getProviderWithSecret(a.provider_id);
  return p ? { ...p, model_id: a.model_id } : null;
}

export function saveProvider({ id, name, baseUrl, apiKey, timeoutMs, maxTokens, maxRetries }) {
  const now = nowMs();
  if (id) {
    const existing = q1('SELECT id FROM ai_providers WHERE id = ?', [id]);
    if (!existing) throw new Error('provider_not_found');
    run(
      `UPDATE ai_providers SET name=?, base_url=?, timeout_ms=?, max_tokens=?, max_retries=?, updated_at=? WHERE id=?`,
      [name, baseUrl, timeoutMs, maxTokens, maxRetries, now, id]
    );
    if (apiKey) {
      run('UPDATE ai_providers SET api_key_enc=?, api_key_hint=? WHERE id=?',
        [encryptSecret(apiKey), keyHint(apiKey), id]);
    }
    return id;
  }
  const newP = newId('aip');
  run(
    `INSERT INTO ai_providers(id, name, base_url, api_key_enc, api_key_hint, timeout_ms, max_tokens, max_retries, created_at, updated_at)
     VALUES(?,?,?,?,?,?,?,?,?,?)`,
    [newP, name, baseUrl, apiKey ? encryptSecret(apiKey) : null, apiKey ? keyHint(apiKey) : null,
      timeoutMs, maxTokens, maxRetries, now, now]
  );
  return newP;
}

export function deleteProvider(id) {
  run('DELETE FROM ai_providers WHERE id = ?', [id]);
  run('DELETE FROM ai_models WHERE provider_id = ?', [id]);
  run('UPDATE ai_active SET provider_id = NULL, model_id = NULL WHERE provider_id = ?', [id]);
}

export function setActive(providerId, modelId) {
  run(
    `INSERT INTO ai_active(singleton, provider_id, model_id) VALUES(1, ?, ?)
     ON CONFLICT(singleton) DO UPDATE SET provider_id=excluded.provider_id, model_id=excluded.model_id`,
    [providerId, modelId]
  );
}

export function clearActive() {
  run('UPDATE ai_active SET provider_id = NULL, model_id = NULL WHERE singleton = 1');
}

/** Rotate only the API key of an existing provider (no other field touched). */
export function updateProviderKey(id, apiKey) {
  const existing = q1('SELECT id FROM ai_providers WHERE id = ?', [id]);
  if (!existing) throw new Error('provider_not_found');
  run('UPDATE ai_providers SET api_key_enc=?, api_key_hint=?, updated_at=? WHERE id=?',
    [encryptSecret(apiKey), keyHint(apiKey), nowMs(), id]);
  return id;
}

/** Remove the stored API key (provider keeps working only if keyless). */
export function deleteProviderKey(id) {
  run('UPDATE ai_providers SET api_key_enc=NULL, api_key_hint=NULL, updated_at=? WHERE id=?', [nowMs(), id]);
}

function normalizeBase(url) {
  return String(url).trim().replace(/\/+$/, '');
}

/** Low-level request to an OpenAI-compatible API. */
export async function providerRequest(provider, { path, method = 'GET', body, timeoutMs }) {
  const base = normalizeBase(provider.base_url);
  const url = `${base}${path}`;
  const controller = new AbortController();
  const timeout = timeoutMs || provider.timeout_ms || 30_000;
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const headers = { 'content-type': 'application/json' };
    if (provider.api_key) headers.authorization = `Bearer ${provider.api_key}`;
    const res = await fetch(url, {
      method,
      headers,
      signal: controller.signal,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* non-JSON body */ }
    return { ok: res.ok, status: res.status, json, text: text.slice(0, 4000) };
  } finally {
    clearTimeout(timer);
  }
}

export async function testConnection(providerId) {
  const p = getProviderWithSecret(providerId);
  if (!p) return { ok: false, error: 'provider_not_found' };
  try {
    const r = await providerRequest(p, { path: '/models', timeoutMs: Math.min(p.timeout_ms, 15_000) });
    if (r.ok) {
      const models = extractModels(r.json);
      return { ok: true, status: r.status, modelsFound: models.length };
    }
    // some providers don't implement /models — fall back to a tiny chat call
    const chat = await chatCompletion(p, { messages: [{ role: 'user', content: 'ping' }], maxTokens: 8 });
    if (chat.ok) return { ok: true, status: chat.status, note: 'via chat/completions (/models not available)' };
    return { ok: false, status: r.status || chat.status, error: cleanError(r.text || chat.text) };
  } catch (e) {
    return { ok: false, error: cleanError(e.message) };
  }
}

export async function testModel(providerId, modelId) {
  const p = getProviderWithSecret(providerId);
  if (!p) return { ok: false, error: 'provider_not_found' };
  const started = Date.now();
  const r = await chatCompletion(p, {
    messages: [
      { role: 'system', content: 'You are a concise security assistant. Reply with one short sentence.' },
      { role: 'user', content: 'Confirm you can analyze security findings. Reply in one sentence.' },
    ],
    model: modelId || undefined,
    maxTokens: 60,
  });
  const latencyMs = Date.now() - started;
  if (r.ok) {
    const content = r.json?.choices?.[0]?.message?.content || '';
    return { ok: true, latencyMs, reply: content.slice(0, 500), model: r.json?.model || modelId };
  }
  return { ok: false, latencyMs, error: cleanError(r.text) };
}

function extractModels(json) {
  return (json?.data || json?.models || []).map((m) => m.id || m.name).filter(Boolean);
}

export async function listModels(providerId) {
  const p = getProviderWithSecret(providerId);
  if (!p) return { ok: false, error: 'provider_not_found' };
  const r = await providerRequest(p, { path: '/models', timeoutMs: Math.min(p.timeout_ms, 15_000) });
  if (!r.ok) return { ok: false, status: r.status, error: cleanError(r.text) };
  const models = extractModels(r.json);
  saveModels(p.id, models);
  return { ok: true, models };
}

function saveModels(providerId, models) {
  const now = nowMs();
  for (const m of models.slice(0, 200)) {
    run(
      `INSERT INTO ai_models(provider_id, model_id, fetched_at) VALUES(?,?,?)
       ON CONFLICT(provider_id, model_id) DO UPDATE SET fetched_at=excluded.fetched_at`,
      [providerId, m, now]
    );
  }
}

export function cachedModels(providerId) {
  return q('SELECT model_id, fetched_at FROM ai_models WHERE provider_id = ? ORDER BY model_id', [providerId]);
}

/** Chat completion against a provider (with bounded retries). */
export async function chatCompletion(provider, { messages, model, maxTokens, temperature = 0.2, jsonMode = false }) {
  const body = {
    model: model || provider.model_id || provider.model,
    messages,
    temperature,
    max_tokens: maxTokens || provider.max_tokens || 2048,
  };
  if (jsonMode) body.response_format = { type: 'json_object' };
  const retries = provider.max_retries ?? 2;
  let last = null;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      last = await providerRequest(provider, { path: '/chat/completions', method: 'POST', body });
      if (last.ok) return last;
      if (last.status && last.status >= 400 && last.status < 500 && last.status !== 429) return last;
    } catch (e) {
      last = { ok: false, status: 0, text: e.message };
    }
    await new Promise((r) => setTimeout(r, 500 * (attempt + 1)));
  }
  return last;
}

/** Strip provider error bodies of anything sensitive before display. */
export function cleanError(text) {
  return String(text || 'unknown_error')
    .replace(/(api[_-]?key|authorization|bearer)\s*[:=]?\s*[\w\-./+]{8,}/gi, '$1=[REDACTED]')
    .slice(0, 300);
}

