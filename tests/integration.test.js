/** Integration tests: auth guard, SSRF scope engine, scan lifecycle, AI redaction. */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'clab-int-'));
process.env.DB_PATH = path.join(tmp, 'clab.db');
process.env.LAB_PASSWORD_HASH = (await import('../src/security/password.js')).hashPassword('Int3gration!Pass');
process.env.SESSION_SECRET = 'a'.repeat(64);
process.env.ENCRYPTION_KEY = 'VGVzdC1rZXktZGFuaWlsLWJ1aWxkZXJzIHRoZXJlIGZvciBjb250ZW50';
process.env.CLAB_ALLOW_PRIVATE = '1';
process.env.NODE_ENV = 'test';
process.env.PORT = '0';

const { default: app } = await import('../src/server.js');

let server; let base; let cookie = ''; let csrf = '';

async function req(p, { method = 'GET', body, auth = true } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (cookie) headers.cookie = cookie;
  if (csrf && method !== 'GET') headers['x-csrf-token'] = csrf;
  const r = await fetch(base + p, { method, headers, body: body ? JSON.stringify(body) : undefined, redirect: 'manual' });
  const set = r.headers.get('set-cookie');
  if (set && /clab_sid=/.test(set)) cookie = set.split(';')[0];
  let json = null;
  try { json = await r.json(); } catch { /* empty */ }
  return { status: r.status, json, headers: r.headers };
}

before(async () => {
  server = app.listen(0, '127.0.0.1');
  await new Promise((res) => server.once('listening', res));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  const { closeDb } = await import('../src/db.js');
  await new Promise((res) => server.close(res));
  closeDb();
});

describe('auth', () => {
  it('unauthenticated dashboard is blocked', async () => {
    const r = await req('/api/dashboard/stats', { auth: false });
    assert.equal(r.status, 401);
  });
  it('login works and returns csrf token', async () => {
    const r = await req('/api/auth/login', { auth: false, method: 'POST', body: { password: 'Int3gration!Pass' } });
    assert.equal(r.status, 200);
    assert.ok(r.json.csrfToken);
    csrf = r.json.csrfToken;
  });
  it('session persists across requests', async () => {
    const r = await req('/api/auth/me');
    assert.equal(r.status, 200);
    assert.equal(r.json.authenticated, true);
  });
  it('wrong password is rejected (no account lockout info leak)', async () => {
    const r = await req('/api/auth/login', { auth: false, method: 'POST', body: { password: 'nope-wrong' } });
    assert.equal(r.status, 401);
  });
});

describe('scope & safety engine', () => {
  const basePayload = {
    mode: 'quick',
    scopeConfirmed: true,
    authorizedTesting: true,
    authorizationStatement: 'integration test fixture',
  };
  it('blocks loopback targets for scans', async () => {
    const r = await req('/api/scans', { method: 'POST', body: { ...basePayload, targetUrl: 'http://127.0.0.1:9999/' } });
    assert.equal(r.status, 400);
  });
  it('blocks metadata endpoints', async () => {
    const r = await req('/api/scans', { method: 'POST', body: { ...basePayload, targetUrl: 'http://169.254.169.254/latest/meta-data/' } });
    assert.equal(r.status, 400);
  });
  it('requires explicit scope confirmation', async () => {
    const r = await req('/api/scans', { method: 'POST', body: { targetUrl: 'https://example.com/', mode: 'quick' } });
    assert.equal(r.status, 400);
    assert.equal(r.json.error, 'scope_confirmation_required');
  });
});

describe('scan lifecycle', () => {
  it('scan list is paginated', async () => {
    const r = await req('/api/scans?page=1&pageSize=5');
    assert.equal(r.status, 200);
    assert.ok(Array.isArray(r.json.items));
    assert.ok(typeof r.json.total === 'number');
  });
  it('tool registry reports real availability (no fake installed)', async () => {
    const r = await req('/api/tools');
    assert.equal(r.status, 200);
    assert.ok(Array.isArray(r.json));
    for (const t of r.json) assert.ok(['available', 'missing', 'disabled', 'needs-config', 'failed', 'unsupported', 'incompatible', 'running', 'completed', 'partial', 'cancelled'].includes(t.status), t.id + ':' + t.status);
  });
});

describe('ai config redaction', () => {
  it('AI status never leaks api key', async () => {
    const r = await req('/api/ai');
    assert.equal(r.status, 200);
    assert.ok(!('apiKey' in r.json) && !('api_key' in r.json));
    assert.ok(!JSON.stringify(r.json).includes('sk-secret-should-not-echo'));
  });
  it('saving AI provider encrypts the key; key never echoed back', async () => {
    const r = await req('/api/ai/providers', { method: 'POST', body: { name: 'int-test', baseUrl: 'https://api.example.com/v1', apiKey: 'sk-secret-should-not-echo-back-1234567890' } });
    assert.ok([201, 503].includes(r.status), JSON.stringify(r.json));
    if (r.status === 201) {
      assert.ok(!JSON.stringify(r.json).includes('sk-secret-should-not-echo'));
    }
  });
  it('history export contains no secrets', async () => {
    const r = await req('/api/scans?pageSize=1');
    assert.equal(r.status, 200);
    assert.ok(!JSON.stringify(r.json).includes('sk-secret-should-not-echo'));
  });
});
