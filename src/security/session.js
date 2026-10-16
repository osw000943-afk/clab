import crypto from 'node:crypto';
import { getDb, run, q1, q } from '../db.js';
import { config, sessionSecretBuffer } from '../config.js';
import { nowMs } from '../util/ids.js';

const COOKIE = 'clab_sid';

function hashToken(token) {
  return crypto.createHmac('sha256', sessionSecretBuffer() || Buffer.alloc(32)).update(token).digest('hex');
}

export function sessionConfigured() {
  return Boolean(config.sessionSecret && config.sessionSecret.length >= 16);
}

/** Create a fresh session (call AFTER successful authentication to prevent fixation). */
export function createSession({ ip, ua }) {
  const id = crypto.randomUUID();
  const token = crypto.randomBytes(32).toString('base64url');
  const now = nowMs();
  const expires = now + config.sessionAbsoluteH * 3600_000;
  run(
    `INSERT INTO sessions(id, token_hash, csrf, created_at, last_seen, expires_at, ip, ua)
     VALUES(?,?,?,?,?,?,?,?)`,
    [id, hashToken(token), crypto.randomBytes(24).toString('base64url'), now, now, expires, ip || '', (ua || '').slice(0, 200)]
  );
  return { id, token, csrf: q1('SELECT csrf FROM sessions WHERE id = ?', [id]).csrf };
}

export function destroySession(sessionId) {
  run('DELETE FROM sessions WHERE id = ?', [sessionId]);
}

export function destroyAllSessions() {
  run('DELETE FROM sessions');
}

/**
 * Resolve and touch a session from cookie value. Enforces absolute and idle expiry.
 * Returns { session } or { expired: true } or {}.
 */
export function resolveSession(cookieValue) {
  if (!cookieValue || !sessionConfigured()) return {};
  const token = String(cookieValue);
  const row = q1('SELECT * FROM sessions WHERE token_hash = ?', [hashToken(token)]);
  if (!row) return {};
  const now = nowMs();
  const idleMs = config.sessionIdleMin * 60_000;
  if (row.expires_at < now || now - row.last_seen > idleMs) {
    destroySession(row.id);
    return { expired: true };
  }
  run('UPDATE sessions SET last_seen = ? WHERE id = ?', [now, row.id]);
  return { session: { id: row.id, csrf: row.csrf, createdAt: row.created_at } };
}

export function setSessionCookie(res, token) {
  const secure = isHttpsRequest(res);
  res.append('Set-Cookie', [
    `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}; Max-Age=${config.sessionAbsoluteH * 3600}`,
  ]);
}

export function clearSessionCookie(res) {
  res.append('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

export function readSessionCookie(req) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === COOKIE) return v.join('=');
  }
  return null;
}

function isHttpsRequest(res) {
  return res.req.secure || res.req.headers['x-forwarded-proto'] === 'https';
}

export function csrfOk(req, session) {
  const method = (req.method || 'GET').toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return true;
  const sent = req.headers['x-csrf-token'];
  if (!sent || !session) return false;
  const a = Buffer.from(String(sent));
  const b = Buffer.from(session.csrf);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/* ---------- login brute-force protection (per ip+username) ---------- */

const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60_000;

export function loginBlocked(ip, username) {
  const since = nowMs() - WINDOW_MS;
  const rows = q('SELECT success FROM login_attempts WHERE ip = ? AND username = ? AND ts > ?', [ip, username, since]);
  const recentFails = rows.filter((r) => !r.success).length;
  return recentFails >= MAX_ATTEMPTS;
}

export function recordLoginAttempt(ip, username, success) {
  run('INSERT INTO login_attempts(ip, username, ts, success) VALUES(?,?,?,?)', [ip, username, nowMs(), success ? 1 : 0]);
  if (success) {
    run('DELETE FROM login_attempts WHERE ip = ? AND username = ? AND success = 1', [ip, username]);
  }
  // opportunistic cleanup
  run('DELETE FROM login_attempts WHERE ts < ?', [nowMs() - 24 * 3600_000]);
}

export function purgeExpiredSessions() {
  run('DELETE FROM sessions WHERE expires_at < ?', [nowMs()]);
}
