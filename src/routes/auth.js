import { Router } from 'express';
import { config, encryptionReady } from '../config.js';
import { verifyPassword } from '../security/password.js';
import {
  createSession, destroySession, setSessionCookie, clearSessionCookie,
  loginBlocked, recordLoginAttempt, sessionConfigured,
} from '../security/session.js';

const r = Router();

/** Unauthenticated status: is the lab configured? Is the client logged in? */
r.get('/status', (req, res) => {
  res.json({
    passwordConfigured: !!config.labPasswordHash,
    sessionSecretConfigured: sessionConfigured(),
    encryptionKeyConfigured: encryptionReady(),
    loggedIn: !!req.session,
    csrfToken: req.session?.csrf || null,
    idleMinutes: config.sessionIdleMin,
    absoluteHours: config.sessionAbsoluteH,
  });
});

r.post('/login', (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const { username, password } = req.body || {};
  const user = String(username || 'owner').slice(0, 64);

  if (!config.labPasswordHash) {
    return res.status(503).json({ error: 'password_not_configured', message: 'Chưa thiết lập mật khẩu chủ Lab. Chạy: npm run set-password' });
  }
  if (loginBlocked(ip, user)) {
    return res.status(429).json({ error: 'too_many_attempts', message: 'Quá nhiều lần thử sai. Thử lại sau 15 phút.' });
  }
  const ok = typeof password === 'string' && password.length > 0 &&
    verifyPassword(password, config.labPasswordHash);
  recordLoginAttempt(ip, user, ok);
  if (!ok) {
    return res.status(401).json({ error: 'invalid_credentials', message: 'Mật khẩu không đúng' });
  }
  // session fixation prevention: brand-new session id issued only after auth
  const { token, csrf } = createSession({ ip, ua: req.headers['user-agent'] });
  setSessionCookie(res, token);
  res.json({ ok: true, csrfToken: csrf });
});

r.post('/logout', (req, res) => {
  if (req.session) destroySession(req.session.id);
  clearSessionCookie(res);
  res.json({ ok: true });
});

export default r;
