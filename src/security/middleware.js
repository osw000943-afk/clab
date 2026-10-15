import { resolveSession, readSessionCookie, csrfOk, sessionConfigured } from '../security/session.js';
import { config } from '../config.js';

/** Attach req.session when a valid cookie session exists. */
export function sessionMiddleware(req, res, next) {
  const cookie = readSessionCookie(req);
  const r = resolveSession(cookie);
  req.session = r.session || null;
  req.sessionExpired = !!r.expired;
  next();
}

/** Require an authenticated owner session for API routes. */
export function requireAuth(req, res, next) {
  if (!sessionConfigured()) {
    return res.status(503).json({ error: 'session_secret_missing', message: 'SESSION_SECRET chưa được cấu hình — xem README' });
  }
  if (!config.labPasswordHash) {
    return res.status(503).json({ error: 'password_not_configured', message: 'Mật khẩu chủ Lab chưa được thiết lập — chạy npm run set-password' });
  }
  if (!req.session) {
    return res.status(401).json({ error: 'unauthorized', expired: !!req.sessionExpired });
  }
  if (!csrfOk(req, req.session)) {
    return res.status(403).json({ error: 'csrf_failed', message: 'Thiếu hoặc sai CSRF token' });
  }
  next();
}

/** Conservative security headers for the dashboard. */
export function securityHeaders(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; " +
    "script-src 'self'; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'");
  next();
}
