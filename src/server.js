import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { config, ensureDirs } from './config.js';
import { openDb, closeDb } from './db.js';
import { log } from './util/log.js';
import { securityHeaders, sessionMiddleware, requireAuth } from './security/middleware.js';
import { refreshToolStatuses } from './scan/tools-registry.js';
import { recoverInterruptedScans, kickWorker, workerState } from './scan/orchestrator.js';
import { purgeExpiredSessions } from './security/session.js';

import authRoutes from './routes/auth.js';
import scanRoutes from './routes/scans.js';
import findingRoutes from './routes/findings.js';
import dashboardRoutes from './routes/dashboard.js';
import toolRoutes from './routes/tools.js';
import aiRoutes from './routes/ai.js';
import settingsRoutes, { healthHandler } from './routes/settings.js';
import dbTargetRoutes from './routes/db-targets.js';
import testAccountRoutes from './routes/test-accounts.js';
import eventRoutes from './routes/events.js';

ensureDirs();
openDb();

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // correct req.ip behind a reverse proxy
app.use(securityHeaders);
app.use(express.json({ limit: '256kb' }));
app.use(sessionMiddleware);

// ---- API ----
app.use('/api/auth', authRoutes);
app.get('/api/health', healthHandler); // public, secret-free health check

// everything below requires the owner session + CSRF
app.use('/api', requireAuth);
app.use('/api/scans', scanRoutes);
app.use('/api/findings', findingRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/tools', toolRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/settings', settingsRoutes);
app.use('/api/db-targets', dbTargetRoutes);
app.use('/api/test-accounts', testAccountRoutes);
app.use('/api/events', eventRoutes);

// JSON 404 for unknown API paths
app.use('/api', (req, res) => res.status(404).json({ error: 'not_found' }));

// ---- static SPA ----
const publicDir = path.join(config.root, 'public');
app.use(express.static(publicDir, { index: 'index.html', maxAge: '1h', setHeaders: (res, p) => {
  if (p.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
} }));
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'not_found' });
  res.sendFile(path.join(publicDir, 'index.html'));
});

// error handler — no stack traces to clients in production
app.use((err, req, res, next) => {
  log.error('unhandled', err.message);
  res.status(500).json({ error: 'internal_error', message: config.isDev ? err.message : 'Lỗi máy chủ nội bộ' });
});

/** Boot side-effects (listen + background jobs). Skipped when imported by tests. */
export function boot() {
  const server = app.listen(config.port, config.host, () => {
    log.info(`clab listening on http://${config.host}:${config.port} (env=${config.nodeEnv})`);
  });

  // background maintenance
  refreshToolStatuses()
    .then((m) => log.info('tool detection done:', Object.values(m).filter((t) => t.status === 'available').length + ' available'))
    .catch((e) => log.warn('tool detection failed', e.message));

  recoverInterruptedScans();

  const sessionSweep = setInterval(() => {
    try { purgeExpiredSessions(); } catch { /* ignore */ }
  }, 10 * 60_000);
  sessionSweep.unref?.();

  function shutdown(sig) {
    log.info(sig + ' received — shutting down');
    clearInterval(sessionSweep);
    server.close(() => {
      closeDb();
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 5000).unref?.();
  }
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('uncaughtException', (e) => log.error('uncaughtException', e.message));
  process.on('unhandledRejection', (e) => log.error('unhandledRejection', String(e && e.message)));
  return server;
}

const isDirectRun = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isDirectRun) boot();

export default app;
