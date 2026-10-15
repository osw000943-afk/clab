import { Router } from 'express';
import { q, q1 } from '../db.js';
import { bus, workerState } from '../scan/orchestrator.js';
import { config } from '../config.js';

const r = Router();

/**
 * Live scan stream (SSE). On (re)connect the client gets a full snapshot
 * from the DB first — refreshing the browser never loses state and never
 * creates a new scan.
 */
r.get('/scans/:id/stream', (req, res) => {
  const scan = q1('SELECT * FROM scans WHERE id=?', [req.params.id]);
  if (!scan) return res.status(404).json({ error: 'not_found' });

  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  const send = (event) => {
    try {
      res.write(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`);
    } catch { /* client gone */ }
  };

  // snapshot from persisted state
  const stages = q('SELECT * FROM scan_stages WHERE scan_id=? ORDER BY rowid', [scan.id]);
  const recentLogs = q('SELECT * FROM stage_logs WHERE scan_id=? ORDER BY id DESC LIMIT 100', [scan.id]).reverse();
  send({ type: 'snapshot', scan, stages, logs: recentLogs, worker: workerState() });

  const listener = (event) => send(event);
  bus.on(scan.id, listener);

  const heartbeat = setInterval(() => {
    try { res.write(`event: heartbeat\ndata: {"ts":${Date.now()}}\n\n`); } catch { /* ignore */ }
  }, config.limits.sseHeartbeatMs);

  req.on('close', () => {
    clearInterval(heartbeat);
    bus.off(scan.id, listener);
  });
});

/** Global worker stream (dashboard header: queue/worker status). */
r.get('/worker/stream', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write(`event: worker\ndata: ${JSON.stringify(workerState())}\n\n`);
  const onAny = (scanId) => {
    try { res.write(`event: worker\ndata: ${JSON.stringify({ ...workerState(), lastScan: scanId })}\n\n`); } catch { /* ignore */ }
  };
  bus.on('scan-status', onAny);
  const heartbeat = setInterval(() => {
    try { res.write(`event: heartbeat\ndata: {"ts":${Date.now()}}\n\n`); } catch { /* ignore */ }
  }, config.limits.sseHeartbeatMs);
  req.on('close', () => {
    clearInterval(heartbeat);
    bus.off('scan-status', onAny);
  });
});

export default r;
