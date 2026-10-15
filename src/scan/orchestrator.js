import { EventEmitter } from 'node:events';
import { q, q1, run, resourceLimits } from '../db.js';
import { newId, nowMs } from '../util/ids.js';
import { log } from '../util/log.js';
import { addFinding } from './normalize.js';
import { assertUrlAllowed, safeFetch } from '../security/scope.js';
import { STAGES, stageListForMode } from './stages/index.js';

/**
 * Scan Orchestrator — strictly sequential worker (1 heavy scan at a time, by design
 * for the 1 GB RAM target). State lives in SQLite so restarts never lose results.
 */

export const bus = new EventEmitter();
bus.setMaxListeners(200);

export function emitScan(scanId, event) {
  bus.emit(scanId, { ...event, ts: Date.now() });
}

let workerRunning = false;
let currentAbort = null;
let currentScanId = null;

export function workerState() {
  return {
    running: workerRunning,
    currentScanId,
    queued: q(`SELECT COUNT(*) AS n FROM scans WHERE status='queued'`).n,
  };
}

export const MODES = {
  quick: ['s01', 's02', 's03', 's06'],
  standard: ['s01', 's02', 's03', 's04', 's05', 's06', 's07', 's10', 's19'],
  deep: ['s01', 's02', 's03', 's04', 's05', 's06', 's07', 's08', 's09', 's10', 's19', 's20', 's21', 's22', 's23'],
  full: ['s01', 's02', 's03', 's04', 's05', 's06', 's07', 's08', 's09', 's10', 's11', 's12', 's13',
    's14', 's15', 's16', 's17', 's18', 's19', 's20', 's21', 's22', 's23', 's24'],
};

export function resolveStageIds(mode, moduleSelection) {
  const base = MODES[mode] || MODES.standard;
  if (Array.isArray(moduleSelection) && moduleSelection.length) {
    const allowed = new Set(Object.keys(STAGES));
    const picked = moduleSelection.filter((s) => allowed.has(s));
    if (picked.length) return picked;
  }
  return base;
}

export function createScan({ targetUrl, mode, modules, options, scope }) {
  const limits = resourceLimits();
  const stageIds = resolveStageIds(mode, modules);
  const id = newId('scan');
  run(
    `INSERT INTO scans(id, target_url, target_host, resolved_ip, scope, mode, modules, options, status, created_at, progress)
     VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
    [id, targetUrl, '', null, JSON.stringify(scope || {}), mode, JSON.stringify(stageIds),
      JSON.stringify(options || {}), 'queued', nowMs(), 0]
  );
  for (const sid of stageIds) {
    run(
      `INSERT INTO scan_stages(id, scan_id, stage_id, name, status) VALUES(?,?,?,?,?)`,
      [newId('st'), id, sid, STAGES[sid].name, 'pending']
    );
  }
  log.info('scan queued', id, targetUrl, mode);
  setTimeout(kickWorker, 0).unref?.();
  return id;
}

export function cancelScan(scanId) {
  const s = q1('SELECT status FROM scans WHERE id=?', [scanId]);
  if (!s) return false;
  if (s.status === 'queued') {
    run(`UPDATE scans SET status='cancelled', finished_at=?, error='cancelled_by_user' WHERE id=?`, [nowMs(), scanId]);
    emitScan(scanId, { type: 'scan-status', status: 'cancelled' });
    return true;
  }
  if (s.status === 'running' && currentScanId === scanId) {
    run(`UPDATE scans SET status='cancelling' WHERE id=?`, [scanId]);
    currentAbort?.abort();
    return true;
  }
  return false;
}

export function kickWorker() {
  if (workerRunning) return;
  workerRunning = true;
  setImmediate(async () => {
    try {
      for (;;) {
        const next = q1(`SELECT id FROM scans WHERE status='queued' ORDER BY created_at LIMIT 1`);
        if (!next) break;
        try {
          await executeScan(next.id);
        } catch (e) {
          log.error('scan crashed', next.id, e.message);
          run(`UPDATE scans SET status='failed', finished_at=?, error=? WHERE id=?`,
            [nowMs(), String(e.message).slice(0, 500), next.id]);
          emitScan(next.id, { type: 'scan-status', status: 'failed', error: e.message });
        }
      }
    } finally {
      workerRunning = false;
      currentScanId = null;
    }
  });
}

/** Startup recovery: interrupted scans become failed with a clear reason (results kept). */
export function recoverInterruptedScans() {
  const rows = q(`SELECT id FROM scans WHERE status IN ('running','cancelling','queued')`);
  for (const r of rows) {
    if (q1(`SELECT1x FROM scan_stages WHERE scan_id=? AND status='running'`, [r.id])) { /* noop */ }
  }
  const running = q(`SELECT id FROM scans WHERE status IN ('running','cancelling')`);
  for (const r of running) {
    run(`UPDATE scans SET status='failed', finished_at=?, error='interrupted_by_server_restart' WHERE id=?`, [nowMs(), r.id]);
    run(`UPDATE scan_stages SET status='failed', error='interrupted_by_server_restart', finished_at=?
         WHERE scan_id=? AND status='running'`, [nowMs(), r.id]);
  }
  if (running.length) log.warn('recovered interrupted scans:', running.map((r) => r.id).join(', '));
  // scans left queued stay queued and will be picked up by the worker
  kickWorker();
}

async function executeScan(scanId) {
  const scan = q1('SELECT * FROM scans WHERE id=?', [scanId]);
  if (!scan || scan.status !== 'queued') return;
  const limits = resourceLimits();
  const abort = new AbortController();
  currentAbort = abort;
  currentScanId = scanId;
  run(`UPDATE scans SET status='running', started_at=? WHERE id=?`, [nowMs(), scanId]);
  emitScan(scanId, { type: 'scan-status', status: 'running' });

  // overall wall-clock cap for the whole scan
  const wallTimer = setTimeout(() => {
    abort.abort();
    run(`UPDATE scans SET error='scan_time_limit_exceeded' WHERE id=?`, [scanId]);
  }, limits.scanTimeoutMin * 60_000);
  wallTimer.unref?.();

  const stageIds = JSON.parse(scan.modules);
  const store = {}; // shared evidence between stages (in-memory, per scan)
  let target = null;

  const ctx = {
    scan: { ...scan, id: scanId },
    limits,
    store,
    signal: abort.signal,
    getTarget: () => target,
    setTarget: (t) => { target = t; },
    log: (level, message) => {
      run('INSERT INTO stage_logs(scan_id, ts, level, message) VALUES(?,?,?,?)',
        [scanId, nowMs(), level, String(message).slice(0, 2000)]);
      emitScan(scanId, { type: 'log', level, message });
    },
    addFinding: (f) => {
      const id = addFinding({ ...f, scanId });
      emitScan(scanId, { type: 'finding', id, title: f.title, severity: f.severity });
      return id;
    },
    fetch: (url, init) => safeFetch(url, { ...init, signal: abort.signal }),
    assertUrl: (url, opts) => assertUrlAllowed(url, opts),
    setSummary: (summary) => { ctx._summary = summary; },
  };

  try {
    let done = 0;
    for (const sid of stageIds) {
      if (abort.signal.aborted) throw new Error('cancelled');
      const check = q1('SELECT status FROM scans WHERE id=?', [scanId]);
      if (check.status === 'cancelling') throw new Error('cancelled');
      const stage = STAGES[sid];
      const stageRow = q1('SELECT id FROM scan_stages WHERE scan_id=? AND stage_id=?', [scanId, sid]);
      run(`UPDATE scan_stages SET status='running', started_at=? WHERE id=?`, [nowMs(), stageRow.id]);
      emitScan(scanId, { type: 'stage-status', stage: sid, name: stage.name, status: 'running' });
      ctx._summary = null;
      try {
        const result = await stage.run(ctx);
        if (abort.signal.aborted) throw new Error('cancelled');
        run(`UPDATE scan_stages SET status='completed', finished_at=?, summary=? WHERE id=?`,
          [nowMs(), JSON.stringify(ctx._summary || result?.summary || null), stageRow.id]);
        emitScan(scanId, { type: 'stage-status', stage: sid, name: stage.name, status: 'completed', summary: ctx._summary || result?.summary || null });
      } catch (stageErr) {
        if (abort.signal.aborted || String(stageErr.message) === 'cancelled') throw new Error('cancelled');
        // a single stage failure must not kill the scan
        run(`UPDATE scan_stages SET status='failed', finished_at=?, error=? WHERE id=?`,
          [nowMs(), String(stageErr.message).slice(0, 500), stageRow.id]);
        emitScan(scanId, { type: 'stage-status', stage: sid, name: stage.name, status: 'failed', error: stageErr.message });
        ctx.log('error', `[${sid}] ${stage.name} failed: ${stageErr.message}`);
      }
      done++;
      const progress = Math.round((done / stageIds.length) * 100) / 100;
      run('UPDATE scans SET progress=? WHERE id=?', [progress, scanId]);
      emitScan(scanId, { type: 'progress', progress });
    }
    run(`UPDATE scans SET status='completed', finished_at=?, progress=1 WHERE id=?`, [nowMs(), scanId]);
    emitScan(scanId, { type: 'scan-status', status: 'completed' });
    // queue AI analysis for new findings (non-blocking)
    import('../ai/ai-analyze.js').then((m) => m.enqueueScanAnalysis(scanId)).catch((e) => log.warn('ai analyze skip', e.message));
  } catch (e) {
    const cancelled = e.message === 'cancelled';
    run(`UPDATE scans SET status=?, finished_at=?, error=? WHERE id=?`,
      [cancelled ? 'cancelled' : 'failed', nowMs(), cancelled ? 'cancelled_by_user' : String(e.message).slice(0, 500), scanId]);
    emitScan(scanId, { type: 'scan-status', status: cancelled ? 'cancelled' : 'failed', error: e.message });
  } finally {
    clearTimeout(wallTimer);
    currentAbort = null;
  }
}

