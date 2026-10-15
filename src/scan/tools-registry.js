import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { run as dbRun, q1, getSetting } from '../db.js';
import { nowMs } from '../util/ids.js';

/**
 * Tool Registry — every scanner clab can drive.
 * Statuses come from REAL detection (binary probe / API key presence), never assumed:
 * available | missing | disabled | unsupported | needs-config.
 */

export const TOOLS = [
  { id: 'dns-native', name: 'DNS utilities (native)', category: 'discovery', mode: 'passive',
    builtin: true, license: 'built-in', heavy: false, stages: ['s02'],
    desc: 'Node dns resolver: A/AAAA/MX/NS/TXT/CNAME/SOA' },
  { id: 'nmap', name: 'Nmap', category: 'discovery', mode: 'active',
    detect: { bin: 'nmap', args: ['--version'] }, parseVersion: /Nmap version ([\d.]+)/,
    license: 'Nmap PSL', heavy: true, stages: ['s05'], desc: 'Port & service scan (rate/time bounded)' },
  { id: 'httpx', name: 'httpx (ProjectDiscovery)', category: 'discovery', mode: 'active',
    detect: { bin: 'httpx', args: ['-version'] }, parseVersion: /httpx[^\d]*v?([\d.]+)/i,
    license: 'MIT', heavy: false, stages: ['s03'], desc: 'HTTP probing — built-in fallback when missing' },
  { id: 'whatweb', name: 'WhatWeb', category: 'fingerprint', mode: 'active',
    detect: { bin: 'whatweb', args: ['--version'] }, parseVersion: /WhatWeb version ([\d.]+)/i,
    license: 'GPL-3.0', heavy: false, stages: ['s04'], desc: 'Technology fingerprinting' },
  { id: 'nikto', name: 'Nikto', category: 'misconfig', mode: 'active',
    detect: { bin: 'nikto', args: ['-Version'] }, parseVersion: /Nikto v([\d.]+)/i,
    license: 'GPL-2.0', heavy: true, stages: ['s08'], desc: 'Web server misconfig scan (request-capped)' },
  { id: 'testssl', name: 'testssl.sh', category: 'tls', mode: 'active',
    detect: { bin: 'testssl.sh', args: ['--version'] }, parseVersion: /testssl\.sh\s*([\d.]+)/i,
    license: 'GPL-2.0', heavy: true, stages: ['s07'], desc: 'TLS/SSL configuration audit' },
  { id: 'ssllabs', name: 'SSL Labs API', category: 'tls', mode: 'passive-external',
    apiCheck: 'ssllabs', needsOptIn: true, license: 'Qualys API terms', heavy: false, stages: ['s07'],
    desc: 'Remote TLS rating — hostname is sent to Qualys when enabled' },
  { id: 'zap', name: 'OWASP ZAP', category: 'dast', mode: 'active',
    detect: { bin: 'zap.sh', args: ['-version'] }, dockerAlt: 'ghcr.io/zaproxy/zaproxy:stable',
    license: 'Apache-2.0', heavy: true, stages: ['s11'], desc: 'DAST — passive scan prioritized' },
  { id: 'burp', name: 'Burp Suite Community', category: 'dast', mode: 'manual',
    detect: { bin: 'burpsuite', args: ['--version'] }, license: 'PortSwigger EULA',
    heavy: false, manual: true, stages: [], desc: 'Manual testing proxy — not automated by clab' },
  { id: 'wpscan', name: 'WPScan', category: 'cms', mode: 'active',
    detect: { bin: 'wpscan', args: ['--version'] }, parseVersion: /WPScan v([\d.]+)/i,
    license: 'GPL-3.0', heavy: true, stages: ['s09'], desc: 'WordPress vulnerability scan' },
  { id: 'sqlmap', name: 'sqlmap', category: 'injection', mode: 'active',
    detect: { bin: 'sqlmap', args: ['--version'] }, parseVersion: /sqlmap version: ([\d.]+)/i,
    license: 'GPL-2.0', heavy: true, stages: ['s12'], desc: 'SQLi testing — no dump/destructive ops' },
  { id: 'dalfox', name: 'Dalfox', category: 'injection', mode: 'active',
    detect: { bin: 'dalfox', args: ['version'] }, parseVersion: /version\s*v?([\d.]+)/i,
    license: 'GPL-3.0', heavy: true, stages: ['s13'], desc: 'XSS scanning with payload limits' },
  { id: 'trivy', name: 'Trivy', category: 'deps', mode: 'passive',
    detect: { bin: 'trivy', args: ['--version'] }, parseVersion: /Version: ([\d.]+)/i,
    license: 'Apache-2.0', heavy: false, stages: ['s14'], desc: 'Dependency/CVE scan (local assets)' },
  { id: 'osv-scanner', name: 'OSV-Scanner', category: 'deps', mode: 'passive',
    detect: { bin: 'osv-scanner', args: ['--version'] }, parseVersion: /OSV-Scanner\s*v?([\d.]+)/i,
    license: 'Apache-2.0', heavy: false, stages: ['s14'], desc: 'Dependency CVE lookup via OSV' },
  { id: 'semgrep', name: 'Semgrep', category: 'sast', mode: 'passive',
    detect: { bin: 'semgrep', args: ['--version'] }, parseVersion: /(\d+\.\d+\.\d+)/,
    license: 'LGPL-2.1', heavy: true, stages: ['s15'], desc: 'Static analysis on authorized source' },
  { id: 'gitleaks', name: 'Gitleaks', category: 'secrets', mode: 'passive',
    detect: { bin: 'gitleaks', args: ['version'] }, parseVersion: /([\d.]+)/,
    license: 'MIT', heavy: false, stages: ['s16'], desc: 'Secret detection in repositories' },
  { id: 'retire', name: 'Retire.js', category: 'secrets', mode: 'passive',
    detect: { bin: 'retire', args: ['--version'] }, npmAlt: 'retire', license: 'BSD-2-Clause',
    heavy: false, stages: ['s16'], desc: 'Vulnerable JavaScript library detection' },
  { id: 'checkov', name: 'Checkov', category: 'iac', mode: 'passive',
    detect: { bin: 'checkov', args: ['--version'] }, parseVersion: /([\d.]+)/,
    license: 'Apache-2.0', heavy: true, stages: ['s17'], desc: 'IaC misconfiguration scan' },
  { id: 'tshark', name: 'TShark', category: 'network', mode: 'passive',
    detect: { bin: 'tshark', args: ['--version'] }, parseVersion: /TShark ([\d.]+)/i,
    license: 'GPL-2.0', heavy: false, stages: ['s18'], desc: 'Capture analysis (authorized pcap only)' },
  { id: 'safe-browsing', name: 'Google Safe Browsing API', category: 'reputation', mode: 'passive-external',
    apiCheck: 'safe-browsing', needsKeySetting: 'gsb_api_key',
    license: 'Google API terms', heavy: false, stages: ['s10'], desc: 'URL reputation — needs API key' },
  { id: 'sucuri', name: 'Sucuri SiteCheck', category: 'reputation', mode: 'passive-external',
    apiCheck: 'sucuri', needsKeySetting: 'sucuri_api_key', license: 'Sucuri Scanning API (paid plan)',
    heavy: false, stages: ['s10'],
    desc: 'Remote malware/blacklist check — public JSON API discontinued; paid key required' },
];

const STATUS_KEY = 'tool_status';

function loadStored() {
  const row = q1('SELECT value FROM settings WHERE key = ?', [STATUS_KEY]);
  if (!row) return {};
  try { return JSON.parse(row.value); } catch { return {}; }
}

function persist(map) {
  dbRun(`INSERT INTO settings(key, value) VALUES(?,?)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value`, [STATUS_KEY, JSON.stringify(map)]);
}

function which(bin) {
  for (const d of (process.env.PATH || '').split(':')) {
    try {
      const p = `${d}/${bin}`;
      fs.accessSync(p, fs.constants.X_OK);
      return p;
    } catch { /* keep looking */ }
  }
  return null;
}

function probeBin(bin, args, timeoutMs = 12000) {
  return new Promise((resolve) => {
    let out = '';
    let done = false;
    const finish = (r) => { if (!done) { done = true; resolve(r); } };
    let child;
    try {
      child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      return finish({ ok: false, error: e.message });
    }
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      finish({ ok: false, error: 'timeout' });
    }, timeoutMs);
    child.stdout.on('data', (d) => { if (out.length < 8192) out += d.toString(); });
    child.stderr.on('data', (d) => { if (out.length < 8192) out += d.toString(); });
    child.on('error', (e) => { clearTimeout(timer); finish({ ok: false, error: e.code || e.message }); });
    child.on('close', (code) => { clearTimeout(timer); finish({ ok: true, code, output: out }); });
  });
}

/** Re-detect every tool and persist statuses. Returns the status map. */
export async function refreshToolStatuses() {
  const stored = loadStored();
  const map = {};
  for (const t of TOOLS) {
    const prev = stored[t.id] || {};
    let status = 'missing';
    let version = prev.version || null;
    let detail = '';

    if (prev.userDisabled) {
      status = 'disabled';
      detail = 'Tắt trong cấu hình / disabled in settings';
    } else if (t.builtin) {
      status = 'available';
      detail = 'Built-in implementation';
    } else if (t.apiCheck === 'safe-browsing') {
      const hasKey = !!getSetting('gsb_api_key');
      status = hasKey ? 'available' : 'needs-config';
      detail = hasKey ? 'API key configured' : 'Cần API key (Settings → System)';
    } else if (t.apiCheck === 'sucuri') {
      const hasKey = !!getSetting('sucuri_api_key') && !!getSetting('sucuri_monitor_domain');
      status = hasKey ? 'available' : 'needs-config';
      detail = hasKey ? 'Scanning API key configured' : 'Cần key Scanning API trả phí (public API đã ngừng hoạt động)';
    } else if (t.apiCheck === 'ssllabs') {
      status = 'available';
      detail = t.needsOptIn ? 'External service — opt-in per scan' : 'Public API, no key required';
    } else if (t.detect) {
      const binPath = which(t.detect.bin);
      if (binPath) {
        const r = await probeBin(t.detect.bin, t.detect.args);
        const m = t.parseVersion ? (r.output || '').match(t.parseVersion) : null;
        if (r.ok && (!t.parseVersion || m)) {
          status = 'available';
          version = m ? m[1] : (prev.version || null);
          detail = `Found at ${binPath}`;
        } else if (r.ok && t.parseVersion && !m) {
          // binary exists but output doesn't match the expected tool (e.g. Python httpx CLI)
          status = 'incompatible';
          detail = `'${t.detect.bin}' tại ${binPath} không phản hồi đúng định dạng của công cụ này (không phải bản ProjectDiscovery?)`;
        } else {
          status = 'failed';
          detail = `Binary at ${binPath} but probe failed: ${r.error || ('exit ' + r.code)}`;
        }
      } else {
        status = 'missing';
        detail = `Không tìm thấy binary '${t.detect.bin}' trong PATH`;
      }
    } else {
      status = 'unsupported';
      detail = 'Chưa hỗ trợ trong môi trường này';
    }
    map[t.id] = { id: t.id, status, version, detail, checkedAt: nowMs(), heavy: !!t.heavy, mode: t.mode };
  }
  persist(map);
  return map;
}

export function getToolStatuses() {
  return loadStored();
}

export function getTool(id) {
  return TOOLS.find((t) => t.id === id) || null;
}

export function setToolDisabled(id, disabled) {
  const stored = loadStored();
  stored[id] = { ...(stored[id] || {}), userDisabled: !!disabled };
  if (disabled) stored[id].status = 'disabled';
  persist(stored);
}

export function toolAvailable(id) {
  const s = loadStored()[id];
  return s && s.status === 'available';
}

/**
 * Safe process runner: argument-vector spawn (never a shell), hard timeout,
 * output byte cap, process-group kill on timeout/cancel.
 */
export function runTool(bin, args, { timeoutMs = 120_000, maxBytes = 512 * 1024, cwd, env, signal, onPartial } = {}) {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let bytes = 0;
    let killed = false;
    let settled = false;
    const started = Date.now();

    let child;
    try {
      child = spawn(bin, args, {
        cwd,
        env: { ...(env || {}), PATH: process.env.PATH },
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: process.platform !== 'win32',
      });
    } catch (e) {
      return resolve({ ok: false, spawnError: e.message, stdout, stderr, exitCode: null, durationMs: 0 });
    }

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
      resolve(result);
    };

    const killTree = () => {
      killed = true;
      try { process.kill(-child.pid, 'SIGTERM'); } catch { try { child.kill('SIGTERM'); } catch { /* */ } }
      setTimeout(() => {
        try { process.kill(-child.pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch { /* */ } }
      }, 3000).unref?.();
    };

    const onAbort = () => killTree();
    if (signal) signal.addEventListener('abort', onAbort, { once: true });

    const timer = setTimeout(killTree, timeoutMs);

    child.stdout.on('data', (d) => {
      bytes += d.length;
      if (bytes <= maxBytes) {
        stdout += d.toString();
        onPartial?.(d.toString());
      } else if (!killed) {
        killTree();
      }
    });
    child.stderr.on('data', (d) => {
      if (stderr.length < 64 * 1024) stderr += d.toString();
    });
    child.on('error', (e) => finish({
      ok: false, spawnError: e.code || e.message, stdout, stderr, exitCode: null, durationMs: Date.now() - started,
    }));
    child.on('close', (code) => {
      finish({
        ok: !killed && code === 0,
        killed,
        timedOut: killed,
        exitCode: code,
        stdout,
        stderr: redactSecrets(stderr),
        durationMs: Date.now() - started,
        truncated: bytes > maxBytes,
      });
    });
  });
}

export function redactSecrets(s) {
  return String(s)
    .replace(/(api[_-]?key|authorization|token|password|secret)\s*[:=]\s*\S+/gi, '$1=[REDACTED]')
    .slice(0, 4096);
}

export function recordToolRun({ scanId, toolId, version, status, exitCode, stderrExcerpt, startedAt }) {
  const id = `tr_${nowMs()}_${Math.random().toString(36).slice(2, 8)}`;
  dbRun(
    `INSERT INTO tool_runs(id, scan_id, tool_id, version, status, exit_code, started_at, finished_at, stderr_excerpt)
     VALUES(?,?,?,?,?,?,?,?,?)`,
    [id, scanId, toolId, version || null, status, exitCode ?? null, startedAt, nowMs(), stderrExcerpt || null]
  );
  return id;
}


