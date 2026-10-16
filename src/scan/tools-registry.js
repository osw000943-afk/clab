import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { run as dbRun, q1, getSetting } from '../db.js';
import { nowMs } from '../util/ids.js';

/**
 * Tool Registry — every scanner clab can drive.
 * Statuses come from REAL detection (binary probe / API key presence), never assumed:
 * available | missing | disabled | needs-config | incompatible | failed | unsupported.
 * Run states (tool_runs): running | completed | partial | failed | cancelled | unsupported.
 */

export const TOOLS = [
  { id: 'dns-native', name: 'DNS utilities (native)', category: 'discovery', mode: 'passive',
    builtin: true, license: 'built-in', heavy: false, stages: ['s02'],
    desc: 'Node dns resolver: A/AAAA/MX/NS/TXT/CNAME/SOA' },
  { id: 'nmap', name: 'Nmap', category: 'discovery', mode: 'active',
    detect: { bin: 'nmap', args: ['--version'] }, parseVersion: /Nmap version ([\d.]+)/,
    license: 'Nmap PSL',
    installHint: 'sudo apt install nmap', heavy: true, stages: ['s05'], desc: 'Port & service scan (rate/time bounded)' },
  { id: 'httpx', name: 'httpx (ProjectDiscovery)', category: 'discovery', mode: 'active',
    detect: { bin: 'httpx', args: ['-version'] }, parseVersion: /httpx[^\d]*v?([\d.]+)/i,
    license: 'MIT',
    installHint: 'go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
    installHint: 'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    installHint: 'sudo apt install feroxbuster  (hoặc cargo install feroxbuster)',
    installHint: 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    installHint: 'go install github.com/gitleaks/gitleaks/v8/cmd/gitleaks@latest',
    installHint: 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest', heavy: false, stages: ['s03'], desc: 'HTTP probing — built-in fallback when missing' },
  { id: 'whatweb', name: 'WhatWeb', category: 'fingerprint', mode: 'active',
    detect: { bin: 'whatweb', args: ['--version'] }, parseVersion: /WhatWeb version ([\d.]+)/i,
    license: 'GPL-3.0',
    installHint: 'go install github.com/hahwul/dalfox/v2@latest',
    installHint: 'sudo apt install wpscan  (hoặc gem install whatweb)',
    installHint: 'Tai tu PortSwigger (manual, khong tu dong cai)',
    installHint: 'sudo apt install whatweb  (hoặc gem install whatweb)', heavy: false, stages: ['s04','s29'], desc: 'Technology fingerprinting (shared adapter, registered once)' },
  { id: 'nikto', name: 'Nikto', category: 'misconfig', mode: 'active',
    detect: { bin: 'nikto', args: ['-Version'] }, parseVersion: /Nikto v([\d.]+)/i,
    license: 'GPL-2.0',
    installHint: 'sudo apt install joomscan  (hoặc git clone https://github.com/rezasp/joomscan.git)',
    installHint: 'pip install droopescan',
    installHint: 'pip install dirsearch',
    installHint: 'sudo apt install tshark',
    installHint: 'sudo apt install sqlmap  (hoặc git clone https://github.com/sqlmapproject/sqlmap)',
    installHint: 'git clone --depth 1 https://github.com/testssl/testssl.sh.git /opt/testssl.sh',
    installHint: 'sudo apt install nikto', heavy: true, stages: ['s08'], desc: 'Web server misconfig scan (request-capped)' },
  { id: 'testssl', name: 'testssl.sh', category: 'tls', mode: 'active',
    detect: { bin: 'testssl.sh', args: ['--version'] }, parseVersion: /testssl\.sh\s*([\d.]+)/i,
    license: 'GPL-2.0', heavy: true, stages: ['s07'], desc: 'TLS/SSL configuration audit' },
  { id: 'ssllabs', name: 'SSL Labs API', category: 'tls', mode: 'passive-external',
    apiCheck: 'ssllabs', needsOptIn: true, license: 'Qualys API terms', heavy: false, stages: ['s07'],
    desc: 'Remote TLS rating — hostname is sent to Qualys when enabled' },
  { id: 'zap', name: 'OWASP ZAP', category: 'dast', mode: 'active',
    detect: { bin: 'zap.sh', args: ['-version'] }, dockerAlt: 'ghcr.io/zaproxy/zaproxy:stable',
    license: 'Apache-2.0',
    installHint: 'go install github.com/OJ/gobuster/v3@latest',
    installHint: 'pip install checkov',
    installHint: 'npm install -g retire',
    installHint: 'go install github.com/google/osv-scanner/cmd/osv-scanner@latest',
    installHint: 'sudo apt install trivy  (hoặc binary release tu GitHub)',
    installHint: 'Tai Zaproxy tai https://github.com/zaproxy/zaproxy/releases (Java)', heavy: true, stages: ['s11'], desc: 'DAST — passive scan prioritized' },
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
    license: 'LGPL-2.1',
    installHint: 'pip install semgrep', heavy: true, stages: ['s15'], desc: 'Static analysis on authorized source' },
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
  { id: 'arachni', name: 'Arachni', category: 'dast', mode: 'active',
    detect: { bin: 'arachni', args: ['--version'] }, parseVersion: /Arachni\s*v?([\d.]+)/i,
    license: 'Apache-2.0 (upstream unmaintained, verify)',
    installHint: 'Khong khuyen khich (upstream ngung duong duy). Tai tu GitHub neu can.', heavy: true, stages: ['s25'],
    desc: 'Web app vuln assessment incl. supported XSS checks. Verify maintenance/compat first.' },
  { id: 'w3af', name: 'w3af', category: 'dast', mode: 'active',
    detect: { bin: 'w3af_console', args: ['--version'] }, parseVersion: /([\d.]+)/,
    license: 'GPL-2.0 (project stalled, verify plugins)',
    installHint: 'git clone https://github.com/andresriancho/w3af.git (du an da ngung)', heavy: true, stages: ['s25'],
    desc: 'Web security framework. Verify version, project status and working plugins.' },
  { id: 'dirsearch', name: 'Dirsearch', category: 'discovery', mode: 'active',
    detect: { bin: 'dirsearch', args: ['--version'] }, parseVersion: /([\d.]+)/,
    license: 'GPL-2.0', heavy: true, rateLimited: true, stages: ['s26'],
    desc: 'Web path/resource discovery. Wordlist, rate limit and depth capped.' },
  { id: 'gobuster', name: 'Gobuster', category: 'discovery', mode: 'active',
    detect: { bin: 'gobuster', args: ['version'] }, parseVersion: /([\d.]+)/,
    license: 'Apache-2.0', heavy: true, rateLimited: true, stages: ['s26'],
    desc: 'Dir/file/subdomain discovery in approved scope. Threads and rate capped.' },
  { id: 'nuclei', name: 'Nuclei', category: 'dast', mode: 'active',
    detect: { bin: 'nuclei', args: ['-version'] }, parseVersion: /([\d.]+)/,
    license: 'MIT', heavy: true, rateLimited: true, stages: ['s25'],
    desc: 'Template-based scan. Template source/version/severity managed, in-scope only.' },
  { id: 'feroxbuster', name: 'Feroxbuster', category: 'discovery', mode: 'active',
    detect: { bin: 'feroxbuster', args: ['--version'] }, parseVersion: /([\d.]+)/,
    license: 'MIT', heavy: true, rateLimited: true, stages: ['s26'],
    desc: 'Web content discovery. Recursion, request count and time bounded.' },
  { id: 'kallor', name: 'Kallor (unverified)', category: 'dast', mode: 'active',
    unverified: true, license: 'unknown, verification required', heavy: false, stages: ['s25'],
    desc: 'Name/repo/function NOT verified. Unsupported until verified, never faked.' },
  { id: 'droopescan', name: 'Droopescan', category: 'cms', mode: 'active',
    detect: { bin: 'droopescan', args: ['--help'] },
    license: 'GPL-2.0', heavy: false, stages: ['s27'], desc: 'CMS scan for supported versions (Drupal, SilverStripe, Moodle).' },
  { id: 'joomscan', name: 'JoomScan', category: 'cms', mode: 'active',
    detect: { bin: 'joomscan', args: ['--version'] }, altBin: '/opt/joomscan/joomscan.pl',
    license: 'GPL-2.0', heavy: false, stages: ['s27'], desc: 'Joomla assessment incl. vulnerable-version markers.' },
  { id: 'a2sv', name: 'A2SV', category: 'tls', mode: 'active',
    detect: { bin: 'a2sv', args: ['--version'] }, parseVersion: /([\d.]+)/,
    license: 'GPL-2.0 (unmaintained, cross-check)',
    installHint: 'git clone https://github.com/hahwul/a2sv.git  (du an it duong duy)', heavy: false, stages: ['s28'],
    desc: 'TLS scan. Verify maintenance and real TLS coverage, cross-check modern tools.' },
  { id: 'coraza', name: 'Coraza WAF', category: 'waf', mode: 'protect',
    protectOnly: true, license: 'Apache-2.0', heavy: false, stages: ['s30'],
    desc: 'WAF / reverse-proxy protection component, NOT a standalone scanner.' },
  { id: 'bunkerweb', name: 'BunkerWeb', category: 'waf', mode: 'protect',
    protectOnly: true, license: 'GPL-3.0', heavy: true, stages: ['s30'],
    desc: 'Web gateway with WAF+TLS+abuse mitigation. Proxy changes only with approval+backup.' },
  { id: 'wazuh', name: 'Wazuh', category: 'monitoring', mode: 'monitor',
    monitorOnly: true, apiCheck: 'wazuh', needsKeySetting: 'wazuh_api',
    license: 'GPL-2.0', heavy: true, stages: ['s30'],
    desc: 'Monitoring/alerting/log analytics via API or agent. Prefer dedicated host (heavy for 1GB).' },
  { id: 'ossec', name: 'OSSEC', category: 'monitoring', mode: 'monitor',
    monitorOnly: true, detect: { bin: 'ossec-control', args: ['status'] },
    license: 'GPL-2.0', heavy: true, stages: ['s30'],
    desc: 'Log monitoring and anomaly detection. Evaluate agent, access and resource needs.' },
  { id: 'subfinder', name: 'Subfinder', category: 'discovery', mode: 'passive',
    detect: { bin: 'subfinder', args: ['-version'] }, parseVersion: /([\d.]+)/,
    license: 'MIT', heavy: false, stages: ['s29'], desc: 'Passive subdomain collection. Providers and sources rate-limited.' },
  { id: 'naabu', name: 'Naabu', category: 'discovery', mode: 'active',
    detect: { bin: 'naabu', args: ['-version'] }, parseVersion: /([\d.]+)/,
    license: 'MIT', heavy: true, rateLimited: true, stages: ['s29'],
    desc: 'Open-port discovery inside allowed scope. Rate and port-count capped.' },
  { id: 'builtwith', name: 'BuiltWith', category: 'fingerprint', mode: 'passive-external',
    apiCheck: 'builtwith', needsKeySetting: 'builtwith_api_key',
    license: 'BuiltWith API terms (paid)', heavy: false, stages: ['s29'],
    desc: 'Technology lookup via official website/API with valid access, not a free local CLI.' },
  { id: 'virustotal', name: 'VirusTotal', category: 'reputation', mode: 'passive-external',
    apiCheck: 'virustotal', needsKeySetting: 'virustotal_api_key',
    license: 'VirusTotal API terms', heavy: false, stages: ['s10'],
    desc: 'URL/domain reputation via official API with key. Never download or execute files.' },
  { id: 'urlscan', name: 'urlscan.io', category: 'reputation', mode: 'passive-external',
    apiCheck: 'urlscan', needsKeySetting: 'urlscan_api_key',
    license: 'urlscan.io API terms', heavy: false, stages: ['s10'],
    desc: 'URL analysis submission. Privacy mode selectable, never submit internal/sensitive URLs.' },
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
    } else if (t.unverified) {
      status = 'unsupported';
      detail = 'Chua xac minh ten du an / repository / chuc nang — khong gia dinh co san';
    } else if (t.protectOnly || t.monitorOnly) {
      status = 'unsupported';
      detail = t.protectOnly
        ? 'Che do bao ve (WAF/gateway), khong phai scanner doc lap — cau hinh rieng'
        : 'Che do giam sat (monitoring), khong phai scanner doc lap — can host giam sat rieng';
    } else if (t.apiCheck) {
      const keyName = t.needsKeySetting;
      const hasKey = keyName ? !!getSetting(keyName) : true;
      if (keyName && !hasKey) { status = 'needs-config'; detail = 'Can API key (Settings → System / external-keys)'; }
      else { status = 'available'; detail = 'API da cau hinh / External service ready'; }
    } else if (t.detect) {
      let binPath = which(t.detect.bin);
      if (!binPath && t.altBin) { try { fs.accessSync(t.altBin, fs.constants.X_OK); binPath = t.altBin; } catch {} }
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

/**
 * Unified adapter runner — every tool uses this interface:
 * installed/API check, version/compat check, scope validation (caller),
 * timeout + resource caps, sanitized stdout/stderr, normalized status,
 * persisted run state + timing + error, abortable, no secrets in logs.
 * States: available | missing | disabled | running | completed | partial | failed | cancelled | unsupported.
 */
export async function runAdapter(ctx, toolId, { args = [], timeoutMs = 120000, maxBytes = 512*1024, parse = null } = {}) {
  const tool = TOOLS.find((x) => x.id === toolId);
  const startedAt = nowMs();
  if (!tool) { return { status: 'unsupported', detail: 'unknown-tool' }; }
  if (tool.unverified) {
    recordToolRun({ scanId: ctx.scan.id, toolId, status: 'unsupported', startedAt, stderrExcerpt: 'unverified-project' });
    ctx.log('warn', tool.name + ': chua xac minh du an/repo/chuc nang — bo qua, khong gia lap ket qua');
    return { status: 'unsupported', detail: 'unverified' };
  }
  if (tool.protectOnly || tool.monitorOnly) {
    recordToolRun({ scanId: ctx.scan.id, toolId, status: 'unsupported', startedAt, stderrExcerpt: tool.protectOnly ? 'protect-mode' : 'monitor-mode' });
    ctx.log('info', tool.name + ': che do ' + (tool.protectOnly ? 'bao ve (WAF/gateway)' : 'giam sat') + ' — khong chay nhu scanner doc lap');
    return { status: 'unsupported', detail: tool.protectOnly ? 'protect-mode' : 'monitor-mode' };
  }
  const stored = loadStored()[toolId];
  if (stored && stored.userDisabled) {
    recordToolRun({ scanId: ctx.scan.id, toolId, status: 'cancelled', startedAt, stderrExcerpt: 'disabled' });
    return { status: 'disabled', detail: 'user-disabled' };
  }
  if (!toolAvailable(toolId)) {
    const st = (stored && stored.status) || 'missing';
    recordToolRun({ scanId: ctx.scan.id, toolId, status: st === 'needs-config' ? 'failed' : st, startedAt, stderrExcerpt: (stored && stored.detail || st).slice(0, 300) });
    ctx.log('info', tool.name + ' khong san sang (' + st + ') — bo qua');
    return { status: st, detail: stored && stored.detail };
  }
  if (!ctx.getTarget()) return { status: 'failed', detail: 'no-target-scope' };
  const bin = tool.detect ? tool.detect.bin : toolId;
  const r = await runTool(bin, args, { timeoutMs, maxBytes, signal: ctx.signal });
  if (ctx.signal && ctx.signal.aborted) {
    recordToolRun({ scanId: ctx.scan.id, toolId, version: stored && stored.version, status: 'cancelled', exitCode: r.exitCode, startedAt, stderrExcerpt: 'cancelled_by_user' });
    return { status: 'cancelled', run: r };
  }
  const status = r.ok ? 'completed' : (r.stdout && r.stdout.length ? 'partial' : 'failed');
  recordToolRun({ scanId: ctx.scan.id, toolId, version: stored && stored.version, status, exitCode: r.exitCode, startedAt, stderrExcerpt: (r.stderr || r.spawnError || '').slice(0, 500) });
  let parsed = null;
  if (parse && r.stdout) { try { parsed = parse(r.stdout.slice(0, 200000)); } catch (e) { parsed = { parseError: String(e.message).slice(0, 200) }; } }
  return { status, run: r, parsed, version: stored && stored.version };
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


