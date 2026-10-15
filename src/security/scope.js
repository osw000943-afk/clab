import dns from 'node:dns';
import net from 'node:net';
import tls from 'node:tls';
import { config } from '../config.js';

/**
 * Scope & Safety Engine.
 *
 * Every outbound request / tool invocation must go through assertUrlAllowed()
 * (or assertHostPortAllowed for raw TCP). We resolve DNS ourselves and block
 * loopback / private / link-local / metadata ranges — including after redirects
 * (call again for each hop) — so clab can never be an internal-network proxy.
 *
 * Escape hatch for authorized internal labs: CLAB_ALLOW_PRIVATE=1 in .env
 * (default OFF; must never be set in an internet-exposed deployment).
 */
const ALLOW_PRIVATE = process.env.CLAB_ALLOW_PRIVATE === '1';
export const allowPrivateTargets = ALLOW_PRIVATE;

const BLOCKED_HOSTNAMES = new Set(['localhost', 'metadata.google.internal', 'instance-data']);

/** Ranges that must NEVER be scan targets (loopback, link-local incl. cloud metadata). */
const NEVER_SCAN = new Set(['127.0.0.0/8', '169.254.0.0/16', 'loopback', 'link-local']);

function ipToBigInt(ip) {
  const p = ip.split('.').map(Number);
  // pure Number arithmetic (no bitwise) -> unsigned 32-bit compare-safe
  return ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3];
}

const w = (a, b, c, d) => ((a * 256 + b) * 256 + c) * 256 + d;
const V4_BLOCKS = [
  ['0.0.0.0/8', w(0,0,0,0), w(255,0,0,0)],
  ['10.0.0.0/8', w(10,0,0,0), w(255,0,0,0)],
  ['100.64.0.0/10', w(100,64,0,0), w(255,192,0,0)],
  ['127.0.0.0/8', w(127,0,0,0), w(255,0,0,0)],
  ['169.254.0.0/16', w(169,254,0,0), w(255,255,0,0)],
  ['172.16.0.0/12', w(172,16,0,0), w(255,240,0,0)],
  ['192.0.0.0/24', w(192,0,0,0), w(255,255,255,0)],
  ['192.0.2.0/24', w(192,0,2,0), w(255,255,255,0)],
  ['192.168.0.0/16', w(192,168,0,0), w(255,255,0,0)],
  ['198.18.0.0/15', w(198,18,0,0), w(255,254,0,0)],
  ['198.51.100.0/24', w(198,51,100,0), w(255,255,255,0)],
  ['203.0.113.0/24', w(203,0,113,0), w(255,255,255,0)],
  ['224.0.0.0/4', w(224,0,0,0), w(240,0,0,0)],
  ['240.0.0.0/4', w(240,0,0,0), w(240,0,0,0)],
];

export function classifyIp(ip) {
  if (net.isIPv4(ip)) {
    const n = ipToBigInt(ip) >>> 0;
    for (const [name, base, mask] of V4_BLOCKS) {
      if (((n & (mask >>> 0)) >>> 0) === (base >>> 0)) return name;
    }
    return 'public';
  }
  if (net.isIPv6(ip)) {
    const norm = ip.toLowerCase();
    if (norm === '::1') return 'loopback';
    if (norm === '::') return 'unspecified';
    if (norm.startsWith('fe80:')) return 'link-local';
    if (/^f[cd]/.test(norm)) return 'ula';
    const m = norm.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (m) return classifyIp(m[1]);
    if (norm.startsWith('ff')) return 'multicast';
    return 'public';
  }
  return 'invalid';
}

export function isBlockedIp(ip) {
  return classifyIp(ip) !== 'public';
}

export async function resolveHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) return { ips: [host], literal: true };
  const [v4, v6] = await Promise.allSettled([
    dns.promises.resolve4(host),
    dns.promises.resolve6(host),
  ]);
  const ips = [];
  if (v4.status === 'fulfilled') ips.push(...v4.value);
  if (v6.status === 'fulfilled') ips.push(...v6.value.filter((i) => !i.startsWith('fe80')));
  if (!ips.length) {
    const e = new Error(`dns_resolution_failed:${host}`);
    e.code = 'DNS_FAIL';
    throw e;
  }
  return { ips, literal: false };
}

/**
 * Validate a user-supplied URL for scanning.
 * @returns {Promise<{url: URL, host: string, port: number, ips: string[], scheme: string}>}
 */
export async function assertUrlAllowed(rawUrl, { allowHttp = true, allowHttps = true } = {}) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw err('invalid_url', 'URL không hợp lệ / invalid URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw err('scheme_not_allowed', `Scheme không được phép: ${url.protocol}`);
  }
  if (url.protocol === 'http:' && !allowHttp) throw err('scheme_not_allowed', 'HTTP bị tắt trong cấu hình');
  if (url.protocol === 'https:' && !allowHttps) throw err('scheme_not_allowed', 'HTTPS bị tắt trong cấu hình');
  if (url.username || url.password) {
    throw err('credentials_in_url', 'Không được đặt username/password trong URL');
  }
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (BLOCKED_HOSTNAMES.has(host) && !(ALLOW_PRIVATE && host === 'localhost')) {
    throw err('blocked_host', `Hostname bị chặn: ${host}`);
  }
  const { ips } = await resolveHost(host);
  // SSRF hard denylist: loopback / link-local / metadata ALWAYS blocked,
  // even in authorized-lab mode.
  const hard = ips.find((ip) => NEVER_SCAN.has(classifyIp(ip)));
  if (hard) {
    throw err('blocked_ip', `Địa chỉ bị cấm tuyệt đối (${classifyIp(hard)}): ${hard} — không bao giờ được quét`);
  }
  const bad = ALLOW_PRIVATE ? null : ips.find(isBlockedIp);
  if (bad) {
    throw err('blocked_ip', `Địa chỉ bị chặn (${classifyIp(bad)}): ${bad} — không được phép quét mạng nội bộ`);
  }
  const port = url.port ? Number(url.port) : (url.protocol === 'https:' ? 443 : 80);
  return { url, host, port, ips, scheme: url.protocol.replace(':', '') };
}

/** Validate a raw host:port pair (used by port scan / DB audit modules). */
export async function assertHostPortAllowed(hostRaw, port) {
  const host = String(hostRaw).replace(/^\[|\]$/g, '');
  const p = Number(port);
  if (!Number.isInteger(p) || p < 1 || p > 65535) throw err('invalid_port', 'Cổng không hợp lệ');
  if (BLOCKED_HOSTNAMES.has(host.toLowerCase()) && !(ALLOW_PRIVATE && host.toLowerCase() === 'localhost')) throw err('blocked_host', `Hostname bị chặn: ${host}`);
  if (!net.isIP(host) && !/^[a-z0-9._-]+$/i.test(host)) throw err('invalid_host', 'Hostname không hợp lệ');
  const { ips } = await resolveHost(host);
  const hard = ips.find((ip) => NEVER_SCAN.has(classifyIp(ip)));
  if (hard) throw err('blocked_ip', `Địa chỉ bị cấm tuyệt đối (${classifyIp(hard)}): ${hard}`);
  const bad = ALLOW_PRIVATE ? null : ips.find(isBlockedIp);
  if (bad) throw err('blocked_ip', `Địa chỉ bị chặn (${classifyIp(bad)}): ${bad}`);
  return { host, port: p, ips };
}

function err(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}

/**
 * Hardened fetch: re-validates every redirect hop, caps response size,
 * enforces timeout. Used by all HTTP probing stages.
 */
export async function safeFetch(rawUrl, init = {}) {
  const maxRedirects = init.maxRedirects ?? 3;
  const maxBytes = init.maxBytes ?? 512 * 1024;
  const timeoutMs = init.timeoutMs ?? 15_000;
  let current = rawUrl;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    const v = await assertUrlAllowed(current);
    const res = await doFetch(v, { ...init, maxBytes, timeoutMs });
    const loc = res.headers.location;
    if ([301, 302, 303, 307, 308].includes(res.status) && loc) {
      current = new URL(loc, v.url.toString()).toString();
      continue;
    }
    return { ...res, finalUrl: v.url.toString(), redirectCount: hop };
  }
  throw err('too_many_redirects', 'Vượt quá số redirect cho phép');
}

async function doFetch(v, init) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), init.timeoutMs);
  try {
    const res = await fetch(v.url.toString(), {
      method: init.method || 'GET',
      redirect: 'manual',
      signal: controller.signal,
      headers: init.headers || { 'user-agent': 'clab-scanner/1.0 (+whitehat-lab)' },
      ...(init.body !== undefined ? { body: init.body } : {}),
    });
    const headers = Object.fromEntries(res.headers.entries());
    let body = null;
    if (init.includeBody !== false && res.body) {
      const chunks = [];
      let total = 0;
      const reader = res.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.length;
        if (total > init.maxBytes) {
          const remain = Math.max(0, init.maxBytes - (total - value.length));
          if (remain > 0) chunks.push(value.subarray(0, remain));
          try { await reader.cancel(); } catch { /* ignore */ }
          break;
        }
        chunks.push(value);
      }
      body = Buffer.concat(chunks);
    }
    return {
      status: res.status,
      statusText: res.statusText,
      headers,
      body,
      truncated: body ? body.length >= init.maxBytes : false,
    };
  } catch (e) {
    if (e.name === 'AbortError') throw err('timeout', `Request hết thời gian chờ: ${v.url}`);
    if (e.code && typeof e.code === 'string' && e.code.startsWith('blocked')) throw e;
    if (e.code && typeof e.code === 'string' && ['invalid_url', 'scheme_not_allowed', 'credentials_in_url', 'too_many_redirects'].includes(e.code)) throw e;
    throw err('fetch_failed', `${v.url}: ${e.message}`);
  } finally {
    clearTimeout(timer);
  }
}

/** TLS handshake probe: certificate, protocol version, cipher (evidence only, no verification). */
export function tlsProbe(host, port, timeoutMs = 8000) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (r) => { if (!settled) { settled = true; resolve(r); } };
    let sock;
    try {
      sock = tls.connect({
        host, port, servername: net.isIP(host) ? undefined : host,
        rejectUnauthorized: false, timeout: timeoutMs,
      });
    } catch (e) {
      return done({ ok: false, error: e.message });
    }
    sock.on('secureConnect', () => {
      const cert = sock.getPeerCertificate(false);
      const out = {
        ok: true,
        protocol: sock.getProtocol(),
        cipher: sock.getCipher(),
        authorized: sock.authorized,
        authError: sock.authorizationError || null,
        cert: cert && cert.subject ? {
          subject: cert.subject, issuer: cert.issuer, valid_from: cert.valid_from,
          valid_to: cert.valid_to, fingerprint256: cert.fingerprint256, subjectaltname: cert.subjectaltname,
        } : null,
      };
      sock.end();
      done(out);
    });
    sock.on('error', (e) => done({ ok: false, error: e.message }));
    sock.on('timeout', () => { sock.destroy(); done({ ok: false, error: 'timeout' }); });
  });
}

/** TCP connect probe with timeout. */
export function tcpProbe(host, port, timeoutMs = 4000) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let settled = false;
    const done = (r) => { if (!settled) { settled = true; sock.destroy(); resolve(r); } };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => done({ open: true }));
    sock.once('timeout', () => done({ open: false, error: 'timeout' }));
    sock.once('error', (e) => done({ open: false, error: e.code || e.message }));
    try { sock.connect(port, host); } catch (e) { done({ open: false, error: e.message }); }
  });
}

