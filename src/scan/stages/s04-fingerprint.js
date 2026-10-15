import { runTool, toolAvailable, recordToolRun } from '../tools-registry.js';

const GEN_RE = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']{1,120})["']/i;
const SIGNATURES = [
  [/wp-content\/|wp-includes\//i, 'WordPress', 'body'],
  [/Drupal\.settings|\/sites\/default\/files\//i, 'Drupal', 'body'],
  [/\/_next\/static\//i, 'Next.js', 'body'],
  [/joomla!/i, 'Joomla', 'body'],
  [/shopify/i, 'Shopify', 'header-or-body'],
  [/\/cdn-cgi\/trace|cf-ray/i, 'Cloudflare', 'header'],
  [/x-powered-by:\s*([\w./-]+)/i, 'tech:x-powered-by', 'header'],
  [/server:\s*([\w./-]+)/i, 'tech:server', 'header'],
];

export default {
  id: 's04',
  name: 'Fingerprinting',
  tools: ['whatweb'],
  async run(ctx) {
    const t = ctx.getTarget();
    const http = ctx.store.http;
    const detected = [];

    if (http) {
      const headerText = Object.entries(http.headers).map(([k, v]) => `${k}: ${v}`).join('\n');
      const hay = headerText + '\n' + (http.bodySnippet || '');
      const gen = (http.bodySnippet || '').match(GEN_RE);
      if (gen) {
        detected.push({ tech: gen[1].split(' ')[0], version: (gen[1].match(/[\d.]+/) || [null])[0], source: 'generator-meta', confidence: 'high' });
      }
      for (const [re, name, src] of SIGNATURES) {
        if (re.test(src === 'header' ? headerText : hay)) {
          detected.push({ tech: name.replace('tech:', ''), source: src, confidence: src === 'header' ? 'medium' : 'high' });
        }
      }
      const cookie = http.headers['set-cookie'] || '';
      if (/PHPSESSID/i.test(cookie)) detected.push({ tech: 'PHP', source: 'cookie', confidence: 'medium' });
      if (/JSESSIONID/i.test(cookie)) detected.push({ tech: 'Java (Servlet)', source: 'cookie', confidence: 'medium' });
      if (/ASP\.NET_SessionId/i.test(cookie)) detected.push({ tech: 'ASP.NET', source: 'cookie', confidence: 'medium' });
    }

    // WhatWeb if available (aggressive off, short timeout)
    let whatweb = null;
    if (toolAvailable('whatweb') && t) {
      const started = now();
      const r = await runTool('whatweb', ['--log-json=-', '--color=never', '-t', '3', '--open-redirection', '0', t.url.toString()],
        { timeoutMs: 90_000, maxBytes: 256 * 1024, signal: ctx.signal });
      recordToolRun({ scanId: ctx.scan.id, toolId: 'whatweb', status: r.ok ? 'completed' : 'failed', exitCode: r.exitCode, startedAt: started, stderrExcerpt: r.stderr?.slice(0, 500) });
      if (r.ok && r.stdout) {
        try {
          for (const line of r.stdout.split('\n')) {
            if (!line.trim()) continue;
            const j = JSON.parse(line);
            for (const [plugin, data] of Object.entries(j.plugins || {})) {
              detected.push({ tech: plugin, version: data.version || null, source: 'whatweb', confidence: 'high', strings: (data.strings || []).slice(0, 3) });
            }
          }
          whatweb = 'ok';
        } catch { whatweb = 'parse-failed'; }
      } else {
        whatweb = `failed:${r.stderr?.slice(0, 120) || r.spawnError || 'unknown'}`;
      }
    } else {
      whatweb = 'tool-missing';
      ctx.log('info', 'WhatWeb không có sẵn — dùng fingerprint nội bộ (built-in signatures)');
    }

    ctx.store.fingerprint = detected;
    ctx.setSummary({ detected, whatweb });
    return { summary: ctx._summary };
  },
};

function now() { return Date.now(); }
