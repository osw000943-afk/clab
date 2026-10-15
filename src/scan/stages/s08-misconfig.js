import { runTool, toolAvailable, recordToolRun } from '../tools-registry.js';

// Bounded wordlist - sensitive paths & common misconfig markers (GET, tiny bodies only).
const PATHS = [
  '/.git/HEAD', '/.env', '/.env.backup', '/.env.local', '/.git/config',
  '/backup.zip', '/backup.sql', '/dump.sql', '/db.sql',
  '/server-status', '/server-info', '/.htaccess', '/.htpasswd',
  '/phpinfo.php', '/info.php', '/test.php',
  '/admin/', '/administrator/', '/wp-admin/', '/phpmyadmin/', '/pma/',
  '/actuator', '/actuator/health', '/actuator/env', '/metrics', '/debug',
  '/.DS_Store', '/.svn/entries', '/.well-known/security.txt',
  '/config.json', '/config.yml', '/swagger.json', '/openapi.json', '/api-docs',
  '/trace.axd', '/elmah.axd', '/console', '/solr/', '/jmx-console/',
];

const SENSITIVE = {
  '/.git/HEAD': { sev: 'high', why: 'Repository Git bi lo cong khai - co the khoi phuc source.' },
  '/.git/config': { sev: 'high', why: 'Cau hinh Git bi lo.' },
  '/.env': { sev: 'critical', why: 'File .env thuong chua secret (API key, DB password).' },
  '/.env.backup': { sev: 'critical', why: 'Backup .env chua secret.' },
  '/.env.local': { sev: 'critical', why: 'File .env.local chua secret.' },
  '/backup.sql': { sev: 'critical', why: 'Dump database cong khai.' },
  '/dump.sql': { sev: 'critical', why: 'Dump database cong khai.' },
  '/db.sql': { sev: 'critical', why: 'Dump database cong khai.' },
  '/backup.zip': { sev: 'high', why: 'File backup cong khai co the chua nguon/secret.' },
  '/.htpasswd': { sev: 'high', why: 'File hash mat khau HTTP bi lo.' },
  '/phpinfo.php': { sev: 'medium', why: 'phpinfo() lo cau hinh server.' },
  '/info.php': { sev: 'medium', why: 'Trang info lo cau hinh server.' },
  '/actuator/env': { sev: 'high', why: 'Spring Actuator env lo bien moi truong (secret).' },
  '/actuator': { sev: 'low', why: 'Actuator endpoints lo thong tin quan tri.' },
  '/.svn/entries': { sev: 'high', why: 'Metadata Subversion bi lo.' },
  '/.DS_Store': { sev: 'low', why: '.DS_Store lo cau truc thu muc.' },
  '/trace.axd': { sev: 'high', why: 'ASP.NET trace lo request noi bo.' },
  '/elmah.axd': { sev: 'high', why: 'ELMAH error log cong khai.' },
  '/console': { sev: 'medium', why: 'Console quan tri cong khai.' },
  '/solr/': { sev: 'medium', why: 'Apache Solr admin cong khai.' },
  '/jmx-console/': { sev: 'high', why: 'JMX Console cong khai.' },
};

export default {
  id: 's08',
  name: 'Web Server Misconfiguration',
  tools: ['nikto'],
  async run(ctx) {
    const t = ctx.getTarget();
    if (!t) throw new Error('no-target');
    const base = t.url.toString().replace(/\/+$/, '');
    const sensitiveHits = [];
    const hits = [];
    const maxPaths = Math.min(ctx.limits.maxProbePaths || 60, PATHS.length);

    for (const p of PATHS.slice(0, maxPaths)) {
      if (ctx.signal.aborted) throw new Error('cancelled');
      try {
        const r = await ctx.fetch(base + p, { method: 'GET', maxBytes: 8192, timeoutMs: 8000 });
        const len = r.body ? r.body.length : 0;
        if (r.status === 200 && len > 0) {
          const bodyHead = r.body ? r.body.toString('utf8', 0, 500) : '';
          const dirList = /<title>\s*index of/i.test(bodyHead);
          hits.push({ path: p, status: r.status, length: len, dirList });
          const s = SENSITIVE[p];
          if (s) {
            sensitiveHits.push(p);
            ctx.addFinding({
              asset: base + p, stageId: 's08', tool: 'builtin-probe', severity: s.sev, confidence: 'high',
              title: 'Duong dan nham cam truy cap duoc: ' + p + ' / Sensitive path exposed',
              description: s.why + ' HTTP 200 voi ' + len + ' bytes. (Chi luu metadata, khong tai noi dung xuong.)',
              evidence: 'GET ' + p + ' -> ' + r.status + ', content-type: ' + (r.headers['content-type'] || 'n/a') + ', length: ' + len,
              component: p, recommendation: 'Chan ' + p + ' o web server/WAF; rotate moi secret co the nam trong do.',
              verification: 'confirmed',
            });
          }
          if (dirList) {
            ctx.addFinding({
              asset: base + p, stageId: 's08', tool: 'builtin-probe', severity: 'medium', confidence: 'high',
              title: 'Danh muc thu muc cong khai: ' + p + ' / Directory listing enabled',
              description: 'Web server liet ke noi dung thu muc - ro ri cau truc file.',
              evidence: 'GET ' + p + ' -> 200, "Index of" detected, length ' + len,
              component: p, recommendation: 'Tat autoindex/directory listing.', verification: 'confirmed',
            });
          }
        } else if (r.status === 401) {
          hits.push({ path: p, status: 401 });
        }
      } catch (e) {
        if (e.code === 'timeout') continue;
        if (['blocked_ip', 'blocked_host'].includes(e.code)) throw e;
      }
    }
    ctx.log('info', 'Path probe: ' + hits.length + ' phan hoi khac 404 tren ' + maxPaths + ' duong dan');

    const nikto = await runNikto(ctx, t);
    ctx.setSummary({ probed: maxPaths, hits: hits.length, sensitiveHits, nikto });
    return { summary: ctx._summary };
  },
};

async function runNikto(ctx, t) {
  if (!toolAvailable('nikto')) {
    ctx.log('info', 'Nikto khong co san - dung path probe noi bo');
    return 'tool-missing';
  }
  const started = Date.now();
  const r = await runTool('nikto', ['-h', t.url.toString(), '-maxtime', '180s', '-nointeractive', '-Format', 'json'],
    { timeoutMs: 240000, maxBytes: 512 * 1024, signal: ctx.signal });
  recordToolRun({ scanId: ctx.scan.id, toolId: 'nikto', status: r.ok ? 'completed' : 'failed', exitCode: r.exitCode, startedAt: started, stderrExcerpt: (r.stderr || '').slice(0, 500) });
  if (!r.ok || !r.stdout) return 'failed:' + (r.stderr || r.spawnError || 'unknown').slice(0, 120);
  try {
    const j = JSON.parse(r.stdout);
    const vulns = (j.Hosts && j.Hosts[0] && j.Hosts[0].Vulnerabilities || []).slice(0, 50);
    for (const v of vulns) {
      ctx.addFinding({
        asset: t.host, stageId: 's08', tool: 'nikto', severity: 'low', confidence: 'medium',
        title: 'Nikto: ' + String(v.msg || '').slice(0, 200),
        description: 'Nikto bao cao: ' + (v.id || 'n/a'),
        evidence: JSON.stringify(v).slice(0, 1500),
        recommendation: 'Doi chieu voi cau hinh web server va neu phu hop thi sua.', verification: 'needs-verification',
      });
    }
    return 'ok:' + vulns.length + ' findings';
  } catch {
    return 'parse-failed';
  }
}
