import { runTool, toolAvailable, recordToolRun } from '../tools-registry.js';
import fs from 'node:fs';

/** Semgrep static analysis — authorized local source only, redacted output. */
export default {
  id: 's15',
  name: 'Static Code Analysis (Semgrep)',
  tools: ['semgrep'],
  async run(ctx) {
    const opts = JSON.parse(ctx.scan.options || '{}');
    const localPath = opts.localPath;
    if (!localPath || !fs.existsSync(localPath)) {
      ctx.log('info', 'Không có mã nguồn cục bộ — bỏ qua Semgrep');
      ctx.setSummary({ skipped: 'no-local-source' });
      return { summary: ctx._summary };
    }
    if (!toolAvailable('semgrep')) {
      ctx.log('info', 'Semgrep không có sẵn (pip install semgrep)');
      ctx.setSummary({ skipped: 'tool-missing' });
      return { summary: ctx._summary };
    }
    const started = Date.now();
    const r = await runTool('semgrep', ['scan', '--json', '--quiet', '--timeout', '60', '--max-target-bytes', '1000000', '--config', 'p/security-audit', localPath],
      { timeoutMs: Math.min(ctx.limits.toolTimeoutMs, 300000), maxBytes: 2048 * 1024, signal: ctx.signal });
    recordToolRun({ scanId: ctx.scan.id, toolId: 'semgrep', status: r.ok ? 'completed' : 'failed', exitCode: r.exitCode, startedAt: started, stderrExcerpt: (r.stderr || '').slice(0, 400) });
    const results = { findings: 0 };
    if (r.ok && r.stdout) {
      try {
        const j = JSON.parse(r.stdout);
        for (const res of (j.results || []).slice(0, 60)) {
          results.findings++;
          ctx.addFinding({
            asset: String(res.path || localPath).slice(0, 300), stageId: 's15', tool: 'semgrep',
            severity: mapSev(res.extra?.severity), confidence: 'medium',
            title: (res.check_id || 'semgrep').split('.').slice(-2).join('.'),
            description: String(res.extra?.message || '').slice(0, 800),
            evidence: 'File: ' + res.path + ':' + res.start?.line + ' rule=' + res.check_id,
            component: res.check_id, recommendation: String(res.extra?.lines || '').slice(0, 200) || 'Xem rule semgrep để sửa.',
            verification: 'needs-verification',
          });
        }
      } catch { results.parseFailed = true; }
    }
    ctx.setSummary(results);
    return { summary: ctx._summary };
  },
};
function mapSev(s) {
  const v = String(s || '').toUpperCase();
  if (v === 'ERROR') return 'high';
  if (v === 'WARNING') return 'medium';
  if (v === 'INFO') return 'low';
  return 'informational';
}
