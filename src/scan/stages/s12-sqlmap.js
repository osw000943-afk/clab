import { runTool, toolAvailable, recordToolRun } from '../tools-registry.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

/**
 * sqlmap — SQL injection testing with hard limits:
 * no dumping, no destructive options, level/risk 1, bounded time.
 */
export default {
  id: 's12',
  name: 'SQL Injection (sqlmap)',
  tools: ['sqlmap'],
  async run(ctx) {
    const t = ctx.getTarget();
    if (!t) throw new Error('no-target');
    if (!ctx.limits.heavyModulesEnabled) {
      ctx.setSummary({ skipped: 'heavy-disabled' });
      return { summary: ctx._summary };
    }
    if (!toolAvailable('sqlmap')) {
      ctx.log('info', 'sqlmap không có sẵn — bỏ qua (cài: https://github.com/sqlmapproject/sqlmap)');
      ctx.setSummary({ skipped: 'tool-missing' });
      return { summary: ctx._summary };
    }
    const urls = (ctx.store.paramUrls || []).slice(0, 5); // cap targets
    if (!urls.length) {
      ctx.log('info', 'Không phát hiện URL có tham số — bỏ qua sqlmap');
      ctx.setSummary({ skipped: 'no-parameterized-urls' });
      return { summary: ctx._summary };
    }
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'clab-sqlmap-'));
    const results = { tested: urls.length, findings: 0 };
    try {
      for (const u of urls) {
        if (ctx.signal.aborted) throw new Error('cancelled');
        const started = Date.now();
        const r = await runTool('sqlmap', [
          '-u', u, '--batch', '--level', '1', '--risk', '1', '--max-time', '120', '--threads', '1',
          '--technique', 'BEUST', '--output-dir', tmp, '--flush-session',
          '--answers', 'follow=N,question1=N,question2=N',
        ], { timeoutMs: 180000, maxBytes: 256 * 1024, signal: ctx.signal });
        recordToolRun({ scanId: ctx.scan.id, toolId: 'sqlmap', status: r.ok ? 'completed' : 'failed', exitCode: r.exitCode, startedAt: started, stderrExcerpt: (r.stderr || '').slice(0, 400) });
        const out = (r.stdout || '') + (r.stderr || '');
        if (/is vulnerable|sqlmap identified the following injection/i.test(out)) {
          results.findings++;
          ctx.addFinding({
            asset: u, stageId: 's12', tool: 'sqlmap', severity: 'high', confidence: 'high',
            title: 'Khả năng SQL Injection trên ' + new URL(u).pathname,
            description: 'sqlmap xác định tham số có khả năng bị SQL injection. Chạy ở level/risk 1, không dump dữ liệu.',
            evidence: out.match(/\[INFO\][^\n]{0,160}/g)?.slice(-8).join('\n') || out.slice(0, 1200),
            recommendation: 'Sử dụng parameterized queries/ORM an toàn; thêm WAF rule; xác minh tay trước khi vá.',
            verification: 'needs-verification',
          });
        }
      }
    } finally {
      try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
    }
    ctx.setSummary(results);
    return { summary: ctx._summary };
  },
};
