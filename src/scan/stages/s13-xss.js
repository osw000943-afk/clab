import { runTool, toolAvailable, recordToolRun } from '../tools-registry.js';

/** Dalfox XSS scanning — bounded. No destructive payloads. */
export default {
  id: 's13',
  name: 'XSS & Input Handling (Dalfox)',
  tools: ['dalfox'],
  async run(ctx) {
    const t = ctx.getTarget();
    if (!t) throw new Error('no-target');
    if (!ctx.limits.heavyModulesEnabled) {
      ctx.setSummary({ skipped: 'heavy-disabled' });
      return { summary: ctx._summary };
    }
    if (!toolAvailable('dalfox')) {
      ctx.log('info', 'Dalfox không có sẵn — bỏ qua (cài: https://github.com/hahwul/dalfox)');
      ctx.setSummary({ skipped: 'tool-missing' });
      return { summary: ctx._summary };
    }
    const urls = (ctx.store.paramUrls || []).slice(0, 5);
    if (!urls.length) {
      ctx.log('info', 'Không có URL có tham số để kiểm thử XSS — bỏ qua');
      ctx.setSummary({ skipped: 'no-parameterized-urls' });
      return { summary: ctx._summary };
    }
    const results = { tested: urls.length, findings: 0 };
    for (const u of urls) {
      if (ctx.signal.aborted) throw new Error('cancelled');
      const started = Date.now();
      const r = await runTool('dalfox', ['url', u, '--format', 'json', '--max-time', '90', '--worker', '1', '--skip-bav'],
        { timeoutMs: 120000, maxBytes: 256 * 1024, signal: ctx.signal });
      recordToolRun({ scanId: ctx.scan.id, toolId: 'dalfox', status: r.ok ? 'completed' : 'failed', exitCode: r.exitCode, startedAt: started, stderrExcerpt: (r.stderr || '').slice(0, 400) });
      for (const line of (r.stdout || '').split('\n')) {
        if (!line.trim()) continue;
        try {
          const j = JSON.parse(line);
          if (j.type === 'XSS' || j.poc) {
            results.findings++;
            ctx.addFinding({
              asset: u, stageId: 's13', tool: 'dalfox', severity: 'high', confidence: 'medium',
              title: 'Khả năng XSS trên parameter ' + (j.param || '?'),
              description: 'Dalfox báo cáo reflection/payload XSS có thể thực thi. Cần xác minh thủ công (payload phá hoại không được gửi).',
              evidence: JSON.stringify({ param: j.param, type: j.type, poc: (j.poc || '').slice(0, 200) }).slice(0, 800),
              recommendation: 'Encode output theo ngữ cảnh; dùng CSP; validate input phía server.',
              verification: 'needs-verification',
            });
          }
        } catch { /* not json line */ }
      }
    }
    ctx.setSummary(results);
    return { summary: ctx._summary };
  },
};
