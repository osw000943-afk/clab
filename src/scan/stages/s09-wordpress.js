import { runTool, toolAvailable, recordToolRun } from '../tools-registry.js';

export default {
  id: 's09',
  name: 'CMS / WordPress',
  tools: ['wpscan'],
  async run(ctx) {
    const t = ctx.getTarget();
    if (!t) throw new Error('no-target');
    const fp = ctx.store.fingerprint || [];
    const http = ctx.store.http;
    const isWp = fp.some((d) => /wordpress/i.test(d.tech)) ||
      /wp-content|wp-includes/i.test(http?.bodySnippet || '') ||
      /WordPress/i.test(http?.headers?.['x-powered-by'] || '');

    if (!isWp) {
      ctx.log('info', 'Không phát hiện WordPress — bỏ qua WPScan');
      ctx.setSummary({ wordpress: false, skipped: 'not-wordpress' });
      return { summary: ctx._summary };
    }

    const gen = fp.find((d) => /wordpress/i.test(d.tech) && d.version);
    ctx.addFinding({
      asset: t.host, stageId: 's09', tool: 'builtin-detect', severity: 'informational', confidence: 'high',
      title: 'Phát hiện WordPress / WordPress detected',
      description: `Website sử dụng WordPress${gen?.version ? ` (phiên bản ${gen.version} theo generator meta)` : ' (chưa xác định phiên bản)'}.`,
      evidence: gen ? `generator: WordPress ${gen.version}` : 'wp-content/wp-includes markers in HTML',
      recommendation: 'Giữ WordPress, plugin và theme cập nhật; giới hạn wp-admin bằng allowlist.',
      verification: 'confirmed',
    });

    let wpscan = 'tool-missing';
    if (toolAvailable('wpscan')) {
      const token = JSON.parse(ctx.scan.options || '{}').wpscanToken;
      const args = ['--url', t.url.toString(), '--format', 'json', '--no-banner', '--detection-mode', 'passive', '--max-time', '180'];
      if (token) args.push('--token', token);
      const started = Date.now();
      const r = await runTool('wpscan', args, { timeoutMs: 240_000, maxBytes: 1024 * 1024, signal: ctx.signal });
      recordToolRun({ scanId: ctx.scan.id, toolId: 'wpscan', status: r.ok ? 'completed' : 'failed', exitCode: r.exitCode, startedAt: started, stderrExcerpt: r.stderr?.slice(0, 500) });
      if (r.ok && r.stdout) {
        try {
          const j = JSON.parse(r.stdout);
          const version = j.version?.number ? String(j.version.number) : null;
          if (version && j.version?.status === 'insecure') {
            ctx.addFinding({
              asset: t.host, stageId: 's09', tool: 'wpscan', severity: 'high', confidence: 'medium',
              title: `WordPress ${version} có lỗ hổng đã biết / Known vulnerable WordPress version`,
              description: 'WPScan đánh giá phiên bản WordPress hiện tại đã có lỗ hổng đã biết.',
              evidence: JSON.stringify(j.version).slice(0, 800),
              recommendation: 'Nâng cấp WordPress lên bản mới nhất.', verification: 'needs-verification',
            });
          }
          const vulns = Object.values(j.vulnerabilities || {}).slice(0, 20);
          for (const v of vulns) {
            ctx.addFinding({
              asset: t.host, stageId: 's09', tool: 'wpscan', severity: 'high', confidence: 'medium',
              title: `WPScan: ${(v.title || 'vulnerability').slice(0, 180)}`,
              description: `Phiên bản WordPress có lỗ hổng đã báo cáo: ${v.id || ''}`,
              evidence: JSON.stringify({ id: v.id, fixed_in: v.fixed_in }).slice(0, 800),
              recommendation: v.fixed_in ? `Nâng cấp lên ${v.fixed_in}.` : 'Tham khảo advisory và nâng cấp.',
              verification: 'needs-verification',
            });
          }
          wpscan = `ok version=${version || 'unknown'}`;
        } catch { wpscan = 'parse-failed'; }
      } else {
        wpscan = `failed:${(r.stderr || r.spawnError || '').slice(0, 120)}`;
      }
    } else {
      ctx.log('info', 'WPScan không có sẵn — chỉ ghi nhận phát hiện WordPress (built-in)');
    }

    ctx.setSummary({ wordpress: true, wpscan });
    return { summary: ctx._summary };
  },
};
