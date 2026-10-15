import { runTool, toolAvailable, recordToolRun } from '../tools-registry.js';
import fs from 'node:fs';

/**
 * Secret detection (Gitleaks on local repos) + vulnerable JS library heuristics
 * from fetched page scripts (native, since Retire.js CLI scans local dirs only).
 */
const KNOWN_LIBS = [
  { re: /jquery[-.](\d+\.\d+\.\d+)\.(?:min\.)?js/i, name: 'jQuery', safe: (v) => cmp(v, '3.5.0') >= 0 },
  { re: /lodash[-.](\d+\.\d+\.\d+)\.(?:min\.)?js/i, name: 'Lodash', safe: (v) => cmp(v, '4.17.21') >= 0 },
  { re: /angular[-.]?(\d+\.\d+\.\d+)\.(?:min\.)?js/i, name: 'AngularJS', safe: (v) => cmp(v, '1.8.3') >= 0 && cmp(v, '2.0.0') < 0 },
  { re: /bootstrap[/.-](\d+\.\d+\.\d+)/i, name: 'Bootstrap', safe: (v) => cmp(v, '3.4.1') >= 0 && (cmp(v, '4.0.0') < 0 || cmp(v, '5.0.0') >= 0) },
  { re: /prototype\.js.*?\d+\.\d+\.\d+/i, name: 'Prototype.js', safe: () => false },
];

export default {
  id: 's16',
  name: 'Secret & JavaScript Audit',
  tools: ['gitleaks', 'retire'],
  async run(ctx) {
    const opts = JSON.parse(ctx.scan.options || '{}');
    const results = {};

    // Gitleaks on authorized local repos
    if (opts.localPath && fs.existsSync(opts.localPath)) {
      if (toolAvailable('gitleaks')) {
        const started = Date.now();
        const r = await runTool('gitleaks', ['detect', '--no-banner', '--report-format', 'json', '--report-path', '/dev/stdout', '--max-target-size', '2', opts.localPath],
          { timeoutMs: 180000, maxBytes: 512 * 1024, signal: ctx.signal });
        recordToolRun({ scanId: ctx.scan.id, toolId: 'gitleaks', status: r.ok ? 'completed' : 'failed', exitCode: r.exitCode, startedAt: started, stderrExcerpt: (r.stderr || '').slice(0, 400) });
        // gitleaks exits 1 when leaks found — stdout still valid JSON
        try {
          const leaks = JSON.parse(r.stdout || '[]');
          results.gitleaks = leaks.length + ' leaks';
          for (const l of leaks.slice(0, 20)) {
            ctx.addFinding({
              asset: (l.File || opts.localPath).slice(0, 300), stageId: 's16', tool: 'gitleaks', severity: 'critical', confidence: 'high',
              title: 'Secret có thể bị lộ: ' + (l.RuleID || 'unknown'),
              description: 'Gitleaks phát hiện secret trong mã nguồn. Giá trị đã được cắt (không lưu đầy đủ).',
              evidence: JSON.stringify({ file: l.File, line: l.StartLine, rule: l.RuleID, match: String(l.Match || '').slice(0, 20) + '…' }).slice(0, 500),
              recommendation: 'Xoá secret khỏi repo, thu hồi/luân chuyển key, thêm vào .gitignore và dùng secret manager.',
              verification: 'confirmed',
            });
          }
        } catch { results.gitleaks = 'parse-failed'; }
      } else {
        results.gitleaks = 'tool-missing';
      }
    } else {
      results.gitleaks = 'skipped-no-local-source';
    }

    // Native JS library version heuristics from fetched page
    const http = ctx.store.http;
    if (http?.bodySnippet) {
      const scriptRe = /<script[^>]+src=["']([^"']+)["']/gi;
      let m;
      const libs = [];
      while ((m = scriptRe.exec(http.bodySnippet))) {
        for (const lib of KNOWN_LIBS) {
          const lm = m[1].match(lib.re);
          if (lm) {
            const ver = lm[1];
            libs.push({ name: lib.name, version: ver, src: m[1].slice(0, 200) });
            if (!lib.safe(ver)) {
              ctx.addFinding({
                asset: ctx.getTarget().host, stageId: 's16', tool: 'builtin-js-check', severity: 'medium', confidence: 'medium',
                title: lib.name + ' ' + ver + ' có lỗ hổng đã biết / Outdated vulnerable library',
                description: 'Thư viện JavaScript phiên bản cũ có lỗ hổng đã công bố (heuristic theo tên file + phiên bản). Cần đối chiếu với Retire.js/CVE.',
                evidence: m[1].slice(0, 300),
                recommendation: 'Nâng cấp ' + lib.name + ' lên bản an toàn mới nhất.',
                verification: 'needs-verification',
              });
            }
          }
        }
        if (libs.length > 30) break;
      }
      results.jsLibs = libs;
    }
    if (!toolAvailable('retire')) results.retire = 'tool-missing (CLI quét thư mục cục bộ)';

    ctx.setSummary(results);
    return { summary: ctx._summary };
  },
};
function cmp(a, b) {
  const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) { if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0); }
  return 0;
}
