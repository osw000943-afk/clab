import { runTool, toolAvailable, recordToolRun } from '../tools-registry.js';
import fs from 'node:fs';
import path from 'node:path';

const IAC_FILES = ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'main.tf', '*.tf', 'k8s.yaml', 'Chart.yaml'];

/** Checkov IaC scan — authorized local files only, no infra changes. */
export default {
  id: 's17',
  name: 'Infrastructure as Code (Checkov)',
  tools: ['checkov'],
  async run(ctx) {
    const opts = JSON.parse(ctx.scan.options || '{}');
    if (!opts.localPath || !fs.existsSync(opts.localPath)) {
      ctx.setSummary({ skipped: 'no-local-source' });
      return { summary: ctx._summary };
    }
    const hasIac = IAC_FILES.some((f) => f.includes('*')
      ? fs.readdirSync(opts.localPath).some((x) => x.endsWith('.tf'))
      : fs.existsSync(path.join(opts.localPath, f)));
    if (!hasIac) {
      ctx.log('info', 'Không tìm thấy file IaC (Dockerfile/Terraform/Compose)');
      ctx.setSummary({ skipped: 'no-iac-files' });
      return { summary: ctx._summary };
    }
    if (!toolAvailable('checkov')) {
      ctx.log('info', 'Checkov không có sẵn (pip install checkov)');
      ctx.setSummary({ skipped: 'tool-missing' });
      return { summary: ctx._summary };
    }
    const started = Date.now();
    const r = await runTool('checkov', ['-d', opts.localPath, '-o', 'json', '--quiet', '--soft-fail'],
      { timeoutMs: Math.min(ctx.limits.toolTimeoutMs, 300000), maxBytes: 2048 * 1024, signal: ctx.signal });
    recordToolRun({ scanId: ctx.scan.id, toolId: 'checkov', status: r.ok ? 'completed' : 'failed', exitCode: r.exitCode, startedAt: started, stderrExcerpt: (r.stderr || '').slice(0, 400) });
    const results = { findings: 0 };
    if (r.ok && r.stdout) {
      try {
        const j = JSON.parse(r.stdout);
        for (const res of (j.results?.failed_checks || []).slice(0, 40)) {
          results.findings++;
          ctx.addFinding({
            asset: (res.file || opts.localPath).slice(0, 300), stageId: 's17', tool: 'checkov',
            severity: res.severity === 'HIGH' ? 'high' : res.severity === 'MEDIUM' ? 'medium' : 'low',
            confidence: 'high',
            title: (res.check_id || 'checkov') + ': ' + String(res.check_name || '').slice(0, 160),
            description: String(res.check_name || '').slice(0, 600),
            evidence: JSON.stringify({ resource: res.resource, file: res.file, line: res.repo_line_range }).slice(0, 500),
            component: res.resource, recommendation: 'Sửa cấu hình IaC theo guidance của check ' + res.check_id + '.',
            verification: 'confirmed',
          });
        }
      } catch { results.parseFailed = true; }
    }
    ctx.setSummary(results);
    return { summary: ctx._summary };
  },
};
