import { runTool, toolAvailable, recordToolRun } from '../tools-registry.js';
import fs from 'node:fs';
import path from 'node:path';

const MANIFESTS = ['package-lock.json', 'package.json', 'requirements.txt', 'Pipfile.lock', 'go.sum', 'Cargo.lock', 'Gemfile.lock', 'composer.lock', 'pom.xml'];

/** Dependency & CVE scan — local authorized source trees only. */
export default {
  id: 's14',
  name: 'Dependency & CVE',
  tools: ['trivy', 'osv-scanner'],
  async run(ctx) {
    const opts = JSON.parse(ctx.scan.options || '{}');
    const localPath = opts.localPath;
    if (!localPath || !fs.existsSync(localPath)) {
      ctx.log('info', 'Không có localPath (mã nguồn cục bộ) — stage này chỉ áp dụng cho repo cục bộ được ủy quyền');
      ctx.setSummary({ skipped: 'no-local-source' });
      return { summary: ctx._summary };
    }
    const root = path.resolve(localPath);
    const found = MANIFESTS.filter((m) => fs.existsSync(path.join(root, m)));
    if (!found.length) {
      ctx.log('info', 'Không tìm thấy manifest dependency trong ' + root);
      ctx.setSummary({ skipped: 'no-manifests', root });
      return { summary: ctx._summary };
    }
    const results = { root, manifests: found, tools: {} };

    if (toolAvailable('trivy')) {
      const started = Date.now();
      const r = await runTool('trivy', ['fs', '--scanners', 'vuln', '--quiet', '--format', 'json', '--timeout', '120s', root],
        { timeoutMs: 180000, maxBytes: 1024 * 1024, signal: ctx.signal });
      recordToolRun({ scanId: ctx.scan.id, toolId: 'trivy', status: r.ok ? 'completed' : 'failed', exitCode: r.exitCode, startedAt: started, stderrExcerpt: (r.stderr || '').slice(0, 400) });
      results.tools.trivy = r.ok ? 'ok' : 'failed';
      if (r.ok) {
        try {
          const j = JSON.parse(r.stdout);
          for (const res of (j.Results || [])) {
            for (const v of (res.Vulnerabilities || []).slice(0, 30)) {
              ctx.addFinding({
                asset: root, stageId: 's14', tool: 'trivy', severity: mapSev(v.Severity), confidence: 'high',
                title: (v.VulnerabilityID || 'CVE') + ' trong ' + (v.PkgName || '?'),
                description: (v.Title || v.Description || '').slice(0, 600),
                evidence: JSON.stringify({ id: v.VulnerabilityID, pkg: v.PkgName, installed: v.InstalledVersion, fixed: v.FixedVersion }).slice(0, 600),
                component: v.PkgName, recommendation: v.FixedVersion ? 'Nâng cấp lên ' + v.FixedVersion + '.' : 'Theo dõi bản vá từ nhà phát hành.',
                verification: 'confirmed',
              });
            }
          }
        } catch { results.tools.trivy = 'parse-failed'; }
      }
    }

    if (toolAvailable('osv-scanner')) {
      const started = Date.now();
      const r = await runTool('osv-scanner', ['scan', '-r', '--format', 'json', root],
        { timeoutMs: 180000, maxBytes: 1024 * 1024, signal: ctx.signal });
      recordToolRun({ scanId: ctx.scan.id, toolId: 'osv-scanner', status: r.ok ? 'completed' : 'failed', exitCode: r.exitCode, startedAt: started, stderrExcerpt: (r.stderr || '').slice(0, 400) });
      results.tools['osv-scanner'] = r.ok ? 'ok' : 'failed';
      if (r.ok) {
        try {
          const j = JSON.parse(r.stdout);
          for (const res of (j.results || [])) {
            for (const v of (res.vulnerabilities || []).slice(0, 30)) {
              ctx.addFinding({
                asset: root, stageId: 's14', tool: 'osv-scanner', severity: 'medium', confidence: 'high',
                title: (v.id || 'OSV') + ' trong ' + (res.package?.name || '?'),
                description: (v.summary || '').slice(0, 400),
                evidence: JSON.stringify({ id: v.id, package: res.package?.name, version: res.package?.version, fixed: (v.affected?.[0]?.ranges?.[0]?.events || []).slice(-1) }).slice(0, 600),
                recommendation: 'Kiểm tra affected versions và nâng cấp theo OSV advisory.',
                verification: 'confirmed',
              });
            }
          }
        } catch { results.tools['osv-scanner'] = 'parse-failed'; }
      }
    }

    if (!Object.keys(results.tools).length) {
      ctx.log('info', 'Cả trivy và osv-scanner đều không có sẵn — stage hoàn thành không có dữ liệu CVE');
      results.tools = { note: 'both-tools-missing' };
    }
    ctx.setSummary(results);
    return { summary: ctx._summary };
  },
};

function mapSev(s) {
  const v = String(s || '').toLowerCase();
  if (v === 'critical') return 'critical';
  if (v === 'high') return 'high';
  if (v === 'medium') return 'medium';
  if (v === 'low') return 'low';
  return 'informational';
}
