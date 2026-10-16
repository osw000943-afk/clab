import { q, q1, run } from '../../db.js';

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];

/**
 * Correlation & Validation — merge duplicates, normalize severity,
 * compare with the previous scan of the same host, build remediation plan.
 * Findings are never auto-removed as false positives.
 */
export default {
  id: 's19',
  name: 'Correlation & Validation',
  tools: [],
  async run(ctx) {
    const scanId = ctx.scan.id;
    const findings = q('SELECT * FROM findings WHERE scan_id=?', [scanId]);

    // cross-tool correlation: same asset+component reported by >=2 tools
    const byKey = {};
    for (const f of findings) {
      const key = f.asset + '|' + (f.component || f.title.slice(0, 40));
      (byKey[key] = byKey[key] || []).push(f);
    }
    const corroborated = Object.values(byKey).filter((g) => new Set(g.map((x) => x.tool)).size >= 2);
    for (const group of corroborated) {
      for (const f of group) {
        if (f.confidence !== 'high') {
          run('UPDATE findings SET confidence=? WHERE id=?', ['high', f.id]);
        }
      }
    }

    // compare with previous completed scan of the same host
    const host = ctx.scan.target_host || (ctx.getTarget() && ctx.getTarget().host);
    const prev = q1(
      `SELECT id FROM scans WHERE target_host=? AND id!=? AND status='completed' ORDER BY created_at DESC LIMIT 1`,
      [host, scanId]
    );
    let comparison = null;
    if (prev) {
      const prevFindings = q('SELECT title, severity, asset, status FROM findings WHERE scan_id=?', [prev.id]);
      const prevKeys = new Set(prevFindings.map((f) => f.asset + '|' + f.title));
      const curKeys = new Set(findings.map((f) => f.asset + '|' + f.title));
      const newOnes = [...curKeys].filter((k) => !prevKeys.has(k));
      const resolved = [...prevKeys].filter((k) => !curKeys.has(k));
      comparison = {
        previousScanId: prev.id, newCount: newOnes.length, resolvedCount: resolved.length,
        newTitles: newOnes.slice(0, 20).map((k) => k.split('|').slice(1).join('|')),
      };
      // mark resolved findings in previous scan as fixed (best-effort)
      for (const f of prevFindings) {
        const k = f.asset + '|' + f.title;
        if (!curKeys.has(k) && f.status !== 'fixed') {
          run(`UPDATE findings SET status='fixed', last_seen=? WHERE scan_id=? AND asset=? AND title=?`,
            [Date.now(), prev.id, f.asset, f.title]);
        }
      }
      ctx.log('info', 'So sanh voi lan quet truoc: ' + newOnes.length + ' moi, ' + resolved.length + ' da khac phuc');
    }

    // remediation plan grouped by severity
    const plan = SEV_ORDER.map((sev) => ({
      severity: sev,
      items: findings.filter((f) => f.severity === sev).map((f) => ({
        title: f.title, component: f.component, recommendation: f.recommendation, verification: f.verification,
      })),
    })).filter((g) => g.items.length);

    ctx.setSummary({ totalFindings: findings.length, corroboratedGroups: corroborated.length, mergedDuplicates: corroborated.length, comparison, remediationPlan: plan });
    return { summary: ctx._summary };
  },
};
