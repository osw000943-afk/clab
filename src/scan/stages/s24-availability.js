/**
 * DDoS & Availability Assessment — APPROVAL-GATED bounded load simulation.
 * Preconditions: settings.availabilityEnabled + per-scan options.availability=true.
 * Limits: <=20 RPS, <=60s, <=300 requests (hard-capped here).
 * Auto-stop: error rate >25% OR p95 latency >3000ms OR owner cancels.
 * Never: floods, amplification, reflection, spoofing, botnet, third-party targets.
 */
const MAX_RPS = 20;
const MAX_DURATION_S = 60;
const MAX_TOTAL = 300;

export default {
  id: 's24',
  name: 'DDoS & Availability Assessment',
  tools: [],
  async run(ctx) {
    const t = ctx.getTarget();
    if (!t) throw new Error('no-target');
    const opts = JSON.parse(ctx.scan.options || '{}');
    if (!ctx.limits.availabilityEnabled) {
      ctx.log('info', 'Availability assessment bị tắt trong Settings → System — bỏ qua');
      ctx.setSummary({ skipped: 'disabled-in-settings' });
      return { summary: ctx._summary };
    }
    if (!opts.availability) {
      ctx.log('info', 'Chưa bật options.availability cho lượt quét này — bỏ qua');
      ctx.setSummary({ skipped: 'not-enabled-for-scan' });
      return { summary: ctx._summary };
    }

    const rps = Math.min(Math.max(Number(opts.loadRps) || 5, 1), MAX_RPS);
    const durationS = Math.min(Math.max(Number(opts.loadSeconds) || 10, 3), MAX_DURATION_S);
    const targetUrl = t.url.toString();
    ctx.log('warn', 'Load simulation: ' + rps + ' RPS trong ' + durationS + 's tới ' + targetUrl + ' (tự dừng nếu lỗi >25% hoặc p95 >3000ms)');

    const latencies = [];
    let errors = 0;
    let total = 0;
    let stopped = null;
    const started = Date.now();
    const intervalMs = 1000 / rps;
    const deadline = started + durationS * 1000;

    while (Date.now() < deadline && total < MAX_TOTAL) {
      if (ctx.signal.aborted) { stopped = 'cancelled-by-owner'; break; }
      const t0 = Date.now();
      try {
        const ctl = new AbortController();
        const to = setTimeout(() => ctl.abort(), 5000);
        const r = await fetch(targetUrl, { signal: ctl.signal, headers: { 'user-agent': 'clab-availability/1.0 (owner-approved load test)' } });
        clearTimeout(to);
        latencies.push(Date.now() - t0);
        if (r.status >= 500) errors++;
        await r.text().catch(() => {}).then((b) => b && b.length > 65536 && null);
      } catch {
        errors++;
        latencies.push(Date.now() - t0);
      }
      total++;
      if (total % 10 === 0) {
        const errRate = errors / total;
        const p95 = percentile(latencies, 0.95);
        if (errRate > 0.25) { stopped = 'error-rate>25% (' + Math.round(errRate * 100) + '%)'; break; }
        if (p95 > 3000) { stopped = 'p95>3000ms (' + p95 + 'ms)'; break; }
      }
      const elapsed = Date.now() - t0;
      if (elapsed < intervalMs) await new Promise((r) => setTimeout(r, intervalMs - elapsed));
    }
    if (!stopped && (Date.now() >= deadline || total >= MAX_TOTAL)) stopped = 'completed';

    const p50 = percentile(latencies, 0.5);
    const p95 = percentile(latencies, 0.95);
    const errRate = total ? errors / total : 0;
    const summary = { rps, durationS, total, errors, errorRate: Math.round(errRate * 1000) / 1000, p50Ms: p50, p95Ms: p95, stopped };

    if (errRate > 0.1) {
      ctx.addFinding({
        asset: targetUrl, stageId: 's24', tool: 'builtin-load', severity: errRate > 0.25 ? 'medium' : 'low', confidence: 'medium',
        title: 'Tỷ lệ lỗi cao dưới tải thấp / Elevated error rate under low load',
        description: 'Chỉ ' + rps + ' RPS đã tạo ' + Math.round(errRate * 100) + '% lỗi (5xx/network) — dấu hiệu thiếu sức chịu tải hoặc cạn connection pool.',
        evidence: JSON.stringify(summary), component: 'availability',
        recommendation: 'Kiểm tra worker/DB pool limits; thêm queuing + horizontal scaling; bật rate limiting để giảm tải đột biến.',
        verification: 'needs-verification',
      });
    }
    if (p95 > 1500) {
      ctx.addFinding({
        asset: targetUrl, stageId: 's24', tool: 'builtin-load', severity: 'low', confidence: 'medium',
        title: 'Latency p95 cao dưới tải thấp / High p95 latency',
        description: 'p95=' + p95 + 'ms ở ' + rps + ' RPS — endpoint có thể thiếu cache hoặc query chậm.',
        evidence: JSON.stringify(summary), component: 'availability',
        recommendation: 'Đo điểm nóng (profiling); tối ưu query/cache; giới hạn request body.',
        verification: 'needs-verification',
      });
    }
    if (!stopped) stopped = 'completed';
    summary.note = 'Mô phỏng tải thấp, có giới hạn, đã được phê duyệt qua cấu hình — không phải flood/DDoS.';
    ctx.setSummary(summary);
    return { summary: ctx._summary };
  },
};

function percentile(arr, p) {
  if (!arr.length) return 0;
  const s = [...arr].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor(p * s.length))];
}
