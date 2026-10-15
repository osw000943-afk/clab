import { tcpProbe } from '../../security/scope.js';

/**
 * Security Bypass Audit — passive-first checks for mechanisms that can be
 * defeated: CORS, method handling, path normalization, rate-limit presence,
 * debug endpoints, trust-boundary headers (X-Forwarded-*), IP allowlist hints.
 * Non-destructive test cases only; no credential bypass, no token theft.
 */
const NORMALIZATION_PROBES = ['/admin', '/./admin', '/admin%20', '/admin;', '/admin..;/', '//admin', '/Admin'];
const DEBUG_PATHS = ['/debug', '/debug/default/view', '/_debug', '/__debug__', '/server-status', '/actuator/mappings', '/trace'];

export default {
  id: 's23',
  name: 'Security Bypass Audit',
  tools: [],
  async run(ctx) {
    const t = ctx.getTarget();
    if (!t) throw new Error('no-target');
    const base = t.url.toString().replace(/\/+$/, '');
    const results = { probes: 0, anomalies: [] };
    const probe = async (path, extra = {}) => {
      results.probes++;
      try {
        const r = await ctx.fetch(base + path, { maxBytes: 8192, timeoutMs: 8000, includeBody: false, ...extra });
        return { status: r.status, headers: r.headers };
      } catch (e) { return { error: e.code || e.message.slice(0, 60) }; }
    };

    // 1. Trust boundary: X-Forwarded-For spoof effect on /admin response
    const adminNormal = await probe('/admin');
    const adminSpoofed = await probe('/admin', { headers: { 'x-forwarded-for': '127.0.0.1', 'x-real-ip': '127.0.0.1' } });
    if (adminNormal.status && adminSpoofed.status && adminNormal.status !== adminSpoofed.status) {
      results.anomalies.push('x-forwarded-for-changes-response');
      ctx.addFinding({
        asset: t.host, stageId: 's23', tool: 'builtin-bypass', severity: 'high', confidence: 'medium',
        title: 'X-Forwarded-For thay đổi phản hồi / Trust-boundary header accepted',
        description: 'Thêm header X-Forwarded-For: 127.0.0.1 đổi mã trạng thái /admin từ ' + adminNormal.status + ' sang ' + adminSpoofed.status + ' — dấu hiệu tin tưởng header client (bypass allowlist/ACL).',
        evidence: JSON.stringify({ normal: adminNormal.status, spoofed: adminSpoofed.status }),
        component: 'proxy trust config', recommendation: 'Chỉ tin X-Forwarded-* từ proxy tin cậy; set internal proxy chain.',
        verification: 'needs-verification',
      });
    }

    // 2. Rate-limit presence: small burst (10 requests)
    const burst = [];
    for (let i = 0; i < 10; i++) {
      const r = await probe('/');
      burst.push(r.status);
      if (r.status === 429) break;
    }
    const has429 = burst.includes(429);
    const limitHeader = !!(adminNormal.headers && (adminNormal.headers['x-ratelimit-limit'] || adminNormal.headers['ratelimit-limit']));
    if (!has429 && !limitHeader) {
      results.anomalies.push('no-rate-limit-signals');
      ctx.addFinding({
        asset: t.host, stageId: 's23', tool: 'builtin-bypass', severity: 'low', confidence: 'medium',
        title: 'Không phát hiện rate limiting / No rate-limit signals',
        description: '10 request liên tiếp không nhận 429 và không có header giới hạn. Không chứng minh bypass, nhưng cho thấy thiếu bảo vệ chống brute-force.',
        evidence: 'burst statuses: ' + JSON.stringify(burst), component: 'rate limiting',
        recommendation: 'Thêm rate limit ở reverse proxy/app cho endpoint nhạy cảm (login, API).',
        verification: 'needs-verification',
      });
    }

    // 3. HTTP method anomalies (OPTIONS/TRACE/PATCH on /)
    for (const method of ['OPTIONS', 'TRACE', 'PATCH']) {
      const r = await probe('/', { method });
      if (method === 'TRACE' && r.status && r.status < 300 && r.status !== 405) {
        results.anomalies.push('trace-enabled');
        ctx.addFinding({
          asset: t.host, stageId: 's23', tool: 'builtin-bypass', severity: 'low', confidence: 'high',
          title: 'HTTP TRACE được bật',
          description: 'TRACE trả HTTP ' + r.status + ' — cho phép phản chiếu request (XST) nếu trình duyệt hỗ trợ.',
          evidence: JSON.stringify({ method, status: r.status }), component: 'http methods',
          recommendation: 'Vô hiệu TRACE ở web server.', verification: 'confirmed',
        });
      }
      if (method === 'OPTIONS' && r.headers && r.headers['access-control-allow-methods'] && /\*/i.test(r.headers['access-control-allow-methods'] || '')) {
        results.anomalies.push('wildcard-allow-methods');
      }
    }

    // 4. Path normalization discrepancy: compare responses for equivalent paths
    const normResponses = [];
    for (const p of NORMALIZATION_PROBES) {
      const r = await probe(p);
      normResponses.push({ p, status: r.status });
    }
    const statuses = new Set(normResponses.map((x) => x.status).filter(Boolean));
    if (statuses.size >= 2 && normResponses.some((x) => x.p !== '/admin' && x.status === 200)) {
      results.anomalies.push('path-normalization-variance');
      ctx.addFinding({
        asset: t.host, stageId: 's23', tool: 'builtin-bypass', severity: 'medium', confidence: 'low',
        title: 'Phản hồi khác nhau giữa các biến thể đường dẫn / Path normalization variance',
        description: 'Các biến thể của cùng path cho trạng thái khác nhau — cần kiểm tra cách server/WAF chuẩn hoá đường dẫn (trailing slash, encoded, dot-segments).',
        evidence: JSON.stringify(normResponses), component: 'URL normalization',
        recommendation: 'Chuẩn hoá path ở tầng proxy trước khi match route; chặn ký tự đặc biệt.',
        verification: 'needs-verification',
      });
    }

    // 5. Debug endpoints exposed
    for (const p of DEBUG_PATHS) {
      const r = await probe(p);
      if (r.status === 200) {
        results.anomalies.push('debug-exposed:' + p);
        ctx.addFinding({
          asset: base + p, stageId: 's23', tool: 'builtin-bypass', severity: 'medium', confidence: 'high',
          title: 'Debug/management endpoint công khai: ' + p,
          description: 'Endpoint gỡ lỗi/quản trị trả HTTP 200 mà không cần xác thực.',
          evidence: JSON.stringify({ path: p, status: r.status }), component: p,
          recommendation: 'Chặn endpoint debug ở production; chỉ mở qua VPN/allowlist.', verification: 'confirmed',
        });
      }
    }

    // 6. Admin unauthenticated access (core BFLA indicator)
    if (adminNormal.status === 200) {
      results.anomalies.push('admin-open-200');
      ctx.addFinding({
        asset: base + '/admin', stageId: 's23', tool: 'builtin-bypass', severity: 'high', confidence: 'medium',
        title: '/admin trả HTTP 200 không xác thực',
        description: 'Truy cập /admin không kèm credentials vẫn nhận 200. Có thể là trang login (xác minh tay) hoặc khu vực quản trị mở.',
        evidence: JSON.stringify(adminNormal), component: '/admin',
        recommendation: 'Đảm bảo mọi route admin yêu cầu authentication + authorization.',
        verification: 'needs-verification',
      });
    }

    ctx.setSummary(results);
    return { summary: ctx._summary };
  },
};
