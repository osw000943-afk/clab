const CHECKS = [
  { header: 'content-security-policy', sev: 'medium', title: 'Thiếu Content-Security-Policy / Missing CSP',
    rec: 'Định nghĩa CSP restrictive để giảm rủi ro XSS và injected content.' },
  { header: 'strict-transport-security', sev: 'low', httpsOnly: true, title: 'Thiếu Strict-Transport-Security / Missing HSTS',
    rec: 'Thêm header Strict-Transport-Security: max-age=31536000; includeSubDomains.' },
  { header: 'x-content-type-options', sev: 'low', title: 'Thiếu X-Content-Type-Options / Missing nosniff',
    rec: 'Thêm X-Content-Type-Options: nosniff.' },
  { header: 'referrer-policy', sev: 'low', title: 'Thiếu Referrer-Policy',
    rec: 'Thêm Referrer-Policy: strict-origin-when-cross-origin (hoặc restrictive hơn).' },
  { header: 'permissions-policy', sev: 'informational', alt: 'feature-policy', title: 'Thiếu Permissions-Policy',
    rec: 'Thêm Permissions-Policy để hạn chế trình duyệt API không cần thiết.' },
  { header: 'x-frame-options', sev: 'low', altCspOnly: true, title: 'Thiếu chống clickjacking (X-Frame-Options / CSP frame-ancestors)',
    rec: 'Thêm X-Frame-Options: DENY (hoặc CSP frame-ancestors \'none\').' },
];

export default {
  id: 's06',
  name: 'Security Headers',
  tools: [],
  async run(ctx) {
    const http = ctx.store.http;
    if (!http) throw new Error('http-stage-did-not-run');
    const t = ctx.getTarget();
    const h = http.headers;
    const isHttps = t.url.protocol === 'https:';
    const missing = [];

    for (const c of CHECKS) {
      if (c.httpsOnly && !isHttps) continue;
      const has = h[c.header] || (c.alt && h[c.alt]);
      if (!has) {
        if (c.altCspOnly) {
          const csp = h['content-security-policy'] || '';
          if (/frame-ancestors/i.test(csp)) continue;
        }
        missing.push(c.title);
        ctx.addFinding({
          asset: t.host, stageId: 's06', tool: 'builtin-headers', severity: c.sev, confidence: 'high',
          title: c.title,
          description: `Phản hồi từ ${http.finalUrl} không chứa header '${c.header}'. Thiếu header không đồng nghĩa website bị xâm nhập, nhưng làm giảm lớp phòng thủ.`,
          evidence: `Trạng thái ${http.status}; headers hiện có: ${Object.keys(h).slice(0, 30).join(', ')}`,
          component: c.header, recommendation: c.rec, verification: 'confirmed',
        });
      }
    }

    // Cookie flags
    const setCookie = h['set-cookie'];
    if (setCookie) {
      const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
      for (const ck of cookies.slice(0, 10)) {
        const name = ck.split('=')[0];
        const issues = [];
        if (!/;\s*secure/i.test(ck) && isHttps) issues.push('Secure');
        if (!/;\s*httponly/i.test(ck)) issues.push('HttpOnly');
        if (!/;\s*samesite/i.test(ck)) issues.push('SameSite');
        if (issues.length) {
          ctx.addFinding({
            asset: t.host, stageId: 's06', tool: 'builtin-headers', severity: 'medium', confidence: 'high',
            title: `Cookie '${name}' thiếu cờ bảo mật / missing flags`,
            description: `Cookie ${name} thiếu: ${issues.join(', ')}.`,
            evidence: ck.replace(/=[^;]*/g, '=[REDACTED]'),
            component: 'cookie', recommendation: `Đặt ${issues.join(', ')} cho cookie ${name}.`, verification: 'confirmed',
          });
        }
      }
    }

    // Informational: technology disclosure
    for (const b of ['server', 'x-powered-by']) {
      if (h[b]) {
        ctx.addFinding({
          asset: t.host, stageId: 's06', tool: 'builtin-headers', severity: 'informational', confidence: 'high',
          title: `Tiết lộ công nghệ qua header ${b} / Technology disclosure`,
          description: `Header ${b}: ${String(h[b]).slice(0, 120)}. Không phải lỗ hổng nhưng giúp kẻ tấn công dò phiên bản.`,
          evidence: `${b}: ${h[b]}`, component: b,
          recommendation: 'Giấu hoặc làm chung phiên bản trong header phản hồi.', verification: 'confirmed',
        });
      }
    }

    ctx.setSummary({ missingHeaders: missing, cookiesChecked: setCookie ? 1 : 0 });
    return { summary: ctx._summary };
  },
};
