import { q1, q } from '../../db.js';

/**
 * Deep Audit — expert analysis over evidence collected by earlier stages.
 * Purely analytical + a few safe probes (CORS reflection, mixed content,
 * error verbosity). Every suspicion gets evidence/component/severity/
 * confidence/impact/remediation/verification-status. Nothing is called a
 * zero-day without evidence; AI (if configured) only adds interpretation.
 */
export default {
  id: 's20',
  name: 'Zero-Day & Critical Vulnerability Audit (Deep)',
  tools: [],
  async run(ctx) {
    const t = ctx.getTarget();
    const http = ctx.store.http;
    const classified = { confirmed: 0, likely: 0, potential: 0, informational: 0 };
    const stageSummary = (sid) => {
      const r = q1('SELECT summary FROM scan_stages WHERE scan_id=? AND stage_id=?', [ctx.scan.id, sid]);
      try { return r && r.summary ? JSON.parse(r.summary) : null; } catch { return null; }
    };

    const add = (f) => {
      classified[f.cls] = (classified[f.cls] || 0) + 1;
      ctx.addFinding({ ...f, cls: undefined, stageId: 's20', tool: 'deep-audit' });
    };

    // ---- 1. CORS reflection probe (safe, single request) ----
    if (t && http) {
      try {
        const r = await ctx.fetch(t.url.toString(), {
          headers: { origin: 'https://clab-probe.invalid', 'user-agent': 'clab-scanner/1.0' },
          maxBytes: 8192, timeoutMs: 10000, includeBody: false,
        });
        const acao = r.headers['access-control-allow-origin'];
        const acac = r.headers['access-control-allow-credentials'];
        if (acao === 'https://clab-probe.invalid' && acac === 'true') {
          add({ cls: 'confirmed', asset: t.host, tool: 'deep-audit', severity: 'high', confidence: 'high',
            title: 'CORS reflects arbitrary origin với credentials / CORS misconfiguration with credentials',
            description: 'Server phản hồi Access-Control-Allow-Origin đúng theo Origin tùy ý KẾT CÙNG Allow-Credentials: true — trang khác có thể đọc dữ liệu đã xác thực của người dùng.',
            evidence: 'acao=' + acao + ', acac=' + acac,
            component: 'CORS policy', verification: 'confirmed',
            recommendation: 'Allow-list chính xác các origin tin cậy; không phản hồi Origin tùy ý kèm credentials.' });
        } else if (acao === 'https://clab-probe.invalid') {
          add({ cls: 'likely', asset: t.host, tool: 'deep-audit', severity: 'medium', confidence: 'high',
            title: 'CORS reflects arbitrary origin (không credentials) / CORS wide reflection',
            description: 'Server phản hồi ACAO theo Origin tùy ý. Không kèm credentials nên rủi ro thấp hơn, nhưng vẫn sai cấu hình.',
            evidence: 'acao=' + acao + ', acac=' + (acac || 'none'),
            component: 'CORS policy', verification: 'confirmed',
            recommendation: 'Giới hạn ACAO theo origin cho phép.' });
        } else if (acao === '*') {
          add({ cls: 'informational', asset: t.host, tool: 'deep-audit', severity: 'low', confidence: 'high',
            title: 'CORS Allow-Origin wildcard (*)', description: 'ACAO=* cho phép mọi origin đọc response công khai.',
            evidence: 'acao=*', component: 'CORS policy', verification: 'confirmed',
            recommendation: 'Chỉ dùng * cho API thực sự công khai, không dùng kèm credentials.' });
        }
      } catch (e) {
        ctx.log('warn', 'CORS probe failed: ' + e.message);
      }

      // ---- 2. Mixed content on HTTPS ----
      if (t.url.protocol === 'https:' && http.bodySnippet) {
        const insecure = http.bodySnippet.match(/(?:src|href)=["']http:\/\/[^"']{1,200}["']/g) || [];
        if (insecure.length) {
          add({ cls: 'confirmed', asset: t.host, tool: 'deep-audit', severity: 'medium', confidence: 'high',
            title: 'Mixed content: resource nạp qua HTTP trên trang HTTPS',
            description: insecure.length + ' resource dùng http:// trên trang https:// — bị trình duyệt chặn hoặc tạo rủi ro MITM.',
            evidence: insecure.slice(0, 5).join('\n'), component: 'frontend', verification: 'confirmed',
            recommendation: 'Dùng https:// cho toàn bộ resource hoặc bật upgrade-insecure-requests.' });
        }
      }

      // ---- 3. Verbose error / stack trace ----
      if (http.bodySnippet && /Traceback \(most recent call last\)|at Object\.<anonymous>|System\..*Exception|org\.springframework/.test(http.bodySnippet)) {
        add({ cls: 'likely', asset: t.host, tool: 'deep-audit', severity: 'low', confidence: 'medium',
          title: 'Stack trace lộ trong response / Verbose error leakage',
          description: 'Response chứa dấu hiệu lỗi chi tiết (stack trace) — lộ cấu trúc nội bộ.',
          evidence: (http.bodySnippet.match(/.{0,80}(Traceback|at Object|Exception).{0,160}/) || [''])[0],
          component: 'error handling', verification: 'confirmed',
          recommendation: 'Hiển thị trang lỗi chung; ghi log chi tiết phía server.' });
      }
    }

    // ---- 4. Auth/session analysis from stage evidence ----
    const headers = stageSummary('s06');
    if (headers && headers.missingHeaders && headers.missingHeaders.length >= 4) {
      add({ cls: 'likely', asset: t.host, tool: 'deep-audit', severity: 'medium', confidence: 'medium',
        title: 'Chính sách header bảo mật yếu trên toàn site',
        description: 'Thiếu nhiều header quan trọng cùng lúc (' + headers.missingHeaders.length + ') — làm tăng bề mặt tấn công (XSS, clickjacking, downgrade).',
        evidence: JSON.stringify(headers.missingHeaders), component: 'security headers', verification: 'confirmed',
        recommendation: 'Áp dụng đầy đủ CSP/HSTS/nosniff/referrer-policy/frame-ancestors.' });
    }

    // ---- 5. TLS weaknesses ----
    const tls = stageSummary('s07');
    if (tls && tls.probe && tls.probe.ok) {
      const p = tls.probe;
      if (['TLSv1', 'TLSv1.1'].includes(p.protocol)) {
        add({ cls: 'confirmed', asset: t.host + ':' + tls.port, tool: 'deep-audit', severity: 'high', confidence: 'high',
          title: 'Giao thức TLS lỗi thời vẫn chấp nhận / Deprecated TLS accepted',
          description: p.protocol + ' chấp nhận handshake — dải cipher yếu có thể bị downgrade.',
          evidence: JSON.stringify({ protocol: p.protocol, cipher: p.cipher }), component: 'TLS', verification: 'confirmed',
          recommendation: 'Chỉ TLS 1.2/1.3.' });
      }
      if (tls.probe.cert && tls.probe.cert.valid_to && new Date(tls.probe.cert.valid_to).getTime() < Date.now()) {
        add({ cls: 'confirmed', asset: t.host + ':' + tls.port, tool: 'deep-audit', severity: 'high', confidence: 'high',
          title: 'Chứng thư TLS hết hạn', description: 'Certificate hết hạn ' + tls.probe.cert.valid_to + '.',
          evidence: JSON.stringify({ valid_to: tls.probe.cert.valid_to, fp: tls.probe.cert.fingerprint256 }),
          component: 'TLS certificate', verification: 'confirmed', recommendation: 'Gia hạn chứng chỉ.' });
      }
    }

    // ---- 6. Exposed sensitive surface (from s08) ----
    const mis = stageSummary('s08');
    if (mis && mis.sensitiveHits && mis.sensitiveHits.length) {
      add({ cls: 'confirmed', asset: t ? t.host : '', tool: 'deep-audit', severity: 'critical', confidence: 'high',
        title: 'Bề mặt dữ liệu nhạy cảm bị lộ (' + mis.sensitiveHits.length + ' đường dẫn)',
        description: 'Các đường dẫn sau trả về 200: ' + mis.sensitiveHits.join(', ') + '. Nếu chứa secret/source thì khả năng bị lợi dụng cao.',
        evidence: JSON.stringify(mis.sensitiveHits), component: 'web server files', verification: 'confirmed',
        recommendation: 'Chặn toàn bộ đường dẫn nhạy cảm ở tầng web server/WAF; rotate secret.' });
    }

    // ---- 7. Open risky services ----
    const ports = ctx.store.openPorts || [];
    const risky = ports.filter((p) => [6379, 27017, 9200, 11211, 445].includes(p.port));
    if (risky.length) {
      add({ cls: 'confirmed', asset: t ? t.host : '', tool: 'deep-audit', severity: 'critical', confidence: 'medium',
        title: 'Dịch vụ lưu trữ/quản trị lộ ra Internet: ' + risky.map((p) => p.port).join(','),
        description: 'Các cổng có rủi ro cao phản hồi từ Internet — nếu không có xác thực mạnh thì dữ liệu bị đọc/sửa ngay.',
        evidence: JSON.stringify(risky), component: 'network', verification: 'needs-verification',
        recommendation: 'Chặn firewall; bắt buộc auth + TLS nội bộ cho các dịch vụ này.' });
    }

    // ---- 8. Combination analysis: findings interaction ----
    const findings = q('SELECT severity, title, tool FROM findings WHERE scan_id=?', [ctx.scan.id]);
    const hasXssSignal = findings.some((f) => /xss/i.test(f.title));
    const noCsp = (headers && headers.missingHeaders || []).some((m) => /Content-Security-Policy/i.test(m));
    if (hasXssSignal && noCsp) {
      add({ cls: 'likely', asset: t ? t.host : '', tool: 'deep-audit', severity: 'high', confidence: 'medium',
        title: 'Tương tác: tín hiệu XSS + thiếu CSP làm tăng tính khai thác',
        description: 'Có tín hiệu XSS ở stage khác VÀ trang thiếu CSP — nếu XSS thực sự tồn tại thì không có lớp chặn thứ hai.',
        evidence: 'xss-signal present, CSP missing', component: 'XSS defense-in-depth', verification: 'needs-verification',
        recommendation: 'Xác minh XSS thủ công; triển khai CSP ngay cả khi chưa có XSS.' });
    }

    // classification legend for the summary
    const summary = {
      classified,
      legend: {
        confirmed: 'Có bằng chứng trực tiếp, đã xác minh bằng evidence',
        likely: 'Có bằng chứng mạnh nhưng cần kiểm tra thêm',
        potential: 'Nghi vấn — cần kiểm chứng tiếp (không phải zero-day đã xác nhận)',
        informational: 'Thông tin, không phải lỗ hổng',
      },
      note: 'Không có phát hiện nào được gọi là zero-day nếu chưa có bằng chứng xác minh.',
    };
    ctx.setSummary(summary);
    return { summary };
  },
};
