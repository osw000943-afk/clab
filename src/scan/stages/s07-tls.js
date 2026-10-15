import { tlsProbe } from '../../security/scope.js';
import { runTool, toolAvailable, recordToolRun } from '../tools-registry.js';

const WEAK_PROTOCOLS = ['TLSv1', 'TLSv1.1', 'TLSv3'];

export default {
  id: 's07',
  name: 'SSL/TLS Audit',
  tools: ['testssl', 'ssllabs'],
  async run(ctx) {
    const t = ctx.getTarget();
    if (!t) throw new Error('no-target');
    if (t.url.protocol !== 'https:' && !(ctx.store.openPorts || []).some((p) => p.port === 443)) {
      ctx.log('info', 'Mục tiêu không dùng HTTPS — bỏ qua TLS audit');
      ctx.setSummary({ skipped: 'not-https' });
      return { summary: ctx._summary };
    }

    const host = t.host;
    const port = t.url.port ? Number(t.url.port) : 443;
    const probe = await tlsProbe(host, port, 10_000);
    const summary = { host, port, probe };

    if (!probe.ok) {
      ctx.log('warn', `TLS probe failed: ${probe.error}`);
      summary.skipped = probe.error;
      ctx.setSummary(summary);
      return { summary };
    }

    // weak protocol
    if (WEAK_PROTOCOLS.includes(probe.protocol)) {
      ctx.addFinding({
        asset: `${host}:${port}`, stageId: 's07', tool: 'builtin-tls', severity: 'high', confidence: 'high',
        title: `Giao thức TLS yếu: ${probe.protocol} / Weak TLS protocol`,
        description: `Handshake thành công với ${probe.protocol} — giao thức đã bị loại bỏ vì lỗi bảo mật (POODLE, BEAST…).`,
        evidence: JSON.stringify({ protocol: probe.protocol, cipher: probe.cipher }),
        recommendation: 'Chỉ cho phép TLS 1.2 và TLS 1.3 trên server.', verification: 'confirmed',
      });
    }

    // certificate expiry / self-signed
    if (probe.cert?.valid_to) {
      const expires = new Date(probe.cert.valid_to).getTime();
      const days = Math.round((expires - Date.now()) / 86400_000);
      summary.certDaysRemaining = days;
      if (days < 0) {
        ctx.addFinding({
          asset: `${host}:${port}`, stageId: 's07', tool: 'builtin-tls', severity: 'high', confidence: 'high',
          title: 'Chứng thư TLS đã hết hạn / Expired TLS certificate',
          description: `Chứng chỉ hết hạn từ ${probe.cert.valid_to}.`,
          evidence: JSON.stringify({ subject: probe.cert.subject, valid_to: probe.cert.valid_to, fingerprint256: probe.cert.fingerprint256 }),
          recommendation: 'Gia hạn chứng chỉ và cấu hình auto-renewal.', verification: 'confirmed',
        });
      } else if (days < 30) {
        ctx.addFinding({
          asset: `${host}:${port}`, stageId: 's07', tool: 'builtin-tls', severity: 'medium', confidence: 'high',
          title: `Chứng thư TLS sắp hết hạn (${days} ngày) / TLS certificate expiring soon`,
          description: `Chứng chỉ hết hạn sau ~${days} ngày.`,
          evidence: JSON.stringify({ valid_to: probe.cert.valid_to, fingerprint256: probe.cert.fingerprint256 }),
          recommendation: 'Lên lịch gia hạn chứng chỉ.', verification: 'confirmed',
        });
      }
      if (!probe.authorized && /self.?signed/i.test(probe.authError || '')) {
        ctx.addFinding({
          asset: `${host}:${port}`, stageId: 's07', tool: 'builtin-tls', severity: 'medium', confidence: 'medium',
          title: 'Chứng thư tự ký / Self-signed certificate',
          description: `Chứng chỉ không thuộc chain tin cậy: ${probe.authError}.`,
          evidence: JSON.stringify({ issuer: probe.cert.issuer, fingerprint256: probe.cert.fingerprint256 }),
          recommendation: 'Dùng chứng chỉ từ CA được tin cậy cho môi trường production.', verification: 'confirmed',
        });
      }
    }

    // testssl.sh when installed (bounded runtime)
    if (toolAvailable('testssl')) {
      const started = Date.now();
      const r = await runTool('testssl.sh', ['--quiet', '--protocols', '--server-defaults', '--curl', host + ':' + port],
        { timeoutMs: Math.min(ctx.limits.toolTimeoutMs, 240_000), maxBytes: 512 * 1024, signal: ctx.signal });
      recordToolRun({ scanId: ctx.scan.id, toolId: 'testssl', status: r.ok ? 'completed' : 'failed', exitCode: r.exitCode, startedAt: started, stderrExcerpt: r.stderr?.slice(0, 500) });
      summary.testssl = r.ok ? { outputChars: r.stdout.length, excerpt: r.stdout.slice(0, 4000) } : { error: (r.stderr || r.spawnError || 'failed').slice(0, 200) };
    } else {
      summary.testssl = 'tool-missing';
    }

    // SSL Labs — only with explicit opt-in (hostname goes to Qualys)
    const opts = JSON.parse(ctx.scan.options || '{}');
    if (opts.ssllabs) {
      summary.ssllabs = 'opted-in — phân tích Qualys chạy ngoài thời gian stage; truy cập ssllabs.com để lấy kết quả';
      ctx.log('warn', 'SSL Labs opt-in: hostname đã được gửi tới Qualys theo yêu cầu của chủ Lab.');
    }

    ctx.setSummary(summary);
    return { summary };
  },
};
