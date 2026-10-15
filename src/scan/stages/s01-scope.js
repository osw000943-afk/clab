import { nowMs } from '../../util/ids.js';

export default {
  id: 's01',
  name: 'Xác minh mục tiêu & phạm vi / Scope verification',
  tools: [],
  async run(ctx) {
    const raw = ctx.scan.target_url;
    const v = await ctx.assertUrl(raw); // throws on blocked/private/invalid
    ctx.setTarget(v);
    ctx.log('info', `Target resolved: ${v.host}:${v.port} → ${v.ips.join(', ')} (${v.scheme})`);

    // The scan cannot exist without scope confirmation at creation time
    // (enforced in routes/scans.js). Record the evidence here.
    let redirectChain = [];
    let finalUrl = v.url.toString();
    try {
      const r = await ctx.fetch(v.url.toString(), { method: 'GET', maxBytes: 8192 });
      finalUrl = r.finalUrl;
      redirectChain.push({ url: v.url.toString(), status: r.status });
    } catch (e) {
      ctx.log('warn', `Base URL probe failed: ${e.message}`);
    }

    // Re-check final URL after redirect — must still be public
    let finalCheck = 'unchanged';
    try {
      await ctx.assertUrl(finalUrl);
      if (finalUrl !== v.url.toString()) finalCheck = 'redirected_and_revalidated';
    } catch (e) {
      finalCheck = `redirected_to_blocked:${e.code}`;
      ctx.addFinding({
        asset: v.host, stageId: 's01', tool: 'scope-engine', severity: 'high', confidence: 'high',
        title: 'Redirect tới địa chỉ bị chặn / Redirect to blocked destination',
        description: `URL mục tiêu redirect tới địa chỉ không được phép: ${finalUrl}`,
        evidence: `finalUrl=${finalUrl}`, verification: 'confirmed',
        recommendation: 'Điều tra cấu hình redirect của máy chủ mục tiêu; đảm bảo không trỏ tới mạng nội bộ.',
      });
    }

    ctx.setSummary({
      normalizedUrl: v.url.toString(), host: v.host, port: v.port,
      resolvedIps: v.ips, redirectCheck: finalCheck,
      confirmedAt: nowMs(),
    });
    return { summary: ctx._summary };
  },
};
