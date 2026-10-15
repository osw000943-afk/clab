import { getSetting } from '../../db.js';
import { getToolStatuses } from '../tools-registry.js';

/**
 * Reputation checks. Both services receive only the target hostname —
 * this is disclosed in the stage summary. Google Safe Browsing needs an
 * API key (Settings → System); Sucuri needs a paid Scanning API key
 * (their public JSON API was discontinued — verified 2026-10).
 */
export default {
  id: 's10',
  name: 'Reputation & Malware Indicators',
  tools: ['safe-browsing', 'sucuri'],
  async run(ctx) {
    const t = ctx.getTarget();
    if (!t) throw new Error('no-target');
    const summary = { host: t.host, externalServicesUsed: [] };

    // ---- Google Safe Browsing v4 ----
    const gsbKey = getSetting('gsb_api_key');
    if (!gsbKey) {
      summary.safeBrowsing = 'needs-config (Settings → System)';
      ctx.log('info', 'Google Safe Browsing: chưa cấu hình API key — bỏ qua');
    } else {
      try {
        const body = {
          client: { clientId: 'clab-whitehat-lab', clientVersion: '1.0.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: `http://${t.host}/` }, { url: `https://${t.host}/` }],
          },
        };
        const r = await ctx.fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(gsbKey)}`,
          { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), timeoutMs: 15_000, maxBytes: 65536 });
        summary.externalServicesUsed.push('google-safe-browsing');
        const j = JSON.parse(r.body.toString('utf8'));
        const matches = j.matches || [];
        summary.safeBrowsing = { matches: matches.length };
        if (matches.length) {
          ctx.addFinding({
            asset: t.host, stageId: 's10', tool: 'safe-browsing', severity: 'critical', confidence: 'high',
            title: 'Google Safe Browsing: URL bị đánh dấu độc hại / Flagged as malicious',
            description: `Google Safe Browsing báo cáo ${matches.length} mối đe dọa cho hostname này.`,
            evidence: JSON.stringify(matches).slice(0, 2000),
            recommendation: 'Xử lý nhiễm độc theo hướng dẫn của Google; kiểm tra mã nguồn và server ngay.',
            verification: 'confirmed',
          });
        }
      } catch (e) {
        summary.safeBrowsing = `failed: ${e.message.slice(0, 150)}`;
        ctx.log('warn', `Safe Browsing error: ${e.message}`);
      }
    }

    // ---- Sucuri Scanning API (paid) ----
    const sucuriKey = getSetting('sucuri_api_key');
    const sucuriDomain = getSetting('sucuri_monitor_domain');
    if (!sucuriKey || !sucuriDomain) {
      summary.sucuri = 'needs-config (paid Scanning API key + monitor domain)';
    } else {
      try {
        const url = `https://${sucuriDomain}/scan-api.php?k=${encodeURIComponent(sucuriKey)}&a=scan&host=${encodeURIComponent(t.host)}&format=simple`;
        const r = await ctx.fetch(url, { timeoutMs: 60_000, maxBytes: 128 * 1024 });
        summary.externalServicesUsed.push('sucuri-scanning-api');
        const text = r.body ? r.body.toString('utf8') : '';
        summary.sucuri = { chars: text.length, excerpt: text.slice(0, 2000) };
        if (/blacklist|malware|infected|injected/i.test(text)) {
          ctx.addFinding({
            asset: t.host, stageId: 's10', tool: 'sucuri', severity: 'high', confidence: 'medium',
            title: 'Sucuri: dấu hiệu nhiễm độc hoặc bị đưa vào blacklist / Malware/blacklist indicators',
            description: 'Báo cáo Sucuri chứa dấu hiệu nhiễm độc. Xem bằng chứng để đối chiếu.',
            evidence: text.slice(0, 2000),
            recommendation: 'Xem chi tiết báo cáo Sucuri và làm sạch theo quy trình.',
            verification: 'needs-verification',
          });
        }
      } catch (e) {
        summary.sucuri = `failed: ${e.message.slice(0, 150)}`;
      }
    }

    // disclosure note — this stage queries external services
    if (summary.externalServicesUsed.length) {
      ctx.log('warn', `Stage này đã gửi hostname tới: ${summary.externalServicesUsed.join(', ')}`);
    }
    ctx.setSummary(summary);
    return { summary };
  },
};
