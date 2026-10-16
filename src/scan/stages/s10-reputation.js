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

    // ---- VirusTotal (official API, key required) ----
    const vtKey = getSetting('virustotal_api_key');
    if (!vtKey) { summary.virustotal = 'needs-config (Settings → System)'; }
    else {
      try {
        ctx.log('warn', 'Sap gui hostname/domain toi VirusTotal theo yeu cau chu Lab. Khong gui du lieu rieng tu.');
        const rr = await ctx.fetch('https://www.virustotal.com/api/v3/domains/' + encodeURIComponent(t.host), { headers: { 'x-apikey': vtKey, 'user-agent': 'clab-scanner/1.0' }, timeoutMs: 15000, maxBytes: 65536 });
        summary.externalServicesUsed.push('virustotal');
        const j = JSON.parse(rr.body.toString('utf8'));
        const stats = j.data && j.data.attributes && j.data.attributes.last_analysis_stats;
        summary.virustotal = stats || { ok: true };
        const mal = stats ? (stats.malicious || 0) + (stats.suspicious || 0) : 0;
        if (mal > 0) ctx.addFinding({ asset: t.host, stageId: 's10', tool: 'virustotal', severity: 'high', confidence: 'high', title: 'VirusTotal: domain bi danh dau doc hai (' + mal + ' engines)', description: 'VirusTotal tra ve ' + mal + ' engines malicious/suspicious. Khong tai hay thuc thi tep.', evidence: JSON.stringify(stats).slice(0,1500), recommendation: 'Dieu tra ma doc theo quy trinh; khong mo tep dang ngo tren may tram.', verification: 'needs-verification' });
      } catch (e) { summary.virustotal = 'failed: ' + e.message.slice(0,120); }
    }
    // ---- urlscan.io (opt-in per scan, privacy selectable) ----
    let scanOpts = {};
    try { scanOpts = JSON.parse(ctx.scan.options || '{}'); } catch {}
    const usKey = getSetting('urlscan_api_key');
    if (!scanOpts.urlscan) { summary.urlscan = 'skipped (opt-in per scan via options.urlscan + visibility)'; }
    else if (!usKey) { summary.urlscan = 'needs-config (urlscan_api_key)'; }
    else if (/localhost|127\.|10\.|192\.168\.|169\.254|\.local|\.internal/i.test(t.url.toString()) || /token=|session|password|secret/i.test(t.url.toString())) { summary.urlscan = 'refused: internal/tokenized/sensitive URL - never submit to public service'; }
    else {
      try {
        const vis = scanOpts.urlscanVisibility === 'unlisted' ? 'unlisted' : 'public';
        ctx.log('warn', 'Sap gui URL toi urlscan.io (' + vis + ') theo yeu cau. Khong gui URL noi bo/token/nhay cam.');
        const rr = await ctx.fetch('https://urlscan.io/api/v1/scan/', { method: 'POST', headers: { 'content-type': 'application/json', 'API-Key': usKey }, body: JSON.stringify({ url: t.url.toString(), visibility: vis }), timeoutMs: 30000, maxBytes: 65536 });
        summary.externalServicesUsed.push('urlscan.io');
        const j = JSON.parse(rr.body.toString('utf8'));
        summary.urlscan = { uuid: j.uuid, result: j.result };
        ctx.addFinding({ asset: t.host, stageId: 's10', tool: 'urlscan', severity: 'informational', confidence: 'high', title: 'urlscan.io: da gui phan tich (' + vis + ')', description: 'URL da duoc gui toi urlscan.io. Thu thap thong tin trang va ket qua do dich vu tra ve.', evidence: JSON.stringify(j).slice(0,1200), recommendation: 'Mo result URL de xem chi tiet.', verification: 'confirmed' });
      } catch (e) { summary.urlscan = 'failed: ' + e.message.slice(0,120); }
    }
    // disclosure note — this stage queries external services
    if (summary.externalServicesUsed.length) {
      ctx.log('warn', `Stage này đã gửi hostname tới: ${summary.externalServicesUsed.join(', ')}`);
    }
    ctx.setSummary(summary);
    return { summary };
  },
};
