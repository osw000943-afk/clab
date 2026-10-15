import dns from 'node:dns';
import net from 'node:net';

const TYPES = [
  ['resolve4', 'A'], ['resolve6', 'AAAA'], ['resolveMx', 'MX'],
  ['resolveNs', 'NS'], ['resolveTxt', 'TXT'], ['resolveCname', 'CNAME'], ['resolveSoa', 'SOA'],
];

export default {
  id: 's02',
  name: 'DNS & tên miền / DNS records',
  tools: ['dns-native'],
  async run(ctx) {
    const host = ctx.getTarget()?.host;
    if (!host) throw new Error('no-target');
    if (net.isIP(host)) {
      ctx.setSummary({ host, literalIp: true, records: {} });
      ctx.log('info', `Target là IP literal (${host}) — bỏ qua tra cứu DNS`);
      return { summary: ctx._summary };
    }
    const records = {};
    for (const [fn, type] of TYPES) {
      if (ctx.signal.aborted) throw new Error('cancelled');
      try {
        const res = await dns.promises[fn](host);
        records[type] = (Array.isArray(res) ? res : [res]).slice(0, 20);
      } catch (e) {
        records[type] = { error: e.code || e.message };
      }
    }
    ctx.log('info', `DNS: A=${JSON.stringify(records.A)} MX=${Array.isArray(records.MX) ? records.MX.length : 'err'}`);
    ctx.setSummary({ host, records });
    return { summary: ctx._summary };
  },
};
