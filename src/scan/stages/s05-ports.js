import { runTool, toolAvailable, recordToolRun } from '../tools-registry.js';
import { tcpProbe } from '../../security/scope.js';

const COMMON_PORTS = [
  21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 2049,
  3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9090, 9200, 11211, 27017,
];

const RISKY = {
  3306: { sev: 'medium', name: 'MySQL' }, 5432: { sev: 'medium', name: 'PostgreSQL' },
  6379: { sev: 'high', name: 'Redis' }, 27017: { sev: 'high', name: 'MongoDB' },
  9200: { sev: 'medium', name: 'Elasticsearch' }, 11211: { sev: 'medium', name: 'Memcached' },
  445: { sev: 'high', name: 'SMB' }, 2049: { sev: 'medium', name: 'NFS' },
  3389: { sev: 'medium', name: 'RDP' }, 5900: { sev: 'medium', name: 'VNC' },
};

export default {
  id: 's05',
  name: 'Port scan (Network)',
  tools: ['nmap'],
  async run(ctx) {
    const t = ctx.getTarget();
    if (!t) throw new Error('no-target');
    const openPorts = [];
    let method = 'none';

    if (toolAvailable('nmap')) {
      method = 'nmap';
      const maxPorts = Math.min(ctx.limits.maxPortCount || 64, 128);
      const started = Date.now();
      const r = await runTool('nmap', [
        '-Pn', '-sV', '--top-ports', String(maxPorts), '-T3', '--max-retries', '1',
        '--host-timeout', '120s', '--open', '-oX', '-', t.host,
      ], { timeoutMs: 180_000, maxBytes: 1024 * 1024, signal: ctx.signal });
      recordToolRun({ scanId: ctx.scan.id, toolId: 'nmap', status: r.ok ? 'completed' : 'failed', exitCode: r.exitCode, startedAt: started, stderrExcerpt: r.stderr?.slice(0, 500) });
      if (r.ok && r.stdout.includes('<port')) {
        const portRe = /<port\s+protocol="(\w+)"\s+portid="(\d+)">([\s\S]*?)<\/port>/g;
        let pm;
        while ((pm = portRe.exec(r.stdout))) {
          const svc = (pm[3].match(/<service[^>]*name="([^"]+)"/) || [])[1] || '';
          const ver = (pm[3].match(/version="([^"]+)"/) || [])[1] || '';
          openPorts.push({ port: Number(pm[2]), protocol: pm[1], service: svc, version: ver, source: 'nmap' });
        }
      } else {
        ctx.log('warn', `nmap failed: ${r.stderr?.slice(0, 200) || r.spawnError || 'unknown'}`);
      }
    }

    if (!openPorts.length && method !== 'nmap') {
      method = 'builtin-tcp';
      ctx.log('info', 'Nmap không có sẵn — TCP connect scan nội bộ, danh sách cổng hạn chế');
      const ports = COMMON_PORTS.slice(0, Math.min(ctx.limits.maxPortCount || 26, COMMON_PORTS.length));
      const concurrency = 8;
      for (let i = 0; i < ports.length; i += concurrency) {
        if (ctx.signal.aborted) throw new Error('cancelled');
        const batch = ports.slice(i, i + concurrency);
        const results = await Promise.all(batch.map(async (p) => ({ p, r: await tcpProbe(t.host, p, 3000) })));
        for (const { p, r } of results) {
          if (r.open) openPorts.push({ port: p, protocol: 'tcp', service: '', version: '', source: 'builtin-tcp' });
        }
      }
    }

    for (const op of openPorts) {
      const risky = RISKY[op.port];
      if (risky && op.port !== t.port) {
        ctx.addFinding({
          asset: `${t.host}:${op.port}`, stageId: 's05', tool: method, severity: risky.sev, confidence: op.version ? 'high' : 'medium',
          title: `Dịch vụ ${risky.name} mở ra Internet / Exposed ${risky.name} service`,
          description: `Cổng ${op.port} (${risky.name}) phản hồi kết nối từ bên ngoài. ` +
            (op.version ? `Phiên bản: ${op.version}.` : '') +
            ' Các dịch vụ dữ liệu không nên truy cập công khai.',
          evidence: JSON.stringify(op),
          recommendation: `Chặn cổng ${op.port} ở firewall/security group hoặc giới hạn theo IP tin cậy; xác minh cấu hình xác thực của ${risky.name}.`,
          verification: 'confirmed',
        });
      }
    }

    ctx.store.openPorts = openPorts;
    ctx.setSummary({ method, openPortCount: openPorts.length, openPorts });
    return { summary: ctx._summary };
  },
};
