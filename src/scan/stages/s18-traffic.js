import { runTool, toolAvailable, recordToolRun } from '../tools-registry.js';
import fs from 'node:fs';

/**
 * Traffic analysis via TShark — ONLY on an owner-provided capture file.
 * No live capture on network interfaces (requires approval + root).
 */
export default {
  id: 's18',
  name: 'Network Traffic Analysis (TShark)',
  tools: ['tshark'],
  async run(ctx) {
    const opts = JSON.parse(ctx.scan.options || '{}');
    const pcap = opts.captureFile;
    if (!pcap || !fs.existsSync(pcap)) {
      ctx.log('info', 'Không có capture file được cấp quyền — bỏ qua TShark (không bắt gói trên interface)');
      ctx.setSummary({ skipped: 'no-capture-file' });
      return { summary: ctx._summary };
    }
    if (!toolAvailable('tshark')) {
      ctx.log('info', 'TShark không có sẵn');
      ctx.setSummary({ skipped: 'tool-missing' });
      return { summary: ctx._summary };
    }
    const started = Date.now();
    const r = await runTool('tshark', ['-r', pcap, '-q', '-z', 'io,phs'],
      { timeoutMs: 120000, maxBytes: 256 * 1024, signal: ctx.signal });
    recordToolRun({ scanId: ctx.scan.id, toolId: 'tshark', status: r.ok ? 'completed' : 'failed', exitCode: r.exitCode, startedAt: started, stderrExcerpt: (r.stderr || '').slice(0, 400) });
    const results = {};
    if (r.ok) {
      // protocol hierarchy statistics — credentials are NOT extracted; output redacted downstream
      results.protocolHierarchy = r.stdout.slice(0, 3000);
      ctx.log('info', 'TShark: đã phân tích protocol hierarchy của capture file');
    }
    ctx.setSummary(results);
    return { summary: ctx._summary };
  },
};
