import { runAdapter } from '../tools-registry.js';
export default {
  id: 's25',
  name: 'Web Vuln Extended (Arachni/w3af/Nuclei)',
  tools: ['arachni','w3af','nuclei','kallor'],
  async run(ctx) {
    const t = ctx.getTarget();
    if (!t) throw new Error('no-target');
    const out = { target: t.url.toString() };
    const lim = Math.min(ctx.limits.toolTimeoutMs || 300000, 240000);
    const a = await runAdapter(ctx, 'arachni', { args: [t.url.toString(), '--output-only-positives', '--timeout', '00:03:00'], timeoutMs: lim, maxBytes: 512*1024 });
    out.arachni = a.status;
    if (a.status === 'completed' && a.run.stdout) {
      const hits = a.run.stdout.match(/vulnerab[^\n]{0,120}/gi) || [];
      for (const h of hits.slice(0,10)) ctx.addFinding({ asset: t.host, stageId: 's25', tool: 'arachni', severity: 'medium', confidence: 'medium', title: 'Arachni: ' + h.slice(0,180), description: 'Arachni reports a possible web vulnerability. Verify maintenance status of Arachni (upstream unmaintained) and confirm manually.', evidence: a.run.stdout.slice(0,1500), recommendation: 'Confirm manually, patch affected component.', verification: 'needs-verification' });
    } else if (a.status==='unsupported') out.arachniNote = 'Arachni upstream unmaintained - compatibility check required';
    const w = await runAdapter(ctx, 'w3af', { args: ['-s', '/dev/null'], timeoutMs: 60000, maxBytes: 65536 });
    out.w3af = w.status;
    if (w.status==='completed') ctx.log('info','w3af probe completed - run full audit manually with working plugins');
    else out.w3afNote = 'Verify w3af version, project status and working plugins before full use';
    const sev = 'medium,high,critical';
    const n = await runAdapter(ctx, 'nuclei', { args: ['-u', t.url.toString(), '-severity', sev, '-rate-limit', '30', '-bulk-size', '10', '-timeout', '10', '-retries', '1', '-silent'], timeoutMs: lim, maxBytes: 1024*1024 });
    out.nuclei = n.status;
    if (n.run && n.run.stdout) {
      for (const line of n.run.stdout.split('\n').slice(0,60)) {
        const s = line.trim(); if (!s) continue;
        let sev2='medium'; const m=s.match(/\[(critical|high|medium|low|info)\]/i); if(m) sev2=m[1].toLowerCase()==='info'?'informational':m[1].toLowerCase();
        ctx.addFinding({ asset: t.host, stageId:'s25', tool:'nuclei', severity: sev2, confidence:'medium', title:'Nuclei: '+s.slice(0,200), description:'Nuclei template matched. Template scope-limited; confirm manually.', evidence:s.slice(0,1200), recommendation:'Review matched template docs and patch.', verification:'needs-verification' });
      }
    }
    const k = await runAdapter(ctx, 'kallor', { args: [], timeoutMs: 10000 });
    out.kallor = k.status;
    ctx.setSummary(out);
    return { summary: out };
  },
};
