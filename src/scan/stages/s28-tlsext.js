import { tlsProbe } from '../../security/scope.js';
import { runAdapter } from '../tools-registry.js';
export default {
  id: 's28',
  name: 'TLS Extended (A2SV cross-check)',
  tools: ['a2sv'],
  async run(ctx) {
    const t = ctx.getTarget();
    if (!t) throw new Error('no-target');
    const host=t.host, port=t.url.port?Number(t.url.port):443;
    const out={host,port};
    const probe=await tlsProbe(host,port,8000);
    out.builtin={protocol:probe.protocol||null,ok:probe.ok,certDays:probe.cert?.valid_to||null};
    if(!probe.ok){out.skipped='tls-unreachable';ctx.setSummary(out);return{summary:out};}
    const r=await runAdapter(ctx,'a2sv',{args:['-t',host,'-p',String(port)],timeoutMs:Math.min(ctx.limits.toolTimeoutMs||300000,120000),maxBytes:256*1024});
    out.a2sv=r.status;
    if(r.run&&r.run.stdout){
      const txt=r.run.stdout.slice(0,4000);
      out.excerpt=txt.slice(0,1200);
      if(/weak|vulnerable|sslv|heartbleed|poodle|beast/i.test(txt)) ctx.addFinding({asset:host+':'+port,stageId:'s28',tool:'a2sv',severity:'medium',confidence:'low',title:'A2SV: possible weak TLS finding (cross-check required)',description:'A2SV is unmaintained; this finding must be cross-checked with testssl.sh / builtin TLS probe before action.',evidence:txt.slice(0,1500),recommendation:'Cross-check with modern TLS audit, then restrict to TLS 1.2/1.3.',verification:'needs-verification'});
      else ctx.log('info','A2SV completed - cross-checked with builtin probe protocol='+probe.protocol);
    } else out.a2svNote='A2SV missing or incompatible - builtin + testssl.sh remain authoritative';
    if(probe.protocol&&['TLSv1','TLSv1.1'].includes(probe.protocol)) ctx.addFinding({asset:host+':'+port,stageId:'s28',tool:'builtin-tls-xcheck',severity:'high',confidence:'high',title:'Weak TLS confirmed by builtin probe: '+probe.protocol,description:'Cross-check confirms weak protocol independent of A2SV.',evidence:JSON.stringify({protocol:probe.protocol,cipher:probe.cipher}),recommendation:'Allow only TLS 1.2/1.3.',verification:'confirmed'});
    ctx.setSummary(out);
    return{summary:out};
  },
};
