import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runAdapter } from '../tools-registry.js';
const FALLBACK = ['admin','login','dashboard','api','backup','test','dev','server-status','.git/HEAD','.env','robots.txt','sitemap.xml'];
export default {
  id: 's26',
  name: 'Content Discovery (Dirsearch/Gobuster/Feroxbuster)',
  tools: ['dirsearch','gobuster','feroxbuster'],
  async run(ctx) {
    const t = ctx.getTarget();
    if (!t) throw new Error('no-target');
    const base = t.url.toString().replace(/\/+$/,'');
    const out = { target: base, rateLimited: true };
    const lim = Math.min(ctx.limits.toolTimeoutMs||300000, 180000);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(),'clab-wordlist-'));
    const wl = path.join(tmp,'wl.txt');
    try {
      fs.writeFileSync(wl, FALLBACK.join('\n'));
      const d = await runAdapter(ctx,'dirsearch',{args:['-u',base,'-w',wl,'--max-rate','20','--max-recursion-depth','1','--max-time','120','-x','404','--format','plain'],timeoutMs:lim,maxBytes:512*1024});
      out.dirsearch=d.status;
      collect(ctx,d,t,'dirsearch',out);
      const g = await runAdapter(ctx,'gobuster',{args:['dir','-u',base,'-w',wl,'-t','5','--delay','100ms','--timeout','8s','-q'],timeoutMs:lim,maxBytes:512*1024});
      out.gobuster=g.status;
      collect(ctx,g,t,'gobuster',out);
      const f = await runAdapter(ctx,'feroxbuster',{args:['-u',base,'-w',wl,'-t','4','-d','1','--time-limit','2m','--rate-limit','20','--auto-tune','-q'],timeoutMs:lim,maxBytes:512*1024});
      out.feroxbuster=f.status;
      collect(ctx,f,t,'feroxbuster',out);
    } finally { try{fs.rmSync(tmp,{recursive:true,force:true});}catch{} }
    ctx.setSummary(out);
    return { summary: out };
  },
};
function collect(ctx,r,t,tool,out){
  if(!r.run||!r.run.stdout) return;
  const lines=r.run.stdout.split('\n').map(s=>s.trim()).filter(s=>s&&!/404|not found/i.test(s)).slice(0,40);
  out[tool+'Hits']=lines.length;
  for(const ln of lines.slice(0,15)){
    const m=ln.match(/(\/[^\s]*)/);
    const p=m?m[1]:ln.slice(0,80);
    ctx.addFinding({asset:base2(t)+p,stageId:'s26',tool,severity:'low',confidence:'medium',title:'Content discovered: '+p.slice(0,160),description:tool+' found a reachable path. Confirm it is intended to be public.',evidence:ln.slice(0,800),component:p,recommendation:'Restrict or remove unintended paths.',verification:'needs-verification'});
  }
}
function base2(t){return t.url.toString().replace(/\/+$/,'');}
