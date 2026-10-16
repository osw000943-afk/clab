import dns from 'node:dns';
import { runAdapter, toolAvailable } from '../tools-registry.js';
import { getSetting } from '../../db.js';
export default {
  id: 's29',
  name: 'OSINT & Attack Surface (Subfinder/Naabu/WhatWeb/BuiltWith)',
  tools: ['subfinder','naabu','whatweb','builtwith'],
  async run(ctx) {
    const t = ctx.getTarget();
    if (!t) throw new Error('no-target');
    const out = { host: t.host, sharedWith: ['s02','s04','s05'] };
    const prev = ctx.store.subdomains || [];
    const subs = new Set(prev);
    const r = await runAdapter(ctx,'subfinder',{args:['-d',t.host,'-silent','-max-time','2'],timeoutMs:Math.min(ctx.limits.toolTimeoutMs||300000,120000),maxBytes:256*1024});
    out.subfinder=r.status;
    if(r.run&&r.run.stdout) for(const ln of r.run.stdout.split('\n')){const s=ln.trim().toLowerCase();if(s&&s.endsWith(t.host.toLowerCase()))subs.add(s);}
    if(toolAvailable('subfinder')===false){try{const rec=await dns.promises.resolve4('www.'+t.host);if(rec&&rec.length){subs.add('www.'+t.host);out.wwwFallback='added';}}catch{}}
    out.subdomains=[...subs].slice(0,50);
    ctx.store.subdomains=out.subdomains;
    const ports=[80,443,8080,8443,8000,8888];
    const lim=Math.min(ctx.limits.toolTimeoutMs||300000,120000);
    const n=await runAdapter(ctx,'naabu',{args:['-host',t.host,'-p',ports.join(','),'-rate','50','-timeout','3000','-silent'],timeoutMs:lim,maxBytes:256*1024});
    out.naabu=n.status;
    if(n.run&&n.run.stdout){const found=[...n.run.stdout.matchAll(/(\d{2,5})/g)].map(m=>Number(m[1])).filter(p=>ports.includes(p));out.naabuOpen=[...new Set(found)];}
    if(out.naabuOpen&&out.naabuOpen.length) ctx.addFinding({asset:t.host,stageId:'s29',tool:'naabu',severity:'low',confidence:'medium',title:'Naabu: open ports '+out.naabuOpen.join(','),description:'Naabu (rate 50/s, capped port list) found open ports. Shared with s05 evidence.',evidence:JSON.stringify(out.naabuOpen),recommendation:'Verify exposure matches s05; close what is not needed.',verification:'needs-verification'});
    if(toolAvailable('whatweb')&&(ctx.store.whatwebShared!==true)){const w=await runAdapter(ctx,'whatweb',{args:['--log-json=-','--color=never','-t','3',t.url.toString()],timeoutMs:90000,maxBytes:256*1024});out.whatwebShared=w.status;ctx.store.whatwebShared=true;if(!ctx.store.fingerprint)ctx.store.fingerprint=[];}
    else out.whatwebShared='reused-s04';
    const bwKey=getSetting('builtwith_api_key');
    if(!bwKey){out.builtwith='needs-config';ctx.log('info','BuiltWith needs API key - not a free local CLI');}
    else{try{const rr=await ctx.fetch('https://api.builtwith.com/v21/api.json?KEY='+encodeURIComponent(bwKey)+'&LOOKUP='+encodeURIComponent(t.host),{timeoutMs:15000,maxBytes:65536});out.builtwith='ok';out.externalServicesUsed=['builtwith'];const j=JSON.parse(rr.body.toString('utf8'));const techs=((j.Results&&j.Results[0]&&j.Results[0].Result&&j.Results[0].Result.Paths)||[]).slice(0,3);if(techs.length)ctx.addFinding({asset:t.host,stageId:'s29',tool:'builtwith',severity:'informational',confidence:'medium',title:'BuiltWith: '+techs.length+' tech paths reported',description:'Official BuiltWith API lookup. Hostname sent to BuiltWith per owner consent.',evidence:JSON.stringify(techs).slice(0,1500),recommendation:'Use for asset inventory.',verification:'needs-verification'});}catch(e){out.builtwith='failed:'+String(e.message).slice(0,120);}}
    ctx.setSummary(out);
    return{summary:out};
  },
};
