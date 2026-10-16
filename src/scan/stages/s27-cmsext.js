import { runAdapter } from '../tools-registry.js';
export default {
  id: 's27',
  name: 'CMS Extended (Droopescan/JoomScan)',
  tools: ['droopescan','joomscan'],
  async run(ctx) {
    const t = ctx.getTarget();
    if (!t) throw new Error('no-target');
    const out = { host: t.host };
    const lim = Math.min(ctx.limits.toolTimeoutMs||300000, 180000);
    const fp = (ctx.store.fingerprint||[]).map(x=>String(x.tech||'')).join(' ');
    const body = (ctx.store.http&&ctx.store.http.bodySnippet)||'';
    const hay = (fp+' '+body).toLowerCase();
    const maybeDrupal = /drupal|sites\/default\/files/.test(hay);
    const maybeJoomla = /joomla|\/administrator\/|com_content/.test(hay);
    const d = await runAdapter(ctx,'droopescan',{args:['scan','drupal','-u',t.url.toString()],timeoutMs:lim,maxBytes:256*1024});
    out.droopescan = maybeDrupal||d.run?.stdout ? d.status : 'skipped:not-detected';
    if(d.run&&d.run.stdout&&/drupal/i.test(d.run.stdout)){
      ctx.addFinding({asset:t.host,stageId:'s27',tool:'droopescan',severity:'informational',confidence:'medium',title:'Droopescan: Drupal markers detected',description:'Droopescan output indicates Drupal. Check supported versions and patch level.',evidence:d.run.stdout.slice(0,1200),recommendation:'Keep Drupal core/modules updated.',verification:'needs-verification'});
    } else if(!maybeDrupal) ctx.log('info','Droopescan skipped - no Drupal/SilverStripe/Moodle markers');
    let jb='/opt/joomscan/joomscan.pl';
    try{const {default:fs}=await import('node:fs');fs.accessSync(jb);}catch{jb=null;}
    const jbin = jb ? 'perl' : 'joomscan';
    const jargs2 = jb ? [jb,'-u',t.url.toString()] : ['--url',t.url.toString(),'--enumerate-components'];
    const {runTool,recordToolRun,toolAvailable}=await import('../tools-registry.js');
    let jstatus='missing';
    if(toolAvailable('joomscan')||jb){
      const started=Date.now();
      const r=await runTool(jbin,jargs2,{timeoutMs:lim,maxBytes:256*1024,signal:ctx.signal});
      jstatus=r.ok?'completed':(r.stdout?'partial':'failed');
      recordToolRun({scanId:ctx.scan.id,toolId:'joomscan',status:jstatus,exitCode:r.exitCode,startedAt:started,stderrExcerpt:(r.stderr||'').slice(0,400)});
      out.joomscan=jstatus;
      const txt=(r.stdout||'').slice(0,6000);
      if(/vulnerable|version\s*[\d.]+/i.test(txt)) ctx.addFinding({asset:t.host,stageId:'s27',tool:'joomscan',severity:'high',confidence:'medium',title:'JoomScan: possible vulnerable Joomla version/config',description:'JoomScan output contains version or vulnerable markers. Confirm version against advisories.',evidence:txt.slice(0,1500),recommendation:'Upgrade Joomla and extensions; harden configuration.',verification:'needs-verification'});
    } else { out.joomscan='missing'; ctx.log('info','JoomScan not installed - skipped'); }
    if(!maybeJoomla&&out.joomscan!=='completed') out.joomscanNote='No Joomla markers; scan skipped unless forced';
    ctx.setSummary(out);
    return {summary:out};
  },
};
