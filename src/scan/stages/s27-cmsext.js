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
    out.droopescan = maybeDrupal||(d.run&&d.run.stdout) ? d.status : 'skipped:not-detected';
    if(d.run&&d.run.stdout&&/drupal/i.test(d.run.stdout)){
      ctx.addFinding({asset:t.host,stageId:'s27',tool:'droopescan',severity:'informational',confidence:'medium',title:'Droopescan: Drupal markers detected',description:'Droopescan output indicates Drupal. Check supported versions and patch level.',evidence:d.run.stdout.slice(0,1200),recommendation:'Keep Drupal core/modules updated.',verification:'needs-verification'});
    } else if(!maybeDrupal) ctx.log('info','Droopescan skipped - no Drupal/SilverStripe/Moodle markers');

    const jb='/opt/joomscan/joomscan.pl';
    const jbin = jb ? 'perl' : 'joomscan';
    const jargs = jb ? [jb,'-u',t.url.toString()] : ['--url',t.url.toString(),'--enumerate-components'];
    const j = await runAdapter(ctx,'joomscan',{args:jargs,timeoutMs:lim,maxBytes:256*1024});
    out.joomscan = maybeJoomla || (j.run&&j.run.stdout) ? j.status : 'skipped:not-detected';
    if(j.run&&j.run.stdout&&/vulnerable|version\s*[\d.]+/i.test(j.run.stdout)){
      const txt=j.run.stdout.slice(0,6000);
      ctx.addFinding({asset:t.host,stageId:'s27',tool:'joomscan',severity:'high',confidence:'medium',title:'JoomScan: possible vulnerable Joomla version/config',description:'JoomScan output contains version or vulnerable markers. Confirm version against advisories.',evidence:txt.slice(0,1500),recommendation:'Upgrade Joomla and extensions; harden configuration.',verification:'needs-verification'});
    } else if(!maybeJoomla) ctx.log('info','JoomScan skipped - no Joomla markers');

    ctx.setSummary(out);
    return {summary:out};
  },
};
