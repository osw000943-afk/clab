import { runAdapter } from '../tools-registry.js';
import { getSetting } from '../../db.js';
export default {
  id: 's30',
  name: 'WAF & Monitoring Guidance (Coraza/BunkerWeb/Wazuh/OSSEC)',
  tools: ['coraza','bunkerweb','wazuh','ossec'],
  async run(ctx) {
    const t = ctx.getTarget();
    const out = { mode: 'guidance-only', noProdChanges: true };
    const c = await runAdapter(ctx,'coraza',{args:[]});
    out.coraza=c.status;
    out.corazaGuidance='Coraza is a WAF / reverse-proxy component, not a standalone scanner. Integrate in gateway if architecture fits; no auto-install.';
    const b = await runAdapter(ctx,'bunkerweb',{args:[]});
    out.bunkerweb=b.status;
    out.bunkerwebGuidance='BunkerWeb gateway option (WAF+TLS+abuse mitigation). Reverse-proxy changes only with approval + backup.';
    const wkey=getSetting('wazuh_api');
    if(!wkey){out.wazuh='needs-config';out.wazuhGuidance='Full Wazuh stack too heavy for 1GB RAM - prefer dedicated monitor host or official API.';}
    else{const w=await runAdapter(ctx,'wazuh',{args:[]});out.wazuh=w.status;out.wazuhGuidance='Connected via API; alerts/log analytics outside web process.';}
    const o=await runAdapter(ctx,'ossec',{args:[]});
    out.ossec=o.status;
    out.ossecGuidance='Evaluate agent needs, access rights and resource use before enabling.';
    if(ctx.getTarget()) ctx.addFinding({asset:t.host,stageId:'s30',tool:'protect-guidance',severity:'informational',confidence:'high',title:'WAF/monitoring posture reviewed (no prod changes made)',description:'Coraza/BunkerWeb are protect-mode; Wazuh/OSSEC are monitor-mode. No SIEM/WAF installed in web process; no proxy config changed.',evidence:JSON.stringify({coraza:out.coraza,bunkerweb:out.bunkerweb,wazuh:out.wazuh,ossec:out.ossec}),recommendation:'If needed: deploy WAF/monitoring on dedicated host with approval + backup.',verification:'confirmed'});
    ctx.setSummary(out);
    return{summary:out};
  },
};
