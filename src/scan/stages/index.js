import s01 from './s01-scope.js';
import s02 from './s02-dns.js';
import s03 from './s03-http.js';
import s04 from './s04-fingerprint.js';
import s05 from './s05-ports.js';
import s06 from './s06-headers.js';
import s07 from './s07-tls.js';
import s08 from './s08-misconfig.js';
import s09 from './s09-wordpress.js';
import s10 from './s10-reputation.js';
import s11 from './s11-zap.js';
import s12 from './s12-sqlmap.js';
import s13 from './s13-xss.js';
import s14 from './s14-deps.js';
import s15 from './s15-sast.js';
import s16 from './s16-secrets.js';
import s17 from './s17-iac.js';
import s18 from './s18-traffic.js';
import s19 from './s19-correlate.js';
import s20 from './s20-deep.js';
import s21 from './s21-dbaudit.js';
import s22 from './s22-privesc.js';
import s23 from './s23-bypass.js';
import s24 from './s24-availability.js';
import s25 from './s25-webvuln.js';
import s26 from './s26-content.js';
import s27 from './s27-cmsext.js';
import s28 from './s28-tlsext.js';
import s29 from './s29-osint.js';
import s30 from './s30-protect.js';

export const STAGES = {
  s01, s02, s03, s04, s05, s06, s07, s08, s09, s10, s11, s12,
  s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23, s24,
  s25, s26, s27, s28, s29, s30,
};

export function stageListForMode(mode, modules) {
  const base = {
    quick: ['s01', 's02', 's03', 's06'],
    standard: ['s01', 's02', 's03', 's04', 's05', 's06', 's07', 's10', 's19'],
    deep: ['s01', 's02', 's03', 's04', 's05', 's06', 's07', 's08', 's09', 's10', 's25', 's26', 's27', 's28', 's29', 's30', 's19', 's20', 's21', 's22', 's23'],
    full: ['s01', 's02', 's03', 's04', 's05', 's06', 's07', 's08', 's09', 's10', 's11', 's12', 's13',
      's14', 's15', 's16', 's17', 's18', 's25', 's26', 's27', 's28', 's29', 's30', 's19', 's20', 's21', 's22', 's23', 's24'],
  }[mode] || null;
  if (Array.isArray(modules) && modules.length) return modules.filter((m) => STAGES[m]);
  return base || ['s01', 's02', 's03', 's06'];
}
