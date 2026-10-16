import { api } from '../api.js';
import { t, esc, fmtDur, toast, statusBadge, $ } from '../app.js';

export async function renderHealth(m, root) {
  root.innerHTML = `
    <div class="toolbar"><button class="btn primary small" id="h-refresh">${esc(t('health.check'))}</button>
      <span class="inline-note" id="h-ts"></span></div>
    <div class="grid cols-3" id="h-cards"></div>
    <div class="card" style="margin-top:16px;max-width:860px"><h3>${esc(t('sys.env'))}</h3><div class="kv" id="h-env"></div></div>`;

  const load = async () => {
    try {
      const h = await api('/api/health');
      $('#h-ts', root).textContent = h.timestamp;
      $('#h-cards', root).innerHTML = `
        <div class="card hoverable"><h3>Status</h3><div class="big" style="color:${h.status === 'ok' ? 'var(--success)' : 'var(--destructive)'}">${esc(h.status)}</div><div class="sub">${esc(t('health.ok'))}</div></div>
        <div class="card hoverable"><h3>${esc(t('health.uptime'))}</h3><div class="big">${fmtDur(h.uptimeSec * 1000)}</div><div class="sub">rss ${h.memory.rssMB} MB · heap ${h.memory.heapMB} MB</div></div>
        <div class="card hoverable"><h3>${esc(t('health.disk'))}</h3><div class="big">${h.diskFreeMB != null ? h.diskFreeMB + ' MB' : '—'}</div><div class="sub">total RAM hệ thống: ${h.memory.totalSystemMB} MB</div></div>
        <div class="card hoverable"><h3>${esc(t('health.db'))}</h3><div class="big">${esc(h.database)}</div><div class="sub">WAL</div></div>
        <div class="card hoverable"><h3>${esc(t('health.worker'))}</h3><div class="big">${h.worker.running ? 'busy' : 'idle'}</div><div class="sub">${t('dash.queue')}: ${h.worker.queued}</div></div>
        <div class="card hoverable"><h3>${esc(t('health.ai'))}</h3><div class="big">${h.ai.configured ? 'ok' : '—'}</div><div class="sub">${h.ai.configured ? t('health.configured') : t('health.notConfigured')}</div></div>`;
      $('#h-env', root).innerHTML = [
        ['Node', navigator.userAgent.includes('Node') ? '—' : 'browser'],
        ['Password', h.auth.passwordConfigured ? t('health.configured') : t('health.notConfigured')],
        ['Session secret', h.auth.sessionSecretConfigured ? t('health.configured') : t('health.notConfigured')],
        ['Encryption key', h.auth.encryptionKeyConfigured ? t('health.configured') : t('health.notConfigured')],
        ['Tools detected', String(h.tools.total)],
      ].map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`).join('');
    } catch (e) {
      $('#h-cards', root).innerHTML = `<div class="empty"><div class="ico"></div><p>${esc(e.message)}</p></div>`;
    }
  };
  $('#h-refresh', root).addEventListener('click', load);
  await load();
}
