import { api } from '../api.js';
import { t, esc, fmtDate, toast, statusBadge, emptyState, $ } from '../app.js';

export async function renderTools(m, root) {
  root.innerHTML = `
    <div class="toolbar">
      <button class="btn primary small" id="tl-refresh">${esc(t('tools.refresh'))}</button>
      <span class="inline-note">${esc(t('tools.verified'))}</span>
    </div>
    <div id="tl-table">${emptyState(t('common.loading'))}</div>`;

  const load = async () => {
    const tools = await api('/api/tools');
    $('#tl-table', root).innerHTML = `<div class="table-wrap"><table class="data">
      <thead><tr><th>Tool</th><th>Status</th><th>Version</th><th>${esc(t('tools.mode'))}</th><th>${esc(t('tools.license'))}</th><th>Note</th><th></th></tr></thead>
      <tbody>${tools.map((x) => `<tr>
        <td><b>${esc(x.name)}</b>${x.heavy ? ' <span class="tag" title="heavy">'+esc(t('tools.heavy'))+'</span>' : ''}<br><small class="muted">${esc(x.desc || '')}</small></td>
        <td>${statusBadge(x.status)}</td>
        <td class="mono">${esc(x.version || '—')}</td>
        <td>${esc(x.mode)}</td>
        <td><small>${esc(x.license || '—')}</small></td>
        <td><small class="muted">${esc(x.detail)}</small></td>
        <td>${x.builtin ? '' : `<button class="btn ghost small tl-toggle" data-id="${esc(x.id)}" data-dis="${x.userDisabled ? '0' : '1'}">${x.userDisabled ? esc(t('tools.enable')) : esc(t('tools.disable'))}</button>`}</td>
      </tr>`).join('')}</tbody></table></div>`;

    root.querySelectorAll('.tl-toggle').forEach((b) => b.addEventListener('click', async () => {
      try {
        await api(`/api/tools/${b.dataset.id}/${b.dataset.dis === '1' ? 'disable' : 'enable'}`, { method: 'POST' });
        load();
      } catch (e) { toast(e.message, 'error'); }
    }));
  };

  $('#tl-refresh', root).addEventListener('click', async () => {
    const b = $('#tl-refresh', root);
    b.disabled = true; b.textContent = t('tools.refreshing');
    try { await api('/api/tools/refresh', { method: 'POST' }); load(); }
    catch (e) { toast(e.message, 'error'); }
    finally { b.disabled = false; b.textContent = t('tools.refresh'); }
  });

  await load();
}
