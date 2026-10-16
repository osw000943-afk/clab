import { api } from '../api.js';
import { t, esc, fmtDate, toast, modal, sevBadge, statusBadge, emptyState, $ } from '../app.js';

export async function renderFindings(m, root) {
  let page = 1, qStr = '', sevStr = '', statusStr = '';
  root.innerHTML = `
    <div class="toolbar">
      <input class="input" id="fi-q" placeholder="${esc(t('findings.search'))}">
      <select class="input" id="fi-sev">
        <option value="">${esc(t('findings.severity'))}: ${esc(t('findings.all'))}</option>
        <option>critical</option><option>high</option><option>medium</option><option>low</option><option>informational</option>
      </select>
      <select class="input" id="fi-st">
        <option value="">${esc(t('findings.status'))}: ${esc(t('findings.all'))}</option>
        <option>new</option><option>confirmed</option><option>needs-verification</option><option>false-positive</option><option>fixed</option><option>accepted-risk</option>
      </select>
      <span class="spacer"></span><span class="inline-note" id="fi-count"></span>
    </div>
    <div id="fi-table"></div>
    <div class="toolbar" style="margin-top:14px">
      <span class="spacer"></span>
      <button class="btn-tilt small" id="fi-prev">${esc(t('common.prev'))}</button>
      <span class="inline-note" id="fi-page"></span>
      <button class="btn-tilt small" id="fi-next">${esc(t('common.next'))}</button>
    </div>`;

  const load = async () => {
    const data = await api(`/api/findings?page=${page}&pageSize=25&q=${encodeURIComponent(qStr)}&severity=${sevStr}&status=${statusStr}`);
    $('#fi-count', root).textContent = `${data.total} ${t('common.of')} ...`;
    $('#fi-page', root).textContent = `${t('common.page')} ${data.page}`;
    $('#fi-table', root).innerHTML = data.items.length ? `<div class="table-wrap"><table class="data">
      <thead><tr><th>Sev</th><th>Title</th><th>Asset</th><th>Scan</th><th>Tool</th><th>Status</th><th>Seen</th></tr></thead>
      <tbody>${data.items.map((f) => `<tr class="clickable" data-fid="${esc(f.id)}" data-sid="${esc(f.scan_id)}">
        <td>${sevBadge(f.severity)}</td>
        <td>${esc(f.title)}</td>
        <td class="mono" style="font-size:12px">${esc(f.asset.slice(0, 48))}</td>
        <td><small class="muted">${esc((f.target_host || '').slice(0, 24))}</small></td>
        <td><span class="tag">${esc(f.tool)}</span></td>
        <td>${statusBadge(f.status)}</td>
        <td class="muted">${fmtDate(f.last_seen)}</td>
      </tr>`).join('')}</tbody></table></div>` : emptyState(t('findings.empty'));

    root.querySelectorAll('tr[data-fid]').forEach((tr) => tr.addEventListener('click', () => {
      location.hash = '#/scans/' + tr.dataset.sid;
    }));
  };

  let d;
  $('#fi-q', root).addEventListener('input', (e) => { clearTimeout(d); d = setTimeout(() => { qStr = e.target.value.trim(); page = 1; load(); }, 300); });
  $('#fi-sev', root).addEventListener('change', (e) => { sevStr = e.target.value; page = 1; load(); });
  $('#fi-st', root).addEventListener('change', (e) => { statusStr = e.target.value; page = 1; load(); });
  $('#fi-prev', root).addEventListener('click', () => { if (page > 1) { page--; load(); } });
  $('#fi-next', root).addEventListener('click', () => { page++; load(); });
  await load();
}
