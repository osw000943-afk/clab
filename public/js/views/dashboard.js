import { api } from '../api.js';
import { t, esc, fmtDate, sevBadge, statusBadge, emptyState, $ } from '../app.js';
import { donut, bars, line, legend } from '../charts.js';

export async function renderDashboard(m, root) {
  root.innerHTML = `<div class="grid cols-4" id="kpis"></div>
    <div class="grid cols-2" style="margin-top:16px">
      <div class="card hoverable"><h3>${esc(t('dash.severity'))}</h3><div id="sev-chart" class="chart-box"></div></div>
      <div class="card hoverable"><h3>${esc(t('dash.trend'))}</h3><div id="trend-chart" class="chart-box"></div></div>
    </div>
    <div class="grid cols-2" style="margin-top:16px">
      <div class="card hoverable"><h3>${esc(t('dash.toolSuccess'))}</h3><div id="tool-chart" class="chart-box"></div></div>
      <div class="card hoverable"><h3>${esc(t('dash.activity'))}</h3><div id="activity"></div></div>
    </div>
    <h3 class="section-title">${esc(t('dash.recent'))}</h3>
    <div id="recent"></div>`;

  let stats;
  try {
    stats = await api('/api/dashboard/stats');
  } catch (e) {
    root.innerHTML = `<div class="empty"><div class="ico"></div><p>${esc(t('common.error') + e.message)}</p></div>`;
    return;
  }

  const ts = stats.toolSummary || {};
  const tsTotal = Object.values(ts).reduce((a, b) => a + b, 0) || 1;
  $('#kpis', root).innerHTML = [
    { label: t('dash.scans'), value: stats.totalScans, sub: `${stats.byStatus.completed || 0} completed` },
    { label: t('dash.assets'), value: stats.uniqueAssets, sub: '' },
    { label: t('dash.serious'), value: stats.openCritical, sub: 'critical + high', danger: stats.openCritical > 0 },
    { label: t('dash.toolsAvail'), value: `${ts.available || 0}/${tsTotal}`, sub: 'available / total' },
  ].map((k) => `<div class="card hoverable"><h3>${esc(k.label)}</h3>
      <div class="big" ${k.danger ? 'style="color:#B91C1C"' : ''}>${esc(String(k.value))}</div>
      <div class="sub">${esc(k.sub || '')}</div></div>`).join('');

  // severity donut — empty state when no data
  const sev = stats.severity;
  const totalSev = Object.values(sev).reduce((a, b) => a + b, 0);
  $('#sev-chart', root).innerHTML = totalSev
    ? donut(sev) + legend(sev)
    : emptyState(t('dash.empty'), t('dash.emptyHint'));

  // trend
  const trend = (stats.trend || []).map((p, i) => ({ label: '#' + (i + 1), value: p.total }));
  $('#trend-chart', root).innerHTML = trend.length
    ? line(trend) + `<div class="inline-note">${(stats.trend || []).map((p) => `${esc(p.target_host)}: ${p.total} (${p.serious} serious)`).join(' · ')}</div>`
    : emptyState(t('dash.noDataChart'));

  // tool success bars
  const toolItems = Object.entries(stats.toolRates || {}).slice(0, 7).map(([id, r]) => ({
    label: id, value: r.rate ?? 0, color: r.rate >= 90 ? '#059669' : r.rate >= 60 ? '#D97706' : '#DC2626',
  }));
  $('#tool-chart', root).innerHTML = toolItems.length
    ? bars(toolItems) + `<div class="inline-note">${esc(Object.entries(stats.toolRates).map(([k, r]) => `${k}: ${r.completed}ok/${r.failed}x`).join(' · '))}</div>`
    : emptyState(t('dash.noDataChart'));

  // activity feed
  const act = stats.activity || [];
  $('#activity', root).innerHTML = act.length ? `<div class="stages">${act.map((a) => `
    <div class="stage-row" style="cursor:pointer" data-goto="${esc(a.id || '')}">
      <span class="st-ico">${a.kind === 'scan' ? '' : ''}</span>
      <span class="st-name">${esc(a.text)}<br><small class="muted">${fmtDate(a.at)}</small></span>
      ${a.severity ? sevBadge(a.severity) : statusBadge(a.status || '')}
    </div>`).join('')}</div>` : emptyState(t('dash.empty'));
  root.querySelectorAll('[data-goto]').forEach((el) => el.addEventListener('click', () => {
    if (el.dataset.goto) location.hash = '#/scans/' + el.dataset.goto;
  }));

  // recent scans table
  const rs = stats.recentScans || [];
  $('#recent', root).innerHTML = rs.length ? `<div class="table-wrap"><table class="data">
    <thead><tr><th>Target</th><th>${esc(t('scan.mode').replace(':', ''))}</th><th>Status</th><th>${esc(t('detail.progress'))}</th><th>Time</th></tr></thead>
    <tbody>${rs.map((s) => `<tr class="clickable" data-id="${esc(s.id)}">
      <td><b>${esc(s.target_host || s.target_url)}</b><br><small class="muted mono">${esc(s.target_url)}</small></td>
      <td><span class="tag">${esc(s.mode)}</span></td>
      <td>${statusBadge(s.status)}</td>
      <td><div class="progress-track" style="min-width:90px"><div class="progress-fill" style="width:${Math.round((s.progress || 0) * 100)}%"></div></div></td>
      <td class="muted">${fmtDate(s.created_at)}</td></tr>`).join('')}</tbody></table></div>`
    : emptyState(t('dash.empty'), t('dash.emptyHint'));
  root.querySelectorAll('tr[data-id]').forEach((tr) => tr.addEventListener('click', () => {
    location.hash = '#/scans/' + tr.dataset.id;
  }));
}
