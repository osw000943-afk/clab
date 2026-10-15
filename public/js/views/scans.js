import { api, openStream } from '../api.js';
import { t, esc, fmtDate, fmtDur, toast, modal, confirmDialog, sevBadge, statusBadge, emptyState, $, $$ } from '../app.js';

const STAGE_LABELS = {
  s01: 'Scope', s02: 'DNS', s03: 'HTTP', s04: 'Fingerprint', s05: 'Ports', s06: 'Headers',
  s07: 'TLS', s08: 'Misconfig', s09: 'WordPress', s10: 'Reputation', s11: 'ZAP', s12: 'SQLi',
  s13: 'XSS', s14: 'Deps/CVE', s15: 'SAST', s16: 'Secrets/JS', s17: 'IaC', s18: 'Traffic',
  s19: 'Correlate', s20: 'Deep Audit', s21: 'DB Audit', s22: 'Privesc', s23: 'Bypass', s24: 'Availability',
};

/* ================= CREATE SCAN ================= */
export async function renderScanNew(m, root) {
  const ALL_STAGES = ['s01','s02','s03','s04','s05','s06','s07','s08','s09','s10','s11','s12','s13','s14','s15','s16','s17','s18','s19','s20','s21','s22','s23','s24'];

  root.innerHTML = `
    <form id="scan-form" class="card" style="max-width:860px">
      <div class="field">
        <label for="f-url">${esc(t('scan.target'))}</label>
        <input id="f-url" class="input" type="url" placeholder="https://example.com" required>
        <div class="hint">${esc(t('scan.targetHint'))}</div>
      </div>
      <div class="field">
        <label for="f-mode">${esc(t('scan.mode'))}</label>
        <select id="f-mode" class="input">
          <option value="quick">${esc(t('scan.mode.quick'))}</option>
          <option value="standard" selected>${esc(t('scan.mode.standard'))}</option>
          <option value="deep">${esc(t('scan.mode.deep'))}</option>
          <option value="full">${esc(t('scan.mode.full'))}</option>
        </select>
      </div>
      <div class="field">
        <label>${esc(t('scan.modules'))}</label>
        <div class="chip-row" id="module-row">
          ${ALL_STAGES.map((s) => `<button type="button" class="chip" data-stage="${s}" title="${s}">${STAGE_LABELS[s]}</button>`).join('')}
        </div>
        <div class="hint">${esc('Bỏ trống để dùng bộ module của chế độ quét đã chọn.')}</div>
      </div>
      <hr class="divider">
      <h4 style="margin:0 0 8px;font-size:13.5px">${esc(t('scan.scopeTitle'))}</h4>
      <label class="checkbox"><input type="checkbox" id="sc1"> <span>${esc(t('scan.scope1'))}</span></label>
      <label class="checkbox"><input type="checkbox" id="sc2"> <span>${esc(t('scan.scope2'))}</span></label>
      <label class="checkbox"><input type="checkbox" id="sc3"> <span>${esc(t('scan.scope3'))}</span></label>
      <div class="field" style="margin-top:12px">
        <label for="f-stmt">${esc(t('scan.statement'))}</label>
        <input id="f-stmt" class="input" maxlength="500">
      </div>
      <details style="margin:14px 0"><summary style="cursor:pointer;font-weight:650;font-size:13.5px">${esc(t('scan.optionsTitle'))}</summary>
        <div style="margin-top:12px">
          <label class="checkbox"><input type="checkbox" id="o-zap"> <span>${esc(t('scan.opt.zap'))}</span></label>
          <label class="checkbox"><input type="checkbox" id="o-ssllabs"> <span>${esc(t('scan.opt.ssllabs'))}</span></label>
          <label class="checkbox"><input type="checkbox" id="o-avail"> <span>${esc(t('scan.opt.availability'))}</span></label>
          <div class="grid cols-2">
            <div class="field"><label for="o-rps">RPS</label><input id="o-rps" class="input" type="number" value="5" min="1" max="20"></div>
            <div class="field"><label for="o-sec">Seconds</label><input id="o-sec" class="input" type="number" value="10" min="3" max="60"></div>
          </div>
        </div>
      </details>
      <div id="scan-form-error" class="form-error hidden" role="alert"></div>
      <button class="btn primary" type="submit" id="start-btn">${esc(t('scan.start'))}</button>
    </form>`;

  const picked = new Set();
  $$('#module-row .chip', root).forEach((chip) => chip.addEventListener('click', () => {
    const s = chip.dataset.stage;
    if (picked.has(s)) { picked.delete(s); chip.classList.remove('on'); }
    else { picked.add(s); chip.classList.add('on'); }
  }));

  $('#scan-form', root).addEventListener('submit', async (e) => {
    e.preventDefault();
    const errBox = $('#scan-form-error', root);
    errBox.classList.add('hidden');
    if (!$('#sc1', root).checked || !$('#sc2', root).checked || !$('#sc3', root).checked) {
      errBox.textContent = t('scan.scopeError');
      errBox.classList.remove('hidden');
      return;
    }
    const btn = $('#start-btn', root);
    btn.disabled = true;
    btn.textContent = t('scan.starting');
    try {
      const r = await api('/api/scans', {
        method: 'POST',
        body: {
          targetUrl: $('#f-url', root).value.trim(),
          mode: $('#f-mode', root).value,
          modules: [...picked],
          scopeConfirmed: true,
          authorizedTesting: true,
          authorizationStatement: $('#f-stmt', root).value.trim(),
          options: {
            zap: $('#o-zap', root).checked,
            ssllabs: $('#o-ssllabs', root).checked,
            availability: $('#o-avail', root).checked,
            loadRps: Number($('#o-rps', root).value),
            loadSeconds: Number($('#o-sec', root).value),
          },
        },
      });
      toast(t('scan.created'), 'success');
      location.hash = '#/scans/' + r.id;
    } catch (ex) {
      errBox.textContent = ex.message;
      errBox.classList.remove('hidden');
    } finally {
      btn.disabled = false;
      btn.textContent = t('scan.start');
    }
  });
}

/* ================= HISTORY ================= */
export async function renderScanList(m, root) {
  let page = 1, qStr = '', statusStr = '';
  root.innerHTML = `
    <div class="toolbar">
      <input class="input" id="h-search" placeholder="${esc(t('history.search'))}">
      <select class="input" id="h-status">
        <option value="">${esc(t('history.allStatus'))}</option>
        <option>queued</option><option>running</option><option>completed</option><option>partial</option><option>failed</option><option>cancelled</option>
      </select>
      <button class="btn small" id="h-compare">${esc(t('history.compare'))}</button>
      <span class="spacer"></span>
      <span class="inline-note" id="h-count"></span>
    </div>
    <div id="h-table"></div>
    <div class="toolbar" style="margin-top:14px">
      <span class="spacer"></span>
      <button class="btn small" id="h-prev">${esc(t('common.prev'))}</button>
      <span class="inline-note" id="h-page"></span>
      <button class="btn small" id="h-next">${esc(t('common.next'))}</button>
    </div>`;

  const load = async () => {
    const data = await api(`/api/scans?page=${page}&pageSize=15&q=${encodeURIComponent(qStr)}&status=${encodeURIComponent(statusStr)}`);
    $('#h-count', root).textContent = `${data.total} ${t('common.of')} …`;
    $('#h-page', root).textContent = `${t('common.page')} ${data.page}`;
    $('#h-table', root).innerHTML = data.items.length ? `<div class="table-wrap"><table class="data">
      <thead><tr><th></th><th>Target</th><th>Mode</th><th>Status</th><th>Findings</th><th>Created</th><th></th></tr></thead>
      <tbody>${data.items.map((s) => `<tr class="clickable" data-id="${esc(s.id)}">
        <td><input type="checkbox" class="h-pick" data-id="${esc(s.id)}" aria-label="select"></td>
        <td><b>${esc(s.target_host || '')}</b><br><small class="muted mono">${esc(s.target_url)}</small></td>
        <td><span class="tag">${esc(s.mode)}</span></td>
        <td>${statusBadge(s.status)}</td>
        <td><span class="sev-critical" style="font-weight:700">${s.findings.critical + s.findings.high}</span> serious · ${Object.values(s.findings).reduce((a, b) => a + b, 0)} total</td>
        <td class="muted">${fmtDate(s.created_at)}</td>
        <td><button class="btn ghost small h-del" data-id="${esc(s.id)}">${esc(t('common.delete'))}</button></td>
      </tr>`).join('')}</tbody></table></div>` : emptyState(t('history.empty'), t('dash.emptyHint'));

    root.querySelectorAll('tr[data-id]').forEach((tr) => tr.addEventListener('click', (e) => {
      if (e.target.closest('input,button')) return;
      location.hash = '#/scans/' + tr.dataset.id;
    }));
    root.querySelectorAll('.h-del').forEach((b) => b.addEventListener('click', async (e) => {
      e.stopPropagation();
      if (!confirm(t('detail.deleteConfirm'))) return;
      try {
        await api('/api/scans/' + b.dataset.id + '?confirm=yes', { method: 'DELETE' });
        toast(t('common.save') + ' ✓', 'success');
        load();
      } catch (ex) { toast(ex.message, 'error'); }
    }));
  };

  let debounce;
  $('#h-search', root).addEventListener('input', (e) => {
    clearTimeout(debounce);
    debounce = setTimeout(() => { qStr = e.target.value.trim(); page = 1; load(); }, 300);
  });
  $('#h-status', root).addEventListener('change', (e) => { statusStr = e.target.value; page = 1; load(); });
  $('#h-prev', root).addEventListener('click', () => { if (page > 1) { page--; load(); } });
  $('#h-next', root).addEventListener('click', () => { page++; load(); });
  $('#h-compare', root).addEventListener('click', () => {
    const picks = $$('.h-pick:checked', root).map((c) => c.dataset.id);
    if (picks.length !== 2) { toast(t('history.selectTwo'), 'error'); return; }
    showCompare(picks[0], picks[1], root);
  });

  await load();
}

async function showCompare(a, b, root) {
  try {
    const r = await api(`/api/scans/${a}/compare/${b}`);
    modal({
      title: t('history.compare'),
      body: `<div class="kv">
        <dt>A</dt><dd class="mono">${esc(r.a.url)} — ${fmtDate(r.a.createdAt)}<br>${JSON.stringify(r.a.counts)}</dd>
        <dt>B</dt><dd class="mono">${esc(r.b.url)} — ${fmtDate(r.b.createdAt)}<br>${JSON.stringify(r.b.counts)}</dd>
      </div>
      <h4 style="margin:16px 0 6px">New in B (${r.newInB.length})</h4>
      <div class="stages">${r.newInB.length ? r.newInB.map((f) => `<div class="stage-row">${sevBadge(f.severity)}<span class="st-name">${esc(f.title)}</span></div>`).join('') : '<p class="muted">0</p>'}</div>
      <h4 style="margin:16px 0 6px">Resolved (${r.resolvedSinceA.length})</h4>
      <div class="stages">${r.resolvedSinceA.length ? r.resolvedSinceA.map((f) => `<div class="stage-row">${sevBadge(f.severity)}<span class="st-name">${esc(f.title)}</span></div>`).join('') : '<p class="muted">0</p>'}</div>`,
      actions: [{ label: t('common.close'), class: 'primary' }],
    });
  } catch (e) { toast(e.message, 'error'); }
}

/* ================= SCAN DETAIL (live) ================= */
export async function renderScanDetail(id, root) {
  root.innerHTML = `
    <div class="card" id="d-head"></div>
    <div class="grid cols-2" style="margin-top:16px">
      <div class="card"><h3>${esc(t('detail.stages'))}</h3><div id="d-stages" class="stages"></div></div>
      <div class="card"><h3>${esc(t('detail.logs'))}</h3><div id="d-logs" class="log-box" aria-live="polite"></div></div>
    </div>
    <div class="card" style="margin-top:16px"><h3>${esc(t('detail.findings'))}</h3><div id="d-findings"></div></div>
    <div class="card" style="margin-top:16px"><h3>${esc(t('detail.tools'))}</h3><div id="d-toolruns"></div></div>`;

  let scan = null;
  let stream = null;
  const load = async () => {
    scan = await api('/api/scans/' + id);
    paint();
  };

  const paint = () => {
    if (!scan) return;
    const counts = scan.counts;
    $('#d-head', root).innerHTML = `
      <div class="toolbar" style="margin-bottom:10px">
        <div>
          <div style="font-weight:750;font-size:16px;letter-spacing:-.01em">${esc(scan.target_url)}</div>
          <div class="muted" style="font-size:12.5px"><span class="tag">${esc(scan.mode)}</span>
            <span class="tag">${esc(scan.id)}</span> ${fmtDate(scan.created_at)}
            ${scan.started_at && scan.finished_at ? ' · ' + fmtDur(scan.finished_at - scan.started_at) : ''}</div>
        </div>
        <span class="spacer"></span>
        ${statusBadge(scan.status)}
        <button class="btn small" id="d-ai">${esc(t('detail.aiRun'))}</button>
        <button class="btn small" id="d-export">${esc(t('detail.export'))} ▾</button>
        <button class="btn small" id="d-rerun">${esc(t('detail.rerun'))}</button>
        ${['queued', 'running', 'cancelling'].includes(scan.status) ? `<button class="btn small danger" id="d-cancel">${esc(t('detail.cancel'))}</button>` : ''}
        <button class="btn ghost small" id="d-del">${esc(t('detail.delete'))}</button>
      </div>
      <div class="progress-track" role="progressbar" aria-valuenow="${Math.round((scan.progress || 0) * 100)}">
        <div class="progress-fill" style="width:${Math.round((scan.progress || 0) * 100)}%"></div>
      </div>
      <div class="stat-row" style="margin-top:12px">
        ${['critical', 'high', 'medium', 'low', 'informational'].map((s) =>
          `<div><span class="kpi-sev sev-${s}"><i></i><b style="font-family:var(--mono)">${counts[s] || 0}</b> ${s}</span></div>`).join('')}
      </div>
      ${scan.scope ? `<details style="margin-top:10px"><summary style="cursor:pointer;font-size:13px;color:var(--text-3)">${esc(t('detail.scope'))}</summary>
        <pre class="evidence" style="margin-top:8px">${esc(JSON.stringify(scan.scope, null, 2))}</pre></details>` : ''}`;

    $('#d-stages', root).innerHTML = (scan.stages || []).map((s) => {
      const ico = { pending: '·', running: '↻', completed: '✓', failed: '!' }[s.status] || '·';
      const summary = s.summary ? `<br><small class="muted mono" style="font-size:11px">${esc(String(s.summary).slice(0, 160))}</small>` : '';
      return `<div class="stage-row ${esc(s.status)}">
        <span class="st-ico">${ico}</span>
        <span class="st-name">${esc(s.stage_id)} · ${esc(STAGE_LABELS[s.stage_id] || s.name)}${summary}</span>
        ${s.error ? `<span class="st-err">${esc(s.error)}</span>` : ''}</div>`;
    }).join('');

    $('#d-logs', root).innerHTML = (scan.logs || []).map((l) =>
      `<div class="log-line ${esc(l.level)}">[${new Date(l.ts).toLocaleTimeString()}] ${esc(l.message)}</div>`).join('')
      || `<div class="log-line muted">…</div>`;
    const logBox = $('#d-logs', root);
    logBox.scrollTop = logBox.scrollHeight;

    const fs = scan.findings || [];
    $('#d-findings', root).innerHTML = fs.length ? `<div class="table-wrap" style="border:0"><table class="data">
      <thead><tr><th>Sev</th><th>Title</th><th>Tool</th><th>Conf</th><th>Status</th><th>AI</th></tr></thead>
      <tbody>${fs.map((f) => `<tr class="clickable" data-fid="${esc(f.id)}">
        <td>${sevBadge(f.severity)}</td>
        <td>${esc(f.title)}<br><small class="muted mono">${esc(f.asset)}</small></td>
        <td><span class="tag">${esc(f.tool)}</span></td>
        <td>${esc(f.confidence)}</td>
        <td>${statusBadge(f.status)}</td>
        <td class="muted" style="font-size:12px">${esc((f.ai_status || '').slice(0, 14))}</td>
      </tr>`).join('')}</tbody></table></div>` : emptyState(t('findings.empty'));

    root.querySelectorAll('[data-fid]').forEach((tr) => tr.addEventListener('click', () => openFinding(tr.dataset.fid)));

    const trs = scan.toolRuns || [];
    $('#d-toolruns', root).innerHTML = trs.length ? `<div class="table-wrap" style="border:0"><table class="data">
      <thead><tr><th>Tool</th><th>Status</th><th>Exit</th><th>Duration</th></tr></thead>
      <tbody>${trs.map((r) => `<tr><td><span class="tag">${esc(r.tool_id)}</span></td>
        <td>${statusBadge(r.status)}</td><td>${r.exit_code ?? '—'}</td>
        <td class="muted">${r.finished_at ? fmtDur(r.finished_at - r.started_at) : '…'}</td></tr>`).join('')}</tbody></table></div>`
      : `<p class="muted" style="margin:0">—</p>`;

    // actions
    $('#d-cancel', root)?.addEventListener('click', () => confirmDialog(t('detail.cancelConfirm'), async () => {
      try { await api(`/api/scans/${id}/cancel`, { method: 'POST' }); toast('…', 'success'); } catch (e) { toast(e.message, 'error'); }
    }));
    $('#d-del', root)?.addEventListener('click', async () => {
      if (!confirm(t('detail.deleteConfirm'))) return;
      try { await api('/api/scans/' + id + '?confirm=yes', { method: 'DELETE' }); location.hash = '#/scans'; } catch (e) { toast(e.message, 'error'); }
    });
    $('#d-rerun', root)?.addEventListener('click', async () => {
      if (!confirm(t('detail.rerunConfirm'))) return;
      try {
        const r = await api(`/api/scans/${id}/rerun`, { method: 'POST', body: { scopeConfirmed: true, authorizedTesting: true } });
        location.hash = '#/scans/' + r.id;
      } catch (e) { toast(e.message, 'error'); }
    });
    $('#d-ai', root)?.addEventListener('click', async () => {
      try {
        const r = await api('/api/ai/analyze/' + id, { method: 'POST' });
        toast(r.status === 'unconfigured' ? t('detail.aiNone') : `AI: ${r.analyzed} findings`, r.status === 'unconfigured' ? '' : 'success');
        load();
      } catch (e) { toast(e.message, 'error'); }
    });
    $('#d-export', root)?.addEventListener('click', () => {
      modal({
        title: t('detail.export'),
        body: `<div class="stages">
          <a class="stage-row" href="/api/scans/${esc(id)}/export?format=json" target="_blank"><span class="st-ico">↓</span><span class="st-name">JSON</span></a>
          <a class="stage-row" href="/api/scans/${esc(id)}/export?format=html" target="_blank"><span class="st-ico">↓</span><span class="st-name">HTML</span></a>
          <a class="stage-row" href="/api/scans/${esc(id)}/export?format=csv" target="_blank"><span class="st-ico">↓</span><span class="st-name">CSV</span></a>
        </div>`,
        actions: [{ label: t('common.close') }],
      });
    });
  };

  const openFinding = async (fid) => {
    let f;
    try { f = (await api('/api/findings/' + fid)); } catch (e) { return toast(e.message, 'error'); }
    let aiHtml = '';
    if (f.ai_analysis) {
      let a = {}; try { a = JSON.parse(f.ai_analysis); } catch { /* */ }
      aiHtml = `<div class="ai-panel"><h4>${esc(t('findings.ai'))}</h4>
        <p>${esc(a.explain || '')}</p>
        ${a.evidence_vs_hypothesis ? `<p><b>Evidence vs hypothesis:</b> ${esc(a.evidence_vs_hypothesis)}</p>` : ''}
        ${a.remediation ? `<p><b>Remediation:</b> ${esc(a.remediation)}</p>` : ''}
        ${a.follow_up ? `<p><b>Follow-up:</b> ${esc(a.follow_up)}</p>` : ''}
        <small class="muted">model: ${esc(a.model || '?')} · ${a.at ? fmtDate(a.at) : ''}</small></div>`;
    } else if (f.ai_status && f.ai_status !== 'ok') {
      aiHtml = `<div class="ai-panel"><h4>${esc(t('findings.ai'))}</h4><p class="muted">AI: ${esc(f.ai_status)}</p></div>`;
    }
    modal({
      title: f.title,
      body: `<div class="kv">
        <dt>Severity</dt><dd>${sevBadge(f.severity)}</dd>
        <dt>Confidence</dt><dd>${esc(f.confidence)}</dd>
        <dt>Status</dt><dd>${statusBadge(f.status)}</dd>
        <dt>Tool / Stage</dt><dd><span class="tag">${esc(f.tool)}</span> <span class="tag">${esc(f.stage_id || '')}</span></dd>
        <dt>Asset</dt><dd class="mono">${esc(f.asset)}</dd>
        <dt>Description</dt><dd>${esc(f.description)}</dd>
        <dt>${esc(t('findings.recommendation'))}</dt><dd>${esc(f.recommendation || '—')}</dd>
        <dt>${esc(t('findings.evidence'))}</dt><dd><div class="evidence">${esc(f.evidence || '—')}</div></dd>
      </div>
      ${aiHtml}
      <div style="margin-top:14px" class="toolbar">
        <select class="input" id="f-status" aria-label="${esc(t('findings.status'))}">
          ${['new', 'confirmed', 'needs-verification', 'false-positive', 'fixed', 'accepted-risk']
            .map((s) => `<option value="${s}" ${f.status === s ? 'selected' : ''}>${s}</option>`).join('')}
        </select>
        <button class="btn small primary" id="f-save">${esc(t('common.save'))}</button>
      </div>`,
      actions: [{ label: t('common.close') }],
    });
    $('#f-save')?.addEventListener('click', async () => {
      try {
        await api('/api/findings/' + fid, { method: 'PATCH', body: { status: $('#f-status').value } });
        toast(t('findings.updated'), 'success');
        document.querySelector('#modal-root .modal-back')?.remove();
        load();
      } catch (e) { toast(e.message, 'error'); }
    });
  };

  await load();

  // live updates — snapshot on (re)connect, no state lost on refresh
  stream = openStream('/api/events/scans/' + id + '/stream', {
    snapshot: (s) => { scan = { ...s.scan, stages: s.stages, logs: s.logs, findings: scan?.findings || [], toolRuns: scan?.toolRuns || [], counts: scan?.counts }; paint(); },
    log: (e) => {
      const box = $('#d-logs', root);
      if (!box) return;
      const div = document.createElement('div');
      div.className = 'log-line ' + e.level;
      div.textContent = `[${new Date(e.ts).toLocaleTimeString()}] ${e.message}`;
      box.appendChild(div);
      box.scrollTop = box.scrollHeight;
      if (scan) scan.logs = [...(scan.logs || []), { ts: e.ts, level: e.level, message: e.message }];
    },
    finding: () => { load(); },
    'stage-status': (e) => {
      if (!scan) return;
      const st = (scan.stages || []).find((x) => x.stage_id === e.stage);
      if (st) { st.status = e.status; st.error = e.error || null; st.summary = e.summary ?? st.summary; }
      paint();
    },
    progress: (e) => { if (scan) { scan.progress = e.progress; paint(); } },
    'scan-status': (e) => { if (scan) { scan.status = e.status; scan.error = e.error || scan.error; } load(); },
  });

  return () => stream && stream.close();
}
