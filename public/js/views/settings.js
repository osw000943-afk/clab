import { api } from '../api.js';
import { t, esc, toast, statusBadge, emptyState, $, $$ } from '../app.js';

/* ================= AI PROVIDER ================= */
export async function renderAiSettings(m, root) {
  root.innerHTML = `<div id="ai-wrap">${emptyState(t('common.loading'))}</div>`;
  let data;
  try { data = await api('/api/ai'); }
  catch (e) { $('#ai-wrap', root).innerHTML = `<div class="empty"><div class="ico">⚠</div><p>${esc(e.message)}</p></div>`; return; }

  const encReady = data.encryptionReady;
  const active = data.active || {};

  const providerCard = (p) => {
    const isActive = active.provider_id === p.id;
    return `<div class="card hoverable" style="margin-bottom:14px" data-pid="${esc(p.id)}">
      <div class="toolbar" style="margin-bottom:12px">
        <div>
          <b>${esc(p.name)}</b> ${isActive ? `<span class="badge ok">${esc(t('ai.active'))}</span>` : ''}
          <br><small class="muted mono">${esc(p.base_url)}</small>
        </div>
        <span class="spacer"></span>
        <button class="btn small a-test">${esc(t('ai.testConn'))}</button>
        <button class="btn small a-models">${esc(t('ai.listModels'))}</button>
        <button class="btn ghost small a-del">${esc(t('common.delete'))}</button>
      </div>
      <div class="grid cols-2">
        <div class="field"><label>${esc(t('ai.apiKeyHint'))}</label>
          <div class="mono" style="font-size:13px;background:var(--surface-2);padding:8px 11px;border-radius:7px;border:1px solid var(--border)">
            ${esc(p.api_key_hint || '— (no key)')}
          </div>
          <div style="margin-top:8px;display:flex;gap:7px">
            <input class="input a-newkey" type="password" placeholder="${esc(t('ai.apiKey'))}" autocomplete="off" style="flex:1">
            <button class="btn small a-rotate">${esc(t('ai.save'))}</button>
            <button class="btn ghost small a-delkey">${esc(t('ai.deleteKey'))}</button>
          </div>
        </div>
        <div>
          <div class="field"><label>${esc(t('ai.selectModel'))}</label>
            <select class="input a-model"><option value="">…</option></select>
          </div>
          <div style="display:flex;gap:8px">
            <button class="btn primary small a-activate">${esc(t('ai.activate'))}</button>
            <button class="btn small a-testmodel">${esc(t('ai.testModel'))}</button>
          </div>
          <div class="muted a-status" style="font-size:12.5px;margin-top:8px"></div>
        </div>
      </div>
    </div>`;
  };

  const paint = (d) => {
    $('#ai-wrap', root).innerHTML = `
      ${!encReady ? `<div class="notice" style="margin-bottom:16px"><strong>${esc(t('ai.noEncryption'))}</strong></div>` : ''}
      <div class="card" style="margin-bottom:18px">
        <h3>${esc(t('ai.add'))}</h3>
        <div class="grid cols-2">
          <div class="field"><label>${esc(t('ai.name'))}</label><input class="input" id="np-name" placeholder="Nemotron (NVIDIA NIM)"></div>
          <div class="field"><label>${esc(t('ai.baseUrl'))}</label><input class="input" id="np-url" placeholder="https://integrate.api.nvidia.com/v1"></div>
        </div>
        <div class="grid cols-3">
          <div class="field"><label>${esc(t('ai.apiKey'))}</label><input class="input" id="np-key" type="password" autocomplete="new-password"></div>
          <div class="field"><label>${esc(t('ai.timeout'))}</label><input class="input" id="np-timeout" type="number" value="30000" min="3000" max="300000"></div>
          <div class="field"><label>${esc(t('ai.maxTokens'))}</label><input class="input" id="np-tokens" type="number" value="2048" min="64" max="32768"></div>
        </div>
        <button class="btn primary" id="np-save" ${encReady ? '' : 'disabled'}>${esc(t('ai.save'))}</button>
        <span class="inline-note" style="margin-left:12px">${esc(t('ai.never'))}</span>
      </div>
      <h3 class="section-title">${esc(t('ai.providers'))}</h3>
      ${d.providers.length ? d.providers.map(providerCard).join('') : `<p class="muted">${esc(t('ai.noProviders'))}</p>`}`;

    // add provider
    $('#np-save', root).addEventListener('click', async () => {
      try {
        await api('/api/ai/providers', { method: 'POST', body: {
          name: $('#np-name', root).value.trim(),
          baseUrl: $('#np-url', root).value.trim(),
          apiKey: $('#np-key', root).value.trim() || undefined,
          timeoutMs: Number($('#np-timeout', root).value),
          maxTokens: Number($('#np-tokens', root).value),
        }});
        toast('✓', 'success');
        renderAiSettings(m, root);
      } catch (e) { toast(e.message, 'error'); }
    });

    // per-provider actions
    for (const card of $$('.card[data-pid]', root)) {
      const pid = card.dataset.pid;
      const status = (msg, ok) => {
        const el = $('.a-status', card);
        el.textContent = msg;
        el.style.color = ok ? 'var(--success)' : 'var(--destructive)';
      };
      const models = $('.a-model', card);
      const fillModels = (list) => {
        models.innerHTML = list.length
          ? list.map((x) => `<option ${active.model_id === x ? 'selected' : ''}>${esc(x)}</option>`).join('')
          : '<option value="">—</option>';
      };

      $('.a-test', card).addEventListener('click', async (e) => {
        e.target.disabled = true;
        try {
          const r = await api(`/api/ai/${pid}/test-connection`, { method: 'POST' });
          status(r.ok ? `✓ ${r.status || 200} · ${r.modelsFound ?? ''} ${r.note || ''}` : `✗ ${r.error}`, r.ok);
        } catch (ex) { status('✗ ' + ex.message, false); }
        finally { e.target.disabled = false; }
      });

      $('.a-models', card).addEventListener('click', async (e) => {
        e.target.disabled = true;
        try {
          const r = await api(`/api/ai/${pid}/models`);
          if (r.ok) fillModels(r.models);
          else { fillModels(r.cached || []); status((r.error || '') + (r.cached?.length ? ' (cached)' : ''), false); }
        } catch (ex) { status('✗ ' + ex.message, false); }
        finally { e.target.disabled = false; }
      });

      $('.a-rotate', card).addEventListener('click', async () => {
        const v = $('.a-newkey', card).value.trim();
        if (!v) return toast('API key?', 'error');
        try {
          await api(`/api/ai/${pid}/rotate-key`, { method: 'POST', body: { apiKey: v } });
          toast('✓', 'success');
          renderAiSettings(m, root);
        } catch (e) { toast(e.message, 'error'); }
      });

      $('.a-delkey', card).addEventListener('click', async () => {
        try { await api(`/api/ai/${pid}/key`, { method: 'DELETE' }); toast('✓', 'success'); renderAiSettings(m, root); }
        catch (e) { toast(e.message, 'error'); }
      });

      $('.a-activate', card).addEventListener('click', async () => {
        const model = models.value;
        if (!model) return toast('Model?', 'error');
        try { await api('/api/ai/activate', { method: 'POST', body: { providerId: pid, modelId: model } }); toast('✓', 'success'); renderAiSettings(m, root); }
        catch (e) { toast(e.message, 'error'); }
      });

      $('.a-testmodel', card).addEventListener('click', async (e) => {
        e.target.disabled = true;
        try {
          const r = await api(`/api/ai/${pid}/test-model`, { method: 'POST', body: { modelId: models.value } });
          status(r.ok ? `✓ ${r.latencyMs}ms — “${(r.reply || '').slice(0, 120)}”` : `✗ ${r.error}`, r.ok);
        } catch (ex) { status('✗ ' + ex.message, false); }
        finally { e.target.disabled = false; }
      });

      $('.a-del', card).addEventListener('click', async () => {
        if (!confirm('Xóa provider?')) return;
        try { await api('/api/ai/providers/' + pid, { method: 'DELETE' }); renderAiSettings(m, root); }
        catch (e) { toast(e.message, 'error'); }
      });
    }
  };

  paint(data);
}

/* ================= SYSTEM SETTINGS ================= */
export async function renderSystemSettings(m, root) {
  root.innerHTML = `
    <div class="card" style="max-width:860px">
      <h3>${esc(t('sys.limits'))}</h3>
      <form id="lim-form">
        <label class="checkbox"><input type="checkbox" id="l-heavy"> <span>${esc(t('sys.heavy'))}</span></label>
        <label class="checkbox"><input type="checkbox" id="l-avail"> <span>${esc(t('sys.availability'))}</span></label>
        <div class="grid cols-2">
          <div class="field"><label>${esc(t('sys.maxPorts'))}</label><input class="input" id="l-ports" type="number" min="1" max="128"></div>
          <div class="field"><label>${esc(t('sys.maxPaths'))}</label><input class="input" id="l-paths" type="number" min="5" max="60"></div>
          <div class="field"><label>${esc(t('sys.toolTimeout'))}</label><input class="input" id="l-to" type="number" min="10000" max="600000" step="1000"></div>
          <div class="field"><label>${esc(t('sys.scanTimeout'))}</label><input class="input" id="l-st" type="number" min="1" max="180"></div>
        </div>
        <button class="btn primary" type="submit">${esc(t('sys.save'))}</button>
      </form>
      <hr class="divider">
      <h3>${esc(t('sys.externalKeys'))}</h3>
      <div class="grid cols-3">
        <div class="field"><label>${esc(t('sys.gsbKey'))}</label><input class="input" id="k-gsb" type="password" autocomplete="new-password" placeholder="AIza…"></div>
        <div class="field"><label>${esc(t('sys.sucuriKey'))}</label><input class="input" id="k-sucuri" type="password" autocomplete="new-password"></div>
        <div class="field"><label>${esc(t('sys.sucuriDomain'))}</label><input class="input" id="k-sdomain" placeholder="monitorx.sucuri.net"></div>
        <div class="field"><label>VirusTotal API key</label><input class="input" id="k-vt" type="password" autocomplete="new-password"></div>
        <div class="field"><label>urlscan.io API key</label><input class="input" id="k-us" type="password" autocomplete="new-password"></div>
        <div class="field"><label>BuiltWith API key</label><input class="input" id="k-bw" type="password" autocomplete="new-password"></div>
        <div class="field"><label>Wazuh API (base|token)</label><input class="input" id="k-wz" type="password" autocomplete="new-password"></div>
      </div>
      <p class="muted" style="font-size:12.5px">VirusTotal/urlscan: hostname/URL chi gui khi co key + opt-in; khong gui du lieu rieng tu. Wazuh: khuyen dung host giam sat rieng (1GB RAM).</p>
      <button class="btn" id="k-save">${esc(t('sys.saveKeys'))}</button>
      <span class="inline-note" id="k-state" style="margin-left:10px"></span>
    </div>

    <div class="card" style="margin-top:18px;max-width:860px">
      <h3>${esc(t('sys.dbTargets'))}</h3>
      <p class="muted" style="font-size:13px">${esc(t('sys.dbHint'))}</p>
      <div id="dbt-list"></div>
      <details style="margin-top:12px"><summary style="cursor:pointer;font-weight:650;font-size:13.5px">${esc(t('sys.dbAdd'))}</summary>
        <div class="grid cols-2" style="margin-top:12px">
          <div class="field"><label>Name</label><input class="input" id="db-name" placeholder="prod-analytics"></div>
          <div class="field"><label>Type</label><select class="input" id="db-type">
            <option value="postgres">PostgreSQL</option><option value="mysql">MySQL/MariaDB</option>
            <option value="mongodb">MongoDB</option><option value="sqlite">SQLite</option></select></div>
          <div class="field"><label>Host</label><input class="input" id="db-host" placeholder="db.example.com (hoặc path cho sqlite)"></div>
          <div class="field"><label>Port</label><input class="input" id="db-port" type="number" placeholder="5432"></div>
          <div class="field"><label>Username</label><input class="input" id="db-user" autocomplete="off"></div>
          <div class="field"><label>Password</label><input class="input" id="db-pass" type="password" autocomplete="new-password"></div>
        </div>
        <label class="checkbox"><input type="checkbox" id="db-scope"> <span>${esc(t('sys.scopeOk'))}</span></label>
        <button class="btn primary small" id="db-add">${esc(t('common.save'))}</button>
      </details>
    </div>

    <div class="card" style="margin-top:18px;max-width:860px">
      <h3>${esc(t('sys.accounts'))}</h3>
      <p class="muted" style="font-size:13px">${esc(t('sys.accountsHint'))}</p>
      <div id="acc-list"></div>
      <details style="margin-top:12px"><summary style="cursor:pointer;font-weight:650;font-size:13.5px">${esc(t('sys.addAccount'))}</summary>
        <div class="grid cols-2" style="margin-top:12px">
          <div class="field"><label>Label</label><input class="input" id="ac-label" placeholder="user-basic"></div>
          <div class="field"><label>Role</label><input class="input" id="ac-role" placeholder="user / admin"></div>
          <div class="field"><label>Base URL</label><input class="input" id="ac-url" placeholder="https://app.example.com"></div>
          <div class="field"><label>Username</label><input class="input" id="ac-user" autocomplete="off"></div>
          <div class="field"><label>Password</label><input class="input" id="ac-pass" type="password" autocomplete="new-password"></div>
          <div class="field"><label>Extra headers (JSON)</label><input class="input" id="ac-headers" placeholder='{"x-api-key":"…"}'></div>
        </div>
        <button class="btn primary small" id="ac-add">${esc(t('common.save'))}</button>
      </details>
    </div>`;

  /* --- limits --- */
  try {
    const sys = await api('/api/settings/system');
    $('#l-heavy', root).checked = sys.limits.heavyModulesEnabled;
    $('#l-avail', root).checked = sys.limits.availabilityEnabled;
    $('#l-ports', root).value = sys.limits.maxPortCount;
    $('#l-paths', root).value = sys.limits.maxProbePaths;
    $('#l-to', root).value = sys.limits.toolTimeoutMs;
    $('#l-st', root).value = sys.limits.scanTimeoutMin;
    $('#k-state', root).textContent = `GSB: ${sys.externalKeys.gsb ? '✓' : '—'} · Sucuri: ${sys.externalKeys.sucuri ? '✓' : '—'} · ${sys.env.passwordConfigured ? 'pass✓' : 'pass—'} ${sys.env.sessionSecretConfigured ? 'sess✓' : 'sess—'} ${sys.env.encryptionKeyConfigured ? 'enc✓' : 'enc—'}`;
  } catch (e) { toast(e.message, 'error'); }

  $('#lim-form', root).addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api('/api/settings/system', { method: 'PUT', body: {
        heavyModulesEnabled: $('#l-heavy', root).checked,
        availabilityEnabled: $('#l-avail', root).checked,
        maxPortCount: $('#l-ports', root).value,
        maxProbePaths: $('#l-paths', root).value,
        toolTimeoutMs: $('#l-to', root).value,
        scanTimeoutMin: $('#l-st', root).value,
      }});
      toast(t('sys.saved'), 'success');
    } catch (ex) { toast(ex.message, 'error'); }
  });

  $('#k-save', root).addEventListener('click', async () => {
    const body = {};
    if ($('#k-gsb', root).value) body.gsb_api_key = $('#k-gsb', root).value.trim();
    if ($('#k-sucuri', root).value) body.sucuri_api_key = $('#k-sucuri', root).value.trim();
    if ($('#k-vt', root).value) body.virustotal_api_key = $('#k-vt', root).value.trim();
    if ($('#k-us', root).value) body.urlscan_api_key = $('#k-us', root).value.trim();
    if ($('#k-bw', root).value) body.builtwith_api_key = $('#k-bw', root).value.trim();
    if ($('#k-wz', root).value) body.wazuh_api = $('#k-wz', root).value.trim();
    if ($('#k-sdomain', root).value) body.sucuri_monitor_domain = $('#k-sdomain', root).value.trim();
    try {
      await api('/api/tools/external-keys', { method: 'POST', body });
      $('#k-gsb', root).value = ''; $('#k-sucuri', root).value = ''; $('#k-vt', root).value=''; $('#k-us', root).value=''; $('#k-bw', root).value=''; $('#k-wz', root).value='';
      toast('✓', 'success');
    } catch (e) { toast(e.message, 'error'); }
  });

  /* --- db targets --- */
  const loadDb = async () => {
    try {
      const d = await api('/api/db-targets');
      $('#dbt-list', root).innerHTML = d.items.length ? `<div class="table-wrap" style="border:0"><table class="data">
        <thead><tr><th>Name</th><th>Type</th><th>Host:Port</th><th>Creds</th><th></th></tr></thead>
        <tbody>${d.items.map((x) => `<tr><td>${esc(x.name)}</td><td><span class="tag">${esc(x.db_type)}</span></td>
          <td class="mono">${esc(x.host)}:${x.port}</td><td>${x.hasCredentials ? '🔑' : '—'}</td>
          <td><button class="btn ghost small db-del" data-id="${esc(x.id)}">${esc(t('common.delete'))}</button></td></tr>`).join('')}</tbody></table></div>`
        : `<p class="muted">—</p>`;
      $$('.db-del', root).forEach((b) => b.addEventListener('click', async () => {
        await api('/api/db-targets/' + b.dataset.id, { method: 'DELETE' }); loadDb();
      }));
    } catch (e) { toast(e.message, 'error'); }
  };
  $('#db-add', root).addEventListener('click', async () => {
    if (!$('#db-scope', root).checked) return toast(t('scan.scopeError'), 'error');
    try {
      await api('/api/db-targets', { method: 'POST', body: {
        name: $('#db-name', root).value.trim(),
        dbType: $('#db-type', root).value,
        host: $('#db-host', root).value.trim(),
        port: Number($('#db-port', root).value) || undefined,
        username: $('#db-user', root).value.trim() || undefined,
        secret: $('#db-pass', root).value || undefined,
        scopeConfirmed: true,
      }});
      toast('✓', 'success'); $('#db-pass', root).value = ''; loadDb();
    } catch (e) { toast(e.message, 'error'); }
  });
  loadDb();

  /* --- test accounts --- */
  const loadAcc = async () => {
    try {
      const d = await api('/api/test-accounts');
      $('#acc-list', root).innerHTML = d.items.length ? `<div class="table-wrap" style="border:0"><table class="data">
        <thead><tr><th>Label</th><th>Role</th><th>Base URL</th><th>Secret</th><th></th></tr></thead>
        <tbody>${d.items.map((x) => `<tr><td>${esc(x.label)}</td><td><span class="tag">${esc(x.role)}</span></td>
          <td class="mono" style="font-size:12px">${esc(x.base_url)}</td><td>${x.hasSecret ? '🔑' : '—'}</td>
          <td><button class="btn ghost small ac-del" data-id="${esc(x.id)}">${esc(t('common.delete'))}</button></td></tr>`).join('')}</tbody></table></div>`
        : `<p class="muted">—</p>`;
      $$('.ac-del', root).forEach((b) => b.addEventListener('click', async () => {
        await api('/api/test-accounts/' + b.dataset.id, { method: 'DELETE' }); loadAcc();
      }));
    } catch (e) { toast(e.message, 'error'); }
  };
  $('#ac-add', root).addEventListener('click', async () => {
    try {
      await api('/api/test-accounts', { method: 'POST', body: {
        label: $('#ac-label', root).value.trim(),
        role: $('#ac-role', root).value.trim(),
        baseUrl: $('#ac-url', root).value.trim(),
        username: $('#ac-user', root).value.trim() || undefined,
        secret: $('#ac-pass', root).value || undefined,
        headers: $('#ac-headers', root).value || '{}',
      }});
      toast('✓', 'success'); $('#ac-pass', root).value = ''; loadAcc();
    } catch (e) { toast(e.message, 'error'); }
  });
  loadAcc();
}
