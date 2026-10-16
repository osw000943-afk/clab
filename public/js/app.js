import { api, setCsrf, openStream } from './api.js';
import { t, setLang, lang, applyStatic, onLangChange } from './i18n.js';
import { renderDashboard } from './views/dashboard.js';
import { renderScanNew, renderScanList, renderScanDetail } from './views/scans.js';
import { renderFindings } from './views/findings.js';
import { renderTools } from './views/tools.js';
import { renderAiSettings, renderSystemSettings } from './views/settings.js';
import { renderHealth } from './views/health.js';

/* ---------- tiny helpers ---------- */
export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export function esc(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export function fmtDate(ts) {
  if (!ts) return t('common.none');
  return new Date(ts).toLocaleString(lang() === 'vi' ? 'vi-VN' : 'en-GB', {
    day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

export function fmtDur(ms) {
  if (!ms && ms !== 0) return t('common.none');
  const s = Math.round(ms / 1000);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  return m + 'm ' + (s % 60) + 's';
}

export function toast(msg, type = '') {
  const root = $('#toast-root');
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.setAttribute('role', 'status');
  el.innerHTML = `<span>${esc(msg)}</span>`;
  root.appendChild(el);
  setTimeout(() => { el.classList.add('leaving'); setTimeout(() => el.remove(), 320); }, 3800);
}

export function modal({ title, body, actions = [] }) {
  const root = $('#modal-root');
  root.innerHTML = `<div class="modal-back" role="dialog" aria-modal="true" aria-label="${esc(title)}">
    <div class="modal"><h3>${esc(title)}</h3><div class="modal-body">${body}</div>
    <div class="modal-actions">${actions.map((a, i) => `<button class="btn ${a.class || ''}" data-act="${i}">${esc(a.label)}</button>`).join('')}</div></div></div>`;
  const close = () => { root.innerHTML = ''; };
  root.querySelector('.modal-back').addEventListener('click', (e) => { if (e.target.classList.contains('modal-back')) close(); });
  actions.forEach((a, i) => root.querySelector(`[data-act="${i}"]`)?.addEventListener('click', async () => {
    const keep = await a.onClick?.(root);
    if (!keep) close();
  }));
  return { close };
}

export function confirmDialog(message, onYes) {
  modal({
    title: t('common.confirm'),
    body: `<p>${esc(message)}</p>`,
    actions: [
      { label: t('common.cancel'), class: 'ghost' },
      { label: t('common.confirm'), class: 'danger', onClick: onYes },
    ],
  });
}

export function sevBadge(sev) {
  return `<span class="badge ${esc(sev)}"><i style="width:7px;height:7px;border-radius:2px;background:currentColor;display:inline-block"></i>${esc(sev)}</span>`;
}
export function statusBadge(st) {
  return `<span class="badge ${esc(st)}">${esc(st)}</span>`;
}
export function emptyState(msg, hint) {
  return `<div class="empty"><div class="ico">◇</div><p><b>${esc(msg)}</b></p>${hint ? `<p>${esc(hint)}</p>` : ''}</div>`;
}
export { t };

/* ---------- auth / shell ---------- */
const loginView = $('#login-view');
const appView = $('#app-view');
let workerStream = null;

async function boot() {
  applyStatic();
  let st;
  try {
    st = await api('/api/auth/status');
  } catch (e) {
    $('#login-error').textContent = t('common.error') + e.message;
    $('#login-error').classList.remove('hidden');
    return showLogin();
  }
  if (!st.passwordConfigured) {
    showLogin();
    $('#login-unconfigured').classList.remove('hidden');
    $('#login-form').classList.add('hidden');
    return;
  }
  if (st.loggedIn) {
    setCsrf(st.csrfToken);
    showApp();
  } else {
    showLogin();
    if (st.sessionExpired || localStorage.getItem('clab_had_session') === '1') {
      $('#login-error').textContent = t('common.sessionExpired');
      $('#login-error').classList.remove('hidden');
    }
  }
}

function showLogin() {
  appView.classList.add('hidden');
  loginView.classList.remove('hidden');
}

function showApp() {
  localStorage.setItem('clab_had_session', '1');
  loginView.classList.add('hidden');
  appView.classList.remove('hidden');
  startWorkerStream();
  route();
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('#login-btn');
  const err = $('#login-error');
  btn.disabled = true;
  err.classList.add('hidden');
  try {
    const r = await api('/api/auth/login', {
      method: 'POST',
      body: { username: $('#login-user').value.trim(), password: $('#login-pass').value },
    });
    setCsrf(r.csrfToken);
    $('#login-pass').value = '';
    showApp();
  } catch (ex) {
    err.textContent = ex.status === 429 ? t('login.locked')
      : ex.status === 503 ? t('login.unconfigured')
      : ex.status === 401 ? t('login.failed')
      : (t('common.error') + (ex.message || ex.code || ex.status));
    err.classList.remove('hidden');
  } finally {
    btn.disabled = false;
  }
});

$('#logout-btn').addEventListener('click', async () => {
  try { await api('/api/auth/logout', { method: 'POST' }); } catch { /* ignore */ }
  workerStream?.close();
  localStorage.removeItem('clab_had_session');
  location.hash = '';
  location.reload();
});

window.addEventListener('clab:unauthorized', () => {
  if (!appView.classList.contains('hidden')) {
    toast(t('common.sessionExpired'), 'error');
    setTimeout(() => { showLogin(); }, 900);
  }
});

for (const btn of $$('.lang-btn')) {
  btn.addEventListener('click', () => { setLang(btn.dataset.lang); });
}
onLangChange(() => {
  applyStatic();
  route(); // re-render current view in the new language
});

$('#menu-btn').addEventListener('click', () => {
  const sb = $('#sidebar');
  const open = sb.classList.toggle('open');
  $('#menu-btn').setAttribute('aria-expanded', open ? 'true' : 'false');
});

function startWorkerStream() {
  workerStream?.close();
  workerStream = openStream('/api/events/worker/stream', {
    worker: (s) => {
      const dot = $('#worker-dot');
      dot.classList.toggle('busy', !!s.running || s.queued > 0);
      dot.querySelector('span').textContent = s.running ? t('worker.busy') : t('worker.idle');
    },
  });
}

/* ---------- router ---------- */
const routes = [
  { pattern: /^#?\/?$/, view: renderDashboard, nav: 'dashboard', title: () => t('dash.title') },
  { pattern: /^#\/dashboard$/, view: renderDashboard, nav: 'dashboard', title: () => t('dash.title') },
  { pattern: /^#\/scans\/new$/, view: renderScanNew, nav: 'scans/new', title: () => t('scan.new.title') },
  { pattern: /^#\/scans$/, view: renderScanList, nav: 'scans', title: () => t('history.title') },
  { pattern: /^#\/scans\/([^/]+)$/, view: (m, root) => renderScanDetail(m[1], root), nav: 'scans', title: () => t('detail.title') },
  { pattern: /^#\/findings$/, view: renderFindings, nav: 'findings', title: () => t('findings.title') },
  { pattern: /^#\/tools$/, view: renderTools, nav: 'tools', title: () => t('tools.title') },
  { pattern: /^#\/settings\/ai$/, view: renderAiSettings, nav: 'settings/ai', title: () => t('ai.title') },
  { pattern: /^#\/settings\/system$/, view: renderSystemSettings, nav: 'settings/system', title: () => t('sys.title') },
  { pattern: /^#\/health$/, view: renderHealth, nav: 'health', title: () => t('health.title') },
];

export let cleanupCurrent = null;

async function route() {
  const hash = location.hash || '#/dashboard';
  const content = $('#content');
  if (typeof cleanupCurrent === 'function') {
    try { cleanupCurrent(); } catch { /* ignore */ }
    cleanupCurrent = null;
  }
  for (const r of routes) {
    const m = hash.match(r.pattern);
    if (m) {
      $$('[data-nav]').forEach((a) => a.classList.toggle('active', a.dataset.nav === r.nav));
      $('#page-title').textContent = r.title();
      $('#sidebar').classList.remove('open');
      content.innerHTML = '';
      try {
        const cleanup = await r.view(m, content);
        if (typeof cleanup === 'function') cleanupCurrent = cleanup;
      } catch (e) {
        content.innerHTML = `<div class="empty"><div class="ico">⚠</div><p>${esc(t('common.error') + e.message)}</p>
          <p><a href="#/dashboard">${esc(t('nav.dashboard'))}</a></p></div>`;
      }
      return;
    }
  }
  location.hash = '#/dashboard';
}

window.addEventListener('hashchange', route);
onLangChange(() => { $('#page-title') && route(); });

boot();
