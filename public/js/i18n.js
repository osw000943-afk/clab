import vi from '../locales/vi.js';
import en from '../locales/en.js';

const DICTS = { vi, en };
let current = localStorage.getItem('clab_lang') || 'vi'; // default: Tiếng Việt
const listeners = new Set();

export function t(key, vars) {
  let s = (DICTS[current] && DICTS[current][key]) || DICTS.vi[key] || key;
  if (vars) for (const [k, v] of Object.entries(vars)) s = s.replace('{' + k + '}', v);
  return s;
}

export function lang() { return current; }

export function setLang(l) {
  if (!DICTS[l]) return;
  current = l;
  localStorage.setItem('clab_lang', l); // preference only — no personal data
  document.documentElement.lang = l;
  for (const fn of listeners) fn(l);
}

export function onLangChange(fn) { listeners.add(fn); }

/** Apply translations to all [data-i18n] nodes. */
export function applyStatic() {
  for (const el of document.querySelectorAll('[data-i18n]')) {
    el.textContent = t(el.dataset.i18n);
  }
  for (const btn of document.querySelectorAll('.lang-btn')) {
    btn.classList.toggle('active', btn.dataset.lang === current);
    btn.setAttribute('aria-pressed', btn.dataset.lang === current ? 'true' : 'false');
  }
}
