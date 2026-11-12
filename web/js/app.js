/* KeyVault frontend entry point. Built out in T5.1.
 *
 * Security note: escapeHtml is applied to every value interpolated into
 * innerHTML (user-provided strings included), so innerHTML here is not an
 * XSS sink. Plain text is set via textContent elsewhere.
 */
'use strict';

const state = {
  csrf: '',
  user: null,
  view: 'unlock', // rendered overlay when locked
};

const VIEWS = {
  dashboard: { name: 'Dashboard', icon: '▣', label: 'Dashboard' },
  keys:      { name: 'API Keys', icon: '🔑', label: 'API Keys' },
  providers: { name: 'Providers', icon: '📦', label: 'Providers' },
  import:    { name: 'Import', icon: '📥', label: 'Import' },
  settings:  { name: 'Settings', icon: '⚙', label: 'Settings' },
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));
}

function toast(message, kind) {
  const el = $('#toast');
  el.textContent = message;
  el.className = 'show' + (kind ? ' ' + kind : '');
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.className = ''; }, 3200);
}

async function api(path, options = {}) {
  const { method = 'GET', body, json = true, headers = {} } = options;
  const hasCSRF = state.csrf && !path.startsWith('/api/auth/');
  if (hasCSRF) headers.set('X-CSRF-Token', state.csrf);
  const res = await fetch(path, {
    method,
    headers: {
      ...headers,
      'Content-Type': 'application/json',
      ...(hasCSRF ? { 'X-CSRF-Token': state.csrf } : {}),
    },
    credentials: 'same-origin',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) return { locked: true, status: res.status };
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try {
      const data = await res.json();
      if (data.error) msg = data.error;
    } catch (_) { /* keep default */ }
    throw new Error(msg);
  }
  return json ? res.json() : null;
}

/* ---------- overlay scaffolding ---------- */
function setOverlayTitle(title) { $('#overlay-title').textContent = title; }
function setOverlaySub(text) { $('#overlay-sub').textContent = text; }

function showOverlay(title, sub, footer) {
  setOverlayTitle(title);
  setOverlaySub(sub);
  const prev = $('#overlay-on');
  if (prev) prev.remove();
  const footerEl = $('#overlay-row');
  if (footer !== undefined && footer !== null && footerEl) {
    footerEl.replaceWith(footer);
  } else if (footerEl) {
    footerEl.remove();
  }
  $('#overlay-backdrop').hidden = false;
  $('#overlay-password').focus();
}

function hideOverlay() {
  $('#overlay-backdrop').hidden = true;
  $('#overlay-password').value = '';
}

/* ---------- view router ---------- */
function currentView() {
  return (location.hash || '#/unlock').replace('#', '');
}

function isActive(view) {
  $$('nav a[data-view]').forEach((el) => el.classList.toggle('active', el.dataset.view === view));
}

function placeholderView(view) {
  const v = VIEWS[view] || { name: view, icon: '•' };
  const root = $('#view-root');
  root.innerHTML = `
    <div class="view">
      <h1>${escapeHtml(v.name)}</h1>
      <p class="lede">This page is being built.</p>
      <div class="btn-row">
        <a class="btn" href="#/keys">Back to API Keys</a>
      </div>
    </div>`;
}

function showView(view) {
  state.view = 'unlock';
  const content = $('#view-root');
  content.innerHTML = '';
  if (state.unlocked) {
    const v = VIEWS[view] || { name: view, icon: '•' };
    content.innerHTML = `
      <div class="view">
        <h1>${escapeHtml(v.name)}</h1>
        <p class="lede">This page is being built.</p>
        <div class="btn-row">
          <a class="btn" href="#/keys">Back to API Keys</a>
        </div>
      </div>`;
    isActive(view);
    return;
  }
  isActive(view);
  showOverlay('Unlock KeyVault', 'Enter your master password to continue.');
}

function onHashChange() {
  const view = currentView().replace('/setup', 'setup').replace('/unlock', 'unlock');
  if (state.unlocked && (view === 'setup' || view === 'unlock')) {
    location.hash = '#/dashboard';
    return;
  }
  showView(view);
}

/* ---------- lock / setup ---------- */
async function doUnlock() {
  const pwd = $('#overlay-password').value;
  if (!pwd) { toast('Enter your master password', 'error'); return; }
  try {
    await api('/api/auth/unlock', { method: 'POST', json: { password: pwd } });
  } catch (err) {
    return toast(err.message, 'error');
  }
  state.unlocked = true;
  state.csrf = '';
  $('#overlay-password').value = '';
  $('#overlay-backdrop').hidden = true;
  $('#status-label').textContent = 'Ready';
  showView('dashboard');
  toast('Welcome back');
}

async function doSetup() {
  const pwd = $('#overlay-setup-pwd') ? $('#overlay-setup-pwd').value : '';
  const confirm = $('#overlay-setup-confirm') ? $('#overlay-setup-confirm').value : '';
  if (!pwd || pwd !== confirm) { toast('Passwords do not match', 'error'); return; }
  try {
    const res = await api('/api/auth/setup', {
      method: 'POST',
      json: { password: pwd, confirm: confirm },
    });
    state.csrf = res.csrf_token || '';
  } catch (err) {
    return toast(err.message, 'error');
  }
  state.unlocked = true;
  hideOverlay();
  $('#status-label').textContent = 'Ready';
  showView('dashboard');
  toast('Account created. Unlock with your master password next time.');
}

/* ---------- init ---------- */
function init() {
  if (state.unlocked) { showView('dashboard'); return; }
  showOverlay('Create an account', 'Set a master password to encrypt your key vault.');
}

document.addEventListener('DOMContentLoaded', () => {
  $$('nav a[data-view]').forEach((a) => {
    a.addEventListener('click', (e) => {
      e.preventDefault();
      if (state.unlocked || a.dataset.view !== 'dashboard' && a.dataset.view !== 'keys') {
        location.hash = a.getAttribute('href');
      } else {
        location.hash = '#/unlock';
      }
    });
  });
  $('#overlay-unlock').addEventListener('click', doUnlock);
  $('#overlay-cancel').addEventListener('click', hideOverlay);
  $('#overlay-backdrop').addEventListener('click', (e) => {
    if (e.target.id === 'overlay-backdrop') hideOverlay();
  });
  $('#overlay-password').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doUnlock();
  });
  window.addEventListener('hashchange', onHashChange);
  init();
});
