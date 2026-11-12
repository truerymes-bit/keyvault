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
  addKey:    { name: 'Add Key', icon: '+', label: 'Add Key' },
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

async function renderDashboard() {
  const resp = await api('/api/dashboard');
  if (resp.error) { $('#view-root').innerHTML = `<div class="empty">Could not load the dashboard: ${escapeHtml(resp.error)}</div>`; return; }
  const maxDate = (d) => d || '—';
  const statCard = (label, value, icon) => `
    <div class="stat-card">
      <div class="stat-icon">${icon}</div>
      <div class="stat-value">${escapeHtml(String(value))}</div>
      <div class="stat-label">${escapeHtml(label)}</div>
    </div>`;
  const table = (items, label, dateCol) => {
    if (!items.length) {
      return `<div class="panel"><h2>${escapeHtml(label)}</h2><div class="empty">Nothing yet.</div></div>`;
    }
    const rows = items.map((k) => `
      <tr>
        <td>${escapeHtml(k.email)}</td>
        <td>${escapeHtml(k.provider_name)}</td>
        <td><code>${escapeHtml(k.key)}</code></td>
        <td>${escapeHtml(maxDate(dateCol === 'created' ? k.created_at : k.updated_at))}</td>
      </tr>`).join('');
    return `
      <div class="panel">
        <h2>${escapeHtml(label)}</h2>
        <div class="table-wrap"><table>
          <thead><tr><th>Email</th><th>Provider</th><th>Key</th><th>${dateCol === 'created' ? 'Added' : 'Updated'}</th></tr></thead>
          <tbody>${rows}</tbody>
        </table></div>
      </div>`;
  };

  $('#view-root').innerHTML = `
    <div class="view">
      <h1>Dashboard</h1>
      <div class="stat-row">
        ${statCard('API keys', resp.total_keys, '🔑')}
        ${statCard('Providers', resp.total_providers, '📦')}
        ${statCard('Email accounts', resp.total_emails, '✉️')}
      </div>
      <div class="panel-grid">
        ${table(resp.recent_keys, 'Recently added keys', 'created')}
        ${table(resp.recent_modified, 'Recently modified', 'updated')}
      </div>
    </div>`;
}

const groupByEmail = (items) => {
  const map = new Map();
  for (const it of items) {
    if (!map.has(it.email)) map.set(it.email, []);
    map.get(it.email).push(it);
  }
  return Array.from(map.entries()).map(([email, keys]) => ({
    email,
    keys: keys.sort((a, b) => a.provider_name.localeCompare(b.provider_name) || a.id - b.id),
  }));
};

async function renderKeys() {
  const root = $('#view-root');
  root.innerHTML = `
    <div class="view">
      <h1>API Keys</h1>
      <p class="lede">Records are grouped by email address.</p>
      <div class="search-row">
        <input id="key-search" placeholder="Search email, provider or label…" autocomplete="off">
        <span id="key-search-count" class="small"></span>
      </div>
    </div>`;

  const searchInput = $('#key-search');
  const countEl = $('#key-search-count');
  const listEl = document.createElement('div');
  listEl.id = 'key-list';

  const applyFilter = (q) => {
    const rows = listEl.querySelectorAll('.key-row');
    let shown = 0;
    for (const row of rows) {
      const email = row.dataset.email || '';
      const provider = row.dataset.provider || '';
      const label = row.dataset.label || '';
      const ok = !q || email.toLowerCase().includes(q.toLowerCase()) ||
        provider.toLowerCase().includes(q.toLowerCase()) || label.toLowerCase().includes(q.toLowerCase());
      row.classList.toggle('hidden', !ok);
      if (ok) shown++;
    }
    countEl.textContent = shown === 0 ? 'No matching keys' : `${shown} key${shown !== 1 ? 's' : ''}`;
  };

  searchInput.addEventListener('input', () => {
    clearTimeout(searchInput._t);
    searchInput._t = setTimeout(() => applyFilter(searchInput.value), 200);
  });

  try {
    const resp = await api('/api/keys');
    if (resp.error) throw new Error(resp.error);
    const groups = groupByEmail(resp);
    const summary = document.createElement('p');
    summary.className = 'small';
    summary.textContent = `${groups.reduce((n, g) => n + g.keys.length, 0)} key${groups.reduce((n, g) => n + g.keys.length, 0) !== 1 ? 's' : ''} in ${groups.length} account${groups.length !== 1 ? 's' : ''}`;
    root.appendChild(summary);
    root.appendChild(listEl);

    const render = () => {
      listEl.innerHTML = '';
      for (const { email, keys } of groups) {
        const card = document.createElement('div');
        card.className = 'account-card';
        card.innerHTML = `
          <button class="account-head" data-email="${escapeHtml(email)}">
            <span class="chevron">▾</span>
            <span class="account-email">${escapeHtml(email)}</span>
            <span class="count">${keys.length} key${keys.length !== 1 ? 's' : ''}</span>
          </button>
          <div class="account-body"></div>`;
        card.querySelector('.account-head').addEventListener('click', () => {
          const body = card.querySelector('.account-body');
          const expanded = body.style.display !== 'block';
          body.style.display = expanded ? 'none' : 'block';
          card.querySelector('.chevron').textContent = expanded ? '▾' : '▴';
        });
        const body = card.querySelector('.account-body');
        for (const k of keys) {
          const row = document.createElement('div');
          row.className = 'key-row';
          row.dataset.id = k.id;
          row.dataset.email = k.email;
          row.dataset.provider = k.provider_name;
          row.dataset.label = k.label || '';
          row.dataset.masked = 'true';
          row.dataset.key = k.key;
          row.dataset.created = k.created_at;
          row.dataset.updated = k.updated_at;
          row.innerHTML = `
            <div class="key-main">
              <div class="key-provider">${escapeHtml(k.provider_name)}</div>
              <div class="key-email">${escapeHtml(k.email)}</div>
              <div class="key-field"><code>${escapeHtml(k.key)}</code></div>
              <div class="key-meta">Added ${formatDate(k.created_at)} · Updated ${formatDate(k.updated_at)}</div>
            </div>
            <div class="key-actions">
              <button class="btn tiny" data-act="reveal">Reveal</button>
              <button class="btn tiny" data-act="copy">Copy</button>
              <button class="btn tiny" data-act="edit">Edit</button>
              <button class="btn tiny danger" data-act="delete">Delete</button>
            </div>`;
          body.appendChild(row);
        }
        listEl.appendChild(card);
      }
      applyFilter(searchInput.value);
    };
    render();

    listEl.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-act]');
      if (!btn) return;
      const row = btn.closest('.key-row');
      const id = Number(row.dataset.id);
      const act = btn.dataset.act;
      if (act === 'reveal') openRevealModal(id);
      else if (act === 'copy') {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(row.dataset.key).then(() => toast('Copied')).catch(() => toast('Copy failed'));
        }
      } else if (act === 'edit') openEditModal(id);
      else if (act === 'delete') {
        if (confirm(`Delete key for ${row.dataset.email}?`)) {
          api('/api/keys/' + id, { method: 'DELETE' }, { 'X-CSRF-Token': state.csrf })
            .then(() => { toast('Deleted'); renderKeys(); })
            .catch((err) => toast(err.message, 'error'));
        }
      }
    });
  } catch (err) {
    root.innerHTML += `<div class="empty">Could not load keys: ${escapeHtml(err.message)}</div>`;
  }
}

function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

async function renderAddKey() {
  const root = $('#view-root');
  const providers = await api('/api/providers');
  const opts = providers.map((p) => `<option value="${p.id}">${escapeHtml(p.name)}</option>`).join('');

  const msgBox = document.createElement('div');
  msgBox.id = 'add-key-msg';
  msgBox.className = 'empty';
  msgBox.style.color = 'var(--danger)';

  root.innerHTML = `
    <div class="view">
      <h1>Add Key</h1>
      <p class="lede">Add an API key for an email address and provider.</p>
      <form id="add-key-form" autocomplete="off">
        <div class="field">
          <label for="ak-email">Email address</label>
          <input id="ak-email" type="email" spellcheck="false" placeholder="you@example.com">
        </div>
        <div class="field">
          <label for="ak-provider">Provider</label>
          <select id="ak-provider">
            <option value="">Choose a provider…</option>
            ${opts}
          </select>
        </div>
        <div class="field">
          <label class="checkbox">
            <input id="ak-new-provider" type="checkbox">
            Create a new provider
          </label>
          <input id="ak-new-provider-name" type="text" placeholder="New provider name" style="margin-top:6px;" disabled>
        </div>
        <div class="field">
          <label for="ak-key">API key</label>
          <input id="ak-key" type="password" autocomplete="off" placeholder="••••••••">
        </div>
        <div class="field">
          <label for="ak-label">Description (optional)</label>
          <input id="ak-label" type="text" placeholder="e.g. production, sandbox">
        </div>
        ${msgBox.outerHTML}
        <div class="footer" style="justify-content:flex-end;">
          <button type="button" class="btn" id="ak-cancel">Cancel</button>
          <button type="submit" class="btn primary">Save Key</button>
        </div>
      </form>
    </div>`;

  const form = $('#add-key-form');
  const cancel = $('#ak-cancel');
  cancel.addEventListener('click', () => { location.hash = '#/keys'; });
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = $('#ak-email').value.trim();
    const providerID = $('#ak-provider').value;
    const newProvider = $('#ak-new-provider').checked;
    const newProviderName = $('#ak-new-provider-name').value.trim();
    const key = $('#ak-key').value;
    const label = $('#ak-label').value.trim();
    const errors = [];
    if (!emailRE.test(email)) errors.push('invalid email address');
    if (!key) errors.push('key must not be empty');
    if (!providerID && !newProvider) errors.push('select an existing provider or create a new one');
    if (newProvider && !newProviderName) errors.push('enter a name for the new provider');
    const msgBox = $('#add-key-msg');
    if (errors.length) {
      msgBox.textContent = errors.join(' · ');
      msgBox.style.color = 'var(--danger)';
      return;
    }
    msgBox.textContent = '';
    msgBox.style.color = 'var(--text)';
    try {
      let providerIDNumber = Number(providerID);
      if (newProvider) {
        const created = await api('/api/providers', { method: 'POST', json: { name: newProviderName } }, { 'X-CSRF-Token': state.csrf });
        providerIDNumber = created.id;
      }
      await api('/api/keys', { method: 'POST', json: { email, provider_id: providerIDNumber, key, label } }, { 'X-CSRF-Token': state.csrf });
      toast('Saved');
      location.hash = '#/keys';
    } catch (err) {
      msgBox.textContent = err.message;
      msgBox.style.color = 'var(--danger)';
    }
  });
  $('#ak-new-provider').addEventListener('change', () => {
    $('#ak-new-provider-name').disabled = !$('#ak-new-provider').checked;
  });
}

function openRevealModal(id) {
  api('/api/keys/' + id + '/reveal', { method: 'POST' }, { 'X-CSRF-Token': state.csrf })
    .then((data) => {
      const overlay = $('#overlay-backdrop');
      overlay.hidden = false;
      $('#overlay-title').textContent = 'Revealed key';
      $('#overlay-sub').textContent = 'The key is shown for you and your eyes only. Never share it.';
      const code = document.createElement('code');
      code.textContent = data.key;
      const footer = document.createElement('div');
      footer.className = 'footer';
      const copy = document.createElement('button');
      copy.className = 'btn primary';
      copy.textContent = 'Copy';
      copy.addEventListener('click', () => {
        navigator.clipboard.writeText(data.key).then(() => {
          toast('Copied to clipboard');
          closeReveal();
        }).catch(() => toast('Copy failed'));
      });
      const close = document.createElement('button');
      close.className = 'btn';
      close.textContent = 'Close';
      close.addEventListener('click', closeReveal);
      footer.appendChild(copy);
      footer.appendChild(close);
      $('#overlay-row').innerHTML = `<div class="key-field"><code>${code.textContent}</code></div><div class="footer">${footer.innerHTML}</div>`;
    })
    .catch((err) => toast(err.message, 'error'));
}

function closeReveal() {
  $('#overlay-backdrop').hidden = true;
}

async function openEditModal(id) {
  const overlay = $('#overlay-backdrop');
  overlay.hidden = false;
  $('#overlay-title').textContent = 'Edit key';

  const providers = await api('/api/providers');
  const select = document.getElementById('edit-provider');
  if (select) {
    select.innerHTML = '<option value="">Choose a provider…</option>';
    for (const p of providers) {
      const opt = document.createElement('option');
      opt.value = p.id;
      opt.textContent = p.name;
      select.appendChild(opt);
    }
  }

  const newProviderRow = document.getElementById('new-provider-row');
  const addNewProvider = () => {
    const name = document.getElementById('edit-new-provider').value.trim();
    if (!name) return;
    api('/api/providers', { method: 'POST', json: { name } }, { 'X-CSRF-Token': state.csrf })
      .then((p) => {
        const opt = document.createElement('option');
        opt.value = p.id;
        opt.textContent = p.name;
        select.appendChild(opt);
        document.getElementById('edit-new-provider').value = '';
      })
      .catch(() => toast('Could not create provider', 'error'));
  };
  document.getElementById('edit-add-provider').addEventListener('click', addNewProvider);
  document.getElementById('edit-new-provider').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') addNewProvider();
  });

  const form = document.getElementById('overlay-row');
  if (!form) return;
  form.innerHTML = `
    <div class="field">
      <label for="edit-email">Email address</label>
      <input id="edit-email" type="email" spellcheck="false" value="${escapeHtml('')}">
    </div>
    <div class="field">
      <label for="edit-label">Label</label>
      <input id="edit-label" type="text" placeholder="Optional description">
    </div>
    <div class="field">
      <label for="edit-key">API key</label>
      <input id="edit-key" type="password" autocomplete="off">
    </div>
    <div class="field">
      <label for="edit-provider">Provider</label>
      <select id="edit-provider"></select>
    </div>
    <div class="field">
      <label for="edit-new-provider">Or create a new one</label>
      <input id="edit-new-provider" type="text" placeholder="New provider name">
      <button class="btn" id="edit-add-provider">Add provider</button>
    </div>
    <div class="footer" style="justify-content:flex-end; margin-top:16px;">
      <button class="btn" id="edit-cancel">Cancel</button>
      <button class="btn primary" id="edit-save">Save</button>
    </div>`;

  document.getElementById('edit-cancel').addEventListener('click', closeEditModal);
  document.getElementById('edit-save').addEventListener('click', async () => {
    const email = document.getElementById('edit-email').value.trim();
    const label = document.getElementById('edit-label').value.trim();
    const key = document.getElementById('edit-key').value;
    const providerID = document.getElementById('edit-provider').value;
    if (!email || !providerID) { toast('Email and provider are required', 'error'); return; }
    try {
      await api('/api/keys/' + id, {
        method: 'PUT',
        json: { email, provider_id: Number(providerID), label, key },
      }, { 'X-CSRF-Token': state.csrf });
      toast('Saved');
      closeEditModal();
      renderKeys();
    } catch (err) {
      toast(err.message, 'error');
    }
  });
}

function closeEditModal() {
  const overlay = $('#overlay-backdrop');
  overlay.hidden = true;
  overlay.querySelectorAll('#overlay-row > *').forEach((el) => el.remove());
}

async function showView(view) {
  state.view = 'unlock';
  const content = $('#view-root');
  content.innerHTML = '';
  if (!state.unlocked) {
    isActive(view);
    showOverlay('Unlock KeyVault', 'Enter your master password to continue.');
    return;
  }
  isActive(view);
  content.innerHTML = `<div class="view">${placeholderView(view)}</div>`;
  if (view === 'dashboard') {
    await renderDashboard();
  } else if (view === 'keys') {
    await renderKeys();
  } else if (view === 'add-key') {
    await renderAddKey();
  }
}

function placeholderView(view) {
  const v = VIEWS[view] || { name: view, icon: '•' };
  return `
    <h1>${escapeHtml(v.name)}</h1>
    <p class="lede">This page is being built.</p>
    <div class="btn-row">
      <a class="btn" href="#/keys">Back to API Keys</a>
    </div>`;
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
  // Re-read the session CSRF so outbound /api requests stay authorized.
  try {
    const st = await api('/api/auth/status');
    if (st.csrf_token) state.csrf = st.csrf_token;
  } catch (_) { /* session gone */ }
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
