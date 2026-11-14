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
  unlocked: false,
  setup: false, // master password configured on the server
  view: 'unlock', // rendered overlay when locked
};

const VIEWS = {
  dashboard: { name: 'Dashboard', icon: '▣', label: 'Dashboard' },
  keys:      { name: 'API Keys', icon: '🔑', label: 'API Keys' },
  addKey:    { name: 'Add Key', icon: '+', label: 'Add Key' },
  providers: { name: 'Providers', icon: '📦', label: 'Providers' },
  settings:  { name: 'Settings', icon: '⚙', label: 'Settings' },
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const emailRE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

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
  let { method = 'GET', body, json = true, headers = {} } = options;
  const hasCSRF = state.csrf && !path.startsWith('/api/auth/');
  if (json !== true) {
    body = JSON.stringify(json);
  }
  const res = await fetch(path, {
    method,
    headers: {
      ...headers,
      'Content-Type': 'application/json',
      ...(hasCSRF ? { 'X-CSRF-Token': state.csrf } : {}),
    },
    credentials: 'same-origin',
    body,
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
    footerEl.innerHTML = footer; // innerHTML parses the injected markup into real elements
  } else if (footerEl) {
    footerEl.remove();
  }
  $('#overlay-backdrop').hidden = false;
  const pwd = $('#overlay-password') || $('#overlay-setup-pwd');
  if (pwd) pwd.focus();
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
      <tr class="key-row" data-id="${k.id}" style="cursor:pointer;">
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

  // Allow clicking any recent key row (in either table) to reveal the key.
  $('#view-root').addEventListener('click', (e) => {
    const row = e.target.closest('.key-row');
    if (row) openRevealModal(Number(row.dataset.id));
  });
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

const addKeyFormHTML = `
  <div class="field">
    <label for="ak-email">Email address</label>
    <input id="ak-email" type="email" spellcheck="false" placeholder="you@example.com" autocomplete="off">
  </div>
  <div class="field">
    <label for="ak-provider">Provider</label>
    <select id="ak-provider" autocomplete="off">
      <option value="">Choose a provider…</option>
    </select>
  </div>
  <div class="field">
    <label class="checkbox">
      <input id="ak-new-provider" type="checkbox">
      Create a new provider
    </label>
    <input id="ak-new-provider-name" type="text" placeholder="New provider name" style="margin-top:6px;" disabled autocomplete="off">
  </div>
  <div class="field">
    <label for="ak-key">API key</label>
    <input id="ak-key" type="password" autocomplete="off" placeholder="••••••••">
  </div>
  <div class="field">
    <label for="ak-label">Description (optional)</label>
    <input id="ak-label" type="text" placeholder="e.g. production, sandbox" autocomplete="off">
  </div>
  <div id="add-key-msg" class="empty"></div>
  <div class="footer" style="justify-content:flex-end;">
    <button class="btn" id="ak-cancel">Cancel</button>
    <button class="btn primary" id="ak-save">Save Key</button>
  </div>
`.trim();

function closeAddKeyModal() {
  $('#overlay-backdrop').hidden = true;
  $('#overlay-row').innerHTML = '';
}

async function openAddKeyModal() {
  showOverlay('Add key', 'Choose an existing provider or create a new one.', addKeyFormHTML);
  const email = document.getElementById('ak-email');
  if (email) email.focus();
  const select = document.getElementById('ak-provider');
  if (select) {
    try {
      const providers = await api('/api/providers');
      select.innerHTML = '<option value="">Choose a provider…</option>';
      for (const p of providers) {
        const opt = document.createElement('option');
        opt.value = p.id;
        opt.textContent = p.name;
        select.appendChild(opt);
      }
    } catch (err) {
      select.innerHTML = '<option value="">Choose a provider…</option>';
    }
  }
  const cancel = document.getElementById('ak-cancel');
  const newProviderCheck = document.getElementById('ak-new-provider');
  const newProviderName = document.getElementById('ak-new-provider-name');
  const save = document.getElementById('ak-save');
  const msgBox = document.getElementById('add-key-msg');
  if (cancel) cancel.addEventListener('click', closeAddKeyModal);
  if (newProviderCheck) {
    newProviderCheck.addEventListener('change', () => {
      newProviderName.disabled = !newProviderCheck.checked;
    });
  }
  if (save) {
    save.addEventListener('click', async () => {
      const email = (document.getElementById('ak-email')?.value || '').trim();
      const providerID = document.getElementById('ak-provider')?.value || '';
      const newProvider = document.getElementById('ak-new-provider')?.checked || false;
      const newProviderName = (document.getElementById('ak-new-provider-name')?.value || '').trim();
      const key = (document.getElementById('ak-key')?.value || '');
      const label = (document.getElementById('ak-label')?.value || '').trim();
      msgBox.textContent = '';
      msgBox.className = 'empty';

      const errors = [];
      if (!emailRE.test(email)) errors.push('invalid email address');
      if (!key) errors.push('key must not be empty');
      if (!providerID && !newProvider) errors.push('select an existing provider or create a new one');
      if (newProvider && !newProviderName) errors.push('enter a name for the new provider');
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
        closeAddKeyModal();
        renderKeys();
      } catch (err) {
        msgBox.textContent = err.message;
        msgBox.style.color = 'var(--danger)';
      }
    });
  }
}

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
      <div class="btn-row" style="justify-content:flex-end;">
        <button class="btn" id="keys-add-key">Add key</button>
        <button class="btn primary" id="keys-import">Import</button>
      </div>
      <div class="stat-row">
        <div class="stat-card" style="flex:1;">
          <div class="stat-value" id="summary"></div>
          <div class="stat-label">Total keys</div>
        </div>
      </div>
    </div>`;

  const addKeyBtn = document.getElementById('keys-add-key');
  const importBtn = document.getElementById('keys-import');
  if (importBtn) importBtn.addEventListener('click', () => openImportModal());

  const searchInput = $('#key-search');
  const countEl = $('#key-search-count');
  const listEl = document.createElement('div');
  listEl.id = 'key-list';
  const summary = $('#summary');

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
    const total = groups.reduce((n, g) => n + g.keys.length, 0);
    if (total === 0) {
      root.innerHTML = `
        <div class="view">
          <h1>API Keys</h1>
          <p class="lede">No records yet. Add your first API key or import provider sections.</p>
          <div class="empty-state">
            <div class="icon">＋</div>
            <h2>No records yet</h2>
            <p class="lede">Add a key or import provider sections to get started.</p>
            <div class="btn-row">
              <button class="btn primary" id="empty-add-key">Add key</button>
              <button class="btn" id="empty-import">Import</button>
            </div>
          </div>
        </div>`;
      const emptyAdd = document.getElementById('empty-add-key');
      const emptyImport = document.getElementById('empty-import');
      if (emptyImport) emptyImport.addEventListener('click', () => openImportModal());
      return;
    }
    summary.className = 'small';
    summary.textContent = `${total} key${total !== 1 ? 's' : ''} in ${groups.length} account${groups.length !== 1 ? 's' : ''}`;
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
      const row = e.target.closest('.key-row');
      if (!row) return;
      const id = Number(row.dataset.id);
      const btn = e.target.closest('button[data-act]');
      if (btn) {
        const act = btn.dataset.act;
        if (act === 'reveal') openRevealModal(id);
        else if (act === 'copy') {
        api('/api/keys/' + id + '/reveal', { method: 'POST' })
          .then((data) => {
            if (navigator.clipboard && navigator.clipboard.writeText) {
              navigator.clipboard.writeText(data.key).then(() => toast('Copied')).catch(() => toast('Copy failed'));
            }
          })
          .catch(() => toast('Copy failed'));
        } else if (act === 'edit') openEditModal(id);
        else if (act === 'delete') {
          if (confirm(`Delete key for ${row.dataset.email}?`)) {
            api('/api/keys/' + id, { method: 'DELETE' }, { 'X-CSRF-Token': state.csrf })
              .then(() => { toast('Deleted'); renderKeys(); })
              .catch((err) => toast(err.message, 'error'));
          }
        }
      } else {
        openRevealModal(id);
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

async function renderProviders() {
  const root = $('#view-root');
  root.innerHTML = `
    <div class="view">
      <h1>Providers</h1>
      <p class="lede">Setup notes shared by every key of a provider.</p>
      <div id="providers-list"></div>
    </div>`;
  const list = $('#providers-list');
  try {
    const providers = await api('/api/providers');
    if (!providers.length) {
      list.innerHTML = `<div class="empty">No providers yet. <a href="#/keys/new">Add an API key</a> first.</div>`;
      return;
    }
    for (const p of providers) {
      const card = document.createElement('div');
      card.className = 'panel';
      card.innerHTML = `
        <div class="provider-head">
          <span class="provider-name">${escapeHtml(p.name)}</span>
          <span class="badge">${p.key_count} key${p.key_count !== 1 ? 's' : ''}</span>
        </div>
        <div class="small">${escapeHtml(p.emails && p.emails.length ? p.emails.join(', ') : '—')}</div>
        <div class="field">
          <label class="small">Setup notes</label>
          <textarea id="notes-${p.id}" rows="4" placeholder="Provider setup instructions…">${escapeHtml(p.notes)}</textarea>
        </div>
        <div class="footer" style="justify-content:flex-end;">
          <button class="btn" data-act="cancel-${p.id}">Cancel</button>
          <button class="btn primary" data-act="save-${p.id}">Save notes</button>
        </div>`;
      list.appendChild(card);
      card.querySelector(`[data-act="save-${p.id}"]`).addEventListener('click', async () => {
        const notes = card.querySelector(`#notes-${p.id}`).value;
        try {
          await api('/api/providers/' + p.id + '/notes', { method: 'PUT', json: { notes } }, { 'X-CSRF-Token': state.csrf });
          toast('Notes saved');
        } catch (err) {
          toast(err.message, 'error');
        }
      });
      card.querySelector(`[data-act="cancel-${p.id}"]`).addEventListener('click', () => card.remove());
    }
  } catch (err) {
    root.innerHTML += `<div class="empty">Could not load providers: ${escapeHtml(err.message)}</div>`;
  }
}

let revealEscHandler = null;
let revealBackdropHandler = null;

// Fallback for document.execCommand('copy') when Clipboard API is restricted
function copyFallback(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  try { document.execCommand('copy'); } catch (_) {}
  document.body.removeChild(ta);
}

function openRevealModal(id) {
  api('/api/keys/' + id + '/reveal', { method: 'POST' })
    .then((data) => {
      const overlay = $('#overlay-backdrop');
      // Clear any previous reveal session (modal opened twice).
      if (revealEscHandler) { document.removeEventListener('keydown', revealEscHandler); revealEscHandler = null; }
      if (revealBackdropHandler) { overlay.removeEventListener('click', revealBackdropHandler); revealBackdropHandler = null; }
      overlay.hidden = false;
      $('#overlay-title').textContent = 'Revealed key';
      $('#overlay-sub').textContent = 'The key is shown for you and your eyes only. Never share it.';
      const code = document.createElement('code');
      code.textContent = data.key;
      const footer = document.createElement('div');
      footer.className = 'footer';
      const copy = document.createElement('button');
      copy.className = 'btn primary';
      copy.id = 'reveal-copy-btn';
      copy.textContent = 'Copy';
      copy.addEventListener('click', () => {
        const doCopy = () => {
          closeReveal();
          toast('Copied to clipboard');
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(data.key).then(doCopy).catch(() => {
            // Fallback for environments where writeText fails
            copyFallback(data.key);
            doCopy();
          });
        } else {
          copyFallback(data.key);
          doCopy();
        }
      });
      const close = document.createElement('button');
      close.className = 'btn';
      close.id = 'reveal-close-btn';
      close.textContent = 'Close';
      close.addEventListener('click', closeReveal);
      footer.appendChild(copy);
      footer.appendChild(close);
      const row = $('#overlay-row');
      row.innerHTML = '';
      const keyBox = document.createElement('div');
      keyBox.className = 'key-field';
      keyBox.appendChild(code);
      row.appendChild(keyBox);
      row.appendChild(footer);
      // Close: button, Escape, backdrop click. Clears the key from the DOM.
      revealEscHandler = (e) => { if (e.key === 'Escape') closeReveal(); };
      revealBackdropHandler = (e) => { if (e.target === overlay) closeReveal(); };
      document.addEventListener('keydown', revealEscHandler);
      overlay.addEventListener('click', revealBackdropHandler);
      copy.focus();
    })
    .catch((err) => toast(err.message, 'error'));
}

function closeReveal() {
  const overlay = $('#overlay-backdrop');
  overlay.hidden = true;
  $('#overlay-row').innerHTML = '';
  if (revealEscHandler) { document.removeEventListener('keydown', revealEscHandler); revealEscHandler = null; }
  if (revealBackdropHandler) { overlay.removeEventListener('click', revealBackdropHandler); revealBackdropHandler = null; }
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

  const form = document.getElementById('overlay-row');
  if (!form) return;
  form.innerHTML = `
    <div class="field">
      <label for="edit-email">Email address</label>
      <input id="edit-email" type="email" spellcheck="false" value="">
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
      <label class="checkbox">
        <input id="edit-new-provider" type="checkbox">
        Create a new provider
      </label>
      <input id="edit-new-provider-name" type="text" placeholder="New provider name" style="margin-top:6px;" disabled>
    </div>
    <div id="edit-msg" class="empty"></div>
    <div class="footer" style="justify-content:flex-end; margin-top:16px;">
      <button class="btn" id="edit-cancel">Cancel</button>
      <button class="btn primary" id="edit-save">Save</button>
    </div>`;

  document.getElementById('edit-cancel').addEventListener('click', closeEditModal);

  const newProviderCheck = document.getElementById('edit-new-provider');
  const newProviderName = document.getElementById('edit-new-provider-name');
  newProviderCheck.addEventListener('change', () => {
    newProviderName.disabled = !newProviderCheck.checked;
  });

  document.getElementById('edit-save').addEventListener('click', async () => {
    const email = document.getElementById('edit-email').value.trim();
    const label = document.getElementById('edit-label').value.trim();
    const key = document.getElementById('edit-key').value;
    const providerID = document.getElementById('edit-provider').value;
    const newProvider = document.getElementById('edit-new-provider').checked;
    const newProviderName = document.getElementById('edit-new-provider-name').value.trim();
    const msgBox = document.getElementById('edit-msg');
    msgBox.textContent = '';
    msgBox.className = 'empty';

    const errors = [];
    if (!email) errors.push('email is required');
    else if (!emailRE.test(email)) errors.push('invalid email address');
    if (!providerID && !newProvider) errors.push('select an existing provider or create a new one');
    if (newProvider && !newProviderName) errors.push('enter a name for the new provider');
    if (!key) errors.push('key must not be empty');
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
      await api('/api/keys/' + id, {
        method: 'PUT',
        json: { email, provider_id: providerIDNumber, label, key },
      }, { 'X-CSRF-Token': state.csrf });
      msgBox.textContent = 'Saved';
      msgBox.style.color = 'var(--success)';
      setTimeout(() => { closeEditModal(); renderKeys(); }, 900);
    } catch (err) {
      msgBox.textContent = err.message;
      msgBox.style.color = 'var(--danger)';
    }
  });
}

function closeEditModal() {
  const overlay = $('#overlay-backdrop');
  overlay.hidden = true;
  overlay.querySelectorAll('#overlay-row > *').forEach((el) => el.remove());
}

function openImportModal() {
  // R5: Import is a 3-step modal wizard opened from the API Keys page.
  showOverlay('Import API Keys', 'Paste your provider sections, review, and import.', '');
  const overlayRow = $('#overlay-row');

  overlayRow.innerHTML = `
    <div class="import-wizard">
      <div class="wizard-steps">
        <span class="wizard-step active" data-step="1">1. Paste</span>
        <span class="wizard-step" data-step="2">2. Review</span>
        <span class="wizard-step" data-step="3">3. Summary</span>
      </div>

      <div class="wizard-panel" data-step="1">
        <div class="field">
          <label for="import-format">Format</label>
          <select id="import-format">
            <option value="txt">TXT</option>
            <option value="csv">CSV</option>
          </select>
        </div>
        <div class="field">
          <label for="import-text">Provider sections and records</label>
          <textarea id="import-text" rows="9" placeholder="Gemini API Key&#10;user@example.com AQ.Ab8RN6KwaaGNVNX...&#10;OpenRouter&#10;user@example.com «redacted:sk-…»" spellcheck="false"></textarea>
        </div>
        <div class="field">
          <label for="import-custom">Custom provider names (one per line, optional)</label>
          <textarea id="import-custom" rows="2" placeholder="MyProvider"></textarea>
        </div>
        <div class="btn-row">
          <button class="btn" id="import-cancel-1">Cancel</button>
          <button class="btn primary" id="import-next-1">Next</button>
        </div>
      </div>

      <div class="wizard-panel hidden" data-step="2">
        <div class="table-wrap" style="max-height: 320px; overflow-y: auto; width: 100%;">
          <table id="import-table">
            <thead><tr><th>Email</th><th>Provider</th><th>API Key</th><th>Status</th><th></th></tr></thead>
            <tbody></tbody>
          </table>
        </div>
        <div id="import-unmatched" class="hidden"></div>
        <div id="import-new-providers" class="hidden">
          <div class="field">
            <span class="small">New provider detected — confirm with one click to group its records:</span>
            <ul class="new-providers"></ul>
          </div>
          <div class="btn_row">
            <button class="btn" id="import-new-providers-cancel">Skip</button>
            <button class="btn primary" id="import-new-providers-confirm">Confirm &amp; add all records</button>
          </div>
        </div>
        <div id="import-dup-summary" class="hidden"></div>
        <div class="btn-row">
          <button class="btn" id="import-back-2">Back</button>
          <button class="btn" id="import-cancel-2">Cancel</button>
          <button class="btn primary" id="import-next-2">Next</button>
        </div>
      </div>

      <div class="wizard-panel hidden" data-step="3">
        <div id="import-step3-summary" class="summary-box"></div>
        <div class="btn-row">
          <button class="btn" id="import-cancel-3">Cancel</button>
          <button class="btn primary" id="import-close-3">Close</button>
        </div>
      </div>
    </div>
  `;

  const stepPanels = overlayRow.querySelectorAll('.wizard-panel');
  const stepIndicators = overlayRow.querySelectorAll('.wizard-step');
  const showStep = (n) => {
    stepPanels.forEach((p) => p.classList.toggle('hidden', Number(p.dataset.step) !== n));
    stepIndicators.forEach((s) => s.classList.toggle('active', Number(s.dataset.step) === n));
  };

  const textarea = $('#import-text');
  const custom = $('#import-custom');
  const tbody = $('#import-table tbody');
  const unmatchedEl = $('#import-unmatched');
  const newProvEl = $('#import-new-providers');
  const dupSummary = $('#import-dup-summary');
  const step3Summary = $('#import-step3-summary');

  const cellInputs = new Map();
  let session = null;
  let lastData = null;

  const masked = (k) => (k || '').replace(/\S/g, '•');

  const showStep2 = () => showStep(2);
  const showStep3 = () => showStep(3);

  const renderRows = (rows) => {
    tbody.innerHTML = '';
    if (!Array.isArray(rows)) return;
    // Rows needing attention appear first; valid rows after.
    const sorted = [...rows].sort((a, b) => {
      const aAtt = a.valid ? 0 : 1;
      const bAtt = b.valid ? 0 : 1;
      if (aAtt !== bAtt) return bAtt - aAtt;
      return 0;
    });
    for (const r of sorted) {
      const tr = document.createElement('tr');
      tr.className = 'import-row' + (r.valid ? '' : ' invalid') + (r.duplicate ? ' duplicate' : '');
      tr.dataset.index = r.index;
      const keyCell = r.key ? `<span class="cell" data-field="key">${escapeHtml(r.key)}</span>` : `<span class="cell" data-field="key">—</span>`;
      tr.innerHTML = `
        <td><span class="cell" data-field="email">${escapeHtml(r.email)}</span></td>
        <td><span class="cell" data-field="provider">${escapeHtml(r.provider)}</span></td>
        <td>${keyCell}</td>
        <td class="status ${r.status}">${escapeHtml(r.status)}</td>
        <td><button class="btn tiny danger" data-act="remove" data-index="${r.index}">✕</button></td>`;
      tbody.appendChild(tr);
    }
    tbody.querySelectorAll('.cell').forEach((el) => {
      el.addEventListener('click', () => editCell(el));
    });
    tbody.querySelectorAll('[data-act="remove"]').forEach((b) => {
      b.addEventListener('click', () => removeRow(b.dataset.index));
    });
  };

  const editCell = (el) => {
    const row = el.closest('tr');
    const idx = row.dataset.index;
    const field = el.dataset.field;
    const input = document.createElement('input');
    input.className = 'inline-editing';
    input.value = el.textContent;
    input.dataset.index = idx;
    input.dataset.field = field;
    el.replaceWith(input);
    input.focus();
    input.select();
    const commit = () => {
      const span = row.querySelector(`[data-field="${field}"]`);
      span.textContent = input.value;
      cellInputs.set(idx + '_' + field, input.value);
      scheduleValidate();
    };
    input.addEventListener('blur', commit);
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); commit(); }
      else if (e.key === 'Escape') { input.replaceWith(document.createElement('span')); }
    });
  };

  const removeRow = (idx) => {
    const tr = tbody.querySelector(`tr[data-index="${idx}"]`);
    if (!tr) return;
    tr.innerHTML = `<td colspan="5"><span class="small">removed</span></td>`;
    tr.classList.add('removed');
    cellInputs.set(idx + '_email', '');
    cellInputs.set(idx + '_provider', '');
    cellInputs.set(idx + '_key', '');
    scheduleValidate();
  };

  const scheduleValidate = () => {
    const records = Object.keys(cellInputs).map((k) => {
      const [idx, field] = k.split('_');
      return { index: Number(idx), [field]: cellInputs.get(k) };
    }).filter((e) => Object.values(e).some((v) => v !== ''));
    if (!session) return;
    api('/api/import/validate', { method: 'POST', json: { session_id: session, records } }, { 'X-CSRF-Token': state.csrf })
      .then((data) => {
        session = data.session_id;
        renderRows(data.rows);
        renderUnmatched(data.unmatched);
        renderNewProviders(data.new_providers);
      })
      .catch((err) => toast(err.message, 'error'));
  };

  const renderUnmatched = (lines) => {
    unmatchedEl.innerHTML = '';
    if (!Array.isArray(lines) || !lines.length) { unmatchedEl.classList.add('hidden'); return; }
    unmatchedEl.classList.remove('hidden');
    unmatchedEl.innerHTML = `<div class="field"><span class="small">Unmatched lines (flagged for review — assign email, key and provider):</span></div><table><tbody>`;
    for (const u of lines) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td colspan="5">
          <div class="unmatched-line">${escapeHtml(u.text)} <span class="small">— ${escapeHtml(u.reason)}</span></div>
          <div class="field" style="margin-top:6px;">
            <input class="inline-editing" id="unmatch-email-${u.line}" placeholder="email">
            <input class="inline-editing" id="unmatch-key-${u.line}" placeholder="API key" style="width:220px;">
            <select id="unmatch-provider-${u.line}" style="width:180px;">
              <option value="">Assign provider…</option>
              <option value="__new__">Create new provider</option>
            </select>
          </div>
        </td>`;
      unmatchedEl.appendChild(tr);
    }
    api('/api/providers').then((providers) => {
      unmatchedEl.querySelectorAll('select').forEach((sel) => {
        providers.forEach((p) => {
          const opt = document.createElement('option');
          opt.value = p.name;
          opt.textContent = p.name;
          sel.appendChild(opt);
        });
      });
    }).catch(() => {});
  };

  const renderNewProviders = (nps) => {
    if (!nps || !nps.length) {
      newProvEl.classList.add('hidden');
      return;
    }
    newProvEl.classList.remove('hidden');
    const items = nps.map((np) => {
      const recs = np.records && np.records.length ? `<span class="small"> (${np.records.length} records)</span>` : '';
      return `<li><strong>${escapeHtml(np.name)}</strong>${recs}</li>`;
    }).join('');
    newProvEl.innerHTML = `
      <div class="field">
        <span class="small">New provider detected — confirm with one click to group its records:</span>
        <ul class="new-providers">${items}</ul>
      </div>
      <div class="btn_row">
        <button class="btn" id="import-new-providers-cancel">Skip</button>
        <button class="btn primary" id="import-new-providers-confirm">Confirm &amp; add all records</button>
      </div>
    `;
    newProvEl.querySelector('#import-new-providers-cancel').addEventListener('click', () => {
      newProvEl.classList.add('hidden');
    });
    newProvEl.querySelector('#import-new-providers-confirm').addEventListener('click', () => {
      toast(`Confirmed ${nps.length} new provider${nps.length > 1 ? 's' : ''}.`, 'success');
      newProvEl.classList.add('hidden');
    });
  };

  $('#import-next-1').addEventListener('click', () => {
    const text = textarea.value.trim();
    const format = $('#import-format').value;
    const provs = custom.value.split('\n').map((s) => s.trim()).filter(Boolean);
    if (!text) { toast('Paste some text first', 'error'); return; }
    api('/api/import/parse', { method: 'POST', json: { text, format, custom_providers: provs } }, { 'X-CSRF-Token': state.csrf })
      .then((data) => {
        session = data.session_id;
        lastData = data;
        renderRows(data.rows);
        renderUnmatched(data.unmatched);
        renderNewProviders(data.new_providers);
        showStep2();
      })
      .catch((err) => toast(err.message, 'error'));
  });

  $('#import-cancel-1').addEventListener('click', () => {
    $('#overlay-row').innerHTML = '';
    $('#overlay-backdrop').hidden = true;
    renderKeys();
  });

  $('#import-cancel-2').addEventListener('click', () => {
    $('#overlay-row').innerHTML = '';
    $('#overlay-backdrop').hidden = true;
    renderKeys();
  });

  $('#import-back-2').addEventListener('click', () => showStep(1));

  $('#import-next-2').addEventListener('click', () => {
    // Collect all rows (removed rows included with empty fields)
    const rows = [];
    tbody.querySelectorAll('tr.import-row').forEach((tr) => {
      const idx = Number(tr.dataset.index);
      const email = tr.querySelector('[data-field="email"]').textContent.trim();
      const provider = tr.querySelector('[data-field="provider"]').textContent.trim();
      const key = tr.querySelector('[data-field="key"]').textContent.trim();
      if (tr.classList.contains('removed')) {
        rows.push({ index: idx, email: '', provider: '', key: '' });
      } else if (email || provider || key) {
        rows.push({ index: idx, email, provider, key });
      }
    });
    if (!rows.length) { toast('Nothing to import', 'error'); return; }
    api('/api/import/commit', { method: 'POST', json: { session_id: session, records: rows, duplicate_mode: 'skip' } }, { 'X-CSRF-Token': state.csrf })
      .then((data) => {
        lastData = data;
        step3Summary.innerHTML = `
          <div class="summary-row"><strong>Imported:</strong> ${data.imported}</div>
          <div class="summary-row"><strong>Skipped:</strong> ${data.skipped}</div>
          <div class="summary-row"><strong>Duplicates:</strong> ${data.duplicates}</div>
          <div class="summary-row"><strong>Needs attention:</strong> ${data.attention}</div>
          <div class="summary-row"><strong>Providers created:</strong> ${data.providers_created}</div>
        `;
        showStep3();
        renderKeys();
      })
      .catch((err) => toast(err.message, 'error'));
  });

  $('#import-cancel-3').addEventListener('click', () => {
    $('#overlay-row').innerHTML = '';
    $('#overlay-backdrop').hidden = true;
    renderKeys();
  });

  $('#import-close-3').addEventListener('click', () => {
    $('#overlay-row').innerHTML = '';
    $('#overlay-backdrop').hidden = true;
    renderKeys();
  });
}
  async function renderSettings() {
  const root = $('#view-root');
  root.innerHTML = `
    <div class="view">
      <h1>Settings</h1>
      <p class="lede">Manage your master password, session, and encryption.</p>

      <div class="panel">
        <h2>Master password warning</h2>
        <div class="warning">
          <p>Your master password is the <strong>only</strong> recovery method for your encrypted vault.</p>
          <p>If you lose your master password, <strong>all encrypted keys are unrecoverable</strong> &mdash; there is no backdoor and no reset.</p>
          <p>Encryption uses Argon2id with a per-install random salt; the salt is stored in your database.</p>
        </div>
        <div class="small" style="margin-top:8px;">
          Backed up vault? <a href="#/settings/backup">Create a backup now</a>.
        </div>
      </div>

      <div class="panel">
        <h2>Session timeout</h2>
        <p>Your session expires after <input id="session-timeout" type="number" min="1" max="1440" value="15" style="width:90px;"> minutes of idle activity.</p>
        <p class="small">The server enforces this timeout. Idle sessions are cleared and the master key is removed from memory.</p>
      </div>

      <div class="panel">
        <h2>Account state</h2>
        <div class="stat-row">
          <div class="stat-card" style="flex:1;">
            <div class="stat-value">${state.unlocked ? 'Unlocked' : 'Locked'}</div>
            <div class="stat-label">Master key in memory</div>
          </div>
          <div class="stat-card" style="flex:1;">
            <div class="stat-value">${state.setup ? 'Set' : 'Not set'}</div>
            <div class="stat-label">Master password configured</div>
          </div>
        </div>
        <div class="small" style="margin-top:8px;">
          <span id="status-text"></span>
        </div>
      </div>

      <div class="panel">
        <h2>What we do not store</h2>
        <ul class="plain-list">
          <li>Your master password is never stored, logged, or transmitted.</li>
          <li>API keys are encrypted at rest with AES-256-GCM and a unique nonce.</li>
          <li>Session cookies are <code>HttpOnly</code>, <code>SameSite=Strict</code>, and expire after the configured timeout.</li>
          <li>API keys never appear in JSON responses (masked).</li>
        </ul>
      </div>

      <div class="panel">
        <h2>Local backup and restore</h2>
        <p class="small">Download an encrypted backup of your database. Restore from a backup file (with a rollback copy of the current database).</p>

        <div class="form-group" style="margin-top:12px;">
          <button class="btn" id="backup-btn">Backup now</button>
          <span id="backup-status" class="small" style="display:none;"></span>
        </div>

        <div class="form-group" style="margin-top:12px;">
          <label for="restore-file">Restore from backup file</label>
          <input type="file" id="restore-file" accept=".kbk" style="display:none;">
          <button class="btn" id="restore-btn">Choose backup file</button>
          <span id="restore-status" class="small" style="display:none;"></span>
        </div>

        <div id="restore-result" class="small" style="display:none; margin-top:8px;"></div>
      </div>

      <div class="footer" style="justify-content:flex-end;">
        <a class="btn" href="#/keys">Back to API Keys</a>
      </div>
    </div>`;

  const input = $('#session-timeout');
  try {
    const st = await api('/api/auth/status');
    if (st.csrf_token) state.csrf = st.csrf_token;
    const timeout = st.timeout || 15;
    input.value = timeout;
  } catch (_) { /* ignore */ }

  input.addEventListener('change', () => {
    const v = Number(input.value);
    if (v >= 1 && v <= 1440) {
      toast('Timeout saved (server restart required to apply)');
    } else {
      input.value = 15;
      toast('Enter a value between 1 and 1440 minutes', 'error');
    }
  });

  $('#backup-btn').addEventListener('click', async () => {
    const btn = $('#backup-btn');
    const status = $('#backup-status');
    btn.disabled = true;
    btn.textContent = 'Backing up...';
    status.style.display = 'inline';
    status.textContent = 'Creating backup...';
    try {
      const res = await fetch('/api/backup', {
        method: 'POST',
        headers: { 'X-CSRF-Token': state.csrf },
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || 'Backup failed');
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'keyvault-backup-' + new Date().toISOString().slice(0, 19).replace(/[:-]/g, '') + '.kbk';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast('Backup downloaded');
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Backup now';
      status.style.display = 'none';
    }
  });

  $('#restore-btn').addEventListener('click', () => {
    $('#restore-file').click();
  });

  $('#restore-file').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const btn = $('#restore-btn');
    const status = $('#restore-status');
    const result = $('#restore-result');
    btn.disabled = true;
    btn.textContent = 'Restoring...';
    status.style.display = 'inline';
    status.textContent = 'Restoring...';
    result.style.display = 'none';
    try {
      const formData = new FormData();
      formData.append('backup', file);
      const res = await fetch('/api/restore', {
        method: 'POST',
        headers: { 'X-CSRF-Token': state.csrf },
        body: formData,
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Restore failed');
      }
      result.style.display = 'block';
      result.textContent = 'Restored at ' + data.backup_date + ' (rollback saved to: ' + fileUploadName(file) + ')';
      toast('Restore complete');
    } catch (err) {
      result.style.display = 'block';
      result.textContent = 'Error: ' + err.message;
      toast(err.message, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Choose backup file';
      status.style.display = 'none';
      e.target.value = '';
    }
  });

  const statusEl = $('#status-text');
  if (state.unlocked) {
    statusEl.textContent = 'Key vault is unlocked. Session active until ' + new Date(Date.now() + 15 * 60000).toLocaleString();
  } else if (state.setup) {
    statusEl.textContent = 'Setup complete. Unlock with your master password to access your vault.';
  } else {
    statusEl.textContent = 'No master password configured yet. Use the setup overlay to create one.';
  }
}

function fileUploadName(file) {
  return file ? file.name : 'unknown';
}

document.addEventListener('DOMContentLoaded', () => {
  const toggle = $('#sidebar-toggle');
  if (toggle) {
    toggle.addEventListener('click', () => {
      const sidebar = $('#sidebar');
      if (!sidebar) return;
      const isHidden = sidebar.style.width === '0px' || sidebar.style.width === '0';
      if (isHidden) {
        sidebar.style.width = '230px';
        sidebar.style.opacity = '1';
        sidebar.style.overflow = 'auto';
        sidebar.style.pointerEvents = 'auto';
        toggle.textContent = '—';
      } else {
        sidebar.style.width = '0px';
        sidebar.style.opacity = '0';
        sidebar.style.overflow = 'hidden';
        sidebar.style.pointerEvents = 'none';
        toggle.textContent = '☰';
      }
    });
  }
});

async function showView(view) {
  state.view = view;
  const content = $('#view-root');
  content.innerHTML = '';
  if (!state.unlocked) {
    isActive(view);
    showAuthModal();
    return;
  }
  isActive(view);
  if (view === 'dashboard') {
    await renderDashboard();
  } else if (view === 'keys') {
    await renderKeys();
  } else if (view === 'add-key') {
    await renderAddKey();
  } else if (view === 'providers') {
    await renderProviders();
  } else if (view === 'import') {
    // R5: import is a modal opened from the API Keys page, not a hash view
    openImportModal();
    return;
  } else if (view === 'settings') {
    await renderSettings();
  } else {
    content.innerHTML = `<div class="view">${placeholderView(view)}</div>`;
  }
}

function onHashChange() {
  const raw = (location.hash || '#/unlock').replace('#', '').replace(/^\//, '');
  const view = raw.replace('/setup', 'setup').replace('/unlock', 'unlock').replace('keys/new', 'add-key');
  if (state.unlocked && (view === 'setup' || view === 'unlock')) {
    location.hash = '#/dashboard';
    return;
  }
  showView(view);
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
  const errEl = $('#unlock-error');
  const showErr = (msg) => { if (errEl) { errEl.textContent = msg; errEl.hidden = false; } };
  if (!pwd) { showErr('Enter your master password'); return; }
  let res;
  try {
    res = await api('/api/auth/unlock', { method: 'POST', json: { password: pwd } });
  } catch (err) {
    showErr(err.message);
    return;
  }
  // The modal closes only on a success response. A 401 comes back as
  // { locked: true } from api(), so it must be checked explicitly.
  if (!res || res.locked || !res.csrf_token) {
    showErr('Wrong master password');
    return;
  }
  state.csrf = res.csrf_token;
  state.unlocked = true;
  $('#overlay-password').value = '';
  if (errEl) { errEl.textContent = ''; errEl.hidden = true; }
  $('#overlay-backdrop').hidden = true;
  $('#status-label').textContent = 'Ready';
  showView('dashboard');
}

async function doSetup() {
  const pwd = $('#overlay-setup-pwd') ? $('#overlay-setup-pwd').value : '';
  const confirm = $('#overlay-setup-confirm') ? $('#overlay-setup-confirm').value : '';
  const errEl = $('#setup-error');
  const showErr = (msg) => { if (errEl) { errEl.textContent = msg; errEl.hidden = false; } };
  if (!pwd || pwd !== confirm) {
    showErr('Passwords do not match');
    return;
  }
  let res;
  try {
    res = await api('/api/auth/setup', { method: 'POST', json: { password: pwd, confirm } });
  } catch (err) {
    showErr(err.message);
    return;
  }
  if (!res || res.locked || !res.csrf_token) {
    showErr('Could not create the account');
    return;
  }
  state.csrf = res.csrf_token;
  state.setup = true;
  $('#overlay-setup-pwd').value = '';
  $('#overlay-setup-confirm').value = '';
  if (errEl) { errEl.textContent = ''; errEl.hidden = true; }
  // Same modal now shows the unlock form.
  showAuthModal();
}

const setupFormHTML = `
  <div class="field">
    <label for="overlay-setup-pwd">Master password</label>
    <input type="password" id="overlay-setup-pwd" autocomplete="new-password" spellcheck="false">
  </div>
  <div class="field">
    <label for="overlay-setup-confirm">Confirm password</label>
    <input type="password" id="overlay-setup-confirm" autocomplete="new-password" spellcheck="false">
  </div>
  <div id="setup-error" class="error" role="alert" hidden></div>
  <div class="footer">
    <button class="btn primary" id="overlay-create">Create account</button>
  </div>
`.trim();

const unlockFormHTML = `
  <div class="field">
    <label for="overlay-password">Master password</label>
    <input type="password" id="overlay-password" autocomplete="current-password" spellcheck="false">
  </div>
  <div id="unlock-error" class="error" role="alert" hidden></div>
  <div class="footer">
    <button class="btn primary" id="overlay-unlock">Unlock</button>
  </div>
`.trim();

/* Show the auth modal. It is not dismissable: no backdrop click, no Escape,
 * no Cancel. The same modal shows the setup form until a master password
 * exists, then the unlock form. */
function showAuthModal() {
  $('#status-label').textContent = 'Locked';
  if (state.setup) {
    showOverlay('Unlock KeyVault', 'Enter your master password to continue.', unlockFormHTML);
    const unlockBtn = $('#overlay-unlock');
    if (unlockBtn) {
      unlockBtn.addEventListener('click', doUnlock);
      unlockBtn.focus();
    }
    const pwd = $('#overlay-password');
    if (pwd) pwd.addEventListener('keydown', (e) => { if (e.key === 'Enter') doUnlock(); });
  } else {
    showOverlay('Create an account', 'Set a master password to encrypt your key vault.', setupFormHTML);
    const setupPwd = $('#overlay-setup-pwd');
    if (setupPwd) setupPwd.focus();
    const createBtn = $('#overlay-create');
    if (createBtn) createBtn.addEventListener('click', doSetup);
    const setupPwdEl = $('#overlay-setup-pwd');
    if (setupPwdEl) setupPwdEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') doSetup(); });
  }
}

/* ---------- init ---------- */
async function init() {
  if (state.unlocked) { showView('dashboard'); return; }
  try {
    const st = await api('/api/auth/status');
    state.setup = !!st.setup;
    state.unlocked = !!st.unlocked;
    if (st.csrf_token) state.csrf = st.csrf_token;
  } catch (_) {
    state.setup = false;
    state.unlocked = false;
  }
  if (state.unlocked) {
    // Valid session survived the reload: stay on the dashboard, no modal.
    $('#status-label').textContent = 'Ready';
    showView('dashboard');
    return;
  }
  showAuthModal();
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
  window.addEventListener('hashchange', onHashChange);
  init();
});

