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

async function renderImport() {
  const root = $('#view-root');
  root.innerHTML = `
    <div class="view">
      <h1>Import API Keys</h1>
      <p class="lede">Paste your provider section text below. Headings set the provider; email/key lines become records.</p>
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
        <button class="btn primary" id="import-parse">Parse</button>
        <button class="btn" id="import-clear">Clear</button>
      </div>
      <div id="import-preview" class="hidden">
        <div class="field"><span class="small">Columns are editable. Click a cell to edit email, provider or key.</span></div>
        <div class="table-wrap">
          <table id="import-table">
            <thead><tr><th>Email</th><th>Provider</th><th>API Key</th><th>Status</th><th></th></tr></thead>
            <tbody></tbody>
          </table>
        </div>
        <div id="import-unmatched" class="hidden"></div>
        <div class="btn-row">
          <button class="btn" id="import-select-all">Select all valid</button>
          <select id="import-duplicate-mode">
            <option value="skip">Skip duplicates</option>
            <option value="import">Import duplicates</option>
            <option value="review">Review duplicates</option>
          </select>
          <button class="btn primary" id="import-commit">Import selected</button>
        </div>
        <div id="import-summary" class="hidden"></div>
        <div class="footer" style="justify-content:flex-end;">
          <a class="btn" href="#/keys">Cancel</a>
        </div>
      </div>
    </div>`;

  const textarea = $('#import-text');
  const custom = $('#import-custom');
  const parseBtn = $('#import-parse');
  const clearBtn = $('#import-clear');
  const preview = $('#import-preview');
  const tbody = $('#import-table tbody');
  const unmatched = $('#import-unmatched');
  const summary = $('#import-summary');
  const selectAll = $('#import-select-all');
  const commitBtn = $('#import-commit');
  const dupMode = $('#import-duplicate-mode');
  const cellInputs = new Map();

  let session = null;

  const masked = (k) => (k || '').replace(/\S/g, '•');

  const renderRows = (rows) => {
    tbody.innerHTML = '';
    for (const r of rows) {
      const tr = document.createElement('tr');
      tr.className = 'import-row' + (r.valid ? '' : ' invalid') + (r.duplicate ? ' duplicate' : '');
      tr.dataset.index = r.index;
      const keyCell = r.key ? `<span class="cell key-cell" data-field="key">${escapeHtml(r.key)}</span>` : `<span class="cell key-cell" data-field="key">—</span>`;
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
        refreshSummary();
      })
      .catch((err) => toast(err.message, 'error'));
  };

  const renderUnmatched = (lines) => {
    unmatched.innerHTML = '';
    if (!lines.length) { unmatched.classList.add('hidden'); return; }
    unmatched.classList.remove('hidden');
    unmatched.innerHTML = `<div class="field"><span class="small">Unmatched lines (flagged for review — assign email, key and provider):</span></div><table><tbody>`;
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
            </select>
          </div>
        </td>`;
      unmatched.appendChild(tr);
    }
    api('/api/providers').then((providers) => {
      unmatched.querySelectorAll('select').forEach((sel) => {
        providers.forEach((p) => {
          const opt = document.createElement('option');
          opt.value = p.name;
          opt.textContent = p.name;
          sel.appendChild(opt);
        });
      });
    }).catch(() => {});
  };

  const refreshSummary = () => {
    const rows = tbody.querySelectorAll('tr.import-row');
    let valid = 0;
    rows.forEach((tr) => { if (tr.classList.contains('valid')) valid++; });
    const counts = { imported: 0, skipped: 0, duplicates: 0, attention: 0, providers_created: 0 };
    // Refresh counts from a fresh session state via the server when possible.
    const pending = document.querySelectorAll('tr.import-row.removed');
    summary.textContent = `Preview: ${rows.length} row${rows.length !== 1 ? 's' : ''}${pending.length ? ' (removed rows shown for review)' : ''}, select all then Import selected.`;
    summary.classList.remove('hidden');
    selectAll.textContent = `Select all valid (${valid})`;
  };

  parseBtn.addEventListener('click', () => {
    const text = textarea.value.trim();
    const format = $('#import-format').value;
    const provs = custom.value.split('\n').map((s) => s.trim()).filter(Boolean);
    if (!text) { toast('Paste some text first', 'error'); return; }
    api('/api/import/parse', { method: 'POST', json: { text, format, custom_providers: provs } }, { 'X-CSRF-Token': state.csrf })
      .then((data) => {
        session = data.session_id;
        renderRows(data.rows);
        renderUnmatched(data.unmatched);
        preview.classList.remove('hidden');
        summary.classList.add('hidden');
        tbody.querySelectorAll('tr.import-row.removed').forEach((tr) => tr.classList.remove('removed'));
        cellInputs.clear();
      })
      .catch((err) => toast(err.message, 'error'));
  });

  clearBtn.addEventListener('click', () => {
    textarea.value = '';
    custom.value = '';
    preview.classList.add('hidden');
    tbody.innerHTML = '';
    unmatched.innerHTML = '';
    summary.classList.add('hidden');
    cellInputs.clear();
    session = null;
  });

  selectAll.addEventListener('click', () => {
    const all = tbody.querySelectorAll('tr.import-row:not(.removed)');
    all.forEach((tr) => {
      if (!tr.classList.contains('valid')) tr.style.backgroundColor = '#1a2744';
    });
  });

  commitBtn.addEventListener('click', () => {
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
    api('/api/import/commit', { method: 'POST', json: { session_id: session, records: rows, duplicate_mode: dupMode.value } }, { 'X-CSRF-Token': state.csrf })
      .then((data) => {
        toast(`Imported ${data.imported} · skipped ${data.skipped} · attention ${data.attention} · duplicates ${data.duplicates} · providers created ${data.providers_created}`);
        summary.textContent = `Imported ${data.imported}, skipped ${data.skipped}, attention ${data.attention}, duplicates ${data.duplicates}, providers created ${data.providers_created}.`;
        summary.classList.remove('hidden');
        preview.classList.add('hidden');
      })
      .catch((err) => toast(err.message, 'error'));
  });

}
  async function showView(view) {
  state.view = view;
  const content = $('#view-root');
  content.innerHTML = '';
  if (!state.unlocked) {
    isActive(view);
    showOverlay('Unlock KeyVault', 'Enter your master password to continue.');
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
    await renderImport();
  } else {
    content.innerHTML = `<div class="view">${placeholderView(view)}</div>`;
  }
}

function onHashChange() {
  const view = currentView().replace('/setup', 'setup').replace('/unlock', 'unlock');
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
async function init() {
  if (state.unlocked) { showView('dashboard'); return; }
  try {
    const st = await api('/api/auth/status');
    if (st.setup) {
      showOverlay('Unlock KeyVault', 'Enter your master password to continue.');
    } else {
      showOverlay('Create an account', 'Set a master password to encrypt your key vault.');
    }
  } catch (_) {
    showOverlay('Create an account', 'Set a master password to encrypt your key vault.');
  }
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

