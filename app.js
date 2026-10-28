const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const show = (s, on) => { $(s).hidden = !on; };
let me = null, providers = {};

function toast(msg) { const t = $('#toast'); t.textContent = msg; t.hidden = false; setTimeout(() => t.hidden = true, 4000); }

async function api(path, method = 'GET', body) {
  const r = await fetch('/api' + path, { method, headers: { 'X-CSRF': '1', 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined });
  if (r.status === 401) { showLogin(); throw new Error('Signed out'); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : 'Request failed');
  return j;
}

function showLogin() {
  show('#login', true); show('#app', false); show('#top', false);
  if (new URLSearchParams(location.search).get('error') === 'not_invited')
    $('#loginMsg').textContent = "That GitHub account hasn't been added yet. Ask the administrator to add your username.";
}

async function init() {
  try { me = await api('/me'); } catch { return; }
  show('#login', false); show('#app', true); show('#top', true);
  document.body.dataset.mode = me.mode;
  $('#who').textContent = '@' + me.login + ' · ' + me.role;
  show('#modeWrap', me.can_maintain); $('#mode').checked = me.mode === 'maintainer';
  show('#adminCard', me.role === 'admin');
  if (!Object.keys(providers).length) {
    providers = await api('/providers');
    $('#provider').innerHTML = Object.keys(providers).map(p => `<option>${esc(p)}</option>`).join('');
    syncProvider();
  }
  loadKeys(); renderWork(); if (me.role === 'admin') loadUsers();
}

function syncProvider() {
  const p = providers[$('#provider').value]; if (!p) return;
  show('#baseUrl', p.custom); $('#model').placeholder = 'Model (' + p.hint + ')';
}

async function loadKeys() {
  const ks = await api('/keys');
  $('#keys').innerHTML = ks.length ? ks.map(k => `<div class="item row"><span>${esc(k.label)}<br><span class="dim">${esc(k.provider)} · ${esc(k.model || 'default')} · ${esc(k.api_key)}</span></span><button class="ghost" data-del-key="${esc(k.id)}">Delete</button></div>`).join('')
    : '<p class="dim">No keys yet. Add one to let the solver use your model.</p>';
}

async function saveKey() {
  await api('/keys', 'POST', { provider: $('#provider').value, label: $('#label').value || 'My key',
    base_url: $('#baseUrl').value, model: $('#model').value, api_key: $('#apiKey').value });
  $('#apiKey').value = ''; loadKeys(); toast('Key validated and saved');
}

function renderWork() {
  if (me.mode === 'maintainer') {
    $('#work').innerHTML = '<h2>Maintainer mode</h2><div class="row"><select id="repoSel"></select><button id="loadRepoIssues">Unassigned issues</button></div><div id="list"></div>';
    api('/maintainer/repos').then(rs => { $('#repoSel').innerHTML = rs.map(r => `<option>${esc(r.full_name)}</option>`).join(''); }).catch(e => toast(e.message));
  } else {
    $('#work').innerHTML = '<h2>Issues assigned to you</h2><button id="loadIssues">Load issues</button><div id="list"></div>';
  }
}

function renderIssues(items) {
  $('#list').innerHTML = items.length ? items.map(i => {
    const link = i.url.startsWith('https://github.com/') ? i.url : '#';
    return `<div class="item"><a href="${esc(link)}" target="_blank" rel="noopener noreferrer">${esc(i.repo)}#${i.number}</a><br>${esc(i.title)}<br>${i.labels.map(l => `<span class="tag">${esc(l)}</span>`).join('')}</div>`;
  }).join('') : '<p class="dim">Nothing here.</p>';
}

async function loadUsers() {
  const us = await api('/admin/users');
  $('#users').innerHTML = us.map(u => `<div class="item row"><span>@${esc(u.login)}<br><span class="dim">added by ${esc(u.added_by || '-')} · last login ${esc(u.last_login || 'never')}</span></span>
    <select data-role="${u.github_id}">${['contributor','maintainer','admin'].map(r => `<option ${r === u.role ? 'selected' : ''}>${r}</option>`).join('')}</select>
    <button class="ghost" data-del-user="${u.github_id}">Remove</button></div>`).join('');
}

document.addEventListener('click', async e => {
  const b = e.target.closest('button'); if (!b) return;
  try {
    if (b.id === 'logout') { await api('/logout', 'POST'); location.href = '/'; }
    else if (b.id === 'saveKey') await saveKey();
    else if (b.dataset.delKey) { await api('/keys/' + b.dataset.delKey, 'DELETE'); loadKeys(); }
    else if (b.id === 'loadIssues') renderIssues(await api('/issues'));
    else if (b.id === 'loadRepoIssues') renderIssues(await api('/maintainer/issues?repo=' + encodeURIComponent($('#repoSel').value)));
    else if (b.id === 'addUser') { await api('/admin/users', 'POST', { username: $('#newUser').value, role: $('#newRole').value }); $('#newUser').value = ''; loadUsers(); }
    else if (b.dataset.delUser && confirm('Remove this user and delete their keys?')) { await api('/admin/users/' + b.dataset.delUser, 'DELETE'); loadUsers(); }
  } catch (err) { toast(err.message); }
});

document.addEventListener('change', async e => {
  const t = e.target;
  try {
    if (t.id === 'mode') { try { await api('/mode', 'POST', { mode: t.checked ? 'maintainer' : 'contributor' }); } catch (err) { t.checked = false; throw err; } init(); }
    else if (t.dataset.role) { try { await api('/admin/users/' + t.dataset.role, 'PATCH', { role: t.value }); } catch (err) { loadUsers(); throw err; } }
    else if (t.id === 'provider') syncProvider();
  } catch (err) { toast(err.message); }
});

init().then(() => { if (!me) showLogin(); });
