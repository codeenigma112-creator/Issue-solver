const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const show = (s, on) => { $(s).hidden = !on; };
let me = null, providers = {}, myKeys = [], pollTimer = null, lastJob = null;

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
  show('#adminCard', me.role === 'admin'); show('#auditCard', me.role === 'admin');
  if (!Object.keys(providers).length) {
    providers = await api('/providers');
    $('#provider').innerHTML = Object.keys(providers).map(p => `<option>${esc(p)}</option>`).join('');
    syncProvider();
  }
  await loadKeys();
  renderWork();
  if (me.role === 'admin') { loadUsers(); loadAudit(); }
}

function syncProvider() {
  const p = providers[$('#provider').value]; if (!p) return;
  show('#baseUrl', p.custom); $('#model').placeholder = 'Model (' + p.hint + ')';
}

function keyOptions() {
  if (!myKeys.length) return '<option value="">No model keys yet</option>';
  return '<option value="">Select a model key</option>' +
    myKeys.map(k => `<option value="${esc(k.id)}">${esc(k.label)} · ${esc(k.provider)}${k.model ? ' · ' + esc(k.model) : ''}</option>`).join('');
}

async function loadKeys() {
  myKeys = await api('/keys');
  $('#keys').innerHTML = myKeys.length ? myKeys.map(k => `<div class="item row"><span>${esc(k.label)}<br><span class="dim">${esc(k.provider)} · ${esc(k.model || 'default')} · ${esc(k.api_key)}</span></span><button class="ghost" data-del-key="${esc(k.id)}">Delete</button></div>`).join('')
    : '<p class="dim">No keys yet. Add one to let the solver use your model.</p>';
}

async function saveKey() {
  const res = await api('/keys', 'POST', { provider: $('#provider').value, label: $('#label').value || 'My key',
    base_url: $('#baseUrl').value, model: $('#model').value, api_key: $('#apiKey').value });
  $('#apiKey').value = ''; await loadKeys(); renderWork(); toast(res.message || 'Key validated and saved');
}

function renderWork() {
  if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
  const keyRow = `<div class="row"><select id="keySel">${keyOptions()}</select><input id="instructions" placeholder="Optional instructions for the model"></div>`;
  if (me.mode === 'maintainer') {
    $('#work').innerHTML = `<h2>Maintainer mode</h2>${keyRow}<div class="row"><select id="repoSel"></select><button id="loadRepoIssues">Unassigned issues</button></div><div id="list"></div><div id="jobOut"></div>`;
    api('/maintainer/repos').then(rs => { $('#repoSel').innerHTML = rs.map(r => `<option>${esc(r.full_name)}</option>`).join(''); }).catch(e => toast(e.message));
  } else {
    $('#work').innerHTML = `<h2>Issues assigned to you</h2>${keyRow}<button id="loadIssues">Load issues</button><div id="list"></div><div id="jobOut"></div>`;
  }
}

function renderIssues(items) {
  const isM = me.mode === 'maintainer';
  $('#list').innerHTML = items.length ? items.map(i => {
    const link = i.url.startsWith('https://github.com/') ? i.url : '#';
    const actions = isM
      ? `<div class="actions"><button class="small" data-action="triage" data-repo="${esc(i.repo)}" data-num="${esc(i.number)}">Triage labels</button><button class="small ghost" data-action="reply" data-repo="${esc(i.repo)}" data-num="${esc(i.number)}">Draft reply</button></div>`
      : `<div class="actions"><button class="small" data-action="solve" data-repo="${esc(i.repo)}" data-num="${esc(i.number)}">Solve issue</button></div>`;
    return `<div class="item"><a href="${esc(link)}" target="_blank" rel="noopener noreferrer">${esc(i.repo)}#${esc(i.number)}</a><br>${esc(i.title)}<br>${i.labels.map(l => `<span class="tag">${esc(l)}</span>`).join('')}${actions}</div>`;
  }).join('') : '<p class="dim">Nothing here.</p>';
}

async function startJob(kind, repo, number) {
  const keyId = $('#keySel') ? $('#keySel').value : '';
  if (!keyId) { toast('Add and select a model key first'); return; }
  if (!repo || !number) { toast('Load an issue first'); return; }
  const key = myKeys.find(k => k.id === keyId);
  const provider = key ? key.provider : 'your provider';
  if (!confirm(`This sends the issue content to ${provider} using your key. Continue?`)) return;
  lastJob = null;
  $('#jobOut').innerHTML = '<div class="out"><span class="status">Queued…</span></div>';
  const job = await api('/jobs', 'POST', { kind, repo, number: Number(number), key_id: keyId,
    instructions: $('#instructions') ? $('#instructions').value : '', consent: true });
  pollJob(job.id, repo, number);
}

async function pollJob(id, repo, number) {
  let job;
  try { job = await api('/jobs/' + encodeURIComponent(id)); } catch (e) { toast(e.message); return; }
  renderJob(job, repo, number);
  if (job.status === 'queued' || job.status === 'running')
    pollTimer = setTimeout(() => pollJob(id, repo, number), 1500);
}

function renderJob(job, repo, number) {
  const out = $('#jobOut');
  if (job.status === 'queued' || job.status === 'running') {
    out.innerHTML = `<div class="out"><span class="status">${esc(job.status)}…</span><p class="dim">This can take a little while. Keep this page open.</p></div>`;
    return;
  }
  lastJob = job;
  if (job.status === 'error') {
    out.innerHTML = `<div class="out"><span class="status">Failed</span><pre>${esc(job.error || 'Unknown error')}</pre></div>`;
    return;
  }
  if (job.kind === 'triage') {
    let data;
    try { data = JSON.parse(job.result || '{}'); } catch { data = { labels: [], rationale: job.result || '' }; }
    const suggested = Array.isArray(data.labels) ? data.labels : [];
    const boxes = suggested.map(l => `<label class="tag"><input type="checkbox" class="triageLabel" value="${esc(l)}" checked> ${esc(l)}</label>`).join(' ')
      || '<span class="dim">No confident labels suggested.</span>';
    out.innerHTML = `<div class="out"><span class="status">Triage suggestions</span><p class="dim">${esc(data.rationale || '')}</p><div class="actions">${boxes}</div><div class="actions"><button class="small" data-action="apply" data-repo="${esc(repo)}" data-num="${esc(number)}">Apply selected labels</button></div></div>`;
  } else {
    out.innerHTML = `<div class="out"><span class="status">${job.kind === 'reply' ? 'Reply draft' : 'Solution draft'}</span><pre>${esc(job.result || '')}</pre><div class="actions"><button class="small ghost" data-action="copy">Copy</button></div></div>`;
  }
}

async function applyLabels(button) {
  const labels = [...document.querySelectorAll('.triageLabel:checked')].map(x => x.value);
  if (!labels.length) { toast('Select at least one label'); return; }
  const res = await api('/maintainer/labels', 'POST', { repo: button.dataset.repo,
    number: Number(button.dataset.num), labels });
  toast('Applied: ' + (res.labels || []).join(', '));
  button.disabled = true;
}

async function loadUsers() {
  const us = await api('/admin/users');
  $('#users').innerHTML = us.map(u => `<div class="item row"><span>@${esc(u.login)}<br><span class="dim">added by ${esc(u.added_by || '-')} · last login ${esc(u.last_login || 'never')}</span></span>
    <select data-role="${u.github_id}">${['contributor','maintainer','admin'].map(r => `<option ${r === u.role ? 'selected' : ''}>${r}</option>`).join('')}</select>
    <button class="ghost" data-del-user="${u.github_id}">Remove</button></div>`).join('');
}

async function loadAudit() {
  const rows = await api('/admin/audit');
  $('#audit').innerHTML = rows.length ? rows.map(a => `<div class="item"><span class="dim">${esc(a.ts)}</span> <b>${esc(a.action)}</b> ${esc(a.actor_login || '-')}${a.target ? ' → ' + esc(a.target) : ''}<br><span class="dim">${esc(a.detail || '')}</span></div>`).join('')
    : '<p class="dim">No events yet.</p>';
}

document.addEventListener('click', async e => {
  const b = e.target.closest('button'); if (!b) return;
  try {
    if (b.id === 'logout') { await api('/logout', 'POST'); location.href = '/'; }
    else if (b.id === 'saveKey') await saveKey();
    else if (b.dataset.delKey) { await api('/keys/' + b.dataset.delKey, 'DELETE'); await loadKeys(); renderWork(); }
    else if (b.id === 'loadIssues') renderIssues(await api('/issues'));
    else if (b.id === 'loadRepoIssues') {
      if (!$('#repoSel').value) { toast('No repository selected'); return; }
      renderIssues(await api('/maintainer/issues?repo=' + encodeURIComponent($('#repoSel').value)));
    }
    else if (b.id === 'addUser') { await api('/admin/users', 'POST', { username: $('#newUser').value, role: $('#newRole').value }); $('#newUser').value = ''; loadUsers(); loadAudit(); }
    else if (b.dataset.delUser && confirm('Remove this user and delete their keys?')) { await api('/admin/users/' + b.dataset.delUser, 'DELETE'); loadUsers(); loadAudit(); }
    else if (b.dataset.action === 'solve') await startJob('solve', b.dataset.repo, b.dataset.num);
    else if (b.dataset.action === 'triage') await startJob('triage', b.dataset.repo, b.dataset.num);
    else if (b.dataset.action === 'reply') await startJob('reply', b.dataset.repo, b.dataset.num);
    else if (b.dataset.action === 'apply') await applyLabels(b);
    else if (b.dataset.action === 'copy') { await navigator.clipboard.writeText(lastJob ? lastJob.result || '' : ''); toast('Copied'); }
  } catch (err) { toast(err.message); }
});

document.addEventListener('change', async e => {
  const t = e.target;
  try {
    if (t.id === 'mode') { try { await api('/mode', 'POST', { mode: t.checked ? 'maintainer' : 'contributor' }); } catch (err) { t.checked = false; throw err; } init(); }
    else if (t.dataset.role) { try { await api('/admin/users/' + t.dataset.role, 'PATCH', { role: t.value }); loadAudit(); } catch (err) { loadUsers(); throw err; } }
    else if (t.id === 'provider') syncProvider();
  } catch (err) { toast(err.message); }
});

init().then(() => { if (!me) showLogin(); });
