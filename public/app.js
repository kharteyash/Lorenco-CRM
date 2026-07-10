// LeadNest — realtor CRM single-page app. Hash routing between sections; all data
// is fetched from /api/realtor/* and scoped server-side to the signed-in account.
(function () {
  'use strict';

  // ---------- tiny helpers ----------
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const escA = (s) => esc(s).replace(/"/g, '&quot;');
  const initials = (n) => (n || '?').trim().split(/\s+/).map(s => s[0]).slice(0, 2).join('').toUpperCase() || '?';
  const icons = () => { if (window.lucide) lucide.createIcons(); };
  function api(url, opts) {
    return fetch(url, Object.assign({ credentials: 'same-origin', headers: { 'Content-Type': 'application/json' } }, opts || {}))
      .then(async r => {
        let data = null; try { data = await r.json(); } catch (e) {}
        if (!r.ok) throw new Error((data && data.error) || ('Request failed (' + r.status + ')'));
        return data;
      });
  }
  let toastTimer;
  function toast(msg, icon) {
    const t = $('toast');
    t.innerHTML = `<i data-lucide="${icon || 'check-circle-2'}"></i><span>${esc(msg)}</span>`;
    t.classList.remove('hidden'); icons();
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.add('hidden'), 2600);
  }
  function normPhone(p) {
    const raw = String(p || '').trim(); const had = raw.startsWith('+'); const d = raw.replace(/\D/g, '');
    if (!d) return ''; if (had) return '+' + d; if (d.length === 10) return '+1' + d; if (d.length === 11 && d[0] === '1') return '+' + d; return '+' + d;
  }
  const telLink = (p) => { const n = normPhone(p); return n ? 'tel:' + n : ''; };
  const smsLink = (p) => { const n = normPhone(p); return n ? 'sms:' + n : ''; };
  const mailLink = (e) => e ? 'mailto:' + e : '';
  function fmtDate(s) {
    if (!s) return '';
    const d = new Date(/^\d{4}-\d{2}-\d{2}$/.test(s) ? s + 'T00:00:00' : s);
    if (isNaN(d)) return esc(s);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  }
  function fmtWhen(s) {
    const d = new Date(s); if (isNaN(d)) return '';
    const diff = (Date.now() - d.getTime()) / 1000;
    if (diff < 60) return 'just now';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }
  const priBadge = (p) => p === 'High' ? 'red' : p === 'Low' ? 'gray' : 'amber';

  const SECTIONS = [
    { id: 'home',     label: 'Home',         icon: 'layout-dashboard' },
    { id: 'leads',    label: 'Leads',        icon: 'user-plus' },
    { id: 'clients',  label: 'Past Clients', icon: 'user-check' },
    { id: 'contacts', label: 'Contacts',     icon: 'contact' },
    { id: 'calls',    label: 'Calls',        icon: 'phone' },
    { id: 'tasks',    label: 'Follow-ups',   icon: 'list-checks' },
    { id: 'settings', label: 'Settings',     icon: 'settings' }
  ];

  const TIMELINES = ['ASAP', '1-3 months', '3-6 months', '6+ months', 'Just browsing'];
  const INTENTS = ['Buying', 'Selling', 'Both'];
  const FINANCING = ['Pre-approved', 'Needs a lender', 'Paying cash', 'Not sure'];
  const CREDIT = ['741+', '681-740', '621-680', '581-620', '<580'];
  const DEALS = ['Bought', 'Sold', 'Both'];

  let me = null;
  let active = 'home';
  let dueBadge = 0;

  // ---------- Auth screen ----------
  let authMode = 'login';
  function showAuth() {
    $('app-screen').classList.add('hidden');
    $('auth-screen').classList.remove('hidden');
    renderAuthMode(); icons();
  }
  function renderAuthMode() {
    const signup = authMode === 'signup';
    $('auth-title').textContent = signup ? 'Create your account' : 'Welcome back';
    $('auth-sub').textContent = signup ? 'Start managing your leads in minutes.' : 'Sign in to your realtor workspace.';
    $('auth-name-wrap').classList.toggle('hidden', !signup);
    $('auth-submit').textContent = signup ? 'Create account' : 'Sign in';
    $('auth-switch-text').textContent = signup ? 'Already have an account?' : 'New here?';
    $('auth-switch').textContent = signup ? 'Sign in' : 'Create an account';
    $('auth-pass').setAttribute('autocomplete', signup ? 'new-password' : 'current-password');
    $('auth-msg').textContent = '';
  }
  $('auth-switch').addEventListener('click', (e) => { e.preventDefault(); authMode = authMode === 'login' ? 'signup' : 'login'; renderAuthMode(); });
  async function submitAuth() {
    const msg = $('auth-msg'); msg.textContent = '';
    const email = $('auth-email').value.trim();
    const password = $('auth-pass').value;
    const name = $('auth-name').value.trim();
    const btn = $('auth-submit'); btn.disabled = true;
    try {
      if (authMode === 'signup') {
        await api('/api/register', { method: 'POST', body: JSON.stringify({ email, name, password }) });
      } else {
        await api('/api/login', { method: 'POST', body: JSON.stringify({ email, password }) });
      }
      await boot();
    } catch (err) {
      msg.textContent = err.message;
    } finally { btn.disabled = false; }
  }
  $('auth-submit').addEventListener('click', submitAuth);
  ['auth-email', 'auth-pass', 'auth-name'].forEach(id => $(id).addEventListener('keydown', e => { if (e.key === 'Enter') submitAuth(); }));

  // ---------- Shell / nav ----------
  function renderShell() {
    $('nav').innerHTML = SECTIONS.map(s => {
      const badge = (s.id === 'tasks' && dueBadge > 0) ? `<span class="nav-badge">${dueBadge > 9 ? '9+' : dueBadge}</span>` : '';
      return `<a class="nav-item ${active === s.id ? 'active' : ''}" data-nav="${s.id}" href="#${s.id}"><i data-lucide="${s.icon}"></i><span>${s.label}</span>${badge}</a>`;
    }).join('');
    $('nav-user').innerHTML = `<div class="avatar sm">${initials(me.name)}</div>
      <div class="min-w-0"><div class="text-[12.5px] font-semibold truncate">${esc(me.name)}</div>
      <div class="text-[11px] text-muted truncate">${esc(me.email)}</div></div>`;
    icons();
    $('nav').querySelectorAll('[data-nav]').forEach(a => a.addEventListener('click', () => closeSidebar()));
  }
  function closeSidebar() { document.querySelector('.sidebar').classList.remove('open'); $('sidebar-scrim').classList.add('hidden'); }
  $('menu-btn').addEventListener('click', () => { document.querySelector('.sidebar').classList.add('open'); $('sidebar-scrim').classList.remove('hidden'); });
  $('sidebar-scrim').addEventListener('click', closeSidebar);
  $('logout-btn').addEventListener('click', async () => { await api('/api/logout', { method: 'POST' }).catch(() => {}); location.hash = ''; me = null; showAuth(); });

  window.addEventListener('hashchange', route);
  function route() {
    const id = (location.hash || '#home').slice(1);
    active = SECTIONS.find(s => s.id === id) ? id : 'home';
    $('topbar-title').textContent = (SECTIONS.find(s => s.id === active) || {}).label || '';
    renderShell();
    render();
  }

  function render() {
    const v = $('view');
    v.innerHTML = `<div class="empty"><i data-lucide="loader"></i></div>`; icons();
    const fn = { home: renderHome, leads: renderLeads, clients: renderClients, contacts: renderContacts, calls: renderCalls, tasks: renderTasks, settings: renderSettings }[active];
    (fn || renderHome)();
  }

  function pageHead(title, sub, actionsHtml) {
    return `<div class="flex items-start justify-between gap-3 mb-5 flex-wrap">
      <div><h1 class="text-[22px] font-bold tracking-tight">${esc(title)}</h1>
      <p class="text-[13px] text-muted mt-0.5">${esc(sub)}</p></div>
      <div class="flex items-center gap-2">${actionsHtml || ''}</div></div>`;
  }
  function emptyState(icon, title, sub) {
    return `<div class="empty"><i data-lucide="${icon}"></i><div class="text-[14px] font-semibold mt-3">${esc(title)}</div>
      <div class="text-[13px] text-muted mt-1">${esc(sub)}</div></div>`;
  }
  function contactActions(name, phone, email) {
    const a = [];
    if (phone) a.push(`<a class="act" href="${telLink(phone)}" title="Call"><i data-lucide="phone"></i></a>`);
    if (phone) a.push(`<a class="act" href="${smsLink(phone)}" title="Text"><i data-lucide="message-square"></i></a>`);
    if (email) a.push(`<a class="act" href="${mailLink(email)}" title="Email"><i data-lucide="mail"></i></a>`);
    return `<div class="flex items-center gap-1.5">${a.join('') || '<span class="text-muted text-[12px]">—</span>'}</div>`;
  }

  // ---------- Home ----------
  async function renderHome() {
    let d;
    try { d = await api('/api/realtor/home'); } catch (e) { return errView(e); }
    dueBadge = d.stats.tasksDue || 0; renderShell();
    const stat = (icon, tone, val, label) => `<div class="panel stat">
      <div class="stat-icon badge ${tone}" style="border-radius:11px"><i data-lucide="${icon}"></i></div>
      <div><div class="text-[22px] font-bold leading-none">${val}</div><div class="text-[12px] text-muted mt-1">${label}</div></div></div>`;
    const queue = d.queue.length ? d.queue.map(x => `
      <div class="flex items-center gap-3 py-2.5 border-b border-[var(--border)] last:border-0">
        <div class="avatar sm">${initials(x.name)}</div>
        <div class="min-w-0 flex-1"><div class="text-[13px] font-semibold truncate">${esc(x.name)}</div>
          <div class="text-[11.5px] text-muted truncate">${esc(x.reason)}</div></div>
        <span class="badge ${priBadge(x.priority)}">${x.priority}</span>
        ${x.phone ? `<a class="act" href="${telLink(x.phone)}" title="Call"><i data-lucide="phone"></i></a>` : ''}
      </div>`).join('') : `<div class="text-[13px] text-muted py-4 text-center">No calls queued — add leads with a phone number.</div>`;
    const tasks = d.tasksToday.length ? d.tasksToday.map(t => `
      <div class="flex items-center gap-3 py-2.5 border-b border-[var(--border)] last:border-0">
        <button class="act" data-done="${t.id}" title="Mark done"><i data-lucide="circle"></i></button>
        <div class="min-w-0 flex-1"><div class="text-[13px] font-medium truncate">${esc(t.title)}</div>
          <div class="text-[11.5px] ${t.overdue ? 'text-rose-500 font-semibold' : 'text-muted'}">${t.overdue ? 'Overdue · ' : ''}${fmtDate(t.due)}</div></div>
        <span class="badge ${priBadge(t.priority)}">${t.priority}</span>
      </div>`).join('') : `<div class="text-[13px] text-muted py-4 text-center">Nothing due. You're all caught up 🎉</div>`;
    const feed = d.activity.length ? d.activity.map(a => `
      <div class="flex items-start gap-3 py-2">
        <div class="stat-icon badge ${a.tone}" style="width:30px;height:30px;border-radius:8px;"><i data-lucide="${a.icon}" style="width:15px;height:15px"></i></div>
        <div class="min-w-0 flex-1"><div class="text-[12.5px]">${esc(a.text)}</div><div class="text-[11px] text-muted">${fmtWhen(a.at)}</div></div>
      </div>`).join('') : `<div class="text-[13px] text-muted py-4 text-center">No recent activity yet.</div>`;

    $('view').innerHTML = `
      ${pageHead('Hi ' + (me.name.split(/\s+/)[0]) + ' 👋', "Here's what needs your attention today.", `<a class="btn-primary" href="#leads" onclick="event.preventDefault();location.hash='leads'"><i data-lucide="plus"></i>Add a lead</a>`)}
      <div class="grid-stats mb-6">
        ${stat('users', 'blue', d.stats.activeLeads, 'Active leads')}
        ${stat('phone-call', 'amber', d.stats.callsToday, 'To call')}
        ${stat('list-checks', 'red', d.stats.tasksDue, 'Follow-ups due')}
        ${stat('user-check', 'green', d.stats.pastClients, 'Past clients')}
      </div>
      <div class="grid-2">
        <div class="panel p-4">
          <div class="flex items-center justify-between mb-1"><h3 class="text-[14px] font-bold">Who to call</h3><a href="#calls" class="text-[12px] font-semibold text-[var(--accent)]">Call queue →</a></div>
          ${queue}
        </div>
        <div class="panel p-4">
          <div class="flex items-center justify-between mb-1"><h3 class="text-[14px] font-bold">Due today</h3><a href="#tasks" class="text-[12px] font-semibold text-[var(--accent)]">All follow-ups →</a></div>
          ${tasks}
        </div>
      </div>
      <div class="panel p-4 mt-5"><h3 class="text-[14px] font-bold mb-1">Recent activity</h3>${feed}</div>`;
    icons();
    $('view').querySelectorAll('[data-done]').forEach(b => b.addEventListener('click', async () => {
      try { await api('/api/realtor/tasks/' + b.dataset.done, { method: 'PATCH', body: JSON.stringify({ status: 'done' }) }); toast('Marked done'); renderHome(); }
      catch (e) { toast(e.message, 'alert-triangle'); }
    }));
  }
  function errView(e) { $('view').innerHTML = `<div class="panel p-8">${emptyState('alert-triangle', 'Something went wrong', e.message)}</div>`; icons(); }

  // ---------- Leads ----------
  let leadCache = [];
  let leadQuery = '';
  async function renderLeads() {
    try { leadCache = await api('/api/realtor/leads'); } catch (e) { return errView(e); }
    $('view').innerHTML = `
      ${pageHead('Leads', 'Your book of business — everyone you\'re working.', `
        <button class="btn-ghost" id="lead-import"><i data-lucide="upload"></i>Import CSV</button>
        <button class="btn-primary" id="lead-add"><i data-lucide="plus"></i>Add lead</button>`)}
      <div class="panel">
        <div class="p-3 border-b border-[var(--border)] flex items-center gap-2">
          <div class="relative flex-1 max-w-[320px]"><i data-lucide="search" class="absolute" style="left:10px;top:9px;width:16px;height:16px;color:var(--muted)"></i>
          <input id="lead-search" class="input" style="padding-left:32px" placeholder="Search leads..." value="${escA(leadQuery)}"></div>
          <span class="text-[12px] text-muted ml-auto" id="lead-count"></span>
        </div>
        <div style="overflow-x:auto"><table class="tbl" id="lead-table"></table></div>
      </div>
      <input type="file" id="lead-file" accept=".csv" class="hidden">`;
    icons();
    $('lead-add').addEventListener('click', () => leadModal(null));
    $('lead-import').addEventListener('click', () => $('lead-file').click());
    $('lead-file').addEventListener('change', importLeadsCsv);
    $('lead-search').addEventListener('input', e => { leadQuery = e.target.value; drawLeads(); });
    drawLeads();
  }
  function drawLeads() {
    const t = $('lead-table'); if (!t) return;
    const ql = leadQuery.trim().toLowerCase();
    const rows = leadCache.filter(l => !ql || (l.name + ' ' + l.email + ' ' + l.phone + ' ' + l.area).toLowerCase().includes(ql));
    $('lead-count').textContent = rows.length + ' of ' + leadCache.length;
    if (!rows.length) { t.innerHTML = `<tbody><tr><td>${emptyState('user-plus', leadCache.length ? 'No matches' : 'No leads yet', leadCache.length ? 'Try a different search.' : 'Add your first lead to get started.')}</td></tr></tbody>`; icons(); return; }
    t.innerHTML = `<thead><tr><th>Name</th><th>Timeline</th><th>Financing</th><th>Readiness</th><th>Contact</th><th></th></tr></thead>
      <tbody>${rows.map(l => {
        const r = clientScore(l);
        return `<tr>
          <td><div class="flex items-center gap-2.5"><div class="avatar sm">${initials(l.name)}</div>
            <div class="min-w-0"><div class="font-semibold text-[13px] truncate">${esc(l.name)}</div>
            <div class="text-[11.5px] text-muted truncate">${esc([l.intent, l.area].filter(Boolean).join(' · ')) || '—'}</div></div></div></td>
          <td>${l.timeline ? esc(l.timeline) : '<span class="text-muted">—</span>'}</td>
          <td>${l.financing ? esc(l.financing) : '<span class="text-muted">—</span>'}</td>
          <td><span class="badge ${priBadge(r.priority)}">${r.priority}</span></td>
          <td>${contactActions(l.name, l.phone, l.email)}</td>
          <td><div class="flex items-center gap-1 justify-end">
            <button class="act" data-log="${l.id}" title="Log call"><i data-lucide="phone-call"></i></button>
            <button class="act" data-view="${l.id}" title="Open"><i data-lucide="panel-right-open"></i></button>
          </div></td>
        </tr>`;
      }).join('')}</tbody>`;
    icons();
    t.querySelectorAll('[data-view]').forEach(b => b.addEventListener('click', () => leadDrawer(+b.dataset.view)));
    t.querySelectorAll('[data-log]').forEach(b => b.addEventListener('click', () => { const l = leadCache.find(x => x.id == b.dataset.log); logCallModal(l); }));
  }

  // Client-side mirror of the server's readiness scoring (display only).
  function clientScore(l) {
    let s = 0;
    if (l.intent === 'Both') s += 10; else if (l.intent) s += 5;
    const tl = (l.timeline || '').toLowerCase();
    if (tl.includes('asap')) s += 40; else if (tl.includes('1-3')) s += 30; else if (tl.includes('3-6')) s += 20; else if (tl.includes('6+')) s += 10;
    const f = l.financing;
    if (f === 'Pre-approved') s += 30; else if (f === 'Paying cash') s += 28; else if (f === 'Needs a lender') s += 12; else if (f === 'Not sure') s += 5;
    const cm = { '741+': 12, '681-740': 8, '621-680': 4, '581-620': 2, '<580': 0 };
    if (Object.prototype.hasOwnProperty.call(cm, l.creditScore)) s += cm[l.creditScore];
    if (String(l.assets || '').trim()) s += 4;
    return { score: s, priority: s >= 55 ? 'High' : s >= 28 ? 'Medium' : 'Low' };
  }

  function leadModal(lead) {
    const l = lead || {};
    const sel = (name, opts, val) => `<select class="input" data-f="${name}"><option value="">—</option>${opts.map(o => `<option ${val === o ? 'selected' : ''}>${o}</option>`).join('')}</select>`;
    openModal(lead ? 'Edit lead' : 'Add lead', `
      <div class="grid-form">
        <div class="field"><label class="lbl">Name *</label><input class="input" data-f="name" value="${escA(l.name)}" placeholder="Full name"></div>
        <div class="field"><label class="lbl">Phone</label><input class="input" data-f="phone" value="${escA(l.phone)}" placeholder="(555) 123-4567"></div>
        <div class="field"><label class="lbl">Email</label><input class="input" data-f="email" value="${escA(l.email)}" placeholder="name@email.com"></div>
        <div class="field"><label class="lbl">Intent</label>${sel('intent', INTENTS, l.intent)}</div>
        <div class="field"><label class="lbl">Timeline</label>${sel('timeline', TIMELINES, l.timeline)}</div>
        <div class="field"><label class="lbl">Financing</label>${sel('financing', FINANCING, l.financing)}</div>
        <div class="field"><label class="lbl">Credit score</label>${sel('creditScore', CREDIT, l.creditScore)}</div>
        <div class="field"><label class="lbl">Budget</label><input class="input" data-f="budget" value="${escA(l.budget)}" placeholder="$400k–$500k"></div>
        <div class="field"><label class="lbl">Property type</label><input class="input" data-f="propertyType" value="${escA(l.propertyType)}" placeholder="Single family"></div>
        <div class="field"><label class="lbl">Area / city</label><input class="input" data-f="area" value="${escA(l.area)}" placeholder="Austin, TX"></div>
        <div class="field"><label class="lbl">Zip</label><input class="input" data-f="zipcode" value="${escA(l.zipcode)}" placeholder="78701"></div>
        <div class="field"><label class="lbl">Liquid assets</label><input class="input" data-f="assets" value="${escA(l.assets)}" placeholder="Down payment on hand"></div>
        <div class="field full"><label class="lbl">Notes</label><textarea class="input" data-f="notes" placeholder="Anything worth remembering...">${esc(l.notes)}</textarea></div>
      </div>`,
      lead ? 'Save changes' : 'Add lead', async (root) => {
        const body = collect(root);
        if (!body.name) throw new Error('A name is required.');
        if (lead) await api('/api/realtor/leads/' + lead.id, { method: 'PATCH', body: JSON.stringify(body) });
        else await api('/api/realtor/leads', { method: 'POST', body: JSON.stringify(body) });
        toast(lead ? 'Lead updated' : 'Lead added');
        renderLeads();
      });
  }

  async function leadDrawer(id) {
    const l = leadCache.find(x => x.id === id); if (!l) return;
    let tl = { items: [] };
    try { tl = await api('/api/realtor/leads/' + id + '/timeline'); } catch (e) {}
    const r = clientScore(l);
    const info = [
      ['Intent', l.intent], ['Timeline', l.timeline], ['Financing', l.financing], ['Credit', l.creditScore],
      ['Budget', l.budget], ['Property', l.propertyType], ['Area', l.area], ['Zip', l.zipcode], ['Assets', l.assets]
    ].filter(x => x[1]).map(x => `<div><div class="lbl">${x[0]}</div><div class="text-[13px] font-medium">${esc(x[1])}</div></div>`).join('');
    const timeline = tl.items.length ? tl.items.map(it => {
      if (it.kind === 'call') return `<div class="flex items-start gap-2.5 py-2 border-b border-[var(--border)] last:border-0">
        <div class="stat-icon badge gray" style="width:28px;height:28px;border-radius:7px"><i data-lucide="phone" style="width:13px;height:13px"></i></div>
        <div class="flex-1 min-w-0"><div class="text-[12.5px]"><b>Call</b> — ${esc(it.outcome)}</div>${it.body ? `<div class="text-[12px] text-muted">${esc(it.body)}</div>` : ''}<div class="text-[11px] text-muted">${fmtWhen(it.at)}</div></div></div>`;
      return `<div class="flex items-start gap-2.5 py-2 border-b border-[var(--border)] last:border-0">
        <div class="stat-icon badge blue" style="width:28px;height:28px;border-radius:7px"><i data-lucide="sticky-note" style="width:13px;height:13px"></i></div>
        <div class="flex-1 min-w-0"><div class="text-[12.5px]">${esc(it.body)}</div><div class="text-[11px] text-muted">${fmtWhen(it.at)}</div></div>
        <button class="act" data-delnote="${it.id}" title="Delete note"><i data-lucide="trash-2"></i></button></div>`;
    }).join('') : `<div class="text-[12.5px] text-muted py-3 text-center">No activity yet. Log a call or add a note.</div>`;

    openModal(l.name, `
      <div class="flex items-center gap-2 mb-3 flex-wrap">
        <span class="badge ${priBadge(r.priority)}">${r.priority} readiness</span>
        ${l.phone ? `<a class="act" href="${telLink(l.phone)}" title="Call"><i data-lucide="phone"></i></a><a class="act" href="${smsLink(l.phone)}" title="Text"><i data-lucide="message-square"></i></a>` : ''}
        ${l.email ? `<a class="act" href="${mailLink(l.email)}" title="Email"><i data-lucide="mail"></i></a>` : ''}
        <div class="ml-auto flex gap-1.5">
          <button class="btn-ghost" data-edit><i data-lucide="pencil"></i>Edit</button>
          <button class="btn-ghost" data-log><i data-lucide="phone-call"></i>Log call</button>
        </div>
      </div>
      ${info ? `<div class="grid grid-cols-3 gap-3 p-3 rounded-lg mb-3" style="background:var(--surface-2)">${info}</div>` : ''}
      ${l.notes ? `<div class="text-[12.5px] p-3 rounded-lg mb-3" style="background:var(--surface-2)">${esc(l.notes)}</div>` : ''}
      <div class="flex gap-2 mb-3">
        <input class="input" id="note-input" placeholder="Add a note...">
        <button class="btn-primary" id="note-add">Add</button>
      </div>
      <div class="text-[11px] font-bold text-muted uppercase tracking-wide mb-1">Timeline</div>
      <div id="drawer-timeline">${timeline}</div>
      <div class="flex justify-between mt-4 pt-3 border-t border-[var(--border)]">
        <button class="btn-ghost" data-close-lead style="color:#1B7F4B"><i data-lucide="party-popper"></i>Close as won</button>
        <button class="btn-ghost" data-del style="color:#C23B3B"><i data-lucide="trash-2"></i>Delete</button>
      </div>`, null, null, { wide: true });

    const root = document.querySelector('.modal');
    root.querySelector('[data-edit]').addEventListener('click', () => { closeModal(); leadModal(l); });
    root.querySelector('[data-log]').addEventListener('click', () => { closeModal(); logCallModal(l); });
    root.querySelector('[data-close-lead]').addEventListener('click', () => { closeModal(); closeLeadModal(l); });
    root.querySelector('[data-del]').addEventListener('click', async () => {
      if (!confirm('Delete this lead? This removes their notes and timeline.')) return;
      await api('/api/realtor/leads/' + l.id, { method: 'DELETE' }); closeModal(); toast('Lead deleted'); renderLeads();
    });
    root.querySelector('#note-add').addEventListener('click', async () => {
      const val = root.querySelector('#note-input').value.trim(); if (!val) return;
      try { await api('/api/realtor/leads/' + l.id + '/notes', { method: 'POST', body: JSON.stringify({ body: val }) }); closeModal(); leadDrawer(id); }
      catch (e) { toast(e.message, 'alert-triangle'); }
    });
    root.querySelector('#note-input').addEventListener('keydown', e => { if (e.key === 'Enter') root.querySelector('#note-add').click(); });
    root.querySelectorAll('[data-delnote]').forEach(b => b.addEventListener('click', async () => {
      await api('/api/realtor/leads/' + l.id + '/notes/' + b.dataset.delnote, { method: 'DELETE' }); leadDrawer(id);
    }));
  }

  function logCallModal(lead) {
    const outcomes = ['Connected', 'Voicemail', 'No Answer', 'Missed'];
    openModal('Log a call — ' + (lead ? lead.name : ''), `
      <div class="field mb-3"><label class="lbl">Outcome *</label>
        <div class="flex gap-2 flex-wrap mt-1" id="oc-pick">${outcomes.map((o, i) => `<button type="button" class="btn-ghost ${i === 0 ? 'sel' : ''}" data-oc="${o}" style="${i === 0 ? 'border-color:var(--accent);color:var(--accent)' : ''}">${o}</button>`).join('')}</div>
      </div>
      <div class="field"><label class="lbl">Notes</label><textarea class="input" data-f="notes" placeholder="What happened on the call?"></textarea></div>`,
      'Save call', async (root) => {
        const outcome = root.querySelector('#oc-pick .sel')?.dataset.oc || 'Connected';
        const notes = root.querySelector('[data-f="notes"]').value.trim();
        await api('/api/realtor/calls', { method: 'POST', body: JSON.stringify({ name: lead.name, phone: lead.phone, leadId: lead.id, outcome, notes }) });
        toast('Call logged');
        if (active === 'leads') renderLeads(); else if (active === 'calls') renderCalls(); else render();
      });
    const root = document.querySelector('.modal');
    root.querySelectorAll('[data-oc]').forEach(b => b.addEventListener('click', () => {
      root.querySelectorAll('[data-oc]').forEach(x => { x.classList.remove('sel'); x.style.borderColor = ''; x.style.color = ''; });
      b.classList.add('sel'); b.style.borderColor = 'var(--accent)'; b.style.color = 'var(--accent)';
    }));
  }

  function closeLeadModal(lead) {
    const today = new Date().toISOString().slice(0, 10);
    openModal('Close ' + lead.name + ' as won 🎉', `
      <p class="text-[12.5px] text-muted mb-3">Capture the deal — this moves them into Past Clients and removes them from your active leads.</p>
      <div class="grid-form">
        <div class="field"><label class="lbl">Deal type</label><select class="input" data-f="dealType"><option value="">—</option>${DEALS.map(d => `<option>${d}</option>`).join('')}</select></div>
        <div class="field"><label class="lbl">Closed date</label><input class="input" type="date" data-f="closedDate" value="${today}"></div>
        <div class="field"><label class="lbl">Sale price</label><input class="input" data-f="price" placeholder="$525,000"></div>
        <div class="field"><label class="lbl">Address</label><input class="input" data-f="address" placeholder="123 Main St"></div>
        <div class="field full"><label class="lbl">Notes</label><textarea class="input" data-f="notes" placeholder="Deal notes..."></textarea></div>
      </div>`,
      'Close deal', async (root) => {
        await api('/api/realtor/leads/' + lead.id + '/close', { method: 'POST', body: JSON.stringify(collect(root)) });
        toast('Congrats on the close! 🎉');
        renderLeads();
      });
  }

  async function importLeadsCsv(e) {
    const file = e.target.files[0]; e.target.value = '';
    if (!file) return;
    try {
      const rows = parseCsv(await file.text());
      if (!rows.length) return toast('No rows found in that file.', 'alert-triangle');
      const mapped = rows.map(mapLeadRow).filter(r => r.name);
      if (!mapped.length) return toast('No rows had a name column.', 'alert-triangle');
      const res = await api('/api/realtor/leads/import', { method: 'POST', body: JSON.stringify({ rows: mapped }) });
      toast(`Imported ${res.imported}${res.skipped ? ', skipped ' + res.skipped : ''}`);
      renderLeads();
    } catch (err) { toast(err.message, 'alert-triangle'); }
  }
  function mapLeadRow(row) {
    const g = (keys) => { for (const k of Object.keys(row)) { const lk = k.toLowerCase().trim(); if (keys.some(x => lk === x || lk.includes(x))) return row[k]; } return ''; };
    return {
      name: g(['name', 'full name', 'client']) || [g(['first']), g(['last'])].filter(Boolean).join(' '),
      phone: g(['phone', 'mobile', 'cell']), email: g(['email', 'e-mail']),
      intent: g(['intent']), timeline: g(['timeline']), budget: g(['budget', 'price range']),
      propertyType: g(['property', 'type']), area: g(['area', 'city', 'location']), zipcode: g(['zip', 'postal']),
      financing: g(['financing', 'finance']), creditScore: g(['credit']), assets: g(['assets']), notes: g(['notes', 'comment'])
    };
  }

  // ---------- Past Clients ----------
  let clientCache = [];
  async function renderClients() {
    try { clientCache = await api('/api/realtor/clients'); } catch (e) { return errView(e); }
    $('view').innerHTML = `
      ${pageHead('Past Clients', 'Your closed deals and relationships to nurture.', `<button class="btn-primary" id="cl-add"><i data-lucide="plus"></i>Add client</button>`)}
      <div class="panel"><div style="overflow-x:auto"><table class="tbl" id="cl-table"></table></div></div>`;
    icons();
    $('cl-add').addEventListener('click', () => clientModal(null));
    const t = $('cl-table');
    if (!clientCache.length) { t.innerHTML = `<tbody><tr><td>${emptyState('user-check', 'No past clients yet', 'Close a lead as won, or add a client directly.')}</td></tr></tbody>`; icons(); return; }
    t.innerHTML = `<thead><tr><th>Name</th><th>Deal</th><th>Price</th><th>Closed</th><th>Contact</th><th></th></tr></thead>
      <tbody>${clientCache.map(c => `<tr>
        <td><div class="flex items-center gap-2.5"><div class="avatar sm">${initials(c.name)}</div>
          <div class="min-w-0"><div class="font-semibold text-[13px] truncate">${esc(c.name)}</div><div class="text-[11.5px] text-muted truncate">${esc(c.area || c.address) || '—'}</div></div></div></td>
        <td>${c.dealType ? `<span class="badge blue">${esc(c.dealType)}</span>` : '<span class="text-muted">—</span>'}</td>
        <td>${c.price ? esc(c.price) : '<span class="text-muted">—</span>'}</td>
        <td>${c.closedDate ? fmtDate(c.closedDate) : '<span class="text-muted">—</span>'}</td>
        <td>${contactActions(c.name, c.phone, c.email)}</td>
        <td><div class="flex items-center gap-1 justify-end">
          <button class="act" data-edit="${c.id}"><i data-lucide="pencil"></i></button>
          <button class="act" data-del="${c.id}"><i data-lucide="trash-2"></i></button></div></td>
      </tr>`).join('')}</tbody>`;
    icons();
    t.querySelectorAll('[data-edit]').forEach(b => b.addEventListener('click', () => clientModal(clientCache.find(x => x.id == b.dataset.edit))));
    t.querySelectorAll('[data-del]').forEach(b => b.addEventListener('click', async () => {
      if (!confirm('Delete this past client?')) return;
      await api('/api/realtor/clients/' + b.dataset.del, { method: 'DELETE' }); toast('Client deleted'); renderClients();
    }));
  }
  function clientModal(client) {
    const c = client || {};
    openModal(client ? 'Edit client' : 'Add past client', `
      <div class="grid-form">
        <div class="field"><label class="lbl">Name *</label><input class="input" data-f="name" value="${escA(c.name)}"></div>
        <div class="field"><label class="lbl">Phone</label><input class="input" data-f="phone" value="${escA(c.phone)}"></div>
        <div class="field"><label class="lbl">Email</label><input class="input" data-f="email" value="${escA(c.email)}"></div>
        <div class="field"><label class="lbl">Deal type</label><select class="input" data-f="dealType"><option value="">—</option>${DEALS.map(d => `<option ${c.dealType === d ? 'selected' : ''}>${d}</option>`).join('')}</select></div>
        <div class="field"><label class="lbl">Sale price</label><input class="input" data-f="price" value="${escA(c.price)}"></div>
        <div class="field"><label class="lbl">Closed date</label><input class="input" type="date" data-f="closedDate" value="${escA(c.closedDate)}"></div>
        <div class="field full"><label class="lbl">Address</label><input class="input" data-f="address" value="${escA(c.address)}"></div>
        <div class="field full"><label class="lbl">Notes</label><textarea class="input" data-f="notes">${esc(c.notes)}</textarea></div>
      </div>`,
      client ? 'Save' : 'Add client', async (root) => {
        const body = collect(root); if (!body.name) throw new Error('A name is required.');
        if (client) await api('/api/realtor/clients/' + client.id, { method: 'PATCH', body: JSON.stringify(body) });
        else await api('/api/realtor/clients', { method: 'POST', body: JSON.stringify(body) });
        toast(client ? 'Client updated' : 'Client added'); renderClients();
      });
  }

  // ---------- Contacts ----------
  let contactCache = [];
  async function renderContacts() {
    try { contactCache = await api('/api/realtor/contacts'); } catch (e) { return errView(e); }
    $('view').innerHTML = `
      ${pageHead('Contacts', 'Your address book — lenders, vendors, and everyone else.', `<button class="btn-primary" id="ct-add"><i data-lucide="plus"></i>Add contact</button>`)}
      <div class="panel"><div style="overflow-x:auto"><table class="tbl" id="ct-table"></table></div></div>`;
    icons();
    $('ct-add').addEventListener('click', () => contactModal(null));
    const t = $('ct-table');
    if (!contactCache.length) { t.innerHTML = `<tbody><tr><td>${emptyState('contact', 'No contacts yet', 'Add lenders, inspectors, and other partners.')}</td></tr></tbody>`; icons(); return; }
    t.innerHTML = `<thead><tr><th>Name</th><th>Company</th><th>Tag</th><th>Reach</th><th></th></tr></thead>
      <tbody>${contactCache.map(c => `<tr>
        <td><div class="flex items-center gap-2.5"><div class="avatar sm">${initials(c.name)}</div>
          <div class="min-w-0"><div class="font-semibold text-[13px] truncate">${esc(c.name)}</div><div class="text-[11.5px] text-muted truncate">${esc(c.email) || esc(c.phone) || '—'}</div></div></div></td>
        <td>${c.company ? esc(c.company) : '<span class="text-muted">—</span>'}</td>
        <td>${c.tag ? `<span class="badge purple">${esc(c.tag)}</span>` : ''}</td>
        <td>${contactActions(c.name, c.phone, c.email)}</td>
        <td><div class="flex items-center gap-1 justify-end">
          <button class="act" data-edit="${c.id}"><i data-lucide="pencil"></i></button>
          <button class="act" data-del="${c.id}"><i data-lucide="trash-2"></i></button></div></td>
      </tr>`).join('')}</tbody>`;
    icons();
    t.querySelectorAll('[data-edit]').forEach(b => b.addEventListener('click', () => contactModal(contactCache.find(x => x.id == b.dataset.edit))));
    t.querySelectorAll('[data-del]').forEach(b => b.addEventListener('click', async () => {
      if (!confirm('Delete this contact?')) return;
      await api('/api/realtor/contacts/' + b.dataset.del, { method: 'DELETE' }); toast('Contact deleted'); renderContacts();
    }));
  }
  function contactModal(contact) {
    const c = contact || {};
    openModal(contact ? 'Edit contact' : 'Add contact', `
      <div class="grid-form">
        <div class="field"><label class="lbl">Name *</label><input class="input" data-f="name" value="${escA(c.name)}"></div>
        <div class="field"><label class="lbl">Company</label><input class="input" data-f="company" value="${escA(c.company)}"></div>
        <div class="field"><label class="lbl">Phone</label><input class="input" data-f="phone" value="${escA(c.phone)}"></div>
        <div class="field"><label class="lbl">Email</label><input class="input" data-f="email" value="${escA(c.email)}"></div>
        <div class="field full"><label class="lbl">Tag</label><input class="input" data-f="tag" value="${escA(c.tag)}" placeholder="Lender, Inspector, Vendor..."></div>
      </div>`,
      contact ? 'Save' : 'Add contact', async (root) => {
        const body = collect(root); if (!body.name) throw new Error('A name is required.');
        if (contact) await api('/api/realtor/contacts/' + contact.id, { method: 'PATCH', body: JSON.stringify(body) });
        else await api('/api/realtor/contacts', { method: 'POST', body: JSON.stringify(body) });
        toast(contact ? 'Contact updated' : 'Contact added'); renderContacts();
      });
  }

  // ---------- Calls ----------
  async function renderCalls() {
    let queue = [], history = [];
    try { [queue, history] = await Promise.all([api('/api/realtor/call-queue'), api('/api/realtor/calls')]); } catch (e) { return errView(e); }
    const qHtml = queue.length ? queue.map(x => `
      <div class="flex items-center gap-3 py-2.5 border-b border-[var(--border)] last:border-0">
        <div class="avatar sm">${initials(x.name)}</div>
        <div class="min-w-0 flex-1"><div class="text-[13px] font-semibold truncate">${esc(x.name)}</div>
          <div class="text-[11.5px] text-muted truncate">${esc(x.reason)}${x.timeline ? ' · ' + esc(x.timeline) : ''}</div></div>
        <span class="badge ${priBadge(x.priority)}">${x.priority}</span>
        ${x.phone ? `<a class="act" href="${telLink(x.phone)}" title="Call"><i data-lucide="phone"></i></a>` : ''}
        <button class="act" data-log="${x.leadId}" title="Log call"><i data-lucide="phone-call"></i></button>
      </div>`).join('') : `<div class="text-[13px] text-muted py-6 text-center">Queue's clear. Add leads with a phone number to fill it.</div>`;
    const hHtml = history.length ? history.map(c => `
      <div class="flex items-center gap-3 py-2.5 border-b border-[var(--border)] last:border-0">
        <div class="stat-icon badge ${c.outcome === 'Connected' ? 'green' : 'gray'}" style="width:30px;height:30px;border-radius:8px"><i data-lucide="phone" style="width:14px;height:14px"></i></div>
        <div class="min-w-0 flex-1"><div class="text-[13px] font-semibold truncate">${esc(c.name)}</div>
          <div class="text-[11.5px] text-muted truncate">${esc(c.outcome)}${c.notes ? ' · ' + esc(c.notes) : ''}</div></div>
        <div class="text-[11px] text-muted">${fmtWhen(c.loggedAt)}</div>
      </div>`).join('') : `<div class="text-[13px] text-muted py-6 text-center">No calls logged yet.</div>`;
    $('view').innerHTML = `
      ${pageHead('Calls', 'Work your call queue and keep a running log.', '')}
      <div class="grid-2">
        <div class="panel p-4"><h3 class="text-[14px] font-bold mb-1">Who to call next</h3>
          <p class="text-[12px] text-muted mb-2">Ranked by readiness. Skips anyone called in the last 2 days.</p>${qHtml}</div>
        <div class="panel p-4"><h3 class="text-[14px] font-bold mb-2">Recent calls</h3>${hHtml}</div>
      </div>`;
    icons();
    $('view').querySelectorAll('[data-log]').forEach(b => b.addEventListener('click', () => {
      const x = queue.find(q => q.leadId == b.dataset.log); logCallModal({ id: x.leadId, name: x.name, phone: x.phone });
    }));
  }

  // ---------- Follow-ups (tasks) ----------
  let taskCache = [];
  async function renderTasks() {
    try { taskCache = await api('/api/realtor/tasks'); } catch (e) { return errView(e); }
    dueBadge = taskCache.filter(t => t.status === 'todo' && t.due && t.due <= new Date().toISOString().slice(0, 10)).length;
    renderShell();
    const open = taskCache.filter(t => t.status === 'todo');
    const done = taskCache.filter(t => t.status === 'done');
    const row = (t) => `<div class="flex items-center gap-3 py-2.5 border-b border-[var(--border)] last:border-0">
      <button class="act" data-toggle="${t.id}" data-status="${t.status}" title="${t.status === 'done' ? 'Reopen' : 'Mark done'}">
        <i data-lucide="${t.status === 'done' ? 'check-circle-2' : 'circle'}" ${t.status === 'done' ? 'style="color:#1B7F4B"' : ''}></i></button>
      <div class="min-w-0 flex-1">
        <div class="text-[13px] font-medium truncate ${t.status === 'done' ? 'line-through text-muted' : ''}">${esc(t.title)}</div>
        <div class="text-[11.5px] text-muted">${[t.leadName, t.due ? fmtDate(t.due) : '', t.auto ? 'auto' : ''].filter(Boolean).join(' · ')}</div>
      </div>
      ${t.due && t.status === 'todo' && t.due < new Date().toISOString().slice(0, 10) ? '<span class="badge red">Overdue</span>' : ''}
      <span class="badge ${priBadge(t.priority)}">${t.priority}</span>
      <button class="act" data-del="${t.id}" title="Delete"><i data-lucide="trash-2"></i></button>
    </div>`;
    $('view').innerHTML = `
      ${pageHead('Follow-ups', 'Your task list — plus auto-reminders from your activity.', `<button class="btn-primary" id="tk-add"><i data-lucide="plus"></i>Add task</button>`)}
      <div class="panel p-4 mb-4">
        <h3 class="text-[14px] font-bold mb-1">Open <span class="text-muted font-medium">(${open.length})</span></h3>
        ${open.length ? open.map(row).join('') : `<div class="text-[13px] text-muted py-6 text-center">Nothing open. 🎉</div>`}
      </div>
      ${done.length ? `<div class="panel p-4"><h3 class="text-[14px] font-bold mb-1">Done <span class="text-muted font-medium">(${done.length})</span></h3>${done.slice(0, 30).map(row).join('')}</div>` : ''}`;
    icons();
    $('tk-add').addEventListener('click', () => taskModal());
    $('view').querySelectorAll('[data-toggle]').forEach(b => b.addEventListener('click', async () => {
      const next = b.dataset.status === 'done' ? 'todo' : 'done';
      await api('/api/realtor/tasks/' + b.dataset.toggle, { method: 'PATCH', body: JSON.stringify({ status: next }) }); renderTasks();
    }));
    $('view').querySelectorAll('[data-del]').forEach(b => b.addEventListener('click', async () => {
      await api('/api/realtor/tasks/' + b.dataset.del, { method: 'DELETE' }); toast('Task deleted'); renderTasks();
    }));
  }
  async function taskModal() {
    let leads = leadCache;
    if (!leads.length) { try { leads = await api('/api/realtor/leads'); } catch (e) {} }
    openModal('Add follow-up', `
      <div class="field mb-3"><label class="lbl">Task *</label><input class="input" data-f="title" placeholder="Call back about inspection"></div>
      <div class="grid-form">
        <div class="field"><label class="lbl">Due date</label><input class="input" type="date" data-f="due"></div>
        <div class="field"><label class="lbl">Priority</label><select class="input" data-f="priority"><option>Medium</option><option>High</option><option>Low</option></select></div>
        <div class="field full"><label class="lbl">Link to lead (optional)</label>
          <select class="input" data-f="leadId"><option value="">— None —</option>${leads.map(l => `<option value="${l.id}">${escA(l.name)}</option>`).join('')}</select></div>
      </div>`,
      'Add task', async (root) => {
        const body = collect(root);
        if (!body.title) throw new Error('A task is required.');
        body.leadId = body.leadId ? Number(body.leadId) : null;
        await api('/api/realtor/tasks', { method: 'POST', body: JSON.stringify(body) });
        toast('Task added'); renderTasks();
      });
  }

  // ---------- Settings ----------
  async function renderSettings() {
    let prefs = { autoFollowups: true };
    try { prefs = await api('/api/realtor/prefs'); } catch (e) {}
    $('view').innerHTML = `
      ${pageHead('Settings', 'Manage your account and automation.', '')}
      <div class="panel p-6 mb-5" style="max-width:560px">
        <div class="flex items-start justify-between gap-4">
          <div><h3 class="text-[15px] font-semibold mb-1">Automatic follow-ups</h3>
            <p class="text-[12.5px] text-muted">When on, we add reminders for you — a call task for every new lead, a retry after a missed call, and check-ins when a hot lead goes quiet.</p></div>
          <button id="auto-toggle" role="switch" aria-checked="${prefs.autoFollowups}" class="flex-shrink-0" style="position:relative;width:44px;height:26px;border-radius:13px;border:none;cursor:pointer;transition:background .15s;background:${prefs.autoFollowups ? 'var(--accent)' : 'var(--border-strong)'}">
            <span style="position:absolute;top:3px;left:${prefs.autoFollowups ? '21px' : '3px'};width:20px;height:20px;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.25);transition:left .15s" id="auto-knob"></span></button>
        </div>
      </div>
      <div class="panel p-6" style="max-width:560px">
        <h3 class="text-[15px] font-semibold mb-1">Change password</h3>
        <p class="text-[12.5px] text-muted mb-4">Update the password you use to sign in.</p>
        <div class="flex flex-col gap-3">
          <div class="field"><label class="lbl">Current password</label><input id="cp-cur" type="password" class="input" autocomplete="current-password"></div>
          <div class="field"><label class="lbl">New password</label><input id="cp-new" type="password" class="input" autocomplete="new-password" placeholder="At least 8 characters"></div>
          <div class="field"><label class="lbl">Confirm new password</label><input id="cp-new2" type="password" class="input" autocomplete="new-password"></div>
          <div id="cp-msg" class="text-[12.5px] font-medium"></div>
          <div><button id="cp-save" class="btn-primary">Update password</button></div>
        </div>
      </div>`;
    icons();
    let on = prefs.autoFollowups;
    $('auto-toggle').addEventListener('click', async () => {
      on = !on;
      $('auto-toggle').style.background = on ? 'var(--accent)' : 'var(--border-strong)';
      $('auto-knob').style.left = on ? '21px' : '3px';
      $('auto-toggle').setAttribute('aria-checked', on);
      try { await api('/api/realtor/prefs', { method: 'PUT', body: JSON.stringify({ autoFollowups: on }) }); toast(on ? 'Auto follow-ups on' : 'Auto follow-ups off'); }
      catch (e) { toast(e.message, 'alert-triangle'); }
    });
    $('cp-save').addEventListener('click', async () => {
      const msg = $('cp-msg'); msg.style.color = '#C23B3B';
      const cur = $('cp-cur').value, nw = $('cp-new').value, nw2 = $('cp-new2').value;
      if (nw !== nw2) { msg.textContent = 'New passwords don\'t match.'; return; }
      try {
        await api('/api/change-password', { method: 'POST', body: JSON.stringify({ current: cur, next: nw }) });
        msg.style.color = '#1B7F4B'; msg.textContent = 'Password updated.';
        $('cp-cur').value = $('cp-new').value = $('cp-new2').value = '';
        toast('Password updated');
      } catch (e) { msg.textContent = e.message; }
    });
  }

  // ---------- Modal + form helpers ----------
  function collect(root) {
    const out = {};
    root.querySelectorAll('[data-f]').forEach(el => { out[el.dataset.f] = el.value.trim ? el.value.trim() : el.value; });
    return out;
  }
  function openModal(title, bodyHtml, saveLabel, onSave, opts) {
    opts = opts || {};
    $('modal-root').innerHTML = `<div class="modal-scrim"><div class="modal ${opts.wide ? 'wide' : ''}">
      <div class="modal-head"><h3 class="text-[16px] font-bold">${esc(title)}</h3><button class="icon-btn" data-x><i data-lucide="x"></i></button></div>
      <div class="modal-body">${bodyHtml}</div>
      ${saveLabel ? `<div class="modal-foot"><button class="btn-ghost" data-x>Cancel</button><button class="btn-primary" data-save>${esc(saveLabel)}</button></div>` : ''}
    </div></div>`;
    icons();
    const scrim = $('modal-root').querySelector('.modal-scrim');
    const root = scrim.querySelector('.modal');
    scrim.addEventListener('mousedown', e => { if (e.target === scrim) closeModal(); });
    root.querySelectorAll('[data-x]').forEach(b => b.addEventListener('click', closeModal));
    const saveBtn = root.querySelector('[data-save]');
    if (saveBtn && onSave) {
      saveBtn.addEventListener('click', async () => {
        saveBtn.disabled = true;
        try { await onSave(root); closeModal(); }
        catch (e) { toast(e.message, 'alert-triangle'); saveBtn.disabled = false; }
      });
      const first = root.querySelector('.modal-body input, .modal-body textarea, .modal-body select'); if (first) first.focus();
    }
  }
  function closeModal() { $('modal-root').innerHTML = ''; }
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

  // ---------- CSV parser (handles quoted fields) ----------
  function parseCsv(text) {
    const rows = []; let row = [], cur = '', q = false;
    text = text.replace(/\r\n?/g, '\n');
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (q) {
        if (c === '"') { if (text[i + 1] === '"') { cur += '"'; i++; } else q = false; }
        else cur += c;
      } else if (c === '"') q = true;
      else if (c === ',') { row.push(cur); cur = ''; }
      else if (c === '\n') { row.push(cur); rows.push(row); row = []; cur = ''; }
      else cur += c;
    }
    if (cur !== '' || row.length) { row.push(cur); rows.push(row); }
    if (!rows.length) return [];
    const headers = rows.shift().map(h => h.trim());
    return rows.filter(r => r.some(c => c.trim())).map(r => {
      const o = {}; headers.forEach((h, i) => { o[h] = (r[i] || '').trim(); }); return o;
    });
  }

  // ---------- Boot ----------
  async function boot() {
    try {
      me = await api('/api/me');
      $('auth-screen').classList.add('hidden');
      $('app-screen').classList.remove('hidden');
      route();
    } catch (e) {
      showAuth();
    }
  }
  boot();
})();
