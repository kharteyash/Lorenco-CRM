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
    { id: 'pipeline', label: 'Pipeline',     icon: 'kanban-square' },
    { id: 'leads',    label: 'Leads',        icon: 'user-plus' },
    { id: 'clients',  label: 'Past Clients', icon: 'user-check' },
    { id: 'contacts', label: 'Contacts',     icon: 'contact' },
    { id: 'calls',    label: 'Calls',        icon: 'phone' },
    { id: 'calendar', label: 'Calendar',     icon: 'calendar' },
    { id: 'tasks',    label: 'Follow-ups',   icon: 'list-checks' },
    { id: 'reports',  label: 'Reports',      icon: 'bar-chart-3' },
    { id: 'emails',   label: 'Auto Emails',  icon: 'mail' },
    { id: 'settings', label: 'Settings',     icon: 'settings' }
  ];

  const TIMELINES = ['ASAP', '1-3 months', '3-6 months', '6+ months', 'Just browsing'];
  const INTENTS = ['Buying', 'Selling', 'Both'];
  const FINANCING = ['Pre-approved', 'Needs a lender', 'Paying cash', 'Not sure'];
  const CREDIT = ['741+', '681-740', '621-680', '581-620', '<580'];
  const DEALS = ['Bought', 'Sold', 'Both'];
  const STAGES = ['New', 'Contacted', 'Showing', 'Offer', 'Under Contract'];
  const stageTone = (st) => ({ 'New': 'gray', 'Contacted': 'blue', 'Showing': 'purple', 'Offer': 'amber', 'Under Contract': 'green' }[st] || 'gray');

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

  // ---------- Theme (light / dark) ----------
  // Applied to <html> so it covers the auth screen too. Persisted per browser;
  // defaults to the OS preference until the user picks one.
  function applyTheme(mode) {
    document.documentElement.setAttribute('data-theme', mode);
    const btn = $('theme-btn');
    if (btn) { btn.innerHTML = `<i data-lucide="${mode === 'dark' ? 'sun' : 'moon'}"></i>`; btn.title = mode === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'; icons(); }
  }
  function currentTheme() {
    return localStorage.getItem('ln-theme')
      || (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  }
  applyTheme(currentTheme());
  $('theme-btn').addEventListener('click', () => {
    const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    localStorage.setItem('ln-theme', next);
    applyTheme(next);
  });

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
    const fn = { home: renderHome, pipeline: renderPipeline, leads: renderLeads, clients: renderClients, contacts: renderContacts, calls: renderCalls, calendar: renderCalendar, tasks: renderTasks, reports: renderReports, emails: renderEmails, settings: renderSettings }[active];
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

    const sched = (d.scheduleToday || []);
    const schedule = sched.length ? sched.map(a => `
      <div class="flex items-center gap-3 py-2.5 border-b border-[var(--border)] last:border-0" data-appt-go="1">
        <div class="stat-icon badge ${apptTone(a.type)}" style="width:34px;height:34px;border-radius:9px"><i data-lucide="calendar" style="width:15px;height:15px"></i></div>
        <div class="min-w-0 flex-1"><div class="text-[13px] font-semibold truncate">${esc(a.title)}</div>
          <div class="text-[11.5px] text-muted truncate">${esc(a.type)}${a.leadName ? ' · ' + esc(a.leadName) : ''}${a.location ? ' · ' + esc(a.location) : ''}</div></div>
        ${a.start ? `<div class="text-[12px] text-muted num" style="flex-shrink:0">${fmtTimeSafe(a.start)}</div>` : ''}
      </div>`).join('') : `<div class="text-[13px] text-muted py-4 text-center">No appointments today. <a href="#calendar" class="font-semibold text-[var(--accent)]">Add one →</a></div>`;

    const pipe = (d.pipeline || []);
    const pipeTotal = pipe.reduce((n, s) => n + s.count, 0);
    const pipeline = `<div class="flex flex-col gap-2.5">${pipe.map(s => {
      const pct = pipeTotal ? Math.round((s.count / pipeTotal) * 100) : 0;
      return `<a href="#pipeline" class="block">
        <div class="flex items-center justify-between text-[12px] mb-1"><span class="font-semibold">${s.stage}</span><span class="text-muted num">${s.count}</span></div>
        <div style="height:7px;border-radius:4px;background:var(--surface-3);overflow:hidden"><div style="height:100%;width:${pct}%;background:var(--accent);border-radius:4px"></div></div>
      </a>`;
    }).join('')}</div>`;

    $('view').innerHTML = `
      ${pageHead('Hi ' + (me.name.split(/\s+/)[0]) + ' 👋', "Here's what needs your attention today.", `<a class="btn-primary" href="#leads" onclick="event.preventDefault();location.hash='leads'"><i data-lucide="plus"></i>Add a lead</a>`)}
      <div class="grid-stats mb-6">
        ${stat('users', 'blue', d.stats.activeLeads, 'Active leads')}
        ${stat('calendar-clock', 'purple', d.stats.apptsToday || 0, 'Appointments today')}
        ${stat('list-checks', 'red', d.stats.tasksDue, 'Follow-ups due')}
        ${stat('user-check', 'green', d.stats.pastClients, 'Past clients')}
      </div>
      <div class="grid-2 mb-5">
        <div class="panel p-4">
          <div class="flex items-center justify-between mb-1"><h3 class="text-[14px] font-bold">Today's schedule</h3><a href="#calendar" class="text-[12px] font-semibold text-[var(--accent)]">Calendar →</a></div>
          ${schedule}
        </div>
        <div class="panel p-4">
          <div class="flex items-center justify-between mb-2"><h3 class="text-[14px] font-bold">Pipeline</h3><a href="#pipeline" class="text-[12px] font-semibold text-[var(--accent)]">Board →</a></div>
          ${pipeline}
        </div>
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
    $('view').querySelectorAll('[data-appt-go]').forEach(el => el.addEventListener('click', () => { location.hash = 'calendar'; }));
    $('view').querySelectorAll('[data-done]').forEach(b => b.addEventListener('click', async () => {
      try { await api('/api/realtor/tasks/' + b.dataset.done, { method: 'PATCH', body: JSON.stringify({ status: 'done' }) }); toast('Marked done'); renderHome(); }
      catch (e) { toast(e.message, 'alert-triangle'); }
    }));
  }
  // Safe time formatter usable before the calendar module's fmtTime is defined at call sites.
  function fmtTimeSafe(t) {
    if (!t || !/^\d{2}:\d{2}$/.test(t)) return '';
    let [h, m] = t.split(':').map(Number); const ap = h < 12 ? 'am' : 'pm'; h = h % 12 || 12;
    return m ? `${h}:${String(m).padStart(2, '0')}${ap}` : `${h}${ap}`;
  }
  function errView(e) { $('view').innerHTML = `<div class="panel p-8">${emptyState('alert-triangle', 'Something went wrong', e.message)}</div>`; icons(); }

  // ---------- Pipeline (kanban) ----------
  async function renderPipeline() {
    try { leadCache = await api('/api/realtor/leads'); } catch (e) { return errView(e); }
    const byStage = {}; STAGES.forEach(s => byStage[s] = []);
    leadCache.forEach(l => { (byStage[l.stage] || byStage['New']).push(l); });

    const card = (l) => {
      const r = clientScore(l);
      return `<div class="pipe-card" draggable="true" data-card="${l.id}">
        <div class="flex items-start justify-between gap-2">
          <div class="font-semibold text-[13px] leading-tight">${esc(l.name)}</div>
          <span class="badge ${priBadge(r.priority)}" style="flex-shrink:0">${r.priority}</span>
        </div>
        <div class="text-[11.5px] text-muted mt-1 truncate">${esc([l.timeline, l.area].filter(Boolean).join(' · ')) || 'No details yet'}</div>
        <div class="flex items-center gap-1.5 mt-2">
          ${l.phone ? `<a class="act" href="${telLink(l.phone)}" title="Call" data-stop><i data-lucide="phone"></i></a><a class="act" href="${smsLink(l.phone)}" title="Text" data-stop><i data-lucide="message-square"></i></a>` : ''}
          ${l.email ? `<a class="act" href="${mailLink(l.email)}" title="Email" data-stop><i data-lucide="mail"></i></a>` : ''}
          ${l.budget ? `<span class="text-[11px] text-muted ml-auto">${esc(l.budget)}</span>` : ''}
        </div>
      </div>`;
    };
    const columns = STAGES.map(st => `
      <div class="pipe-col" data-col="${st}">
        <div class="pipe-col-head">
          <span class="badge ${stageTone(st)}">${st}</span>
          <span class="text-[12px] text-muted num">${byStage[st].length}</span>
        </div>
        <div class="pipe-col-body" data-drop="${st}">
          ${byStage[st].map(card).join('') || `<div class="pipe-empty">Drop leads here</div>`}
        </div>
      </div>`).join('');

    $('view').innerHTML = `
      ${pageHead('Pipeline', 'Drag a lead across stages as the deal moves. Click a card to open it.', `<button class="btn-primary" id="pipe-add"><i data-lucide="plus"></i>Add lead</button>`)}
      <div class="pipe-board">${columns}</div>`;
    icons();
    $('pipe-add').addEventListener('click', () => leadModal(null));

    // Open the lead on click (but not when using a quick action).
    $('view').querySelectorAll('[data-card]').forEach(c => {
      c.addEventListener('click', (e) => { if (e.target.closest('[data-stop]')) return; leadDrawer(+c.dataset.card); });
      c.addEventListener('dragstart', (e) => { e.dataTransfer.setData('text/plain', c.dataset.card); e.dataTransfer.effectAllowed = 'move'; c.classList.add('dragging'); });
      c.addEventListener('dragend', () => c.classList.remove('dragging'));
    });
    $('view').querySelectorAll('[data-stop]').forEach(a => a.addEventListener('click', e => e.stopPropagation()));

    // Drop zones.
    $('view').querySelectorAll('[data-drop]').forEach(zone => {
      zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('drop-hover'); });
      zone.addEventListener('dragleave', () => zone.classList.remove('drop-hover'));
      zone.addEventListener('drop', async (e) => {
        e.preventDefault(); zone.classList.remove('drop-hover');
        const id = Number(e.dataTransfer.getData('text/plain'));
        const stage = zone.dataset.drop;
        const lead = leadCache.find(l => l.id === id);
        if (!lead || lead.stage === stage) return;
        const prev = lead.stage; lead.stage = stage;
        renderPipeline(); // optimistic
        try { await api('/api/realtor/leads/' + id + '/stage', { method: 'PATCH', body: JSON.stringify({ stage }) }); toast(`Moved to ${stage}`); }
        catch (err) { lead.stage = prev; toast(err.message, 'alert-triangle'); renderPipeline(); }
      });
    });
  }

  // ---------- Leads ----------
  let leadCache = [];
  let leadQuery = '';
  async function renderLeads() {
    try { leadCache = await api('/api/realtor/leads'); } catch (e) { return errView(e); }
    $('view').innerHTML = `
      ${pageHead('Leads', 'Your book of business — everyone you\'re working.', `
        <button class="btn-ghost" id="lead-intake"><i data-lucide="share-2"></i>Intake form</button>
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
    $('lead-intake').addEventListener('click', intakeModal);
    $('lead-import').addEventListener('click', () => $('lead-file').click());
    $('lead-file').addEventListener('change', importLeadsCsv);
    $('lead-search').addEventListener('input', e => { leadQuery = e.target.value; drawLeads(); });
    drawLeads();
  }

  // Shareable public intake-form link.
  async function intakeModal() {
    let data;
    try { data = await api('/api/realtor/capture'); } catch (e) { return toast(e.message, 'alert-triangle'); }
    openModal('Your intake form', `
      <p class="text-[12.5px] text-muted mb-3">Share this link on your website, social bio, or email signature. Anyone who fills it out lands straight in your Leads (marked <b>Intake form</b>).</p>
      <div class="field mb-2"><label class="lbl">Your form link</label>
        <div class="flex gap-2 mt-1">
          <input id="intake-url" class="input" readonly value="${escA(data.url)}">
          <button class="btn-primary" id="intake-copy" style="flex-shrink:0"><i data-lucide="copy"></i>Copy</button>
        </div>
      </div>
      <div class="flex items-center gap-3 mt-3">
        <a class="btn-ghost" href="${escA(data.url)}" target="_blank" rel="noopener"><i data-lucide="external-link"></i>Preview form</a>
        <button class="btn-ghost" id="intake-regen" style="color:#C23B3B"><i data-lucide="refresh-cw"></i>Reset link</button>
      </div>`, null, null, { wide: false });
    const root = document.querySelector('.modal');
    root.querySelector('#intake-copy').addEventListener('click', async () => {
      const url = root.querySelector('#intake-url').value;
      try { await navigator.clipboard.writeText(url); toast('Link copied'); }
      catch (e) { root.querySelector('#intake-url').select(); document.execCommand('copy'); toast('Link copied'); }
    });
    root.querySelector('#intake-regen').addEventListener('click', async () => {
      if (!confirm('Reset your link? The current one will stop working immediately.')) return;
      try { const d = await api('/api/realtor/capture/regenerate', { method: 'POST' }); root.querySelector('#intake-url').value = d.url; toast('New link created'); }
      catch (e) { toast(e.message, 'alert-triangle'); }
    });
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
        <div class="field"><label class="lbl">Stage</label><select class="input" data-f="stage">${STAGES.map(o => `<option ${(l.stage || 'New') === o ? 'selected' : ''}>${o}</option>`).join('')}</select></div>
        <div class="field"><label class="lbl">Source</label><input class="input" data-f="source" value="${escA(l.source)}" placeholder="Zillow, referral, open house..."></div>
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
        render();
      });
  }

  async function leadDrawer(id) {
    const l = leadCache.find(x => x.id === id); if (!l) return;
    let tl = { items: [] };
    try { tl = await api('/api/realtor/leads/' + id + '/timeline'); } catch (e) {}
    const r = clientScore(l);
    const info = [
      ['Intent', l.intent], ['Timeline', l.timeline], ['Financing', l.financing], ['Credit', l.creditScore],
      ['Budget', l.budget], ['Property', l.propertyType], ['Area', l.area], ['Zip', l.zipcode], ['Assets', l.assets], ['Source', l.source]
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
        <span class="badge ${stageTone(l.stage || 'New')}">${esc(l.stage || 'New')}</span>
        <span class="badge ${priBadge(r.priority)}">${r.priority} readiness</span>
        ${l.phone ? `<a class="act" href="${telLink(l.phone)}" title="Call"><i data-lucide="phone"></i></a><a class="act" href="${smsLink(l.phone)}" title="Text"><i data-lucide="message-square"></i></a>` : ''}
        ${l.email ? `<a class="act" href="${mailLink(l.email)}" title="Email"><i data-lucide="mail"></i></a>` : ''}
        <div class="ml-auto flex gap-1.5">
          ${l.email ? `<button class="btn-ghost" data-email><i data-lucide="send"></i>Email</button>` : ''}
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
    const emailBtn = root.querySelector('[data-email]');
    if (emailBtn) emailBtn.addEventListener('click', () => { closeModal(); emailLeadModal(l); });
    root.querySelector('[data-edit]').addEventListener('click', () => { closeModal(); leadModal(l); });
    root.querySelector('[data-log]').addEventListener('click', () => { closeModal(); logCallModal(l); });
    root.querySelector('[data-close-lead]').addEventListener('click', () => { closeModal(); closeLeadModal(l); });
    root.querySelector('[data-del]').addEventListener('click', async () => {
      if (!confirm('Delete this lead? This removes their notes and timeline.')) return;
      await api('/api/realtor/leads/' + l.id, { method: 'DELETE' }); closeModal(); toast('Lead deleted'); render();
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

  // 1:1 email to a lead, sent via the agent's Gmail/SMTP and logged to the timeline.
  function emailLeadModal(lead) {
    const first = (lead.name || '').trim().split(/\s+/)[0] || 'there';
    const agent = (me && me.name) || 'Your agent';
    const fill = (t) => t.replace(/\{name\}/g, first).replace(/\{agent\}/g, agent);
    const TEMPLATES = {
      'Blank': { subject: '', body: '' },
      'Intro': { subject: 'Great to connect, {name}', body: `Hi {name},\n\nThanks for reaching out — I'd love to help you with your move. When's a good time for a quick call this week?\n\nBest,\n{agent}` },
      'Check-in': { subject: 'Checking in, {name}', body: `Hi {name},\n\nJust wanted to check in and see how your home search is going. Anything I can do to help right now?\n\nTalk soon,\n{agent}` },
      'New listings': { subject: 'A few listings you might like', body: `Hi {name},\n\nA couple of new listings came up that match what you're looking for — want me to send them over or set up showings?\n\nBest,\n{agent}` },
      'Thank you': { subject: 'Thank you, {name}!', body: `Hi {name},\n\nThank you for your time today — it was great talking. I'll follow up with the next steps shortly.\n\nBest,\n{agent}` }
    };
    const keys = Object.keys(TEMPLATES);
    openModal('Email ' + lead.name, `
      <p class="text-[12px] text-muted mb-3">Sends from your connected Gmail to <b>${escA(lead.email)}</b> and logs it on the timeline.</p>
      <div class="field mb-3"><label class="lbl">Template</label>
        <select class="input mt-1" id="tpl">${keys.map(k => `<option>${k}</option>`).join('')}</select></div>
      <div class="field mb-3"><label class="lbl">Subject</label><input class="input mt-1" id="em-subj" value="${escA(fill(TEMPLATES.Intro.subject))}"></div>
      <div class="field"><label class="lbl">Message</label><textarea class="input mt-1" id="em-bd" style="min-height:180px">${esc(fill(TEMPLATES.Intro.body))}</textarea></div>`,
      'Send email', async (root) => {
        const subject = root.querySelector('#em-subj').value.trim();
        const body = root.querySelector('#em-bd').value.trim();
        if (!subject) throw new Error('A subject is required.');
        if (!body) throw new Error('The message is empty.');
        const r = await api('/api/realtor/leads/' + lead.id + '/email', { method: 'POST', body: JSON.stringify({ subject, body }) });
        toast('Email sent' + (r.via === 'gmail' ? ' via Gmail' : ''));
        // Reopen the lead after this modal closes so the logged email shows.
        setTimeout(() => { if (active === 'leads' || active === 'pipeline') leadDrawer(lead.id); }, 20);
      });
    const root = document.querySelector('.modal');
    // Default the picker to Intro (already prefilled) and swap on change.
    root.querySelector('#tpl').value = 'Intro';
    root.querySelector('#tpl').addEventListener('change', (e) => {
      const t = TEMPLATES[e.target.value] || TEMPLATES.Blank;
      root.querySelector('#em-subj').value = fill(t.subject);
      root.querySelector('#em-bd').value = fill(t.body);
    });
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

  // ---------- Calendar & appointments ----------
  const APPT_TYPES = ['Showing', 'Open House', 'Closing', 'Call', 'Meeting', 'Other'];
  const apptTone = (t) => ({ 'Showing': 'blue', 'Open House': 'purple', 'Closing': 'green', 'Call': 'amber', 'Meeting': 'gray', 'Other': 'gray' }[t] || 'gray');
  const pad2 = (n) => String(n).padStart(2, '0');
  const ymd = (y, m, d) => `${y}-${pad2(m + 1)}-${pad2(d)}`;
  function fmtTime(t) {
    if (!t || !/^\d{2}:\d{2}$/.test(t)) return '';
    let [h, m] = t.split(':').map(Number); const ap = h < 12 ? 'am' : 'pm'; h = h % 12 || 12;
    return m ? `${h}:${pad2(m)}${ap}` : `${h}${ap}`;
  }
  // Google-Calendar-style views. The cursor date anchors the visible range;
  // follow-up tasks show as all-day items on their due date; events from the
  // connected Google Calendar merge in read-only (mirrors of our own
  // appointments are excluded server-side so nothing shows twice).
  let calView = ['month', 'week', 'day'].includes(localStorage.getItem('ln-calview')) ? localStorage.getItem('ln-calview') : 'month';
  let calCursor = null; // Date, local midnight
  const CAL_DOW = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const dstr = (d) => ymd(d.getFullYear(), d.getMonth(), d.getDate());
  const parseYmd = (s) => { const [y, m, d] = s.split('-').map(Number); return new Date(y, m - 1, d); };
  const calAddDays = (d, n) => { const x = new Date(d); x.setDate(x.getDate() + n); return x; };
  const startOfWeek = (d) => calAddDays(d, -d.getDay()); // Sunday
  const taskColor = (p) => p === 'High' ? '#C94747' : p === 'Medium' ? '#B07A00' : '#8A8AA0';
  // Hour rows: a default 8am–6pm window, expanded to fit any timed event.
  function calHours(list) {
    let min = 8, max = 18;
    list.forEach(e => { if (e.start) { const h = +e.start.slice(0, 2); if (h < min) min = h; if (h > max) max = h; } });
    const out = []; for (let h = min; h <= max; h++) out.push(h); return out;
  }

  async function renderCalendar() {
    const today = new Date();
    const todayStr = dstr(today);
    if (!calCursor) calCursor = parseYmd(todayStr);

    // One-time toast after returning from the Google consent screen.
    const gp = new URLSearchParams(location.search).get('gmail');
    if (gp) {
      history.replaceState(null, '', location.pathname + location.hash);
      toast(gp === 'connected' ? 'Google account connected' : 'Google connect failed', gp === 'connected' ? 'check-circle-2' : 'alert-triangle');
    }

    // Visible range for the current view.
    let from, to;
    if (calView === 'month') {
      from = ymd(calCursor.getFullYear(), calCursor.getMonth(), 1);
      to = ymd(calCursor.getFullYear(), calCursor.getMonth(), new Date(calCursor.getFullYear(), calCursor.getMonth() + 1, 0).getDate());
    } else if (calView === 'week') {
      const s = startOfWeek(calCursor);
      from = dstr(s); to = dstr(calAddDays(s, 6));
    } else { from = to = dstr(calCursor); }

    let appts = [], tasks = [], g = null;
    try {
      [appts, tasks, g] = await Promise.all([
        api(`/api/realtor/appointments?from=${from}&to=${to}`),
        api('/api/realtor/tasks'),
        api(`/api/realtor/gcal?from=${from}&to=${to}`).catch(() => null)
      ]);
    } catch (e) { return errView(e); }
    const gEvents = (g && g.events) || [];
    // One merged, per-day-sortable list; all-day items first, then by time.
    const events = appts.map(a => Object.assign({ source: 'crm' }, a)).concat(gEvents);
    const eventsOn = (ds) => events.filter(e => e.date === ds)
      .sort((a, b) => (a.start || '') === (b.start || '') ? 0 : !a.start ? -1 : !b.start ? 1 : a.start < b.start ? -1 : 1);
    const tasksOn = (ds) => tasks.filter(t => t.status === 'todo' && t.due === ds);

    // ----- Small renderers -----
    const gi = (e) => events.indexOf(e); // stable index for click lookup
    function evChip(e) { // compact chip (month cells, week grid)
      const time = e.start ? `<b>${fmtTime(e.start)}</b> ` : '';
      if (e.source === 'google') {
        return `<div class="cal-chip google" data-gev="${gi(e)}" title="${escA(e.title)}${e.meetLink ? ' — Google Meet' : ' — from Google Calendar'}">${time}${esc(e.title)}${e.meetLink ? ' ·&nbsp;Join' : ''}</div>`;
      }
      return `<div class="cal-chip ${apptTone(e.type)}" data-appt="${e.id}" title="${escA(e.title)}">${time}${esc(e.title)}</div>`;
    }
    function evBlock(e) { // full-size block (day view)
      const sub = [e.start ? fmtTime(e.start) + (e.end ? ' – ' + fmtTime(e.end) : '') : 'All day',
                   e.source === 'google' ? 'Google Calendar' : e.type, e.leadName, e.location].filter(Boolean).join(' · ');
      const attrs = e.source === 'google' ? `data-gev="${gi(e)}"` : `data-appt="${e.id}"`;
      return `<div class="cal-chip cal-block ${e.source === 'google' ? 'google' : apptTone(e.type)}" ${attrs} title="${escA(e.title)}">
        <div class="font-semibold" style="font-size:12.5px">${esc(e.title)}${e.meetLink ? ' · Join' : ''}</div>
        <div style="font-size:11px;opacity:.85">${esc(sub)}</div></div>`;
    }
    const taskChip = (t) => `<div class="cal-chip task" data-task="1" style="border-left:3px solid ${taskColor(t.priority)}" title="${escA(t.title)} — ${t.priority} (open Follow-ups)"><i data-lucide="check-square"></i>${esc(t.title)}</div>`;
    // The red "now" line, placed inside the current hour's cell for today.
    const nowLine = (ds, h) => (ds === todayStr && today.getHours() === h)
      ? `<div class="cal-nowline" style="top:${Math.round(today.getMinutes() / 60 * 100)}%"></div>` : '';

    // ----- Views -----
    function monthBody() {
      const y = calCursor.getFullYear(), m = calCursor.getMonth();
      const startDay = new Date(y, m, 1).getDay();
      const daysIn = new Date(y, m + 1, 0).getDate();
      const cells = [];
      for (let i = 0; i < startDay; i++) cells.push(`<div class="cal-cell empty"></div>`);
      for (let d = 1; d <= daysIn; d++) {
        const ds = ymd(y, m, d);
        const items = tasksOn(ds).map(taskChip).concat(eventsOn(ds).map(evChip));
        const more = items.length > 3 ? `<div class="cal-more" data-more="${ds}">+${items.length - 3} more</div>` : '';
        cells.push(`<div class="cal-cell ${ds === todayStr ? 'today' : ''}" data-day="${ds}">
          <div class="cal-daynum">${d}</div>${items.slice(0, 3).join('')}${more}</div>`);
      }
      while (cells.length % 7 !== 0) cells.push(`<div class="cal-cell empty"></div>`);
      return `<div class="cal-grid cal-head">${CAL_DOW.map(d => `<div class="cal-dow">${d}</div>`).join('')}</div>
        <div class="cal-grid">${cells.join('')}</div>`;
    }

    function weekBody() {
      const days = Array.from({ length: 7 }, (_, i) => calAddDays(startOfWeek(calCursor), i));
      const keys = days.map(dstr);
      const timed = keys.flatMap(ds => eventsOn(ds).filter(e => e.start));
      const header = `<div class="cal-wk-row" style="border-top:none;min-height:0">
        <div></div>${days.map((d, i) => `
          <div class="text-center py-1.5" style="border-left:1px solid var(--border)">
            <div class="cal-dow" style="padding:0">${CAL_DOW[d.getDay()]}</div>
            <div class="cal-wk-num ${keys[i] === todayStr ? 'today' : ''}">${d.getDate()}</div>
          </div>`).join('')}</div>`;
      const allDayItems = (ds) => tasksOn(ds).map(taskChip).concat(eventsOn(ds).filter(e => !e.start).map(evChip));
      const anyAllDay = keys.some(ds => allDayItems(ds).length);
      const allDayRow = anyAllDay ? `<div class="cal-wk-row" style="min-height:0;background:var(--surface-2)">
        <div class="cal-wk-time" style="font-size:10px">all-day</div>
        ${keys.map(ds => `<div class="cal-wk-cell" data-slot="${ds}">${allDayItems(ds).join('')}</div>`).join('')}</div>` : '';
      const rows = calHours(timed).map(h => `<div class="cal-wk-row">
        <div class="cal-wk-time">${fmtTime(pad2(h) + ':00')}</div>
        ${keys.map(ds => `<div class="cal-wk-cell ${ds === todayStr ? 'today' : ''}" data-slot="${ds}" data-hour="${h}">
          ${nowLine(ds, h)}${eventsOn(ds).filter(e => e.start && +e.start.slice(0, 2) === h).map(evChip).join('')}</div>`).join('')}</div>`).join('');
      return `<div style="overflow-x:auto"><div class="cal-wk">${header}${allDayRow}${rows}</div></div>`;
    }

    function dayBody() {
      const ds = dstr(calCursor);
      const dayTasks = tasksOn(ds);
      const allDay = eventsOn(ds).filter(e => !e.start);
      const timed = eventsOn(ds).filter(e => e.start);
      const top = (dayTasks.length || allDay.length) ? `<div class="mb-3 flex flex-col gap-1.5">
        ${dayTasks.map(taskChip).join('')}${allDay.map(evBlock).join('')}</div>` : '';
      const rows = calHours(timed).map(h => `<div class="cal-wk-row" style="grid-template-columns:64px 1fr">
        <div class="cal-wk-time">${fmtTime(pad2(h) + ':00')}</div>
        <div class="cal-wk-cell" data-slot="${ds}" data-hour="${h}">
          ${nowLine(ds, h)}${timed.filter(e => +e.start.slice(0, 2) === h).map(evBlock).join('')}</div></div>`).join('');
      return `${top}<div style="border:1px solid var(--border);border-radius:12px;overflow:hidden">${rows}</div>`;
    }

    // ----- Toolbar label -----
    let label;
    if (calView === 'month') label = calCursor.toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
    else if (calView === 'day') label = calCursor.toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' });
    else {
      const a = startOfWeek(calCursor), b = calAddDays(a, 6);
      const left = a.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
      const right = a.getMonth() === b.getMonth()
        ? `${b.getDate()}, ${b.getFullYear()}`
        : b.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
      label = `${left} – ${right}`;
    }

    // ----- Sync banner -----
    let banner = '';
    if (g && g.configured !== false) {
      if (g.calendarOk) {
        banner = `<div class="text-[12px] text-muted flex items-center gap-1.5 mb-3">
          <i data-lucide="check-circle-2" style="width:14px;height:14px;color:#1B7F4B"></i>
          Synced with Google Calendar — appointments appear in both places.</div>`;
      } else {
        const reconnect = g.connected && !g.calendarOk;
        const msg = reconnect
          ? 'Calendar access isn’t granted yet — reconnect Google to sync (and make sure the Google Calendar API is enabled).'
          : 'Connect your Google account to sync this calendar with Google Calendar.';
        banner = `<div class="panel mb-4 flex items-center justify-between gap-3 flex-wrap" style="padding:13px 16px;border-left:3px solid #B07A00">
          <div class="flex items-center gap-2 text-[13px]"><i data-lucide="calendar-clock" style="width:16px;height:16px;color:#B07A00;flex-shrink:0"></i><span>${msg}</span></div>
          <button class="btn-primary" id="cal-connect" style="white-space:nowrap"><i data-lucide="calendar"></i>${reconnect ? 'Reconnect Google' : 'Connect Google'}</button></div>`;
      }
    }

    const upcoming = appts.filter(a => a.date >= todayStr).slice(0, 6);
    $('view').innerHTML = `
      ${pageHead('Calendar', 'Appointments, follow-ups due, and your Google Calendar — in one place.', `<button class="btn-primary" id="cal-add"><i data-lucide="plus"></i>New appointment</button>`)}
      ${banner}
      <div class="panel p-4">
        <div class="flex items-center gap-2 mb-3 flex-wrap">
          <button class="icon-btn" id="cal-prev"><i data-lucide="chevron-left"></i></button>
          <div class="text-[15px] font-bold" style="min-width:150px;text-align:center">${label}</div>
          <button class="icon-btn" id="cal-next"><i data-lucide="chevron-right"></i></button>
          <button class="btn-ghost" id="cal-today" style="margin-left:6px">Today</button>
          <div class="cal-tabs" style="margin-left:auto">
            ${['month', 'week', 'day'].map(v => `<div class="cal-tab ${calView === v ? 'active' : ''}" data-calview="${v}">${v[0].toUpperCase() + v.slice(1)}</div>`).join('')}
          </div>
        </div>
        ${calView === 'month' ? monthBody() : calView === 'week' ? weekBody() : dayBody()}
      </div>
      ${calView === 'month' && upcoming.length ? `<div class="panel p-4 mt-5"><h3 class="text-[14px] font-bold mb-1">Upcoming</h3>
        ${upcoming.map(a => `<div class="flex items-center gap-3 py-2.5 border-b border-[var(--border)] last:border-0" data-appt="${a.id}" style="cursor:pointer">
          <div class="stat-icon badge ${apptTone(a.type)}" style="width:34px;height:34px;border-radius:9px;flex-direction:column"><i data-lucide="calendar" style="width:15px;height:15px"></i></div>
          <div class="min-w-0 flex-1"><div class="text-[13px] font-semibold truncate">${esc(a.title)}</div>
            <div class="text-[11.5px] text-muted truncate">${esc(a.type)}${a.leadName ? ' · ' + esc(a.leadName) : ''}${a.location ? ' · ' + esc(a.location) : ''}</div></div>
          <div class="text-[12px] text-muted text-right" style="flex-shrink:0">${fmtDate(a.date)}${a.start ? '<br>' + fmtTime(a.start) : ''}</div>
        </div>`).join('')}</div>` : ''}`;
    icons();

    // ----- Bindings -----
    const step = calView === 'day' ? 1 : 7;
    $('cal-add').addEventListener('click', () => apptModal(null, dstr(calCursor) >= todayStr ? dstr(calCursor) : todayStr));
    $('cal-prev').addEventListener('click', () => {
      if (calView === 'month') calCursor = new Date(calCursor.getFullYear(), calCursor.getMonth() - 1, 1);
      else calCursor = calAddDays(calCursor, -step);
      renderCalendar();
    });
    $('cal-next').addEventListener('click', () => {
      if (calView === 'month') calCursor = new Date(calCursor.getFullYear(), calCursor.getMonth() + 1, 1);
      else calCursor = calAddDays(calCursor, step);
      renderCalendar();
    });
    $('cal-today').addEventListener('click', () => { calCursor = parseYmd(todayStr); renderCalendar(); });
    $('view').querySelectorAll('[data-calview]').forEach(t => t.addEventListener('click', () => {
      calView = t.dataset.calview; localStorage.setItem('ln-calview', calView); renderCalendar();
    }));
    const connectBtn = $('cal-connect');
    if (connectBtn) connectBtn.addEventListener('click', () => { location.href = '/api/google/connect?from=calendar'; });

    // Clicks: an empty day/slot adds an appointment there; chips open their thing.
    $('view').querySelectorAll('[data-day]').forEach(c => c.addEventListener('click', (e) => {
      if (e.target.closest('[data-appt],[data-gev],[data-task],[data-more]')) return;
      apptModal(null, c.dataset.day);
    }));
    $('view').querySelectorAll('[data-slot]').forEach(c => c.addEventListener('click', (e) => {
      if (e.target.closest('[data-appt],[data-gev],[data-task]')) return;
      apptModal(null, c.dataset.slot, c.dataset.hour ? pad2(c.dataset.hour) + ':00' : '');
    }));
    $('view').querySelectorAll('[data-appt]').forEach(el => el.addEventListener('click', (e) => {
      e.stopPropagation();
      const a = appts.find(x => x.id == el.dataset.appt);
      if (a) apptModal(a, a.date);
    }));
    $('view').querySelectorAll('[data-gev]').forEach(el => el.addEventListener('click', (e) => {
      e.stopPropagation();
      const ev = events[+el.dataset.gev];
      if (ev && ev.meetLink) window.open(ev.meetLink, '_blank', 'noopener');
    }));
    $('view').querySelectorAll('[data-task]').forEach(el => el.addEventListener('click', (e) => { e.stopPropagation(); location.hash = 'tasks'; }));
    $('view').querySelectorAll('[data-more]').forEach(el => el.addEventListener('click', (e) => {
      e.stopPropagation();
      calCursor = parseYmd(el.dataset.more); calView = 'day'; localStorage.setItem('ln-calview', 'day');
      renderCalendar();
    }));
  }
  async function apptModal(appt, presetDate, presetStart) {
    let leads = leadCache;
    if (!leads.length) { try { leads = await api('/api/realtor/leads'); } catch (e) {} }
    const a = appt || { start: presetStart || '' };
    openModal(appt ? 'Edit appointment' : 'New appointment', `
      <div class="grid-form">
        <div class="field full"><label class="lbl">Title *</label><input class="input" data-f="title" value="${escA(a.title)}" placeholder="Showing at 123 Main St"></div>
        <div class="field"><label class="lbl">Type</label><select class="input" data-f="type">${APPT_TYPES.map(o => `<option ${(a.type || 'Showing') === o ? 'selected' : ''}>${o}</option>`).join('')}</select></div>
        <div class="field"><label class="lbl">Date *</label><input class="input" type="date" data-f="date" value="${escA(a.date || presetDate || '')}"></div>
        <div class="field"><label class="lbl">Start</label><input class="input" type="time" data-f="start" value="${escA(a.start)}"></div>
        <div class="field"><label class="lbl">End</label><input class="input" type="time" data-f="end" value="${escA(a.end)}"></div>
        <div class="field full"><label class="lbl">Location</label><input class="input" data-f="location" value="${escA(a.location)}" placeholder="Address or place"></div>
        <div class="field full"><label class="lbl">Link to lead (optional)</label>
          <select class="input" data-f="leadId"><option value="">— None —</option>${leads.map(l => `<option value="${l.id}" ${a.leadId === l.id ? 'selected' : ''}>${escA(l.name)}</option>`).join('')}</select></div>
        <div class="field full"><label class="lbl">Notes</label><textarea class="input" data-f="notes">${esc(a.notes)}</textarea></div>
      </div>
      ${appt ? `<div class="mt-3"><button class="btn-ghost" data-del-appt style="color:#C23B3B"><i data-lucide="trash-2"></i>Delete appointment</button></div>` : ''}`,
      appt ? 'Save' : 'Add appointment', async (root) => {
        const body = collect(root);
        if (!body.title) throw new Error('A title is required.');
        if (!body.date) throw new Error('A date is required.');
        body.leadId = body.leadId ? Number(body.leadId) : null;
        if (appt) await api('/api/realtor/appointments/' + appt.id, { method: 'PATCH', body: JSON.stringify(body) });
        else await api('/api/realtor/appointments', { method: 'POST', body: JSON.stringify(body) });
        toast(appt ? 'Appointment updated' : 'Appointment added');
        renderCalendar();
      });
    const delBtn = document.querySelector('.modal [data-del-appt]');
    if (delBtn) delBtn.addEventListener('click', async () => {
      if (!confirm('Delete this appointment?')) return;
      try { await api('/api/realtor/appointments/' + appt.id, { method: 'DELETE' }); closeModal(); toast('Appointment deleted'); renderCalendar(); }
      catch (e) { toast(e.message, 'alert-triangle'); }
    });
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

  // ---------- Automatic Emails ----------
  let emailData = null;
  async function renderEmails() {
    try { emailData = await api('/api/realtor/emails'); } catch (e) { return errView(e); }
    // One-time toast after returning from the Google consent screen.
    const gp = new URLSearchParams(location.search).get('gmail');
    if (gp) { toast(gp === 'connected' ? 'Gmail connected' : 'Couldn\'t connect Gmail', gp === 'connected' ? 'check-circle-2' : 'alert-triangle'); history.replaceState(null, '', location.pathname + location.hash); }

    const s = emailData.settings, wd = emailData.weekdays, gmail = emailData.gmail;

    // Gmail connection card — top of the section.
    const gmailCard = gmail.connected ? `
      <div class="panel p-4 mb-5 flex items-center gap-3 flex-wrap">
        <div class="stat-icon badge green" style="border-radius:11px"><i data-lucide="mail-check"></i></div>
        <div class="min-w-0 flex-1"><div class="text-[13.5px] font-bold">Gmail connected</div>
          <div class="text-[12px] text-muted truncate">Weekly emails send from ${esc(gmail.email || 'your Google account')}.</div></div>
        <button class="btn-ghost" id="gm-disconnect"><i data-lucide="unlink"></i>Disconnect</button>
      </div>`
      : gmail.configured ? `
      <div class="panel p-4 mb-5 flex items-center gap-3 flex-wrap">
        <div class="stat-icon badge gray" style="border-radius:11px"><i data-lucide="mail"></i></div>
        <div class="min-w-0 flex-1"><div class="text-[13.5px] font-bold">Send from your Gmail</div>
          <div class="text-[12px] text-muted">Connect your Google account so weekly emails go out as you.</div></div>
        <a class="btn-primary" href="/api/google/connect"><i data-lucide="mail"></i>Connect Gmail</a>
      </div>`
      : `
      <div class="panel p-4 mb-5 flex items-center gap-3 flex-wrap">
        <div class="stat-icon badge gray" style="border-radius:11px"><i data-lucide="mail"></i></div>
        <div class="min-w-0 flex-1"><div class="text-[13.5px] font-bold">Connect Gmail</div>
          <div class="text-[12px] text-muted">Add <span class="font-mono">GOOGLE_CLIENT_ID</span> / <span class="font-mono">GOOGLE_CLIENT_SECRET</span> on the server to enable this (see <span class="font-mono">.env.example</span>).</div></div>
        <button class="btn-ghost" disabled style="opacity:.55;cursor:not-allowed"><i data-lucide="mail"></i>Connect Gmail</button>
      </div>`;

    const notice = emailData.canSend ? '' : `
      <div class="panel p-3 mb-4" style="border-color:#E8C36A;background:var(--accent-weak)">
        <div class="flex items-start gap-2 text-[12.5px]">
          <i data-lucide="info" style="width:15px;height:15px;flex-shrink:0;margin-top:1px;color:var(--accent)"></i>
          <div>You can build your list, schedule, and message now. To actually <b>send</b>, connect Gmail above (or configure SMTP). Until then, sending is paused.</div>
        </div>
      </div>`;
    const recips = emailData.recipients;
    const recipRows = recips.length ? recips.map(r => `
      <div class="flex items-center gap-3 py-2 border-b border-[var(--border)] last:border-0">
        <div class="avatar sm">${initials(r.name || r.email)}</div>
        <div class="min-w-0 flex-1"><div class="text-[13px] font-semibold truncate">${esc(r.name || r.email)}</div>
          ${r.name ? `<div class="text-[11.5px] text-muted truncate">${esc(r.email)}</div>` : ''}</div>
        <button class="act" data-rm="${r.id}" title="Remove"><i data-lucide="trash-2"></i></button>
      </div>`).join('') : `<div class="text-[13px] text-muted py-6 text-center">No one on the list yet. Add your first contact above.</div>`;
    const history = emailData.history.length ? `
      <div class="panel p-4 mt-5"><h3 class="text-[14px] font-bold mb-1">Recent sends</h3>
      ${emailData.history.map(h => `<div class="flex items-center gap-3 py-2 border-b border-[var(--border)] last:border-0">
        <div class="stat-icon badge ${h.failed ? 'amber' : 'green'}" style="width:30px;height:30px;border-radius:8px"><i data-lucide="send" style="width:14px;height:14px"></i></div>
        <div class="min-w-0 flex-1"><div class="text-[12.5px] font-medium truncate">${esc(h.subject)}</div>
          <div class="text-[11.5px] text-muted">${h.sent}/${h.recipients} sent${h.failed ? ' · ' + h.failed + ' failed' : ''} · ${h.trigger}</div></div>
        <div class="text-[11px] text-muted">${fmtWhen(h.at)}</div></div>`).join('')}</div>` : '';

    $('view').innerHTML = `
      ${pageHead('Automatic Emails', 'Build a list, write your message, and let it send every week.', '')}
      ${gmailCard}
      ${notice}
      <div class="grid-2">
        <div class="panel p-4">
          <h3 class="text-[14px] font-bold mb-1">Mailing list <span class="text-muted font-medium">(${recips.length})</span></h3>
          <p class="text-[12px] text-muted mb-3">Everyone here gets the weekly email.</p>
          <div class="flex gap-2 mb-1">
            <input id="em-email" class="input" placeholder="name@email.com" style="flex:1">
            <input id="em-name" class="input" placeholder="Name (optional)" style="width:120px">
            <button class="btn-primary" id="em-add"><i data-lucide="plus"></i></button>
          </div>
          <div class="text-[11.5px] text-muted mb-3">Tip: paste several addresses separated by commas to add them all.</div>
          ${recipRows}
        </div>
        <div class="panel p-4">
          <div class="flex items-start justify-between gap-3 mb-3">
            <div><h3 class="text-[14px] font-bold">Weekly schedule</h3><p class="text-[12px] text-muted">Send automatically once a week.</p></div>
            <button id="em-toggle" role="switch" aria-checked="${s.enabled}" style="position:relative;width:44px;height:26px;border-radius:13px;border:none;cursor:pointer;flex-shrink:0;transition:background .15s;background:${s.enabled ? 'var(--accent)' : 'var(--border-strong)'}">
              <span id="em-knob" style="position:absolute;top:3px;left:${s.enabled ? '21px' : '3px'};width:20px;height:20px;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.25);transition:left .15s"></span></button>
          </div>
          <div class="field mb-3"><label class="lbl">Send every</label>
            <select id="em-day" class="input mt-1">${wd.map((d, i) => `<option value="${i}" ${s.sendDay === i ? 'selected' : ''}>${d}</option>`).join('')}</select></div>
          <div class="text-[12px] text-muted mb-3">${s.lastRun ? 'Last sent ' + fmtDate(s.lastRun) + '.' : 'Not sent yet.'}</div>
          <button class="btn-ghost w-full justify-center" id="em-send"><i data-lucide="send"></i>Send to everyone now</button>
        </div>
      </div>
      <div class="panel p-5 mt-5" style="max-width:720px">
        <h3 class="text-[14px] font-bold mb-1">The email</h3>
        <p class="text-[12px] text-muted mb-3">This is what goes out each week. Edit it anytime.</p>
        <div class="field mb-3"><label class="lbl">Subject</label><input id="em-subject" class="input mt-1" value="${escA(s.subject)}"></div>
        <div class="field mb-3"><label class="lbl">Message</label><textarea id="em-body" class="input mt-1" style="min-height:180px">${esc(s.body)}</textarea></div>
        <div class="flex items-center gap-3"><button class="btn-primary" id="em-save"><i data-lucide="check"></i>Save email</button><span id="em-msg" class="text-[12.5px] font-medium"></span></div>
      </div>
      ${history}`;
    icons();

    // Disconnect Gmail
    const disc = $('gm-disconnect');
    if (disc) disc.addEventListener('click', async () => {
      if (!confirm('Disconnect your Gmail? Weekly emails will stop sending until you reconnect (or configure SMTP).')) return;
      try { await api('/api/google/disconnect', { method: 'POST' }); toast('Gmail disconnected'); renderEmails(); }
      catch (e) { toast(e.message, 'alert-triangle'); }
    });

    // Add recipient(s)
    async function addRecip() {
      const raw = $('em-email').value.trim(); const name = $('em-name').value.trim();
      if (!raw) return;
      const parts = raw.split(/[,\n;]+/).map(x => x.trim()).filter(Boolean);
      try {
        if (parts.length > 1) {
          const res = await api('/api/realtor/emails/recipients/import', { method: 'POST', body: JSON.stringify({ emails: parts }) });
          toast(`Added ${res.added}${res.skipped ? ', skipped ' + res.skipped : ''}`);
        } else {
          await api('/api/realtor/emails/recipients', { method: 'POST', body: JSON.stringify({ email: parts[0], name }) });
          toast('Added to list');
        }
        renderEmails();
      } catch (e) { toast(e.message, 'alert-triangle'); }
    }
    $('em-add').addEventListener('click', addRecip);
    $('em-email').addEventListener('keydown', e => { if (e.key === 'Enter') addRecip(); });
    $('em-name').addEventListener('keydown', e => { if (e.key === 'Enter') addRecip(); });
    $('view').querySelectorAll('[data-rm]').forEach(b => b.addEventListener('click', async () => {
      await api('/api/realtor/emails/recipients/' + b.dataset.rm, { method: 'DELETE' }); toast('Removed'); renderEmails();
    }));

    // Save settings helper (subject/body/enabled/sendDay)
    async function saveSettings(patch, okMsg) {
      const body = Object.assign({ subject: $('em-subject').value, body: $('em-body').value, enabled: s.enabled, sendDay: Number($('em-day').value) }, patch);
      const res = await api('/api/realtor/emails/settings', { method: 'PUT', body: JSON.stringify(body) });
      emailData.settings = res; Object.assign(s, res);
      if (okMsg) toast(okMsg);
      return res;
    }
    let on = s.enabled;
    $('em-toggle').addEventListener('click', async () => {
      on = !on;
      $('em-toggle').style.background = on ? 'var(--accent)' : 'var(--border-strong)';
      $('em-knob').style.left = on ? '21px' : '3px';
      $('em-toggle').setAttribute('aria-checked', on);
      try { await saveSettings({ enabled: on }, on ? 'Weekly sending on' : 'Weekly sending off'); }
      catch (e) { toast(e.message, 'alert-triangle'); }
    });
    $('em-day').addEventListener('change', async () => { try { await saveSettings({ sendDay: Number($('em-day').value) }, 'Schedule updated'); } catch (e) { toast(e.message, 'alert-triangle'); } });
    $('em-save').addEventListener('click', async () => {
      const msg = $('em-msg'); msg.style.color = '#C23B3B';
      try { await saveSettings({}); msg.style.color = '#1B7F4B'; msg.textContent = 'Saved.'; toast('Email saved'); }
      catch (e) { msg.textContent = e.message; }
    });
    $('em-send').addEventListener('click', async () => {
      if (!recips.length) return toast('Add someone to your list first.', 'info');
      if (!confirm(`Send this email to all ${recips.length} recipient${recips.length === 1 ? '' : 's'} now?`)) return;
      const btn = $('em-send'); btn.disabled = true;
      try { const r = await api('/api/realtor/emails/send-now', { method: 'POST' }); toast(`Sent to ${r.sent} of ${r.recipients}`); renderEmails(); }
      catch (e) { toast(e.message, 'alert-triangle'); btn.disabled = false; }
    });
  }

  // ---------- Reports ----------
  function money(n) {
    n = Number(n) || 0;
    if (n >= 1e6) return '$' + (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + 'M';
    if (n >= 1e3) return '$' + Math.round(n / 1e3) + 'k';
    return '$' + n.toLocaleString();
  }
  async function renderReports() {
    let d;
    try { d = await api('/api/realtor/reports'); } catch (e) { return errView(e); }
    const stat = (icon, tone, val, label) => `<div class="panel stat">
      <div class="stat-icon badge ${tone}" style="border-radius:11px"><i data-lucide="${icon}"></i></div>
      <div><div class="text-[22px] font-bold leading-none">${val}</div><div class="text-[12px] text-muted mt-1">${label}</div></div></div>`;

    // Funnel: stages + closed, as proportional bars.
    const funnelRows = d.funnel.concat([{ stage: 'Closed', count: d.closedTotal }]);
    const maxF = Math.max(1, ...funnelRows.map(f => f.count));
    const funnel = funnelRows.map(f => {
      const pct = Math.round((f.count / maxF) * 100);
      const tone = f.stage === 'Closed' ? 'var(--accent)' : 'var(--accent-2, var(--accent))';
      return `<div class="mb-2.5">
        <div class="flex items-center justify-between text-[12.5px] mb-1"><span class="font-semibold">${f.stage}</span><span class="text-muted num">${f.count}</span></div>
        <div style="height:22px;border-radius:6px;background:var(--surface-3);overflow:hidden">
          <div style="height:100%;width:${Math.max(pct, f.count ? 6 : 0)}%;background:${tone};border-radius:6px;transition:width .3s"></div></div>
      </div>`;
    }).join('');

    // Source ROI table.
    const maxSrc = Math.max(1, ...d.sources.map(s => s.leads + s.closed));
    const srcRows = d.sources.length ? d.sources.map(s => {
      const total = s.leads + s.closed;
      const conv = total ? Math.round((s.closed / total) * 100) : 0;
      return `<tr>
        <td class="font-semibold">${esc(s.source)}</td>
        <td class="num">${s.leads}</td>
        <td class="num">${s.closed}</td>
        <td class="num">${conv}%</td>
        <td style="width:120px"><div style="height:8px;border-radius:4px;background:var(--surface-3);overflow:hidden"><div style="height:100%;width:${Math.round((total / maxSrc) * 100)}%;background:var(--accent);border-radius:4px"></div></div></td>
      </tr>`;
    }).join('') : `<tr><td colspan="5"><div class="text-[13px] text-muted py-6 text-center">No lead sources yet. Add a source when creating leads (or use the intake form).</div></td></tr>`;

    $('view').innerHTML = `
      ${pageHead('Reports', 'Your funnel, this month\'s production, and where deals come from.', '')}
      <div class="grid-stats mb-6">
        ${stat('trending-up', 'blue', d.month.newLeads, 'New leads this month')}
        ${stat('handshake', 'green', d.month.deals, 'Deals closed this month')}
        ${stat('dollar-sign', 'amber', money(d.month.volume), 'Volume this month')}
        ${stat('percent', 'purple', d.totals.conversion + '%', 'Lead → close rate')}
      </div>
      <div class="grid-2">
        <div class="panel p-5">
          <h3 class="text-[14px] font-bold mb-3">Pipeline funnel</h3>
          ${funnel}
          <div class="text-[12px] text-muted mt-3 pt-3 border-t border-[var(--border)]">All-time closed volume: <b>${money(d.totals.volume)}</b> across ${d.closedTotal} deal${d.closedTotal === 1 ? '' : 's'}.</div>
        </div>
        <div class="panel p-5">
          <h3 class="text-[14px] font-bold mb-1">Lead sources</h3>
          <p class="text-[12px] text-muted mb-3">Which channels bring leads — and which actually close.</p>
          <div style="overflow-x:auto"><table class="tbl">
            <thead><tr><th>Source</th><th>Leads</th><th>Closed</th><th>Conv.</th><th>Volume</th></tr></thead>
            <tbody>${srcRows}</tbody></table></div>
        </div>
      </div>`;
    icons();
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
