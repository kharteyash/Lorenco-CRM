// LeadNest server: Express + Postgres + bcrypt + cookie sessions.
// A realtor CRM — each account manages its own leads, contacts, calls, follow-up
// tasks, and past clients. Everything is scoped to the signed-in account; there is
// no loan-officer side and no cross-account messaging.

const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');

// Load environment variables from .env (DATABASE_URL, etc.).
try { process.loadEnvFile(path.join(__dirname, '.env')); } catch (e) { /* no .env file — that's fine */ }

if (!process.env.DATABASE_URL) {
  console.error('\n❌ DATABASE_URL is not set.');
  console.error('   Create a free Postgres database (e.g. neon.tech) and put its connection');
  console.error('   string in a .env file as DATABASE_URL=postgres://...  then run `npm start`.\n');
  process.exit(1);
}

const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const SESSION_COOKIE = 'ln_session';
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

// ----- Google OAuth (for "send as my Gmail") -----
const GOOGLE = {
  clientId: process.env.GOOGLE_CLIENT_ID || '',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
  redirectUri: process.env.GOOGLE_REDIRECT_URI || `http://localhost:${PORT}/api/google/callback`,
  scopes: ['openid', 'email', 'profile', 'https://www.googleapis.com/auth/gmail.send']
};
const googleConfigured = () => !!(GOOGLE.clientId && GOOGLE.clientSecret);
const oauthStates = new Map(); // state -> { userId, exp }  (CSRF + user mapping)

// Optional encryption at rest for OAuth tokens. Set TOKEN_ENC_KEY (any strong
// passphrase) to turn it on; without it tokens are stored as-is. Reads handle
// both encrypted ("enc:v1:…") and legacy plaintext transparently.
const TOKEN_KEY = process.env.TOKEN_ENC_KEY
  ? crypto.createHash('sha256').update(String(process.env.TOKEN_ENC_KEY)).digest() : null;
function encToken(plain) {
  if (plain == null || !TOKEN_KEY) return plain;
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', TOKEN_KEY, iv);
  const enc = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return 'enc:v1:' + Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64');
}
function decToken(stored) {
  if (typeof stored !== 'string' || !stored.startsWith('enc:v1:')) return stored;
  if (!TOKEN_KEY) { console.error('TOKEN_ENC_KEY missing but an encrypted token was found.'); return null; }
  try {
    const raw = Buffer.from(stored.slice(7), 'base64');
    const d = crypto.createDecipheriv('aes-256-gcm', TOKEN_KEY, raw.subarray(0, 12));
    d.setAuthTag(raw.subarray(12, 28));
    return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8');
  } catch (e) { console.error('Token decrypt failed:', e.message); return null; }
}

// ----- Database -----
const isLocalDb = /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL);
// TLS to the database is verified by default (closes a man-in-the-middle gap).
// Neon and most managed providers use publicly-trusted certs, so Node's built-in
// CA store validates them with no extra config. Escape hatches:
//   DATABASE_CA_CERT            — a custom CA (PEM string) to trust instead
//   DATABASE_SSL_NO_VERIFY=true — restore unverified behavior (last resort)
function dbSsl() {
  if (isLocalDb) return false;
  if (String(process.env.DATABASE_SSL_NO_VERIFY).toLowerCase() === 'true') return { rejectUnauthorized: false };
  if (process.env.DATABASE_CA_CERT) return { ca: process.env.DATABASE_CA_CERT, rejectUnauthorized: true };
  return { rejectUnauthorized: true };
}
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: dbSsl() });
const q   = async (text, params) => (await pool.query(text, params)).rows;
const one = async (text, params) => { const r = await pool.query(text, params); return r.rows[0] || null; };

// Today's date as YYYY-MM-DD (server-local).
const serverToday = () => {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
};
// Add n days to a 'YYYY-MM-DD' string, returning the same format.
const addDaysStr = (ymd, n) => {
  const d = new Date(ymd + 'T00:00:00');
  d.setDate(d.getDate() + n);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
};
// Today's date (YYYY-MM-DD) as it reads in the given IANA tz, falling back to
// server-local time. Matters because the app often runs in UTC when hosted:
// without it, call queues and task due dates roll over at UTC midnight instead
// of the user's local midnight.
const todayInTz = (tz) => {
  try {
    const map = {};
    for (const p of new Intl.DateTimeFormat('en-CA',
      { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(new Date())) {
      map[p.type] = p.value;
    }
    if (map.year && map.month && map.day) return `${map.year}-${map.month}-${map.day}`;
  } catch (e) { /* invalid tz → fall back below */ }
  return serverToday();
};
// Today for a specific user, honoring their configured timezone.
async function userToday(userId) {
  const u = await one('SELECT tz FROM users WHERE id = $1', [userId]);
  return (u && u.tz) ? todayInTz(u.tz) : serverToday();
}

// Display phone numbers as (xxx) xxx-xxxx. Standard US 10-digit numbers (or
// 11-digit starting with a 1) are reformatted; anything else (international,
// extensions, partials) is returned trimmed but otherwise untouched.
const formatPhone = (raw) => {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return '';
  let d = s.replace(/\D/g, '');
  if (d.length === 11 && d[0] === '1') d = d.slice(1);
  if (d.length === 10) return `(${d.slice(0, 3)}) ${d.slice(3, 6)}-${d.slice(6)}`;
  return s;
};

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    email         TEXT NOT NULL,
    name          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    phone         TEXT,
    tz            TEXT,
    auto_tasks_enabled BOOLEAN DEFAULT TRUE,
    created_at    TIMESTAMPTZ DEFAULT now()
  );
  CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_idx ON users (lower(email));
  ALTER TABLE users ADD COLUMN IF NOT EXISTS tz TEXT;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS auto_tasks_enabled BOOLEAN DEFAULT TRUE;
  -- Public lead-capture form token (the shareable /apply/<token> intake link).
  ALTER TABLE users ADD COLUMN IF NOT EXISTS capture_token TEXT;
  CREATE UNIQUE INDEX IF NOT EXISTS users_capture_token_idx ON users (capture_token);

  CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
  );

  -- A realtor's leads (their book of business).
  CREATE TABLE IF NOT EXISTS realtor_leads (
    id            SERIAL PRIMARY KEY,
    realtor_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    phone         TEXT,
    email         TEXT,
    intent        TEXT,            -- Buying | Selling | Both
    timeline      TEXT,
    budget        TEXT,
    property_type TEXT,
    area          TEXT,
    zipcode       TEXT,
    financing     TEXT,            -- Pre-approved | Needs a lender | Paying cash | Not sure
    credit_score  TEXT,
    assets        TEXT,
    notes         TEXT,
    stage         TEXT DEFAULT 'New',   -- New | Contacted | Showing | Offer | Under Contract
    source        TEXT,                 -- where the lead came from (Zillow, referral, ...)
    created_at    TIMESTAMPTZ DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS realtor_leads_owner ON realtor_leads (realtor_id, id);
  ALTER TABLE realtor_leads ADD COLUMN IF NOT EXISTS stage TEXT DEFAULT 'New';
  ALTER TABLE realtor_leads ADD COLUMN IF NOT EXISTS source TEXT;

  -- A realtor's own saved contacts (their address book, separate from leads).
  CREATE TABLE IF NOT EXISTS realtor_contacts (
    id         SERIAL PRIMARY KEY,
    realtor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    email      TEXT,
    phone      TEXT,
    company    TEXT,
    tag        TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS realtor_contacts_owner ON realtor_contacts (realtor_id, id);

  -- A realtor's logged calls (drives "who to call next" and the call history).
  CREATE TABLE IF NOT EXISTS realtor_calls (
    id         SERIAL PRIMARY KEY,
    realtor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lead_id    INTEGER,
    name       TEXT NOT NULL,
    phone      TEXT,
    outcome    TEXT NOT NULL,         -- Connected | Voicemail | No Answer | Missed
    notes      TEXT,
    logged_at  TIMESTAMPTZ DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS realtor_calls_owner ON realtor_calls (realtor_id, id);

  -- A realtor's past clients (closed leads): carries the lead info + the deal.
  CREATE TABLE IF NOT EXISTS realtor_clients (
    id            SERIAL PRIMARY KEY,
    realtor_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    phone         TEXT,
    email         TEXT,
    intent        TEXT,
    budget        TEXT,
    property_type TEXT,
    area          TEXT,
    zipcode       TEXT,
    deal_type     TEXT,        -- Bought | Sold | Both
    address       TEXT,
    price         TEXT,
    closed_date   TEXT,        -- YYYY-MM-DD
    notes         TEXT,
    created_at    TIMESTAMPTZ DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS realtor_clients_owner ON realtor_clients (realtor_id, id);

  -- A realtor's personal follow-up tasks ("Call back Tuesday"). Optionally tied
  -- to one of their own leads so the task shows in that lead's timeline.
  CREATE TABLE IF NOT EXISTS realtor_tasks (
    id           SERIAL PRIMARY KEY,
    realtor_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lead_id      INTEGER REFERENCES realtor_leads(id) ON DELETE SET NULL,
    title        TEXT NOT NULL,
    due_date     TEXT,                 -- YYYY-MM-DD
    priority     TEXT DEFAULT 'Medium',-- High | Medium | Low
    status       TEXT DEFAULT 'todo',  -- todo | done
    source       TEXT DEFAULT 'manual',-- 'manual' or 'auto:new-lead' / 'auto:missed-call' / ...
    created_at   TIMESTAMPTZ DEFAULT now(),
    completed_at TIMESTAMPTZ
  );
  CREATE INDEX IF NOT EXISTS realtor_tasks_owner ON realtor_tasks (realtor_id, id);

  -- Append-only, timestamped notes on a realtor's lead (the activity timeline).
  CREATE TABLE IF NOT EXISTS realtor_lead_notes (
    id         SERIAL PRIMARY KEY,
    realtor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lead_id    INTEGER NOT NULL REFERENCES realtor_leads(id) ON DELETE CASCADE,
    body       TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS realtor_lead_notes_lead ON realtor_lead_notes (lead_id, id);

  -- Automatic emails: a mailing list of recipients per account.
  CREATE TABLE IF NOT EXISTS email_recipients (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email      TEXT NOT NULL,
    name       TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS email_recipients_owner ON email_recipients (user_id, id);
  -- One address only once per account.
  CREATE UNIQUE INDEX IF NOT EXISTS email_recipients_uniq ON email_recipients (user_id, lower(email));

  -- The weekly-email settings for an account: the template (subject/body), whether
  -- it's on, which weekday to send (0=Sun..6=Sat), and the last date it ran (guards
  -- against double-sends). One row per user.
  CREATE TABLE IF NOT EXISTS email_settings (
    user_id       INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    subject       TEXT,
    body          TEXT,
    enabled       BOOLEAN DEFAULT FALSE,
    send_day      INTEGER DEFAULT 1,
    last_run_date TEXT,
    updated_at    TIMESTAMPTZ DEFAULT now()
  );

  -- Per-user connected Google account (for sending weekly email as themselves
  -- via the Gmail API). Tokens may be stored encrypted (see TOKEN_ENC_KEY).
  CREATE TABLE IF NOT EXISTS google_accounts (
    user_id       INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    email         TEXT,
    access_token  TEXT,
    refresh_token TEXT,
    expires_at    BIGINT
  );

  -- A record of each weekly send, for the "recent sends" history.
  CREATE TABLE IF NOT EXISTS email_sends (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject     TEXT,
    recipients  INTEGER DEFAULT 0,
    sent        INTEGER DEFAULT 0,
    failed      INTEGER DEFAULT 0,
    trigger     TEXT,           -- 'weekly' | 'manual'
    created_at  TIMESTAMPTZ DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS email_sends_owner ON email_sends (user_id, id);
`;

// Periodically clear expired sessions.
setInterval(() => {
  pool.query('DELETE FROM sessions WHERE expires_at <= now()').catch(() => {});
}, 60 * 60 * 1000);

// ----- Session helpers -----
async function createSession(userId) {
  const id = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  await q('INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, $3)', [id, userId, expires]);
  return id;
}
async function loadUserFromSession(sid) {
  if (!sid) return null;
  const row = await one(`
    SELECT u.id, u.email, u.name, u.phone, u.auto_tasks_enabled
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.id = $1 AND s.expires_at > now()
  `, [sid]);
  if (!row) return null;
  return {
    id: row.id, email: row.email, name: row.name, phone: row.phone || '',
    // Default to ON when the column is NULL (existing rows before this feature).
    autoTasks: row.auto_tasks_enabled !== false
  };
}
function setSessionCookie(res, sid) {
  res.cookie(SESSION_COOKIE, sid, {
    httpOnly: true, sameSite: 'lax', secure: IS_PROD, maxAge: SESSION_TTL_MS
  });
}

// ----- App -----
const app = express();
app.set('trust proxy', 1); // behind most PaaS proxies, for secure cookies
app.use(express.json());
app.use(cookieParser());

// Baseline security headers.
app.use((req, res, next) => {
  res.set('X-Frame-Options', 'SAMEORIGIN');
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.set('Cross-Origin-Opener-Policy', 'same-origin');
  if (IS_PROD) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});
// API responses must never be cached by the browser.
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) res.set('Cache-Control', 'no-store');
  next();
});
// Resolve req.user from the session cookie (skip static assets to avoid a DB hit per file).
app.use(async (req, res, next) => {
  const needsUser = req.path === '/' || req.path.endsWith('.html') || req.path.startsWith('/api/');
  if (needsUser) {
    try { req.user = await loadUserFromSession(req.cookies[SESSION_COOKIE]); }
    catch (e) { req.user = null; }
  }
  next();
});

// Wraps a route handler (sync or async) so any thrown/rejected error becomes a JSON 500.
function safe(handler) {
  return (req, res, next) => {
    Promise.resolve()
      .then(() => handler(req, res, next))
      .catch(err => {
        console.error(`[${req.method} ${req.path}] error:`, err);
        if (!res.headersSent) res.status(500).json({ error: 'Server error: ' + (err.message || String(err)) });
      });
  };
}
// Gate every /api/* route (except the auth basics) behind a valid session.
function requireUser(req, res) {
  if (!req.user) { res.status(401).json({ error: 'Not authenticated.' }); return false; }
  return true;
}

// ----- In-memory per-IP rate limiter (single instance — fine for this deployment) -----
const rateBuckets = new Map();
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  const b = rateBuckets.get(key);
  if (!b || b.reset <= now) { rateBuckets.set(key, { count: 1, reset: now + windowMs }); return true; }
  b.count++;
  return b.count <= max;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, b] of rateBuckets) if (b.reset <= now) rateBuckets.delete(k);
}, 10 * 60 * 1000).unref();

// ===================================================================
// Auth
// ===================================================================
app.post('/api/register', safe(async (req, res) => {
  if (!rateLimit('reg:' + req.ip, 10, 15 * 60 * 1000)) {
    return res.status(429).json({ error: 'Too many attempts. Please wait a few minutes and try again.' });
  }
  const { email, name, password } = req.body || {};
  if (!email || !name || !password) return res.status(400).json({ error: 'All fields are required.' });
  if (String(password).length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const emailNorm = String(email).trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(emailNorm)) return res.status(400).json({ error: 'Enter a valid email address.' });

  const existing = await one('SELECT id FROM users WHERE lower(email) = lower($1)', [emailNorm]);
  if (existing) return res.status(409).json({ error: 'An account with that email already exists.' });

  const hash = bcrypt.hashSync(String(password), 10);
  const row = await one('INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3) RETURNING id',
    [emailNorm, String(name).trim().slice(0, 120), hash]);
  const sid = await createSession(row.id);
  setSessionCookie(res, sid);
  res.json({ id: row.id, email: emailNorm, name: String(name).trim() });
}));

// A constant bcrypt hash to compare against when an email isn't found, so a
// missing account takes the same time as a wrong password (no timing oracle).
const DUMMY_HASH = bcrypt.hashSync('ln-timing-equalizer', 10);

app.post('/api/login', safe(async (req, res) => {
  if (!rateLimit('login:' + req.ip, 15, 15 * 60 * 1000)) {
    return res.status(429).json({ error: 'Too many attempts. Please wait a few minutes and try again.' });
  }
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
  const user = await one('SELECT * FROM users WHERE lower(email) = lower($1)', [String(email).trim()]);
  const ok = bcrypt.compareSync(String(password), user ? user.password_hash : DUMMY_HASH);
  if (!user || !ok) return res.status(401).json({ error: 'Invalid email or password.' });
  const sid = await createSession(user.id);
  setSessionCookie(res, sid);
  res.json({ id: user.id, email: user.email, name: user.name });
}));

app.post('/api/logout', safe(async (req, res) => {
  const sid = req.cookies[SESSION_COOKIE];
  if (sid) await q('DELETE FROM sessions WHERE id = $1', [sid]);
  res.clearCookie(SESSION_COOKIE);
  res.json({ ok: true });
}));

app.get('/api/me', safe(async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated.' });
  res.json({ id: req.user.id, email: req.user.email, name: req.user.name, phone: req.user.phone, autoTasks: req.user.autoTasks });
}));

app.post('/api/change-password', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const { current, next } = req.body || {};
  if (!current || !next) return res.status(400).json({ error: 'Both fields are required.' });
  if (String(next).length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  const user = await one('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
  if (!bcrypt.compareSync(String(current), user.password_hash)) {
    return res.status(400).json({ error: 'Your current password is incorrect.' });
  }
  await q('UPDATE users SET password_hash = $1 WHERE id = $2', [bcrypt.hashSync(String(next), 10), req.user.id]);
  // Sign out other sessions for safety, keep the current one.
  await q('DELETE FROM sessions WHERE user_id = $1 AND id <> $2', [req.user.id, req.cookies[SESSION_COOKIE]]);
  res.json({ ok: true });
}));

// ===================================================================
// Lead scoring & auto follow-ups (the "who to call next" brain)
// ===================================================================
// Readiness is inferred from what the realtor captured: timeline, financing,
// credit, intent. Higher = more ready to transact, so call them first.
function scoreRealtorLead(l) {
  let score = 0; const why = [];
  if (l.intent === 'Both') { score += 10; why.push('Buying & selling'); }
  else if (l.intent) { score += 5; why.push(l.intent); }
  const tl = (l.timeline || '').toLowerCase();
  if (tl.includes('asap')) { score += 40; why.push('ASAP'); }
  else if (tl.includes('1-3')) { score += 30; why.push('1-3 months'); }
  else if (tl.includes('3-6')) { score += 20; why.push('3-6 months'); }
  else if (tl.includes('6+')) { score += 10; why.push('6+ months'); }
  else if (tl.includes('brows')) { score += 0; why.push('Just browsing'); }
  const fin = (l.financing || '');
  if (fin === 'Pre-approved') { score += 30; why.push('Pre-approved'); }
  else if (fin === 'Paying cash') { score += 28; why.push('Paying cash'); }
  else if (fin === 'Needs a lender') { score += 12; why.push('Needs a lender'); }
  else if (fin === 'Not sure') { score += 5; }
  const cred = String(l.credit_score || '').trim();
  const credMap = { '741+': 12, '681-740': 8, '621-680': 4, '581-620': 2, '<580': 0 };
  if (Object.prototype.hasOwnProperty.call(credMap, cred)) {
    score += credMap[cred];
    if (credMap[cred] >= 8) why.push(`${cred} credit`);
  } else {
    const m = cred.match(/\d{3}/); const cs = m ? +m[0] : NaN;
    if (!isNaN(cs)) { if (cs >= 740) { score += 12; why.push(`${cs} credit`); } else if (cs >= 680) { score += 8; why.push(`${cs} credit`); } else if (cs >= 620) { score += 4; } }
  }
  if (String(l.assets || '').trim()) { score += 4; }
  const priority = score >= 55 ? 'High' : score >= 28 ? 'Medium' : 'Low';
  const reason = why.slice(0, 3).join(' · ') || 'Follow up';
  return { score, priority, reason };
}

const REALTOR_MISS_OUTCOMES = ['Voicemail', 'No Answer', 'Missed'];
// Auto-create follow-up tasks from a realtor's own activity. Idempotent: the
// `source` tag + lead_id guard against duplicates, and a completed/deleted auto
// task is never recreated for the same trigger. Respects the realtor's toggle.
//   1 new-lead    — has a phone, never called            -> once per lead
//   2 missed-call — most recent call was a miss           -> once per miss
//   3 cold        — High-readiness, quiet 7+ days         -> recurs weekly
//   4 timeline    — ASAP/1-3mo timeline, quiet 10+ days   -> recurs ~2 weeks
async function ensureRealtorFollowups(userId) {
  const u = await one('SELECT auto_tasks_enabled FROM users WHERE id = $1', [userId]);
  if (u && u.auto_tasks_enabled === false) return;
  const today = await userToday(userId);

  const leads = await q('SELECT * FROM realtor_leads WHERE realtor_id = $1', [userId]);
  if (!leads.length) return;

  const calls = await q('SELECT lead_id, name, outcome, logged_at FROM realtor_calls WHERE realtor_id = $1 ORDER BY logged_at DESC', [userId]);
  const noteRows = await q('SELECT lead_id, MAX(created_at) AS at FROM realtor_lead_notes WHERE realtor_id = $1 GROUP BY lead_id', [userId]);
  const noteAt = {}; noteRows.forEach(n => { noteAt[n.lead_id] = n.at; });
  const latestCallFor = (l) => calls.find(c => c.lead_id === l.id || (c.name && l.name && c.name.toLowerCase() === l.name.toLowerCase())) || null;

  const autoRows = await q(`SELECT lead_id, source, MAX(created_at) AS at FROM realtor_tasks
                            WHERE realtor_id = $1 AND source LIKE 'auto:%' AND lead_id IS NOT NULL
                            GROUP BY lead_id, source`, [userId]);
  const lastAuto = {}; autoRows.forEach(r => { lastAuto[r.lead_id + '|' + r.source] = r.at; });
  const autoAt = (leadId, source) => lastAuto[leadId + '|' + source];
  const daysSince = (d) => d ? (Date.now() - new Date(d).getTime()) / 864e5 : Infinity;

  const insert = (leadId, title, due, priority, source) => pool.query(
    `INSERT INTO realtor_tasks (realtor_id, lead_id, title, due_date, priority, source) VALUES ($1,$2,$3,$4,$5,$6)`,
    [userId, leadId, title, due, priority, source]);

  for (const l of leads) {
    const phone = String(l.phone || '').trim();
    const lc = latestCallFor(l);

    // Rule 1 — brand-new lead, never called.
    if (phone && !lc) {
      if (!autoAt(l.id, 'auto:new-lead')) await insert(l.id, `Call ${l.name} — new lead`, today, 'High', 'auto:new-lead');
      continue;
    }
    // Rule 2 — most recent call was a miss; one retry per miss event.
    if (lc && REALTOR_MISS_OUTCOMES.indexOf(lc.outcome) >= 0) {
      const at = autoAt(l.id, 'auto:missed-call');
      if (!at || new Date(at) <= new Date(lc.logged_at))
        await insert(l.id, `Try ${l.name} again — ${String(lc.outcome).toLowerCase()}`, addDaysStr(today, 2), 'Medium', 'auto:missed-call');
      continue;
    }
    const quietDays = Math.min(daysSince(lc ? lc.logged_at : null), daysSince(noteAt[l.id]));
    const pri = scoreRealtorLead(l).priority;
    // Rule 3 — hot lead going cold (High readiness, quiet 7+ days). Recurs weekly.
    if (phone && pri === 'High' && quietDays >= 7) {
      const at = autoAt(l.id, 'auto:cold');
      if (!at || daysSince(at) >= 7) await insert(l.id, `Follow up with ${l.name} — hot lead going quiet`, today, 'High', 'auto:cold');
      continue;
    }
    // Rule 4 — urgent timeline check-in (ASAP / 1-3mo, quiet 10+ days). Recurs ~2 weeks.
    const tl = String(l.timeline || '').toLowerCase();
    if (phone && (tl.includes('asap') || tl.includes('1-3')) && quietDays >= 10) {
      const at = autoAt(l.id, 'auto:timeline');
      if (!at || daysSince(at) >= 14) await insert(l.id, `Check in with ${l.name} — ${l.timeline} timeline`, today, 'Medium', 'auto:timeline');
    }
  }
}

// ===================================================================
// Leads
// ===================================================================
const REALTOR_LEAD_INTENTS = ['Buying', 'Selling', 'Both'];
const REALTOR_LEAD_FINANCING = ['Pre-approved', 'Needs a lender', 'Paying cash', 'Not sure'];
const REALTOR_LEAD_STAGES = ['New', 'Contacted', 'Showing', 'Offer', 'Under Contract'];
function realtorLeadRowToJson(r) {
  return {
    id: r.id, name: r.name, phone: r.phone || '', email: r.email || '',
    intent: r.intent || '', timeline: r.timeline || '', budget: r.budget || '',
    propertyType: r.property_type || '', area: r.area || '', zipcode: r.zipcode || '', financing: r.financing || '',
    creditScore: r.credit_score || '', assets: r.assets || '', notes: r.notes || '',
    stage: r.stage || 'New', source: r.source || '', created: r.created_at
  };
}
function cleanRealtorLead(b) {
  const s = (v, n) => String(v == null ? '' : v).trim().slice(0, n);
  const oneOf = (v, list) => { const t = s(v, 40); return list.includes(t) ? t : ''; };
  return {
    name: s(b.name, 120), phone: formatPhone(s(b.phone, 40)), email: s(b.email, 160),
    intent: oneOf(b.intent, REALTOR_LEAD_INTENTS), timeline: s(b.timeline, 60), budget: s(b.budget, 60),
    propertyType: s(b.propertyType, 60), area: s(b.area, 120), zipcode: s(b.zipcode, 20),
    financing: oneOf(b.financing, REALTOR_LEAD_FINANCING), creditScore: s(b.creditScore, 40),
    assets: s(b.assets, 120), notes: s(b.notes, 2000),
    stage: REALTOR_LEAD_STAGES.includes(s(b.stage, 40)) ? s(b.stage, 40) : 'New',
    source: s(b.source, 60)
  };
}
async function ownRealtorLead(realtorId, leadId) {
  if (!leadId) return null;
  const r = await one('SELECT id FROM realtor_leads WHERE id = $1 AND realtor_id = $2', [leadId, realtorId]);
  return r ? r.id : null;
}

app.get('/api/realtor/leads', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const rows = await q('SELECT * FROM realtor_leads WHERE realtor_id = $1 ORDER BY id DESC', [req.user.id]);
  res.json(rows.map(realtorLeadRowToJson));
}));

app.post('/api/realtor/leads', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const f = cleanRealtorLead(req.body || {});
  if (!f.name) return res.status(400).json({ error: 'A name is required.' });
  const row = await one(
    `INSERT INTO realtor_leads (realtor_id, name, phone, email, intent, timeline, budget, property_type, area, financing, notes, credit_score, assets, zipcode, stage, source)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *`,
    [req.user.id, f.name, f.phone, f.email, f.intent, f.timeline, f.budget, f.propertyType, f.area, f.financing, f.notes, f.creditScore, f.assets, f.zipcode, f.stage, f.source]
  );
  res.json(realtorLeadRowToJson(row));
}));

app.patch('/api/realtor/leads/:id', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id.' });
  const cur = await one('SELECT * FROM realtor_leads WHERE id = $1 AND realtor_id = $2', [id, req.user.id]);
  if (!cur) return res.status(404).json({ error: 'Lead not found.' });
  const f = cleanRealtorLead(req.body || {});
  if (!f.name) return res.status(400).json({ error: 'A name is required.' });
  // Keep the current stage/source when the caller doesn't send them (e.g. the
  // edit form) so a plain edit never resets a lead's pipeline position.
  const stage = (req.body || {}).stage !== undefined ? f.stage : (cur.stage || 'New');
  const source = (req.body || {}).source !== undefined ? f.source : (cur.source || '');
  const row = await one(
    `UPDATE realtor_leads SET name=$1, phone=$2, email=$3, intent=$4, timeline=$5, budget=$6, property_type=$7,
       area=$8, financing=$9, notes=$10, credit_score=$11, assets=$12, zipcode=$15, stage=$16, source=$17 WHERE id=$13 AND realtor_id=$14 RETURNING *`,
    [f.name, f.phone, f.email, f.intent, f.timeline, f.budget, f.propertyType, f.area, f.financing, f.notes, f.creditScore, f.assets, id, req.user.id, f.zipcode, stage, source]
  );
  res.json(realtorLeadRowToJson(row));
}));

// Quick stage change (used by the pipeline board's drag-and-drop).
app.patch('/api/realtor/leads/:id/stage', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id.' });
  const stage = String((req.body || {}).stage || '');
  if (!REALTOR_LEAD_STAGES.includes(stage)) return res.status(400).json({ error: 'Invalid stage.' });
  const r = await pool.query('UPDATE realtor_leads SET stage = $1 WHERE id = $2 AND realtor_id = $3', [stage, id, req.user.id]);
  if (r.rowCount === 0) return res.status(404).json({ error: 'Lead not found.' });
  res.json({ ok: true, stage });
}));

app.delete('/api/realtor/leads/:id', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id.' });
  const r = await pool.query('DELETE FROM realtor_leads WHERE id = $1 AND realtor_id = $2', [id, req.user.id]);
  if (r.rowCount === 0) return res.status(404).json({ error: 'Lead not found.' });
  res.json({ ok: true });
}));

// Bulk import (rows pre-parsed client-side from CSV). Needs at least a name.
app.post('/api/realtor/leads/import', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const rows = (req.body || {}).rows;
  if (!Array.isArray(rows) || !rows.length) return res.status(400).json({ error: 'No rows to import.' });
  if (rows.length > 5000) return res.status(400).json({ error: 'Too many rows (max 5000 per import).' });
  let imported = 0, skipped = 0;
  for (const raw of rows) {
    const f = cleanRealtorLead(raw || {});
    if (!f.name) { skipped++; continue; }
    await pool.query(
      `INSERT INTO realtor_leads (realtor_id, name, phone, email, intent, timeline, budget, property_type, area, financing, notes, credit_score, assets, zipcode, stage, source)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
      [req.user.id, f.name, f.phone, f.email, f.intent, f.timeline, f.budget, f.propertyType, f.area, f.financing, f.notes, f.creditScore, f.assets, f.zipcode, f.stage, f.source]
    );
    imported++;
  }
  res.json({ ok: true, imported, skipped });
}));

// ----- Public lead-capture form -----
async function ensureCaptureToken(userId) {
  const u = await one('SELECT capture_token FROM users WHERE id = $1', [userId]);
  if (u && u.capture_token) return u.capture_token;
  const token = crypto.randomBytes(9).toString('base64url'); // ~12 url-safe chars
  await q('UPDATE users SET capture_token = $1 WHERE id = $2', [token, userId]);
  return token;
}
const captureUrl = (req, token) => `${req.protocol}://${req.get('host')}/apply/${token}`;

// The agent fetches (and lazily creates) their shareable intake link.
app.get('/api/realtor/capture', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const token = await ensureCaptureToken(req.user.id);
  res.json({ token, url: captureUrl(req, token) });
}));
// Rotate the link (old one stops working).
app.post('/api/realtor/capture/regenerate', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const token = crypto.randomBytes(9).toString('base64url');
  await q('UPDATE users SET capture_token = $1 WHERE id = $2', [token, req.user.id]);
  res.json({ token, url: captureUrl(req, token) });
}));

// Public: validate a link + personalize the form ("Work with <agent>").
app.get('/api/public/capture/:token', safe(async (req, res) => {
  const u = await one('SELECT name FROM users WHERE capture_token = $1', [String(req.params.token || '')]);
  if (!u) return res.status(404).json({ error: 'This form link is invalid or has been turned off.' });
  res.json({ ok: true, agent: u.name });
}));

// Public: accept a form submission → create a lead for that agent.
app.post('/api/public/leads/:token', safe(async (req, res) => {
  if (!rateLimit('capture:' + req.ip, 20, 10 * 60 * 1000)) {
    return res.status(429).json({ error: 'Too many submissions. Please try again in a bit.' });
  }
  const owner = await one('SELECT id FROM users WHERE capture_token = $1', [String(req.params.token || '')]);
  if (!owner) return res.status(404).json({ error: 'This form link is invalid or has been turned off.' });
  const b = req.body || {};
  if (String(b.website || '').trim()) return res.json({ ok: true }); // honeypot: silently drop bots
  const f = cleanRealtorLead(b);
  if (!f.name) return res.status(400).json({ error: 'Please enter your name.' });
  if (!f.phone && !f.email) return res.status(400).json({ error: 'Please add a phone number or email so we can reach you.' });
  await pool.query(
    `INSERT INTO realtor_leads (realtor_id, name, phone, email, intent, timeline, budget, property_type, area, financing, notes, credit_score, assets, zipcode, stage, source)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'New',$15)`,
    [owner.id, f.name, f.phone, f.email, f.intent, f.timeline, f.budget, f.propertyType, f.area, f.financing, f.notes, f.creditScore, f.assets, f.zipcode, 'Intake form']
  );
  res.json({ ok: true });
}));

// ----- Lead activity timeline: notes + logged calls, newest first -----
app.get('/api/realtor/leads/:id/timeline', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id.' });
  const lead = await one('SELECT id, name FROM realtor_leads WHERE id = $1 AND realtor_id = $2', [id, req.user.id]);
  if (!lead) return res.status(404).json({ error: 'Lead not found.' });
  const notes = await q('SELECT id, body, created_at FROM realtor_lead_notes WHERE lead_id = $1 AND realtor_id = $2', [id, req.user.id]);
  const calls = await q(`SELECT id, outcome, notes, logged_at FROM realtor_calls
                         WHERE realtor_id = $1 AND (lead_id = $2 OR lower(name) = lower($3))`, [req.user.id, id, lead.name]);
  const items = [];
  for (const n of notes) items.push({ kind: 'note', id: n.id, body: n.body, at: n.created_at });
  for (const c of calls) items.push({ kind: 'call', id: c.id, outcome: c.outcome, body: c.notes || '', at: c.logged_at });
  items.sort((a, b) => new Date(b.at) - new Date(a.at));
  res.json({ items });
}));

app.post('/api/realtor/leads/:id/notes', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id.' });
  const lead = await one('SELECT id FROM realtor_leads WHERE id = $1 AND realtor_id = $2', [id, req.user.id]);
  if (!lead) return res.status(404).json({ error: 'Lead not found.' });
  const body = String((req.body || {}).body || '').trim().slice(0, 2000);
  if (!body) return res.status(400).json({ error: 'Note is empty.' });
  const row = await one(`INSERT INTO realtor_lead_notes (realtor_id, lead_id, body) VALUES ($1,$2,$3) RETURNING id, body, created_at`,
    [req.user.id, id, body]);
  res.json({ kind: 'note', id: row.id, body: row.body, at: row.created_at });
}));

app.delete('/api/realtor/leads/:id/notes/:noteId', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const noteId = Number(req.params.noteId);
  if (!Number.isInteger(noteId)) return res.status(400).json({ error: 'Invalid id.' });
  const r = await pool.query('DELETE FROM realtor_lead_notes WHERE id = $1 AND realtor_id = $2', [noteId, req.user.id]);
  if (r.rowCount === 0) return res.status(404).json({ error: 'Note not found.' });
  res.json({ ok: true });
}));

// ===================================================================
// Contacts (address book)
// ===================================================================
function realtorContactRowToJson(r) {
  return { id: r.id, name: r.name, email: r.email || '', phone: r.phone || '', company: r.company || '', tag: r.tag || 'Contact' };
}
app.get('/api/realtor/contacts', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const rows = await q('SELECT * FROM realtor_contacts WHERE realtor_id = $1 ORDER BY lower(name)', [req.user.id]);
  res.json(rows.map(realtorContactRowToJson));
}));
app.post('/api/realtor/contacts', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const b = req.body || {};
  const name = String(b.name || '').trim().slice(0, 120);
  if (!name) return res.status(400).json({ error: 'A name is required.' });
  const row = await one(
    `INSERT INTO realtor_contacts (realtor_id, name, email, phone, company, tag)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [req.user.id, name, String(b.email || '').trim().slice(0, 160), formatPhone(String(b.phone || '').slice(0, 40)),
     String(b.company || '').trim().slice(0, 120), (String(b.tag || '').trim().slice(0, 40) || 'Contact')]
  );
  res.json(realtorContactRowToJson(row));
}));
app.patch('/api/realtor/contacts/:id', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id.' });
  const cur = await one('SELECT * FROM realtor_contacts WHERE id = $1 AND realtor_id = $2', [id, req.user.id]);
  if (!cur) return res.status(404).json({ error: 'Contact not found.' });
  const b = req.body || {};
  const name = b.name != null ? String(b.name).trim().slice(0, 120) : cur.name;
  if (!name) return res.status(400).json({ error: 'A name is required.' });
  const upd = await one(
    `UPDATE realtor_contacts SET name=$1, email=$2, phone=$3, company=$4, tag=$5 WHERE id=$6 AND realtor_id=$7 RETURNING *`,
    [name,
     b.email != null ? String(b.email).trim().slice(0, 160) : (cur.email || ''),
     b.phone != null ? formatPhone(String(b.phone).slice(0, 40)) : (cur.phone || ''),
     b.company != null ? String(b.company).trim().slice(0, 120) : (cur.company || ''),
     b.tag != null ? (String(b.tag).trim().slice(0, 40) || 'Contact') : (cur.tag || 'Contact'),
     id, req.user.id]
  );
  res.json(realtorContactRowToJson(upd));
}));
app.delete('/api/realtor/contacts/:id', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id.' });
  const r = await pool.query('DELETE FROM realtor_contacts WHERE id = $1 AND realtor_id = $2', [id, req.user.id]);
  if (r.rowCount === 0) return res.status(404).json({ error: 'Contact not found.' });
  res.json({ ok: true });
}));

// ===================================================================
// Calls: a "who to call next" queue ranked from the lead info
// ===================================================================
app.get('/api/realtor/call-queue', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const leads = await q(`
    SELECT * FROM realtor_leads l
    WHERE l.realtor_id = $1 AND l.phone IS NOT NULL AND btrim(l.phone) <> ''
      AND NOT EXISTS (
        SELECT 1 FROM realtor_calls c
        WHERE c.realtor_id = $1 AND (c.lead_id = l.id OR lower(c.name) = lower(l.name))
          AND c.logged_at > now() - interval '2 days')
    ORDER BY id DESC`, [req.user.id]);
  const queue = leads.map(l => {
    const s = scoreRealtorLead(l);
    return { leadId: l.id, name: l.name, phone: l.phone || '', intent: l.intent || '', timeline: l.timeline || '', priority: s.priority, reason: s.reason, score: s.score };
  }).sort((a, b) => b.score - a.score);
  res.json(queue);
}));

app.get('/api/realtor/calls', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const rows = await q('SELECT id, lead_id, name, phone, outcome, notes, logged_at FROM realtor_calls WHERE realtor_id = $1 ORDER BY id DESC LIMIT 100', [req.user.id]);
  res.json(rows.map(r => ({ id: r.id, leadId: r.lead_id, name: r.name, phone: r.phone || '', outcome: r.outcome, notes: r.notes || '', loggedAt: r.logged_at })));
}));

app.post('/api/realtor/calls', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const b = req.body || {};
  const name = String(b.name || '').trim().slice(0, 120);
  if (!name) return res.status(400).json({ error: 'A name is required.' });
  if (!['Connected', 'Voicemail', 'No Answer', 'Missed'].includes(b.outcome)) return res.status(400).json({ error: 'Choose a valid outcome.' });
  const leadId = Number.isInteger(b.leadId) ? await ownRealtorLead(req.user.id, b.leadId) : null;
  const row = await one(
    `INSERT INTO realtor_calls (realtor_id, lead_id, name, phone, outcome, notes)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, lead_id, name, phone, outcome, notes, logged_at`,
    [req.user.id, leadId, name, formatPhone(String(b.phone || '').slice(0, 40)), b.outcome, String(b.notes || '').trim().slice(0, 2000)]
  );
  res.json({ id: row.id, leadId: row.lead_id, name: row.name, phone: row.phone || '', outcome: row.outcome, notes: row.notes || '', loggedAt: row.logged_at });
}));

// ===================================================================
// Past clients (closed leads)
// ===================================================================
function realtorClientRowToJson(r) {
  return {
    id: r.id, name: r.name, phone: r.phone || '', email: r.email || '',
    intent: r.intent || '', budget: r.budget || '', propertyType: r.property_type || '', area: r.area || '', zipcode: r.zipcode || '',
    dealType: r.deal_type || '', address: r.address || '', price: r.price || '',
    closedDate: r.closed_date || '', notes: r.notes || '', created: r.created_at
  };
}
const REALTOR_DEAL_TYPES = ['Bought', 'Sold', 'Both'];
function cleanRealtorClient(b) {
  const s = (v, n) => String(v == null ? '' : v).trim().slice(0, n);
  return {
    name: s(b.name, 120), phone: formatPhone(s(b.phone, 40)), email: s(b.email, 160),
    intent: s(b.intent, 40), budget: s(b.budget, 60), propertyType: s(b.propertyType, 60), area: s(b.area, 120), zipcode: s(b.zipcode, 20),
    dealType: REALTOR_DEAL_TYPES.includes(s(b.dealType, 20)) ? s(b.dealType, 20) : '',
    address: s(b.address, 200), price: s(b.price, 60),
    closedDate: /^\d{4}-\d{2}-\d{2}$/.test(s(b.closedDate, 10)) ? s(b.closedDate, 10) : '',
    notes: s(b.notes, 2000)
  };
}
async function insertRealtorClient(realtorId, f) {
  return one(
    `INSERT INTO realtor_clients (realtor_id, name, phone, email, intent, budget, property_type, area, deal_type, address, price, closed_date, notes, zipcode)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
    [realtorId, f.name, f.phone, f.email, f.intent, f.budget, f.propertyType, f.area, f.dealType, f.address, f.price, f.closedDate || await userToday(realtorId), f.notes, f.zipcode]
  );
}

// Close a lead: capture the deal, move it into past clients, delete the lead.
app.post('/api/realtor/leads/:id/close', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id.' });
  const lead = await one('SELECT * FROM realtor_leads WHERE id = $1 AND realtor_id = $2', [id, req.user.id]);
  if (!lead) return res.status(404).json({ error: 'Lead not found.' });
  const b = req.body || {};
  const s = (v, n) => String(v == null ? '' : v).trim().slice(0, n);
  const dealType = REALTOR_DEAL_TYPES.includes(s(b.dealType, 20)) ? s(b.dealType, 20) : '';
  const closedDate = /^\d{4}-\d{2}-\d{2}$/.test(s(b.closedDate, 10)) ? s(b.closedDate, 10) : await userToday(req.user.id);
  const row = await one(
    `INSERT INTO realtor_clients (realtor_id, name, phone, email, intent, budget, property_type, area, deal_type, address, price, closed_date, notes, zipcode)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
    [req.user.id, lead.name, lead.phone, lead.email, lead.intent, lead.budget, lead.property_type, lead.area,
     dealType, s(b.address, 200), s(b.price, 60), closedDate, s(b.notes, 2000) || lead.notes || '', lead.zipcode || '']
  );
  await pool.query('DELETE FROM realtor_leads WHERE id = $1 AND realtor_id = $2', [id, req.user.id]);
  res.json(realtorClientRowToJson(row));
}));

app.get('/api/realtor/clients', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const rows = await q('SELECT * FROM realtor_clients WHERE realtor_id = $1 ORDER BY id DESC', [req.user.id]);
  res.json(rows.map(realtorClientRowToJson));
}));

app.post('/api/realtor/clients', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const f = cleanRealtorClient(req.body || {});
  if (!f.name) return res.status(400).json({ error: 'A name is required.' });
  const row = await insertRealtorClient(req.user.id, f);
  res.json(realtorClientRowToJson(row));
}));

app.post('/api/realtor/clients/import', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const rows = (req.body || {}).rows;
  if (!Array.isArray(rows) || !rows.length) return res.status(400).json({ error: 'No rows to import.' });
  if (rows.length > 5000) return res.status(400).json({ error: 'Too many rows (max 5000 per import).' });
  let imported = 0, skipped = 0;
  for (const raw of rows) {
    const f = cleanRealtorClient(raw || {});
    if (!f.name) { skipped++; continue; }
    await insertRealtorClient(req.user.id, f);
    imported++;
  }
  res.json({ ok: true, imported, skipped });
}));

app.patch('/api/realtor/clients/:id', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id.' });
  const cur = await one('SELECT * FROM realtor_clients WHERE id = $1 AND realtor_id = $2', [id, req.user.id]);
  if (!cur) return res.status(404).json({ error: 'Client not found.' });
  const b = req.body || {};
  const s = (v, n) => String(v == null ? '' : v).trim().slice(0, n);
  const name = b.name != null ? s(b.name, 120) : cur.name;
  if (!name) return res.status(400).json({ error: 'A name is required.' });
  const dealType = b.dealType != null ? (REALTOR_DEAL_TYPES.includes(s(b.dealType, 20)) ? s(b.dealType, 20) : '') : (cur.deal_type || '');
  const closedDate = b.closedDate != null ? (/^\d{4}-\d{2}-\d{2}$/.test(s(b.closedDate, 10)) ? s(b.closedDate, 10) : (cur.closed_date || '')) : (cur.closed_date || '');
  const row = await one(
    `UPDATE realtor_clients SET name=$1, phone=$2, email=$3, deal_type=$4, address=$5, price=$6, closed_date=$7, notes=$8
     WHERE id=$9 AND realtor_id=$10 RETURNING *`,
    [name,
     b.phone != null ? formatPhone(s(b.phone, 40)) : (cur.phone || ''),
     b.email != null ? s(b.email, 160) : (cur.email || ''),
     dealType,
     b.address != null ? s(b.address, 200) : (cur.address || ''),
     b.price != null ? s(b.price, 60) : (cur.price || ''),
     closedDate,
     b.notes != null ? s(b.notes, 2000) : (cur.notes || ''),
     id, req.user.id]
  );
  res.json(realtorClientRowToJson(row));
}));

app.delete('/api/realtor/clients/:id', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id.' });
  const r = await pool.query('DELETE FROM realtor_clients WHERE id = $1 AND realtor_id = $2', [id, req.user.id]);
  if (r.rowCount === 0) return res.status(404).json({ error: 'Client not found.' });
  res.json({ ok: true });
}));

// ===================================================================
// Follow-up tasks
// ===================================================================
const REALTOR_TASK_PRIORITIES = ['High', 'Medium', 'Low'];
function realtorTaskRowToJson(r) {
  return {
    id: r.id, leadId: r.lead_id || null, leadName: r.lead_name || '',
    title: r.title, due: r.due_date || '', priority: r.priority || 'Medium',
    status: r.status || 'todo', created: r.created_at, completedAt: r.completed_at || null,
    auto: !!(r.source && r.source.indexOf('auto') === 0)
  };
}
function cleanRealtorTask(b) {
  const s = (v, n) => String(v == null ? '' : v).trim().slice(0, n);
  const due = s(b.due, 10);
  return {
    title: s(b.title, 200),
    due: /^\d{4}-\d{2}-\d{2}$/.test(due) ? due : '',
    priority: REALTOR_TASK_PRIORITIES.includes(s(b.priority, 10)) ? s(b.priority, 10) : 'Medium',
    leadId: Number.isInteger(b.leadId) ? b.leadId : null
  };
}

app.get('/api/realtor/tasks', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  try { await ensureRealtorFollowups(req.user.id); } catch (e) { console.error('auto follow-ups:', e); }
  const rows = await q(`
    SELECT t.*, l.name AS lead_name
    FROM realtor_tasks t LEFT JOIN realtor_leads l ON l.id = t.lead_id
    WHERE t.realtor_id = $1
    ORDER BY (t.status = 'done'), (t.due_date IS NULL), t.due_date, t.id DESC`, [req.user.id]);
  res.json(rows.map(realtorTaskRowToJson));
}));

app.post('/api/realtor/tasks', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const f = cleanRealtorTask(req.body || {});
  if (!f.title) return res.status(400).json({ error: 'A task is required.' });
  const leadId = await ownRealtorLead(req.user.id, f.leadId);
  const row = await one(
    `INSERT INTO realtor_tasks (realtor_id, lead_id, title, due_date, priority)
     VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [req.user.id, leadId, f.title, f.due || null, f.priority]
  );
  const withName = await one(`SELECT t.*, l.name AS lead_name FROM realtor_tasks t LEFT JOIN realtor_leads l ON l.id = t.lead_id WHERE t.id = $1`, [row.id]);
  res.json(realtorTaskRowToJson(withName));
}));

app.patch('/api/realtor/tasks/:id', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id.' });
  const cur = await one('SELECT * FROM realtor_tasks WHERE id = $1 AND realtor_id = $2', [id, req.user.id]);
  if (!cur) return res.status(404).json({ error: 'Task not found.' });
  const b = req.body || {};
  let status = cur.status, completedAt = cur.completed_at;
  if (b.status === 'done' || b.status === 'todo') {
    status = b.status;
    completedAt = b.status === 'done' ? new Date() : null;
  }
  const title = b.title != null ? String(b.title).trim().slice(0, 200) : cur.title;
  if (!title) return res.status(400).json({ error: 'A task is required.' });
  const dueRaw = b.due != null ? String(b.due).trim().slice(0, 10) : cur.due_date;
  const due = (dueRaw && /^\d{4}-\d{2}-\d{2}$/.test(dueRaw)) ? dueRaw : (b.due === '' ? null : cur.due_date);
  const priority = REALTOR_TASK_PRIORITIES.includes(String(b.priority || '')) ? b.priority : cur.priority;
  let leadId = cur.lead_id;
  if (b.leadId !== undefined) leadId = await ownRealtorLead(req.user.id, Number.isInteger(b.leadId) ? b.leadId : null);
  await pool.query(
    `UPDATE realtor_tasks SET title=$1, due_date=$2, priority=$3, status=$4, completed_at=$5, lead_id=$6 WHERE id=$7 AND realtor_id=$8`,
    [title, due, priority, status, completedAt, leadId, id, req.user.id]
  );
  const row = await one(`SELECT t.*, l.name AS lead_name FROM realtor_tasks t LEFT JOIN realtor_leads l ON l.id = t.lead_id WHERE t.id = $1`, [id]);
  res.json(realtorTaskRowToJson(row));
}));

app.delete('/api/realtor/tasks/:id', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id.' });
  const r = await pool.query('DELETE FROM realtor_tasks WHERE id = $1 AND realtor_id = $2', [id, req.user.id]);
  if (r.rowCount === 0) return res.status(404).json({ error: 'Task not found.' });
  res.json({ ok: true });
}));

// Realtor preferences (currently just the automatic-follow-ups toggle).
app.get('/api/realtor/prefs', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  res.json({ autoFollowups: req.user.autoTasks !== false });
}));
app.put('/api/realtor/prefs', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const on = !!(req.body || {}).autoFollowups;
  await pool.query('UPDATE users SET auto_tasks_enabled = $1 WHERE id = $2', [on, req.user.id]);
  res.json({ autoFollowups: on });
}));

// ===================================================================
// Home dashboard
// ===================================================================
app.get('/api/realtor/home', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const rid = req.user.id;
  try { await ensureRealtorFollowups(rid); } catch (e) { console.error('auto follow-ups:', e); }

  const lc = await one(`SELECT count(*)::int AS n FROM realtor_leads WHERE realtor_id = $1`, [rid]);
  const cc = await one(`SELECT count(*)::int AS n FROM realtor_clients WHERE realtor_id = $1`, [rid]);
  const activeLeads = lc ? lc.n : 0;
  const pastClients = cc ? cc.n : 0;

  // Follow-ups due today or overdue (open tasks).
  const today = await userToday(rid);
  const dueRows = await q(`
    SELECT t.*, l.name AS lead_name
    FROM realtor_tasks t LEFT JOIN realtor_leads l ON l.id = t.lead_id
    WHERE t.realtor_id = $1 AND t.status = 'todo' AND t.due_date IS NOT NULL AND t.due_date <= $2
    ORDER BY t.due_date, t.id DESC LIMIT 8`, [rid, today]);
  const tasksToday = dueRows.map(r => ({
    id: r.id, title: r.title, due: r.due_date || '', priority: r.priority || 'Medium',
    leadId: r.lead_id || null, leadName: r.lead_name || '', overdue: !!(r.due_date && r.due_date < today)
  }));

  // Who to call today — same rule as the call queue.
  const callLeads = await q(`
    SELECT * FROM realtor_leads l
    WHERE l.realtor_id = $1 AND l.phone IS NOT NULL AND btrim(l.phone) <> ''
      AND NOT EXISTS (
        SELECT 1 FROM realtor_calls c
        WHERE c.realtor_id = $1 AND (c.lead_id = l.id OR lower(c.name) = lower(l.name))
          AND c.logged_at > now() - interval '2 days')
    ORDER BY id DESC`, [rid]);
  const fullQueue = callLeads.map(l => {
    const s = scoreRealtorLead(l);
    return { leadId: l.id, name: l.name, phone: l.phone || '', priority: s.priority, reason: s.reason, score: s.score };
  }).sort((a, b) => b.score - a.score);

  // Activity feed — recent events pulled from existing tables.
  const activity = [];
  const calls = await q(`SELECT name, outcome, logged_at FROM realtor_calls
                         WHERE realtor_id = $1 AND logged_at > now() - interval '21 days' ORDER BY id DESC LIMIT 6`, [rid]);
  for (const c of calls) activity.push({ icon: 'phone', tone: 'gray', text: `You logged a call with ${c.name} — ${c.outcome}`, at: c.logged_at });
  const newLeads = await q(`SELECT name, created_at FROM realtor_leads
                            WHERE realtor_id = $1 AND created_at > now() - interval '21 days' ORDER BY id DESC LIMIT 6`, [rid]);
  for (const l of newLeads) activity.push({ icon: 'user-plus', tone: 'blue', text: `You added a new lead — ${l.name}`, at: l.created_at });
  const closed = await q(`SELECT name, created_at FROM realtor_clients
                          WHERE realtor_id = $1 AND created_at > now() - interval '21 days' ORDER BY id DESC LIMIT 6`, [rid]);
  for (const c of closed) activity.push({ icon: 'party-popper', tone: 'green', text: `You closed ${c.name} 🎉`, at: c.created_at });
  activity.sort((a, b) => new Date(b.at) - new Date(a.at));

  res.json({
    realtor: { name: req.user.name, email: req.user.email },
    stats: { activeLeads, pastClients, callsToday: fullQueue.length, tasksDue: tasksToday.length },
    queue: fullQueue.slice(0, 6),
    tasksToday,
    activity: activity.slice(0, 15)
  });
}));

// ===================================================================
// Google OAuth + Gmail send ("send as my Gmail")
// ===================================================================
async function saveGoogleTokens(userId, email, accessToken, refreshToken, expiresAt) {
  await q(`
    INSERT INTO google_accounts (user_id, email, access_token, refresh_token, expires_at)
    VALUES ($1,$2,$3,$4,$5)
    ON CONFLICT (user_id) DO UPDATE SET
      email = EXCLUDED.email,
      access_token = EXCLUDED.access_token,
      refresh_token = COALESCE(EXCLUDED.refresh_token, google_accounts.refresh_token),
      expires_at = EXCLUDED.expires_at
  `, [userId, email, encToken(accessToken), refreshToken ? encToken(refreshToken) : null, expiresAt]);
}
// Valid access token for the user, refreshing if needed. null if not connected.
async function getGoogleToken(userId) {
  const row = await one('SELECT * FROM google_accounts WHERE user_id = $1', [userId]);
  if (!row) return null;
  const accessToken = decToken(row.access_token);
  const refreshToken = decToken(row.refresh_token);
  const exp = Number(row.expires_at);
  if (exp && exp > Date.now() + 60000) return accessToken;
  if (!refreshToken) return exp ? null : accessToken;
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: GOOGLE.clientId, client_secret: GOOGLE.clientSecret, refresh_token: refreshToken, grant_type: 'refresh_token' })
  });
  const tok = await r.json();
  if (!r.ok) { console.error('Google token refresh failed:', tok); return null; }
  const expiresAt = Date.now() + (tok.expires_in || 3600) * 1000;
  await q('UPDATE google_accounts SET access_token = $1, expires_at = $2 WHERE user_id = $3', [encToken(tok.access_token), expiresAt, userId]);
  return tok.access_token;
}
async function googleStatus(userId) {
  const row = await one('SELECT email FROM google_accounts WHERE user_id = $1', [userId]);
  return { connected: !!row, email: row ? (row.email || '') : '', configured: googleConfigured() };
}
// Send one message through the user's Gmail. Throws on failure.
async function sendViaGmail(userId, from, to, subject, body) {
  const token = await getGoogleToken(userId);
  if (!token) throw new Error('Your Google connection expired — reconnect Gmail.');
  const headers = [
    `From: ${from}`, `To: ${to}`,
    `Subject: ${subject}`, 'MIME-Version: 1.0', 'Content-Type: text/plain; charset="UTF-8"', '', body
  ].join('\r\n');
  const raw = Buffer.from(headers).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const r = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
    method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ raw })
  });
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error((e.error && e.error.message) || 'Gmail rejected the message.'); }
}

// Start the OAuth flow — redirect the user to Google's consent screen.
app.get('/api/google/connect', safe(async (req, res) => {
  if (!req.user) return res.status(401).send('Sign in first.');
  if (!googleConfigured()) return res.status(400).send('Google sign-in is not configured on this server.');
  const state = crypto.randomBytes(16).toString('hex');
  oauthStates.set(state, { userId: req.user.id, exp: Date.now() + 10 * 60 * 1000 });
  const url = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
    client_id: GOOGLE.clientId, redirect_uri: GOOGLE.redirectUri, response_type: 'code',
    scope: GOOGLE.scopes.join(' '), access_type: 'offline', prompt: 'consent',
    include_granted_scopes: 'true', state
  });
  res.redirect(url);
}));

// OAuth callback — exchange the code, store tokens, bounce back to the app.
app.get('/api/google/callback', safe(async (req, res) => {
  const { code, state } = req.query;
  const st = state && oauthStates.get(state);
  oauthStates.delete(state);
  if (!code || !st || st.exp < Date.now()) return res.redirect('/#emails');
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ code, client_id: GOOGLE.clientId, client_secret: GOOGLE.clientSecret, redirect_uri: GOOGLE.redirectUri, grant_type: 'authorization_code' })
  });
  const tok = await r.json();
  if (!r.ok) { console.error('Google token exchange failed:', tok); return res.redirect('/?gmail=error#emails'); }
  const expiresAt = Date.now() + (tok.expires_in || 3600) * 1000;
  // Get the connected address.
  let email = '';
  try {
    const ui = await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers: { Authorization: 'Bearer ' + tok.access_token } });
    if (ui.ok) email = (await ui.json()).email || '';
  } catch (e) { /* non-fatal */ }
  await saveGoogleTokens(st.userId, email, tok.access_token, tok.refresh_token, expiresAt);
  res.redirect('/?gmail=connected#emails');
}));

app.post('/api/google/disconnect', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  await pool.query('DELETE FROM google_accounts WHERE user_id = $1', [req.user.id]);
  res.json({ ok: true });
}));

// ===================================================================
// Automatic emails (weekly mailing list)
// ===================================================================
// Sending goes through SMTP if it's configured in the environment. Without it,
// the list/schedule/template are still saved and editable; sends just report
// "email isn't set up" instead of silently doing nothing.
//   SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASS, SMTP_FROM
// For a weekly cron that works even when a free host is asleep, hit:
//   GET /api/cron/dispatch?key=CRON_SECRET   (e.g. from cron-job.org)
function emailConfigured() {
  return !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}
let _transport;
function mailer() {
  if (!emailConfigured()) return null;
  if (!_transport) {
    const port = Number(process.env.SMTP_PORT) || 587;
    _transport = nodemailer.createTransport({
      host: process.env.SMTP_HOST, port, secure: port === 465,
      auth: { user: process.env.SMTP_USER, pass: String(process.env.SMTP_PASS).replace(/\s+/g, '') }
    });
  }
  return _transport;
}
const mailFrom = () => process.env.SMTP_FROM || process.env.SMTP_USER || 'no-reply@localhost';

const DEFAULT_SUBJECT = 'A quick note from your agent';
const DEFAULT_BODY = `Hi there,

Just checking in with this week's update. If you're thinking about buying or
selling — or know someone who is — I'd love to help.

Reply anytime; I'm always happy to talk.

Best,
Your agent`;
const WEEKDAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

async function loadEmailSettings(userId) {
  let s = await one('SELECT * FROM email_settings WHERE user_id = $1', [userId]);
  if (!s) {
    s = await one(`INSERT INTO email_settings (user_id, subject, body, enabled, send_day)
                   VALUES ($1, $2, $3, FALSE, 1) RETURNING *`, [userId, DEFAULT_SUBJECT, DEFAULT_BODY]);
  }
  return s;
}
function emailSettingsJson(s) {
  return {
    subject: s.subject || DEFAULT_SUBJECT, body: s.body || DEFAULT_BODY,
    enabled: s.enabled === true, sendDay: Number.isInteger(s.send_day) ? s.send_day : 1,
    lastRun: s.last_run_date || null
  };
}
const validEmail = (e) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(e || '').trim());

// Send one account's list now. Prefers the user's connected Gmail (sends as
// them); falls back to shared SMTP. Returns { sent, failed, recipients, via, error? }.
async function sendWeeklyFor(userId, trigger) {
  const s = await loadEmailSettings(userId);
  const recips = await q('SELECT email, name FROM email_recipients WHERE user_id = $1', [userId]);
  if (!recips.length) return { sent: 0, failed: 0, recipients: 0, error: 'No recipients on your list yet.' };

  const subject = s.subject || DEFAULT_SUBJECT;
  const body = s.body || DEFAULT_BODY;

  // Pick a channel: connected Gmail first, else SMTP.
  const gmail = await one('SELECT email FROM google_accounts WHERE user_id = $1', [userId]);
  const tx = mailer();
  let via = null, gmailFrom = '';
  if (gmail) {
    const u = await one('SELECT name FROM users WHERE id = $1', [userId]);
    gmailFrom = u && u.name ? `${u.name} <${gmail.email}>` : gmail.email;
    via = 'gmail';
  } else if (tx) { via = 'smtp'; }
  else return { sent: 0, failed: 0, recipients: recips.length, error: 'Connect Gmail (or configure SMTP) to send.' };

  let sent = 0, failed = 0;
  for (const r of recips) {
    try {
      if (via === 'gmail') await sendViaGmail(userId, gmailFrom, r.email, subject, body);
      else await tx.sendMail({ from: mailFrom(), to: r.email, subject, text: body,
        html: `<div style="white-space:pre-wrap;font-family:sans-serif">${body.replace(/&/g, '&amp;').replace(/</g, '&lt;')}</div>` });
      sent++;
    } catch (e) { console.error('email send failed to', r.email, e.message); failed++; }
  }
  await pool.query(`INSERT INTO email_sends (user_id, subject, recipients, sent, failed, trigger)
                    VALUES ($1,$2,$3,$4,$5,$6)`, [userId, subject, recips.length, sent, failed, trigger || 'manual']);
  return { sent, failed, recipients: recips.length, via };
}

app.get('/api/realtor/emails', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const recipients = await q('SELECT id, email, name FROM email_recipients WHERE user_id = $1 ORDER BY lower(email)', [req.user.id]);
  const settings = emailSettingsJson(await loadEmailSettings(req.user.id));
  const history = await q('SELECT subject, recipients, sent, failed, trigger, created_at FROM email_sends WHERE user_id = $1 ORDER BY id DESC LIMIT 10', [req.user.id]);
  const gmail = await googleStatus(req.user.id);
  res.json({
    recipients: recipients.map(r => ({ id: r.id, email: r.email, name: r.name || '' })),
    settings,
    weekdays: WEEKDAYS,
    gmail,
    // Sending works if Gmail is connected OR SMTP is set up.
    canSend: gmail.connected || emailConfigured(),
    history: history.map(h => ({ subject: h.subject, recipients: h.recipients, sent: h.sent, failed: h.failed, trigger: h.trigger, at: h.created_at }))
  });
}));

app.post('/api/realtor/emails/recipients', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const email = String((req.body || {}).email || '').trim().toLowerCase().slice(0, 160);
  const name = String((req.body || {}).name || '').trim().slice(0, 120);
  if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  const dup = await one('SELECT id FROM email_recipients WHERE user_id = $1 AND lower(email) = $2', [req.user.id, email]);
  if (dup) return res.status(409).json({ error: 'That address is already on your list.' });
  const row = await one('INSERT INTO email_recipients (user_id, email, name) VALUES ($1,$2,$3) RETURNING id, email, name',
    [req.user.id, email, name]);
  res.json({ id: row.id, email: row.email, name: row.name || '' });
}));

// Bulk add (comma / newline separated addresses, pre-split client-side).
app.post('/api/realtor/emails/recipients/import', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const list = (req.body || {}).emails;
  if (!Array.isArray(list) || !list.length) return res.status(400).json({ error: 'No addresses to add.' });
  if (list.length > 2000) return res.status(400).json({ error: 'Too many at once (max 2000).' });
  let added = 0, skipped = 0;
  for (const raw of list) {
    const email = String(raw || '').trim().toLowerCase().slice(0, 160);
    if (!validEmail(email)) { skipped++; continue; }
    try {
      const r = await pool.query('INSERT INTO email_recipients (user_id, email) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.id, email]);
      if (r.rowCount) added++; else skipped++;
    } catch (e) { skipped++; }
  }
  res.json({ ok: true, added, skipped });
}));

app.delete('/api/realtor/emails/recipients/:id', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id.' });
  const r = await pool.query('DELETE FROM email_recipients WHERE id = $1 AND user_id = $2', [id, req.user.id]);
  if (r.rowCount === 0) return res.status(404).json({ error: 'Recipient not found.' });
  res.json({ ok: true });
}));

app.put('/api/realtor/emails/settings', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  await loadEmailSettings(req.user.id); // ensure the row exists
  const b = req.body || {};
  const cur = await one('SELECT * FROM email_settings WHERE user_id = $1', [req.user.id]);
  const subject = b.subject != null ? String(b.subject).trim().slice(0, 200) : cur.subject;
  const body = b.body != null ? String(b.body).slice(0, 10000) : cur.body;
  const enabled = b.enabled != null ? !!b.enabled : cur.enabled;
  let sendDay = cur.send_day;
  if (b.sendDay != null) { const d = Number(b.sendDay); if (Number.isInteger(d) && d >= 0 && d <= 6) sendDay = d; }
  if (!String(subject || '').trim()) return res.status(400).json({ error: 'A subject is required.' });
  const row = await one(`UPDATE email_settings SET subject=$1, body=$2, enabled=$3, send_day=$4, updated_at=now()
                         WHERE user_id=$5 RETURNING *`, [subject, body, enabled, sendDay, req.user.id]);
  res.json(emailSettingsJson(row));
}));

// Send to the whole list right now (manual test / one-off blast).
app.post('/api/realtor/emails/send-now', safe(async (req, res) => {
  if (!requireUser(req, res)) return;
  const r = await sendWeeklyFor(req.user.id, 'manual');
  if (r.error) return res.status(400).json(r);
  res.json(r);
}));

// Weekly dispatcher: send for every enabled account whose configured weekday is
// today and that hasn't already run today. Called by the internal timer and by
// the external cron endpoint. Idempotent via last_run_date.
async function dispatchWeeklyEmails() {
  // Include whether each user has a Gmail connected; a user can send if that's
  // true or shared SMTP is configured. If neither path exists at all, bail early.
  const smtp = emailConfigured();
  const rows = await q(`SELECT s.user_id, s.send_day, s.last_run_date, u.tz,
                          (g.user_id IS NOT NULL) AS has_gmail
                        FROM email_settings s
                        JOIN users u ON u.id = s.user_id
                        LEFT JOIN google_accounts g ON g.user_id = s.user_id
                        WHERE s.enabled = TRUE`);
  let ran = 0;
  for (const s of rows) {
    if (!smtp && !s.has_gmail) continue; // no way to send for this user
    const today = (s.tz ? todayInTz(s.tz) : serverToday());
    const weekday = new Date(today + 'T00:00:00').getDay();
    if (weekday !== s.send_day) continue;
    if (s.last_run_date === today) continue; // already sent today
    // Claim the day first so overlapping runs can't double-send.
    const claim = await pool.query(
      `UPDATE email_settings SET last_run_date = $1 WHERE user_id = $2 AND (last_run_date IS DISTINCT FROM $1)`,
      [today, s.user_id]);
    if (claim.rowCount === 0) continue;
    try { await sendWeeklyFor(s.user_id, 'weekly'); ran++; }
    catch (e) { console.error('weekly dispatch for user', s.user_id, e.message); }
  }
  return { ran };
}

// External cron trigger (protect with CRON_SECRET). Safe to call every few minutes.
app.get('/api/cron/dispatch', safe(async (req, res) => {
  const secret = process.env.CRON_SECRET;
  if (!secret || req.query.key !== secret) return res.status(403).json({ error: 'Forbidden.' });
  const r = await dispatchWeeklyEmails();
  res.json({ ok: true, ...r });
}));

// Internal timer: also runs hourly while the process is awake (belt-and-braces
// alongside the external cron, which is what matters on hosts that sleep).
setInterval(() => { dispatchWeeklyEmails().catch(e => console.error('weekly timer:', e.message)); }, 60 * 60 * 1000).unref();

// ===================================================================
// Static files + start
// ===================================================================
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

// Public lead-capture form (standalone page; reads its token from the URL).
app.get('/apply/:token', (req, res) => res.sendFile(path.join(__dirname, 'public', 'apply.html')));

// SPA fallback: any non-API GET serves the app shell (client-side routing).
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// JSON 404 for unknown API routes.
app.use((req, res) => res.status(404).json({ error: 'Not found.' }));

(async () => {
  try {
    await pool.query(SCHEMA);
    console.log('✔ Database ready.');
  } catch (e) {
    console.error('❌ Failed to initialize the database:', e.message);
    process.exit(1);
  }
  app.listen(PORT, () => console.log(`✔ LeadNest running at http://localhost:${PORT}`));
})();
