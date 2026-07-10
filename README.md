# LeadNest

> **Name is a placeholder.** Rename it anywhere it appears (`package.json` `name`,
> the `<title>` and brand text in `public/index.html`, and the console banner in
> `server.js`) once you settle on one.

A realtor CRM — add leads, work them, and close deals. Each account manages its
own leads, contacts, calls, follow-up tasks, and past clients; everything is
scoped to the signed-in user server-side. Email/password auth with HTTP-only
cookie sessions. No mock data; every page reads real per-account data.

This is the **realtor side** rebuilt as a standalone app: there is no loan-officer
portal and **no cross-account messaging/chat**.

## What's inside

- **Home** — stats, "who to call" queue, follow-ups due today, and an activity feed.
- **Leads** — add/edit/import leads, a readiness score (timeline, financing, credit,
  intent), per-lead activity **timeline** (notes + logged calls), log a call, and
  **close as won** (moves the lead into Past Clients).
- **Past Clients** — closed deals with deal type, price, and close date; add/import too.
- **Contacts** — a simple address book (lenders, vendors, partners).
- **Calls** — a ranked "who to call next" queue (skips anyone called in the last
  2 days) plus a running call log.
- **Follow-ups** — a task list, plus **automatic reminders** generated from your
  activity (new-lead call, missed-call retry, hot-lead-going-quiet, timeline
  check-in). Toggle the automation off in Settings.
- **Settings** — automatic-follow-ups toggle and change password.

Leads/clients/contacts are "contacted" via device links — tap-to-call (`tel:`),
text (`sms:`), and email (`mailto:`) — so it works from a phone with no email
provider setup.

## Stack

- **Backend:** Node + Express, Postgres (`pg`), bcrypt password hashing, HTTP-only
  cookie sessions.
- **Frontend:** a static single-page app — `public/index.html` + `public/app.js` +
  `public/styles.css` (Tailwind + Lucide via CDN, no build step).

## Run locally

1. **Create a Postgres database** (free): <https://neon.tech> → new project → copy
   the connection string.
2. **Configure env** — copy `.env.example` to `.env` and set:
   ```
   DATABASE_URL=postgres://user:password@host/dbname?sslmode=require
   ```
3. **Install & start:**
   ```bash
   npm install
   npm start          # or: npm run dev  (auto-restarts on file changes)
   ```
4. Open <http://localhost:3000>, create an account, and you're in. Tables are
   created automatically on first start.

## Deploy

Any host that runs Node and gives you a `DATABASE_URL` works (Render, Railway,
Fly, a VM). Set `NODE_ENV=production` to enable secure cookies (the app trusts the
proxy). `PORT` is read from the environment.

## Project layout

```
server.js            Express server + Postgres + all API routes (/api/realtor/*)
public/index.html    App shell (auth screen + sidebar layout)
public/app.js        Single-page app: routing, all sections, modals, CSV import
public/styles.css    Styles
```

## Security notes

- Passwords are bcrypt-hashed; sessions are random tokens stored server-side.
- Every `/api/realtor/*` route is gated on a valid session and scoped by
  `realtor_id`, so accounts can only ever see their own data.
- `.env` is gitignored; never commit secrets.
