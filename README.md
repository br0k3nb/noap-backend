<div align="center">
  <br>
  <h1>Noap 📝 — Rust Backend</h1>
  <strong>Your next notes application — now 100% Rust</strong>
</div>
<br>

> This is the **Rust port** of the original Noap backend (Node/Express/Mongoose). The entire API has been re-implemented in Rust with **Axum + MongoDB** and is a drop-in replacement for the Node server. It exposes the **identical HTTP contract** so the existing React frontend (`/noap`) works without changes.

## Stack
- **Runtime:** Rust 1.82+ (tested on 1.97) — no Node.js anywhere in this backend
- **Web:** Axum 0.8 + Tokio + Tower-HTTP (CORS, Trace)
- **DB:** MongoDB (official `mongodb` 3.1 driver, `bson` 2.15) — same collections as the Node version (`users`, `notes`, `noteStates`, `labels`, `sessions`, `otps`, `2fa`)
- **Auth:** `jsonwebtoken` HS512 + `bcrypt` 0.17, middleware `verify_user`
- **Mail:** `lettre` 0.11 (SMTP, HTML OTP from `utils/mail.rs`)
- **2FA:** `totp-rs` 5.6 + `qrcode` 0.14 (`generate_2fa_qrcode`, `verify_2fa_code`)
- **Geo/IP:** `reqwest` → `https://api.ipgeolocation.io/ipgeo`
- **Device:** raw user-agent stored per session, country flag emoji from geo lookup

## Prerequisites
- Rust 1.82+ (`rustup`), Cargo
- MongoDB (local or Atlas) — set `MONGODB_URL`
- `.env` (see `.env.example`)

## Quick start

```bash
# 1. Clone
git clone <repo> && cd noap-backend

# 2. Configure
cp .env.example .env
# edit MONGODB_URL, SECRET (HS512), mail, IPGEOLOCATION_KEY

# 3. Build & run
cargo run              # → listening on 0.0.0.0:3002 (or $PORT)
# or
cargo build --release && ./target/release/noap-server

# 4. Frontend (unchanged)
cd ../noap
npm install && npm run dev   # expects VITE_API_URL=http://0.0.0.0:3002 or defaults to https://noap-backend.vercel.app
```

## Environment

| Var | Required | Default | Description |
|-----|----------|---------|-------------|
| `MONGODB_URL` | **yes** | — | MongoDB connection string (e.g. `mongodb://localhost:27017/noap` or Atlas) |
| `SECRET` | **yes** | — | JWT HS512 secret (64+ chars, no default — startup fails without it) |
| `ALLOWED_ORIGINS` | **yes in prod** | localhost dev origins | Exact frontend origin(s), comma-separated, e.g. `https://noap.vercel.app` |
| `COOKIE_SECURE` | no | `true` | Set `false` for plain-http local dev (SameSite auto-downgrades to Lax) |
| `COOKIE_SAMESITE` | no | `None` | `None` (cross-site, requires Secure) or `Lax` |
| `WEBAUTHN_RP_ID` | no | `localhost` | Passkey relying-party ID — must be the frontend host (`noap.vercel.app` in prod) |
| `WEBAUTHN_ORIGIN` | no | `http://localhost:5173` | Passkey origin — must be the frontend origin (`https://noap.vercel.app` in prod) |
| `WEBAUTHN_RP_NAME` | no | `Noap` | Human-readable relying-party name shown by authenticators || `MAIL_HOSTNAME` | no | — | SMTP host (OTP mails skipped if empty) |
| `MAIL_PORT` | no | 587 | SMTP port |
| `MAIL_USERNAME` | no | — | SMTP user |
| `MAIL_PASSWORD` | no | — | SMTP pass |
| `HOST_MAIL` | no | `$MAIL_USERNAME` | From address |
| `IPGEOLOCATION_KEY` | no | — | api.ipgeolocation.io key (geo fallback to Unknown) |
| `VAPID_PRIVATE_KEY` | no | — | Base64url-no-pad VAPID private key; enables server-side Web Push (devices subscribe via `POST /push/subscribe/:userId`, cron fans out). Unset = push endpoints 503, in-tab reminders still work |
| `VAPID_SUBJECT` | no | `mailto:noreply@noap.example.com` | Contact attached to VAPID signatures (required by RFC8292) |
| `CRON_SECRET` | **yes in prod** | — | Bearer secret authorizing `POST /cron/push-due` (Vercel sends it automatically when set). Unset = route open (local dev only) |
| `PORT` | no | 3002 | Listen port |
| `RUST_LOG` | no | info | Tracing level |

## API (identical to Node)

All routes are mounted at `/` (see `src/main.rs:44`):

**Users**
```
POST   /sign-up
POST   /sign-in
POST   /sign-in/google
POST   /verify-otp
POST   /2fa/remove
POST   /2fa/verify
POST   /find-user
PATCH  /change-pass
POST   /sign-out              (auth)
POST   /verify-user           (auth)
POST   /2fa/qrcode            (auth)
POST   /verify-token          (public, self-validating: cookie/Bearer, one-time legacy body token)
PATCH  /lastOpenedNote/:id    (auth)
PATCH  /convert/account/email (auth)
PATCH  /convert/account/google (auth)
POST   /passkeys/auth/start
POST   /passkeys/auth/finish
POST   /passkeys/register/start     (auth)
POST   /passkeys/register/finish    (auth)
GET    /passkeys                    (auth)
DELETE /passkeys/:credId            (auth)
PATCH  /settings/change-theme/:id                (auth)
POST   /settings/note-text/:id                   (auth)
POST   /settings/pin-notes-folder/:id            (auth)
PATCH  /settings/note-visualization/:id         (auth)
PATCH  /settings/onLoginGoToLastOpenedNote/:id (auth)
PATCH  /settings/global-note-background-color/:id (auth)
```

**Sessions**
```
GET    /get/sessions/:userId                    (auth)
DELETE /delete/session/:userId/:sessionId       (auth)
DELETE /delete/all/sessions/:userId             (auth)
```

**Notes**
```
POST   /add                                     (auth)
PATCH  /edit                                    (auth)
GET    /note/:id?author=                        (auth)
DELETE /delete/:id                              (auth)
GET    /notes/:page/:author?search=&limit=&pinnedNotesPage= (auth)
POST   /note/add/label                          (auth)
POST   /note/rename/:id                         (auth)
POST   /note/pin-note/:noteId                   (auth)
POST   /note/image/:noteId                      (auth)
DELETE /note/delete/label/:id/:noteId           (auth)
DELETE /note/delete-all/label/:noteId           (auth)
PATCH  /settings/note-background-color/:noteId  (auth)
```

**Labels**
```
GET    /labels/:userId?search=&page=&limit=      (auth)
POST   /label/add/:userId                        (auth)
PATCH  /label/edit/:userId                       (auth)
DELETE /label/delete/:id                         (auth)
```

**Activities** (schedules that trigger frontend browser notifications — trigger types: `daily` at `HH:MM`, `once` at `DD/MM/YYYY` + `HH:MM`; all times use the America/Recife timezone. An activity can link a note as its recurring todo list via `noteId`; `POST /activity/complete/:id` records the `doneDates` history that drives the streak, and the frontend resets the note's checkboxes on completion + on each new occurrence tracked in `seenOccurrences`)
```
GET    /activities/:userId                       (auth)
POST   /activity/add/:userId                     (auth, accepts optional noteId)
PATCH  /activity/edit/:userId                    (auth, accepts optional noteId to link/unlink)
POST   /activity/toggle/:id                      (auth)
POST   /activity/triggered/:id                   (auth)
POST   /activity/link-note/:id                   (auth, { noteId })
POST   /activity/unlink-note/:id                 (auth)
POST   /activity/complete/:id                    (auth, { date?: "DD/MM/YYYY" } -> streak)
POST   /activity/seen/:id                        (auth, { occurrenceKey } rollover bookkeeping)
GET    /activity/progress/:id                    (auth, doneDates + currentStreak + doneToday)
DELETE /activity/delete/:id                      (auth)
```

**Server-side push** (Web Push, RFC8030 — rings every subscribed device, phone or PC, even with no Noap tab open; `POST /cron/push-due` every minute fans out due activities, deduped per occurrence via `activities.lastPushKey`)
```
GET    /push/vapid-key                           (public, 503 while VAPID_PRIVATE_KEY is unset)
POST   /push/subscribe/:userId                   (auth, { endpoint, p256dh, auth, userAgent? })
POST   /push/unsubscribe/:userId                 (auth, { endpoint })
GET    /push/subscriptions/:userId               (auth, "your devices" list)
GET/POST /cron/push-due                          (CRON_SECRET bearer, NOT session auth)
```

### Web Push setup (one-time, ~5 min)

Server-side push needs a VAPID keypair (identifies your server to push
services) plus a per-minute cron tick:

```bash
# Generate a keypair (any one of):
npx web-push generate-vapid-keys
```

Then set env vars (local `.env` + Vercel dashboard): `VAPID_PRIVATE_KEY` to the
base64url-no-pad private key, `VAPID_SUBJECT=mailto:you@example.com` (contact,
required by RFC8292), `CRON_SECRET` to a long random string (authorizes
`/cron/push-due`; Vercel sends it as `Authorization: Bearer <CRON_SECRET>`
automatically when set). The backend derives + serves the public key at
`GET /push/vapid-key` — no need to store it anywhere. Add the cron job to the
backend `vercel.json` (`{ "crons": [{ "path": "/cron/push-due",
"schedule": "* * * * *" }] }` — Vercel plan limits apply: Hobby allows daily
crons, so use an external per-minute pinger e.g. cron-job.org hitting
`POST /cron/push-due` with the bearer header, while Pro allows every-minute
crons). Each device opts in once: Activities → Enable under "Ring this device
even with Noap closed". Desktop Chrome needs the site allowed; iOS needs Noap
added to Home Screen + push allowed (iOS 16.4+).

Auth = HttpOnly session cookie (`noap_session`) or `Authorization: Bearer <JWT>` + session existence + `exp`/`expAt` checks (see `src/middleware/auth.rs`). Cookie-authed state-changing requests additionally require an allowlisted `Origin`/`Referer` (CSRF guard). Brute-forceable public endpoints (`/sign-in`, `/sign-in/google`, `/find-user`, `/verify-otp`, `/2fa/verify`) are per-IP rate-limited.

## Project layout

```
noap-backend/
├── Cargo.toml          # Rust manifest — the only backend toolchain
├── Cargo.lock          # tracked: reproducible application builds
├── api/index.rs        # Vercel Rust Function entrypoint
├── src/
│   ├── lib.rs          # shared Axum router, CORS, DB init, 30+ routes
│   ├── main.rs         # local/Docker TCP server entrypoint
│   ├── models.rs       # User, Note, NoteState, Label, Session, Otp, Tfa
│   ├── handlers/
│   │   ├── user.rs     # sign_up, sign_in, google_login, OTP, TFA, settings…
│   │   ├── note.rs     # view, get, add, edit, delete, pin, labels…
│   │   ├── label.rs    # view, add, edit, delete
│   │   └── session.rs  # view, delete, delete_all
│   ├── middleware/auth.rs
│   └── utils/{mail,geo,flag,crypto,cookies,ratelimit}.rs
├── .env.example
└── vercel.json         # native Rust Function build and catch-all rewrite
```

## Why Rust?

- Memory safety + fearless concurrency (Tokio)
- 10–20× lower memory, faster cold starts than Node
- Single static binary (`cargo build --release`) — no `node_modules`, no `tsc`

## Passkeys (WebAuthn)

Passwordless sign-in via `webauthn-rs` + `@simplewebauthn/browser`. Passwords
stay valid alongside passkeys (a passkey is never a sole credential).

- All backend verification, storage, and session handling runs in Rust. The flow uses
  the [webauthn-rs discoverable APIs](https://docs.rs/webauthn-rs/latest/webauthn_rs/struct.Webauthn.html#method.start_discoverable_authentication)
  and follows its requirement to keep ceremony state server-side.
- Ceremony state is stored in MongoDB with a random 256-bit opaque `stateToken`.
  Finish atomically consumes it, checks purpose/account and a strict 10-minute expiry,
  and rejects replays across instances. TTL cleanup removes abandoned ceremonies.
- Registration: settings → Passkeys (session required and rate limited). New
  credentials request resident storage for discoverable, usernameless sign-in.
- Sign-in uses discoverable authentication, verifies the user handle and current
  stored credential, and requires user verification (PIN/biometric). This satisfies
  the second-factor requirement, so successful passkey sign-in skips TOTP.
- API `options` contains the inner WebAuthn public-key options expected by
  `@simplewebauthn/browser`. `stateToken` is opaque, not a JWT. Email scoping is
  no longer supported; authentication starts disclose no account-specific options.
- Env: `WEBAUTHN_RP_ID` / `WEBAUTHN_ORIGIN` must match the frontend host
  (localhost values for dev; production HTTPS origin otherwise).
- Startup ensures the unique `passkey_credentials { cred_id: 1 }` index and
  TTL `passkey_ceremonies { expires_at: 1 }` index. Database credentials must allow
  index creation. Existing duplicate credential IDs must be resolved before startup.
  An optional `{ userId: 1 }` index speeds up credential listing.
- Deploy frontend and backend together. Existing JWT ceremony tokens are rejected;
  users can restart an in-progress ceremony. Previously created non-discoverable
  credentials need re-registration; password/Google sign-in remains available.

## Deploy

- **Docker:** `cargo build --release` → `FROM debian:bookworm-slim` + binary + `.env`
- **Vercel:** The native Rust runtime compiles `api/index.rs`; `vercel.json` rewrites all API paths to that Axum function. Deploy with `vercel deploy` for Preview or `vercel deploy --prod` for Production. No legacy community runtime is required.
  > **One-time dashboard step:** this repo has no `package.json`, so Vercel falls back to the **Project Settings → Build and Deployment → Node.js Version** for its build container (Node is provisioned even for Rust-only builds). If it still points at a discontinued version (e.g. `18.x`), deployments fail with `Found invalid or discontinued Node.js Version`. Set it to **24.x** once — no Node files are added to the repo by this.
  > The empty `public/` directory is intentional: Vercel requires an output directory to exist even for API-only deployments, so it must not be deleted.

## License

ISC — Rodrigo Oliveira
