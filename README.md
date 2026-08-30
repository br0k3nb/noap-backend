<div align="center">
  <br>
  <h1>Noap 📝 — Rust Backend</h1>
  <strong>Your next notes application — now 100% Rust</strong>
</div>
<br>

> This is the **Rust port** of the original Noap backend (Node/Express/Mongoose). The entire API has been re-implemented in Rust with **Axum + MongoDB** and is a drop-in replacement for the Node server. It exposes the **identical HTTP contract** so the existing React frontend (`/noap`) works without changes.

## Stack
- **Runtime:** Rust 1.82+ (tested on 1.97, Node 24/26 not required for backend)
- **Web:** Axum 0.7 + Tokio + Tower-HTTP (CORS, Trace)
- **DB:** MongoDB (official `mongodb` 3.1 driver, `bson` 2.15) — same collections as the Node version (`users`, `notes`, `noteStates`, `labels`, `sessions`, `otps`, `2fa`)
- **Auth:** `jsonwebtoken` HS512 + `bcrypt` 0.17, middleware `verify_user`
- **Mail:** `lettre` 0.11 (SMTP, HTML OTP from `utils/mail.rs`)
- **2FA:** `totp-rs` 5.6 + `qrcode` 0.14 (`generate_2fa_qrcode`, `verify_2fa_code`)
- **Geo/IP:** `reqwest` → `https://api.ipgeolocation.io/ipgeo`
- **Device:** `uaparser` (UA → browser/client/device), `country_code_to_flag` for emoji

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
| `SECRET` | **yes** | `secret` | JWT HS512 secret (64+ chars) |
| `MAIL_HOSTNAME` | no | — | SMTP host (OTP mails skipped if empty) |
| `MAIL_PORT` | no | 587 | SMTP port |
| `MAIL_USERNAME` | no | — | SMTP user |
| `MAIL_PASSWORD` | no | — | SMTP pass |
| `HOST_MAIL` | no | `$MAIL_USERNAME` | From address |
| `IPGEOLOCATION_KEY` | no | — | api.ipgeolocation.io key (geo fallback to Unknown) |
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
POST   /verify-token          (auth)
PATCH  /lastOpenedNote/:id    (auth)
PATCH  /convert/account/email
PATCH  /convert/account/google
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

Auth = `Authorization: Bearer <JWT>` + session existence + `exp` check (same as `src/middlewares/verifyUser.ts`).

## Project layout

```
noap-backend/
├── Cargo.toml          # Rust manifest (replaces package.json for runtime)
├── package.json        # kept for reference / legacy Node tooling
├── src/
│   ├── main.rs         # Axum router, CORS, DB init, 30+ routes
│   ├── models.rs       # User, Note, NoteState, Label, Session, Otp, Tfa
│   ├── handlers/
│   │   ├── user.rs     # sign_up, sign_in, google_login, OTP, TFA, settings…
│   │   ├── note.rs     # view, get, add, edit, delete, pin, labels…
│   │   ├── label.rs    # view, add, edit, delete
│   │   └── session.rs  # view, delete, delete_all
│   ├── middleware/auth.rs
│   └── utils/{mail,geo,flag,crypto}.rs
├── .env.example
└── vercel.json         # rewrites (unchanged, adapt for Rust if deploying)
```

## Why Rust?

- Memory safety + fearless concurrency (Tokio)
- 10–20× lower memory, faster cold starts than Node
- Single static binary (`cargo build --release`) — no `node_modules`, no `tsc`

## Legacy Node

The original Express code is still in `src/server.ts` / `src/controllers/*` / `src/models/*` for reference. To run the Node version: `yarn install && yarn start` (requires Node 18). The Rust binary is the **primary** backend now.

## Deploy

- **Docker:** `cargo build --release` → `FROM debian:bookworm-slim` + binary + `.env`
- **Vercel:** Use `vercel-rust` runtime or deploy binary to Fly.io / Render. Keep `vercel.json` rewrites.

## License

ISC — Rodrigo Oliveira
