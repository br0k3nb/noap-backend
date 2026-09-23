#![allow(
    warnings,
    non_snake_case,
    dead_code,
    unused_imports,
    unused_variables,
    unused_mut
)]

mod handlers;
mod middleware;
mod models;
mod utils;

use axum::{
    http::{header, HeaderValue, Method},
    routing::{delete, get, patch, post},
    Router,
};
use mongodb::{Client, Database};
use std::{env, sync::Arc};
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use handlers::{activity, label, note, passkey, push, session, user};
use utils::ratelimit::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub http: reqwest::Client,
    /// Raw base64url (no pad) VAPID private key for Web Push signing. `None`
    /// means server-side push is disabled (subscription endpoints 503).
    pub vapid_private_key: Option<String>,
    /// `mailto:` contact attached to VAPID signatures (required by RFC8292).
    pub vapid_subject: String,
    /// Base64url (no pad) VAPID public key handed to browsers at subscribe
    /// time. Derived from the private key at boot so the pair can never
    /// mismatch; `None` while push is disabled.
    pub vapid_public_key: Option<String>,
    /// Shared secret authorizing the `/cron/push-due` route (Vercel sends it
    /// as `Authorization: Bearer <CRON_SECRET>` automatically when set).
    /// `None` leaves the route open — local dev only, never production.
    pub cron_secret: Option<String>,
    pub jwt_secret: String,
    pub mail_host: String,
    pub mail_port: u16,
    pub mail_user: String,
    pub mail_pass: String,
    pub mail_from: String,
    pub ipgeo_key: String,
    /// Exact origins allowed to call this API (scheme + host + port).
    pub allowed_origins: Vec<String>,
    pub cookie_secure: bool,
    pub cookie_samesite: String,
    pub rate_limiter: Arc<RateLimiter>,
    /// WebAuthn relying-party identity (passkeys are bound to these).
    pub webauthn_rp_id: String,
    pub webauthn_rp_origin: String,
    pub webauthn_rp_name: String,
}

pub fn init_tracing() {
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .try_init();
}

// NOTE on indexes: creating them at boot was tried and reverted — on this
// platform boots are frequent (fresh runtime per burst of invocations, as the
// logs show), so 8 sequential index round trips taxed every cold path while
// buying nothing measurable on collections this small (scans are single-digit
// ms). If collections ever grow large, create these once out of band
// (mongosh/Compass) instead of at startup:
//   notes:    { author: 1, "settings.pinned": 1, createdAt: 1 }
//   labels:   { userId: 1 }
//   sessions: { userId: 1 }, { token: 1 }
//   users:     { email: 1 } (unique)
//   otps:      { userId: 1 }, 2fa: { userId: 1 }, noteStates: { noteId: 1 }

pub async fn build_app() -> anyhow::Result<Router> {
    dotenvy::dotenv().ok();

    let mongodb_url = env::var("MONGODB_URL").expect("MONGODB_URL must be set");
    // No insecure default: starting without a real secret would mint
    // forgeable session tokens for every user.
    let jwt_secret = env::var("SECRET").expect("SECRET must be set");
    let mail_host = env::var("MAIL_HOSTNAME").unwrap_or_default();
    let mail_port: u16 = env::var("MAIL_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(587);
    let mail_user = env::var("MAIL_USERNAME").unwrap_or_default();
    let mail_pass = env::var("MAIL_PASSWORD").unwrap_or_default();
    let mail_from = env::var("HOST_MAIL").unwrap_or_else(|_| mail_user.clone());
    let ipgeo_key = env::var("IPGEOLOCATION_KEY").unwrap_or_default();

    // Explicit CORS allowlist (no wildcards: cookies require exact origins).
    // Production MUST set ALLOWED_ORIGINS to the deployed frontend origin(s),
    // e.g. ALLOWED_ORIGINS=https://noap.vercel.app
    let allowed_origins_from_env = env::var("ALLOWED_ORIGINS").ok();
    let allowed_origins: Vec<String> = allowed_origins_from_env
        .clone()
        .unwrap_or_else(|| {
            "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000".to_string()
        })
        .split(',')
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if allowed_origins_from_env.is_none() {
        // Fail-loud, not fail-open: localhost-only defaults block every
        // cross-origin production caller until this is configured.
        tracing::warn!(
            "ALLOWED_ORIGINS is not set — using localhost-only defaults {:?}. Production deployments MUST set ALLOWED_ORIGINS to the deployed frontend origin(s).",
            allowed_origins
        );
    } else {
        tracing::info!("CORS allowed origins: {:?}", allowed_origins);
    }

    // Cookie transport. Production defaults (Secure + SameSite=None) are
    // required for cross-site cookie auth over HTTPS. For plain-http local
    // dev set COOKIE_SECURE=false (SameSite auto-downgrades to Lax).
    let cookie_secure: bool = env::var("COOKIE_SECURE")
        .map(|v| !(v == "false" || v == "0" || v.eq_ignore_ascii_case("no")))
        .unwrap_or(true);
    let cookie_samesite =
        env::var("COOKIE_SAMESITE").unwrap_or_else(|_| "None".to_string());
    // WebAuthn relying-party identity. Passkeys are cryptographically bound
    // to the RP ID, so these MUST match the frontend origin:
    // localhost values for dev, the deployed frontend host for production
    // (registrations do not transfer between the two — by design).
    let webauthn_rp_id = env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let webauthn_rp_origin =
        env::var("WEBAUTHN_ORIGIN").unwrap_or_else(|_| "http://localhost:5173".to_string());
    let webauthn_rp_name = env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "Noap".to_string());
    // Server-side Web Push (activity reminders on every device, tab or not).
    // Generate a pair once (see README "Web Push setup") and set the private
    // half here; the public half is derived at boot and served to browsers.
    let vapid_private_key = env::var("VAPID_PRIVATE_KEY").ok().filter(|k| !k.trim().is_empty());
    let vapid_subject =
        env::var("VAPID_SUBJECT").unwrap_or_else(|_| "mailto:noreply@noap.example.com".to_string());
    let vapid_public_key = vapid_private_key.as_deref().and_then(|k| {
        match web_push::VapidSignatureBuilder::from_base64_no_sub(k.trim()) {
            Ok(partial) => {
                let raw = partial.get_public_key();
                Some(base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    raw,
                ))
            }
            Err(e) => {
                tracing::error!("VAPID_PRIVATE_KEY is invalid ({}) — server-side push disabled", e);
                None
            }
        }
    });
    // A present-but-invalid private key must not silently half-enable push.
    let vapid_private_key = match (&vapid_private_key, &vapid_public_key) {
        (Some(_), Some(_)) => {
            tracing::info!("Web Push enabled (VAPID subject {})", vapid_subject);
            vapid_private_key
        }
        (Some(_), None) => None,
        (None, _) => {
            tracing::warn!("VAPID_PRIVATE_KEY is not set — server-side push notifications disabled (in-app reminders still work while a tab is open)");
            None
        }
    };
    let cron_secret = env::var("CRON_SECRET").ok().filter(|s| !s.is_empty());
    if cron_secret.is_none() {
        tracing::warn!("CRON_SECRET is not set — /cron/push-due accepts unauthenticated calls. Set it in production.");
    }
    tracing::info!(
        "WebAuthn RP: id={} origin={}",
        webauthn_rp_id,
        webauthn_rp_origin
    );    {
        // Log the effective mode so a misconfigured deployment is obvious:
        // SameSite=None without Secure is rejected by browsers, so the
        // cookie layer downgrades it to Lax (local http dev).
        let effective_samesite = if !cookie_secure && cookie_samesite.eq_ignore_ascii_case("none") {
            "Lax (downgraded: SameSite=None requires Secure)"
        } else {
            cookie_samesite.as_str()
        };
        tracing::info!(
            "Session cookies: HttpOnly, Secure={}, SameSite={}",
            cookie_secure,
            effective_samesite
        );
        if cookie_secure {
            tracing::info!("Cookie transport assumes HTTPS origins — plain-http local dev needs COOKIE_SECURE=false.");
        }
    }

    let client = Client::with_uri_str(&mongodb_url).await?;
    let db = client
        .default_database()
        .unwrap_or_else(|| client.database("noap"));
    tracing::info!("MongoDB client initialized");
    passkey::ensure_indexes(&db).await?;

    let state = Arc::new(AppState {
        db,
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new()),
        vapid_private_key,
        vapid_subject,
        vapid_public_key,
        cron_secret,
        jwt_secret,
        mail_host,
        mail_port,
        mail_user,
        mail_pass,
        mail_from,
        ipgeo_key,
        allowed_origins: allowed_origins.clone(),
        cookie_secure,
        cookie_samesite,
        rate_limiter: Arc::new(RateLimiter::new()),
        webauthn_rp_id,
        webauthn_rp_origin,
        webauthn_rp_name,
    });

    let mut valid_origins = Vec::new();
    for origin in &allowed_origins {
        match HeaderValue::from_str(origin) {
            Ok(v) => valid_origins.push(v),
            Err(e) => tracing::warn!("Ignoring invalid ALLOWED_ORIGINS entry {:?}: {}", origin, e),
        }
    }
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(valid_origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(AllowHeaders::list(vec![
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::ORIGIN,
        ]))
        .allow_credentials(true)
        .allow_private_network(true);

    let public_routes = Router::new()
        .route("/sign-up", post(user::sign_up))
        .route("/sign-in", post(user::sign_in))
        .route("/sign-in/google", post(user::google_login))
        .route("/verify-otp", post(user::verify_otp))
        .route("/2fa/remove", post(user::remove_2fa))
        .route("/2fa/verify", post(user::verify_2fa_code))
        .route("/find-user", post(user::find_and_send_code))
        .route("/change-pass", patch(user::change_password))
        .route("/passkeys/auth/start", post(passkey::auth_start))
        .route("/passkeys/auth/finish", post(passkey::auth_finish))
        // Public on purpose: the handler performs full token + session
        // validation itself (it must also accept legacy body tokens once, to
        // migrate pre-cookie clients into HttpOnly cookies).
        .route("/verify-token", post(user::verify_token))
        // Public on purpose: browsers need the VAPID public key to subscribe
        // before they hold any session; it identifies the server, grants nothing.
        .route("/push/vapid-key", get(push::vapid_key))
        // Cron fan-out: authenticated by CRON_SECRET bearer inside the handler
        // (cron has no user session, so it stays OUTSIDE verify_user).
        // GET + POST: Vercel Cron invokes paths with GET; external per-minute
        // pingers (cron-job.org on Hobby) can use either.
        .route("/cron/push-due", get(push::cron_push_due).post(push::cron_push_due));

    let protected_routes = Router::new()
        .route("/sign-out", post(user::sign_out))
        .route("/verify-user", post(user::verify_user))
        .route("/2fa/qrcode", post(user::generate_2fa_qrcode))
        .route("/passkeys/register/start", post(passkey::register_start))
        .route("/passkeys/register/finish", post(passkey::register_finish))
        .route("/passkeys", get(passkey::list))
        .route("/passkeys/{credId}", delete(passkey::remove))
        // Account conversion is a settings action: only the session owner
        // may convert their own account.
        .route("/convert/account/email", patch(user::convert_into_normal))
        .route("/convert/account/google", patch(user::convert_into_google))
        .route("/lastOpenedNote/{id}", patch(user::last_opened_note))
        .route("/settings/change-theme/{id}", patch(user::change_theme))
        .route("/settings/note-text/{id}", post(user::note_text_expanded))
        .route(
            "/settings/pin-notes-folder/{id}",
            post(user::show_pinned_in_folder),
        )
        .route(
            "/settings/note-visualization/{id}",
            patch(user::change_visualization),
        )
        .route(
            "/settings/onLoginGoToLastOpenedNote/{id}",
            patch(user::on_login_go_to_last),
        )
        .route(
            "/settings/global-note-background-color/{id}",
            patch(user::change_global_bg),
        )
        .route("/get/sessions/{userId}", get(session::view))
        .route(
            "/delete/session/{userId}/{sessionId}",
            delete(session::delete_one),
        )
        .route("/delete/all/sessions/{userId}", delete(session::delete_all))
        .route("/add", post(note::add))
        .route("/edit", patch(note::edit))
        .route("/note/{id}", get(note::get_note))
        .route("/delete/{id}", delete(note::delete))
        .route("/notes/{page}/{author}", get(note::view))
        .route("/note/add/label", post(note::add_label))
        .route("/note/rename/{id}", post(note::rename))
        .route("/note/pin-note/{noteId}", post(note::pin_note))
        .route("/note/image/{noteId}", post(note::change_image))
        .route(
            "/note/delete/label/{id}/{noteId}",
            delete(note::delete_label),
        )
        .route(
            "/note/delete-all/label/{noteId}",
            delete(note::delete_all_labels),
        )
        .route(
            "/settings/note-background-color/{noteId}",
            patch(note::change_bg),
        )
        .route("/labels/{userId}", get(label::view))
        .route("/label/add/{userId}", post(label::add))
        .route("/label/edit/{userId}", patch(label::edit))
        .route("/label/delete/{id}", delete(label::delete))
        .route("/activities/{userId}", get(activity::view))
        .route("/activity/add/{userId}", post(activity::add))
        .route("/activity/edit/{userId}", patch(activity::edit))
        .route("/activity/toggle/{id}", post(activity::toggle))
        .route("/activity/triggered/{id}", post(activity::mark_triggered))
        .route("/activity/delete/{id}", delete(activity::delete))
        .route("/activity/link-note/{id}", post(activity::link_note))
        .route("/activity/unlink-note/{id}", post(activity::unlink_note))
        .route("/activity/complete/{id}", post(activity::complete))
        .route("/activity/seen/{id}", post(activity::record_seen))
        .route("/activity/progress/{id}", get(activity::progress))
        .route("/push/subscribe/{userId}", post(push::subscribe))
        .route("/push/unsubscribe/{userId}", post(push::unsubscribe))
        .route("/push/subscriptions/{userId}", get(push::list))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth::verify_user,
        ));

    Ok(Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .route("/", get(|| async { "Noap Rust API running" }))
        .layer(cors)
        .with_state(state))
}
