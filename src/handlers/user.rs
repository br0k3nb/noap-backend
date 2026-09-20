use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    Json,
};
use bson::{doc, oid::ObjectId, Bson, DateTime as BsonDateTime};
use chrono::{DateTime, Utc};
use futures::TryStreamExt;
use mongodb::Database;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};

use crate::{
    middleware::auth::{bearer_session_user, request_session_token, require_owner},
    models::{Otp, Session, Tfa, User},
    utils::{
        cookies::{self, CookieConfig},
        crypto::{
            create_reset_token, create_tfa_token, create_token, verify_reset_token, Claims, JwtSub,
        },
        flag::country_code_to_flag,
        geo::{fetch_geo, GeoInfo},
        mail::mail_html,
        ratelimit::client_key,
    },
    AppState,
};

/// Generic database-failure response: details go to server logs only, so
/// driver internals are never leaked to API clients.
fn db_err<E: std::fmt::Display>(e: E) -> (StatusCode, Json<Value>) {
    tracing::error!("DB error: {}", e);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"message": "Database error, please try again later"})),
    )
}

fn validate_password(password: &str) -> Result<(), (StatusCode, Json<Value>)> {
    if password.len() < 6 || password.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Password must be between 6 and 128 characters!"})),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    email: Option<String>,
    id: Option<String>,
}

/// Verifies the Google OAuth access token server-side and confirms it belongs
/// to the claimed account. Without this, anyone could POST an arbitrary email
/// to /sign-in/google and hijack the account.
async fn verify_google_token(
    access_token: &str,
    expected_email: &str,
    expected_id: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    let client = reqwest::Client::new();
    let resp = client
        .get("https://www.googleapis.com/oauth2/v1/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Google userinfo request failed: {}", e);
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"message": "Could not verify Google account, please try again"})),
            )
        })?;
    if !resp.status().is_success() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Google verification failed, please try again"})),
        ));
    }
    let info: GoogleUserInfo = resp.json().await.map_err(|e| {
        tracing::error!("Google userinfo parse failed: {}", e);
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Google verification failed, please try again"})),
        )
    })?;
    let email_ok = info
        .email
        .as_deref()
        .map(|e| e.eq_ignore_ascii_case(expected_email))
        .unwrap_or(false);
    let id_ok = info
        .id
        .as_deref()
        .map(|i| i == expected_id)
        .unwrap_or(false);
    if !email_ok || !id_ok {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Google account mismatch, please try again"})),
        ));
    }
    Ok(())
}

// ---------- Session-cookie plumbing ----------

fn cookie_config(state: &AppState) -> CookieConfig {
    CookieConfig {
        secure: state.cookie_secure,
        same_site: state.cookie_samesite.clone(),
    }
}

fn set_cookie_headers(pairs: &[String]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for pair in pairs {
        if let Ok(v) = HeaderValue::from_str(pair) {
            headers.append("set-cookie", v);
        }
    }
    headers
}

/// Sliding-window guard for brute-forceable public endpoints. Returns 429
/// with a generic message (no timing oracle beyond the status itself).
async fn enforce_rate_limit_key(
    state: &AppState,
    key: String,
    max_attempts: u32,
    window_secs: u64,
) -> Result<(), (StatusCode, Json<Value>)> {
    match state
        .rate_limiter
        .check(key, max_attempts, Duration::from_secs(window_secs))
        .await
    {
        Ok(()) => Ok(()),
        Err(retry_secs) => {
            tracing::warn!("Rate limit exceeded (retry in {}s)", retry_secs);
            Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"message": "Too many attempts, please try again later"})),
            ))
        }
    }
}

async fn enforce_rate_limit(
    state: &AppState,
    headers: &HeaderMap,
    scope: &str,
    max_attempts: u32,
    window_secs: u64,
) -> Result<(), (StatusCode, Json<Value>)> {
    enforce_rate_limit_key(
        state,
        client_key(headers, scope),
        max_attempts,
        window_secs,
    )
    .await
}

/// Per-account budget key (OTP/TOTP guessing, email bombing). The identifier
/// is caller-supplied — that is the point: it caps attempts against one
/// target account even when the attacker rotates IPs. Sanitized so crafted
/// identifiers can't blow up the limiter map.
fn account_rate_key(scope: &str, id: &str) -> String {
    let clean: String = id
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| {
            c.is_ascii_alphanumeric() || *c == '.' || *c == '@' || *c == '_' || *c == '-'
        })
        .take(128)
        .collect();
    format!("{scope}:{}", if clean.is_empty() { "unknown" } else { &clean })
}

struct SessionMeta {
    ua: String,
    identifier: String,
}

/// Creates the session DB row and returns the raw JWT. Callers place it in
/// the HttpOnly session cookie — it must never appear in a JSON body.
async fn mint_session(
    db: &Database,
    uid: ObjectId,
    sub: JwtSub,
    meta: &SessionMeta,
    geo: &GeoInfo,
    secret: &str,
) -> Result<String, (StatusCode, Json<Value>)> {
    let token = create_token(sub, secret).map_err(|e| {
        tracing::error!("session token creation failed: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"message": "Internal error, please try again later"})),
        )
    })?;
    let sess = Session {
        id: None,
        userId: uid,
        token: token.clone(),
        expAt: (Utc::now().timestamp() + cookies::SESSION_MAX_AGE_SECS) as i64,
        ip: if meta.identifier.is_empty() {
            "Unknown".to_string()
        } else {
            meta.identifier.clone()
        },
        browserData: meta.ua.clone(),
        location: format!("{}, {}, {}", geo.city, geo.state_prov, geo.country_name),
        countryFlag: country_code_to_flag(&geo.country_code),
        deviceData: bson::to_bson(&serde_json::json!({"ua": meta.ua})).unwrap_or(Bson::Null),
        clientData: meta.ua.clone(),
        createdAt: Some(Utc::now()),
    };
    db.collection::<Session>("sessions")
        .insert_one(sess)
        .await
        .map_err(db_err)?;
    Ok(token)
}

// ---------- Request structs ----------
#[derive(Deserialize)]
pub struct SignUpReq {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginReq {
    pub email: String,
    pub password: String,
    /// Client public IP for session metadata. Optional: the frontend sends ""
    /// when its IP-lookup service is unreachable, and auth must not depend on it.
    #[serde(default)]
    pub identifier: String,
}

#[derive(Deserialize)]
pub struct GoogleLoginReq {
    pub email: String,
    pub name: String,
    pub id: String,
    #[serde(default)]
    pub identifier: String,
    /// Google OAuth2 access token, verified server-side against Google's
    /// userinfo endpoint. Required: prevents account takeover via forged
    /// email/id pairs.
    pub access_token: String,
}

#[derive(Deserialize)]
pub struct VerifyTokenReq {
    /// Legacy body token: accepted exactly once to migrate pre-cookie
    /// clients (localStorage JWT) into an HttpOnly cookie. New clients send
    /// no body at all — the cookie (or Bearer header) is the credential.
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub identifier: String,
}

#[derive(Deserialize)]
pub struct ChangePassReq {
    pub userId: String,
    pub password: String,
    /// Proof of email ownership from /verify-otp. Required when the caller
    /// has no live session (password-recovery flow).
    #[serde(default)]
    pub resetToken: Option<String>,
}

#[derive(Deserialize)]
pub struct FindUserReq {
    pub email: String,
    pub remove2FA: Option<String>,
}

#[derive(Deserialize)]
pub struct VerifyOtpReq {
    pub userId: String,
    pub otp: String,
}

#[derive(Deserialize)]
pub struct Gen2FAReq {
    pub userId: String,
}

#[derive(Deserialize)]
pub struct Verify2FAReq {
    pub userId: String,
    #[serde(rename = "TFACode")]
    pub tfa_code: String,
    /// Optional client IP for the session record minted after 2FA.
    #[serde(default)]
    pub identifier: String,
}

#[derive(Deserialize)]
pub struct Remove2FAReq {
    pub userId: String,
    /// Proof of email ownership from /verify-otp. Required when the caller
    /// has no live session (2FA-recovery flow).
    #[serde(default)]
    pub resetToken: Option<String>,
}

#[derive(Deserialize)]
pub struct ConvertNormalReq {
    #[serde(rename = "_id")]
    pub id: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct ConvertGoogleReq {
    #[serde(rename = "_id")]
    pub _id: String,
    pub email: String,
    pub name: String,
    #[serde(rename = "id")]
    pub google_id: String,
}

#[derive(Deserialize, Debug)]
pub struct ConvertGoogleReq2 {
    #[serde(rename = "_id")]
    pub _id: String,
    pub email: String,
    pub name: String,
    pub id: String,
}

#[derive(Deserialize)]
pub struct VerifyUserReq {
    pub _id: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct ThemeReq {
    pub theme: String,
}

#[derive(Deserialize)]
pub struct ConditionReq {
    pub condition: bool,
}

#[derive(Deserialize)]
pub struct GlobalBgReq {
    pub globalNoteBackgroundColor: String,
}

#[derive(Deserialize)]
pub struct VisualizationReq {
    pub visualization: String,
}

#[derive(Deserialize)]
pub struct OnLoginReq {
    pub onLoginGoToLastOpenedNote: bool,
}

#[derive(Deserialize)]
pub struct LastOpenedReq {
    pub lastOpenedNote: String,
}

#[derive(Deserialize)]
pub struct SignOutReq {
    pub userId: String,
    pub token: String,
}

// ---------- Handlers ----------
pub async fn sign_up(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SignUpReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    validate_password(&payload.password)?;
    if payload.name.trim().is_empty() || payload.email.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Name and email are required!"})),
        ));
    }
    let db = &state.db;
    let coll = db.collection::<User>("users");
    let existing = coll
        .find_one(doc! {"email": &payload.email})
        .await
        .map_err(db_err)?;
    if existing.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "User already exists, please sign in!"})),
        ));
    }
    let hashed = bcrypt::hash(&payload.password, 10).map_err(|e| {
        tracing::error!("bcrypt hash failed: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"message": "Internal error, please try again later"})),
        )
    })?;
    let user = User {
        id: None,
        email: payload.email,
        name: payload.name,
        password: Some(hashed),
        verified: None,
        googleId: None,
        tfa_status: None,
        googleAccount: Some(false),
        lastOpenedNote: None,
        settings: Some(crate::models::UserSettings {
            noteTextExpanded: Some(true),
            theme: Some("dark".to_string()),
            ..Default::default()
        }),
    };
    coll.insert_one(user).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    Ok((
        StatusCode::OK,
        Json(json!({"message": "User created successfully!"})),
    ))
}

pub async fn sign_in(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<LoginReq>,
) -> Result<(StatusCode, HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    enforce_rate_limit(&state, &headers, "signin", 20, 600).await?;
    // User-Agent and client IP are advisory metadata only: privacy tools and
    // third-party IP lookups fail often enough that rejecting on them locks
    // legitimate users out. Never gate authentication on them.
    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let ua = if ua.is_empty() {
        "Unknown".to_string()
    } else {
        ua
    };
    let db = &state.db;
    let coll = db.collection::<User>("users");
    let user = coll
        .find_one(doc! {"email": &payload.email})
        .await
        .map_err(db_err)?;
    let user = match user {
        Some(u) => u,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Wrong email or password combination!"})),
            ))
        }
    };
    if user.googleAccount.unwrap_or(false) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "The selected sign in method isn't available to this email!"})),
        ));
    }
    // geo
    let geo = fetch_geo(&payload.identifier, &state.ipgeo_key).await;
    // TFA check
    let tfa_enabled = if let Some(tfa_id) = user.tfa_status {
        let tfa_coll = db.collection::<Tfa>("2fa");
        if let Ok(Some(tfa)) = tfa_coll.find_one(doc! {"_id": tfa_id}).await {
            tfa.verified
        } else {
            false
        }
    } else {
        false
    };

    let db_pass = user.password.clone().unwrap_or_default();
    let ok = bcrypt::verify(&payload.password, &db_pass).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Wrong email or password combination!"})),
        )
    })?;
    if !ok {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Wrong email or password combination!"})),
        ));
    }
    let uid = user.id.unwrap();
    let cfg = cookie_config(&state);
    if tfa_enabled {
        // Password is correct but 2FA is still pending: mint NO session yet.
        // The short-lived pending cookie is the only credential /2fa/verify
        // will accept to create the real session.
        let pending = create_tfa_token(&uid.to_hex(), &state.jwt_secret).map_err(|e| {
            tracing::error!("tfa token creation failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Internal error, please try again later"})),
            )
        })?;
        let headers_out =
            set_cookie_headers(&[cookies::tfa_cookie(&pending, &cfg)]);
        return Ok((
            StatusCode::OK,
            headers_out,
            Json(json!({
                "_id": uid.to_hex(),
                "name": user.name,
                "TFAEnabled": true,
                "settings": user.settings,
                "lastOpenedNote": user.lastOpenedNote.map(|o| o.to_hex())
            })),
        ));
    }
    let sub = JwtSub {
        _id: uid.to_hex(),
        name: user.name.clone(),
        googleAccount: false,
    };
    let meta = SessionMeta {
        ua: ua.clone(),
        identifier: payload.identifier.clone(),
    };
    let token = mint_session(db, uid, sub, &meta, &geo, &state.jwt_secret).await?;
    // The JWT lives in the HttpOnly cookie only — it must never appear in a
    // JSON body where page JavaScript could read it.
    let headers_out = set_cookie_headers(&[cookies::session_cookie(
        &token,
        cookies::SESSION_MAX_AGE_SECS,
        &cfg,
    )]);
    Ok((
        StatusCode::OK,
        headers_out,
        Json(json!({
            "_id": uid.to_hex(),
            "name": user.name,
            "TFAEnabled": false,
            "settings": user.settings,
            "lastOpenedNote": user.lastOpenedNote.map(|o| o.to_hex())
        })),
    ))
}

pub async fn google_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<GoogleLoginReq>,
) -> Result<(StatusCode, HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    enforce_rate_limit(&state, &headers, "signin-google", 20, 600).await?;
    // The claimed Google identity must be proven with the OAuth access token:
    // the frontend cannot be trusted to report email/id truthfully.
    verify_google_token(&payload.access_token, &payload.email, &payload.id).await?;
    // User-Agent and client IP are advisory metadata only (see sign_in).
    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let ua = if ua.is_empty() {
        "Unknown".to_string()
    } else {
        ua
    };
    let db = &state.db;
    let coll = db.collection::<User>("users");
    let existing = coll
        .find_one(doc! {"email": &payload.email})
        .await
        .map_err(db_err)?;
    let geo = fetch_geo(&payload.identifier, &state.ipgeo_key).await;
    let cfg = cookie_config(&state);
    let meta = SessionMeta {
        ua: ua.clone(),
        identifier: payload.identifier.clone(),
    };
    if existing.is_none() {
        let new_user = User {
            id: None,
            email: payload.email.clone(),
            name: payload.name.clone(),
            password: None,
            verified: None,
            googleId: Some(payload.id.clone()),
            tfa_status: None,
            googleAccount: Some(true),
            lastOpenedNote: None,
            settings: Some(crate::models::UserSettings {
                noteTextExpanded: Some(true),
                theme: Some("dark".to_string()),
                ..Default::default()
            }),
        };
        coll.insert_one(new_user).await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
        let user = coll
            .find_one(doc! {"email": &payload.email})
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    crate::utils::db_err_json(e),
                )
            })?
            .unwrap();
        let uid = user.id.unwrap();
        let tfa_enabled = false;
        let sub = JwtSub {
            _id: uid.to_hex(),
            name: user.name.clone(),
            googleAccount: true,
        };
        // Brand-new Google users never have 2FA yet: mint the session.
        let token = mint_session(db, uid, sub, &meta, &geo, &state.jwt_secret).await?;
        let headers_out = set_cookie_headers(&[cookies::session_cookie(
            &token,
            cookies::SESSION_MAX_AGE_SECS,
            &cfg,
        )]);
        return Ok((
            StatusCode::OK,
            headers_out,
            Json(
                json!({"message":"Success","_id":uid.to_hex(),"name":user.name,"googleAccount":true,"TFAEnabled":tfa_enabled,"settings":user.settings}),
            ),
        ));
    } else {
        let user = existing.unwrap();
        if !user.googleAccount.unwrap_or(false) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"message": "User already exists, please sign in using your email and password!"}),
                ),
            ));
        }
        let uid = user.id.unwrap();
        let tfa_enabled = if let Some(tfa_id) = user.tfa_status {
            let tfa_coll = db.collection::<Tfa>("2fa");
            if let Ok(Some(tfa)) = tfa_coll.find_one(doc! {"_id": tfa_id}).await {
                tfa.verified
            } else {
                false
            }
        } else {
            false
        };
        if tfa_enabled {
            // Password-equivalent (Google) OK, 2FA pending: no session yet.
            let pending = create_tfa_token(&uid.to_hex(), &state.jwt_secret).map_err(|e| {
                tracing::error!("tfa token creation failed: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"message": "Internal error, please try again later"})),
                )
            })?;
            let headers_out =
                set_cookie_headers(&[cookies::tfa_cookie(&pending, &cfg)]);
            return Ok((
                StatusCode::OK,
                headers_out,
                Json(
                    json!({"message":"Success","_id":uid.to_hex(),"name":user.name,"googleAccount":true,"TFAEnabled":true,"settings":user.settings}),
                ),
            ));
        }
        let sub = JwtSub {
            _id: uid.to_hex(),
            name: user.name.clone(),
            googleAccount: true,
        };
        let token = mint_session(db, uid, sub, &meta, &geo, &state.jwt_secret).await?;
        let headers_out = set_cookie_headers(&[cookies::session_cookie(
            &token,
            cookies::SESSION_MAX_AGE_SECS,
            &cfg,
        )]);
        return Ok((
            StatusCode::OK,
            headers_out,
            Json(
                json!({"message":"Success","_id":uid.to_hex(),"name":user.name,"googleAccount":true,"TFAEnabled":tfa_enabled,"settings":user.settings}),
            ),
        ));
    }
}

pub async fn verify_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<VerifyTokenReq>>,
) -> Result<(StatusCode, HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    // Credential priority: Bearer header → HttpOnly session cookie → legacy
    // body token (accepted exactly once to migrate pre-cookie clients holding
    // a localStorage JWT into a cookie; the cookie is set below on success).
    let (token, migrate) = match request_session_token(&headers) {
        Some((t, _)) => (t, false),
        None => match body
            .as_ref()
            .map(|b| b.token.trim().to_string())
            .filter(|t| !t.is_empty())
        {
            Some(t) => (t, true),
            None => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"message": "Access denied, sign in again"})),
                ))
            }
        },
    };
    let claims =
        crate::utils::crypto::decode_token(&token, &state.jwt_secret).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"message": "Access denied, sign in again"})),
            )
        })?;
    // decode_token skips exp validation; enforce it here since this endpoint
    // no longer sits behind the auth middleware.
    if claims.exp < Utc::now().timestamp() as usize {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Session expired, please sign in again"})),
        ));
    }
    let db = &state.db;
    let uid = ObjectId::parse_str(&claims.sub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    let user = db
        .collection::<User>("users")
        .find_one(doc! {"_id": uid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    let user = user.ok_or((
        StatusCode::BAD_REQUEST,
        Json(json!({"message": "User not found"})),
    ))?;
    let sess_coll = db.collection::<Session>("sessions");
    let sessions: Vec<Session> = sess_coll
        .find(doc! {"userId": uid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?
        .try_collect()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    if sessions.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Access denied, sign in again"})),
        ));
    }
    let matching = sessions.iter().find(|s| s.token == token);
    let matching = matching.ok_or((
        StatusCode::UNAUTHORIZED,
        Json(json!({"message": "Access denied, sign in again"})),
    ))?;
    // Enforce server-side session expiry: a stolen long-lived token stops
    // working once its session record expires, even if the JWT itself hasn't.
    if matching.expAt < Utc::now().timestamp() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Session expired, please sign in again"})),
        ));
    }
    let mut headers_out = HeaderMap::new();
    if migrate {
        // Promote the legacy token into an HttpOnly cookie, capped at the
        // session's remaining lifetime so the cookie can't outlive it.
        let max_age = (matching.expAt - Utc::now().timestamp()).max(0);
        headers_out = set_cookie_headers(&[cookies::session_cookie(
            &token,
            max_age,
            &cookie_config(&state),
        )]);
    }
    // Check ip? original checks identifier vs session.ip? but they store ip as identifier string directly, not hashed. So compare equality.
    // Original: const verifySessionIp = matchingSession ? identifier: false; then if (!verifySessionIp) fail. That is just check identifier truthy.
    // So we just pass.
    let tfa_enabled = user.tfa_status.is_some();
    let settings = user.settings.clone().unwrap_or_default();
    // return userDataObj matching Node: spread sub fields
    let jwt_sub = claims.jwt_sub();
    // Use name/googleAccount from token if available, fallback to DB
    let name = if !jwt_sub.name.is_empty() {
        jwt_sub.name.clone()
    } else {
        user.name.clone()
    };
    let google_account = jwt_sub.googleAccount;
    Ok((
        StatusCode::OK,
        headers_out,
        Json(json!({
            "_id": jwt_sub._id,
            "name": name,
            "googleAccount": google_account,
            "TFAEnabled": tfa_enabled,
            "settings": settings,
        })),
    ))
}

pub async fn verify_user(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<VerifyUserReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_owner(&claims, &payload._id)?;
    let db = &state.db;
    let uid = ObjectId::parse_str(&payload._id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "User not found!"})),
        )
    })?;
    let user = db
        .collection::<User>("users")
        .find_one(doc! {"_id": uid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    let user = user.ok_or((
        StatusCode::BAD_REQUEST,
        Json(json!({"message": "User not found!"})),
    ))?;
    let db_pass = user.password.unwrap_or_default();
    let ok = bcrypt::verify(&payload.password, &db_pass).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Wrong password, please try again!"})),
        )
    })?;
    if ok {
        Ok((StatusCode::OK, Json(json!({"message": "Authenticated"}))))
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Wrong password, please try again!"})),
        ))
    }
}

pub async fn change_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ChangePassReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    // Dual-use endpoint: settings flow (live session) and recovery flow
    // (proof of email ownership). One of them must authorize this call —
    // a bare userId is not authorization.
    let session_owner = bearer_session_user(&state, &headers).await;
    let authorized = match session_owner {
        Some(owner) => owner == payload.userId,
        None => payload
            .resetToken
            .as_deref()
            .and_then(|t| verify_reset_token(t, &state.jwt_secret))
            .map(|uid| uid == payload.userId)
            .unwrap_or(false),
    };
    if !authorized {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Access denied, sign in again"})),
        ));
    }
    validate_password(&payload.password)?;
    let db = &state.db;
    let uid = ObjectId::parse_str(&payload.userId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "User not found, please try again or later!"})),
        )
    })?;
    let coll = db.collection::<User>("users");
    let exists = coll.find_one(doc! {"_id": uid}).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    if exists.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "User not found, please try again or later!"})),
        ));
    }
    let hashed = bcrypt::hash(&payload.password, 10)
        .map_err(|e| crate::utils::internal_err(e, "bcrypt hash"))?;
    coll.update_one(doc! {"_id": uid}, doc! {"$set": {"password": hashed}})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    Ok((
        StatusCode::OK,
        Json(json!({"message": "Password changed!"})),
    ))
}

pub async fn find_and_send_code(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<FindUserReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    // Email enumeration + mail-bomb guard (per IP; the handler itself is
    // additionally per-account throttled via the OTP spam field).
    enforce_rate_limit(&state, &headers, "find-user", 10, 600).await?;
    // Per-recipient budget: caps inbox bombing / enumeration of one address
    // even when the caller rotates IPs.
    enforce_rate_limit_key(
        &state,
        account_rate_key("find-user-acct", &payload.email),
        5,
        600,
    )
    .await?;
    let db = &state.db;
    let coll = db.collection::<User>("users");
    let user = coll
        .find_one(doc! {"email": &payload.email})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    if user.is_none() {
        return Ok((
            StatusCode::OK,
            Json(
                json!({"message": "If an account with this email exists, the code will be sent", "code": 1}),
            ),
        ));
    }
    let user = user.unwrap();
    let uid = user.id.unwrap();
    // TFA checks
    if let Some(tfa_id) = user.tfa_status {
        let tfa_coll = db.collection::<Tfa>("2fa");
        if let Ok(Some(tfa)) = tfa_coll.find_one(doc! {"_id": tfa_id}).await {
            if tfa
                .options
                .as_ref()
                .and_then(|o| o.useToResetPass)
                .unwrap_or(false)
                && payload.remove2FA.as_deref() != Some("2fa")
            {
                return Ok((
                    StatusCode::OK,
                    Json(json!({"code": 5, "userId": uid.to_hex()})),
                ));
            }
        }
    }
    if user.tfa_status.is_none() && payload.remove2FA.as_deref() == Some("2fa") {
        return Ok((
            StatusCode::OK,
            Json(json!({"message": "If an account with this email exists, the code will be sent"})),
        ));
    }
    let otp_coll = db.collection::<Otp>("otps");
    let otps: Vec<Otp> = otp_coll
        .find(doc! {"userId": uid.to_hex()})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?
        .try_collect()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    // Clean after 24h
    if let Some(last) = otps.last() {
        if let Some(created) = last.createdAt {
            if created + chrono::Duration::days(1) <= Utc::now() {
                let ids: Vec<ObjectId> = otps.iter().filter_map(|o| o.id).collect();
                otp_coll
                    .delete_many(doc! {"userId": uid.to_hex(), "_id": {"$in": ids}})
                    .await
                    .map_err(|e| {
                        (
                            StatusCode::BAD_REQUEST,
                            crate::utils::db_err_json(e),
                        )
                    })?;
            }
        }
    }
    let now = Utc::now();
    let can_send = if otps.is_empty() {
        true
    } else {
        let last_spam = otps
            .last()
            .and_then(|o| o.spam)
            .unwrap_or(now - chrono::Duration::hours(1));
        otps.len() < 5 && last_spam < now
    };
    if !can_send {
        if otps.len() >= 5 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"message": "Maximum number of otp codes exceeded, please try again after 24 hours!", "code": 3}),
                ),
            ));
        } else {
            let spam = otps.last().and_then(|o| o.spam).unwrap_or(now);
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"message": "Wait at least a 2 minutes to send another email!", "spam": spam.to_rfc3339(), "code": 4}),
                ),
            ));
        }
    }
    let otp_code = format!("{:04}", rand::random::<u16>() % 9000 + 1000);
    let hashed = bcrypt::hash(&otp_code, 10)
        .map_err(|e| crate::utils::internal_err(e, "bcrypt hash"))?;
    // send mail
    if !state.mail_host.is_empty() {
        let mail_html = mail_html(&otp_code, &user.name);
        // Use lettre
        let creds = lettre::transport::smtp::authentication::Credentials::new(
            state.mail_user.clone(),
            state.mail_pass.clone(),
        );
        let mailer = lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::relay(&state.mail_host)
            .map_err(|e| {
                tracing::error!("SMTP relay setup failed: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"message": "Internal error, please try again later", "code": 2})),
                )
            })?
            .credentials(creds)
            .port(state.mail_port)
            .build();
        let email = lettre::Message::builder()
            .from(
                state
                    .mail_from
                    .parse()
                    .map_err(|e: lettre::address::AddressError| {
                        crate::utils::internal_err(e, "mail From address")
                    })?,
            )
            .to(user
                .email
                .parse()
                .map_err(|e: lettre::address::AddressError| {
                    crate::utils::internal_err(e, "mail To address")
                })?)
            .subject("Noap OTP code verification")
            .header(lettre::message::header::ContentType::TEXT_HTML)
            .body(mail_html)
            .map_err(|e| crate::utils::internal_err(e, "mail build"))?;
        let _ = lettre::AsyncTransport::send(&mailer, email).await; // ignore error, continue
    }
    let otp_doc = Otp {
        id: None,
        userId: uid.to_hex(),
        otp: hashed,
        createdAt: Some(now),
        expiresAt: Some(now + chrono::Duration::hours(1)),
        spam: Some(now + chrono::Duration::minutes(2)),
    };
    otp_coll.insert_one(otp_doc).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    Ok((
        StatusCode::OK,
        Json(
            json!({"message": "If an account with this email exists, the code will be sent", "userId": uid.to_hex()}),
        ),
    ))
}

pub async fn verify_otp(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<VerifyOtpReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    // 4-digit codes are guessable: strict per-IP budget on top of expiry.
    enforce_rate_limit(&state, &headers, "verify-otp", 10, 600).await?;
    // Per-account budget: rotating IPs must not buy extra guesses against
    // one victim's code.
    enforce_rate_limit_key(
        &state,
        account_rate_key("verify-otp-acct", &payload.userId),
        10,
        600,
    )
    .await?;
    let db = &state.db;
    let coll = db.collection::<Otp>("otps");
    let otps: Vec<Otp> = coll
        .find(doc! {"userId": &payload.userId})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?
        .try_collect()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    if otps.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Wrong OTP code, please try again!"})),
        ));
    }
    let last = otps.last().unwrap();
    let ok = bcrypt::verify(&payload.otp, &last.otp).unwrap_or(false);
    let not_expired = last.expiresAt.map(|e| e > Utc::now()).unwrap_or(false);
    if ok && not_expired {
        // delete all
        let ids: Vec<ObjectId> = otps.iter().filter_map(|o| o.id).collect();
        if otps.len() > 1 {
            coll.delete_many(doc! {"userId": &payload.userId, "_id": {"$in": ids}})
                .await
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        crate::utils::db_err_json(e),
                    )
                })?;
        } else {
            coll.delete_one(doc! {"_id": last.id.unwrap()})
                .await
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        crate::utils::db_err_json(e),
                    )
                })?;
        }
        // Proof of email ownership for the next recovery step (/change-pass,
        // /2fa/remove without a session). Short-lived (15 min), single purpose.
        let reset_token = create_reset_token(&payload.userId, &state.jwt_secret).map_err(|e| {
            tracing::error!("reset token creation failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Internal error, please try again later"})),
            )
        })?;
        Ok((
            StatusCode::OK,
            Json(json!({"message": "Verified!", "resetToken": reset_token})),
        ))
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Wrong OTP code, please try again!"})),
        ))
    }
}

pub async fn generate_2fa_qrcode(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<Gen2FAReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_owner(&claims, &payload.userId)?;
    let db = &state.db;
    let tfa_coll = db.collection::<Tfa>("2fa");
    let uid = ObjectId::parse_str(&payload.userId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid userId"})),
        )
    })?;
    let existing: Vec<Tfa> = tfa_coll
        .find(doc! {"userId": uid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?
        .try_collect()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    if !existing.is_empty() {
        return Ok((StatusCode::OK, Json(json!(existing[0].qrcode))));
    }
    // generate secret
    let secret = totp_rs::Secret::generate_secret();
    let secret_b32 = secret.to_encoded().to_string();
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().unwrap(),
        Some("Noap".to_string()),
        "".to_string(),
    )
    .map_err(|e| crate::utils::internal_err(e, "TOTP init"))?;
    let url = totp.get_url();
    // generate qrcode to data url
    let code = qrcode::QrCode::new(url.as_bytes())
        .map_err(|e| crate::utils::internal_err(e, "QR render"))?;
    let image = code.render::<image::Luma<u8>>().build();
    let mut buf = Vec::new();
    image
        .write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
        .map_err(|e| crate::utils::internal_err(e, "QR PNG encode"))?;
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &buf);
    let data_url = format!("data:image/png;base64,{}", b64);
    let tfa = Tfa {
        id: None,
        qrcode: data_url.clone(),
        userId: uid,
        secret: secret_b32,
        options: Some(crate::models::TfaOptions {
            useToResetPass: Some(true),
        }),
        verified: false,
    };
    tfa_coll.insert_one(tfa).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    let inserted = tfa_coll
        .find_one(doc! {"userId": uid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?
        .unwrap();
    db.collection::<User>("users")
        .update_one(
            doc! {"_id": uid},
            doc! {"$set": {"TFAStatus": inserted.id.unwrap()}},
        )
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    Ok((StatusCode::OK, Json(json!(data_url))))
}

pub async fn verify_2fa_code(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<Verify2FAReq>,
) -> Result<(StatusCode, HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    enforce_rate_limit(&state, &headers, "2fa-verify", 10, 600).await?;
    // Per-account budget: TOTP codes are short-lived but online guessing
    // must stay infeasible even with IP rotation.
    enforce_rate_limit_key(
        &state,
        account_rate_key("2fa-verify-acct", &payload.userId),
        10,
        600,
    )
    .await?;
    // A 2FA-pending cookie (password already proven at sign-in) must belong
    // to this userId before its code can mint a session. Other callers
    // (settings flow with a live session, recovery proofs) only get code
    // verification here — never a new session.
    let pending_owner = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|c| cookies::get_cookie(c, cookies::TFA_COOKIE))
        .and_then(|t| crate::utils::crypto::verify_tfa_token(&t, &state.jwt_secret));
    let db = &state.db;
    let uid = ObjectId::parse_str(&payload.userId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid userId"})),
        )
    })?;
    let tfa_coll = db.collection::<Tfa>("2fa");
    let tfa: Vec<Tfa> = tfa_coll
        .find(doc! {"userId": uid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?
        .try_collect()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    if tfa.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Wrong code, please try again"})),
        ));
    }
    let secret = &tfa[0].secret;
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(secret.clone()).to_bytes().unwrap(),
        None,
        "".to_string(),
    )
    .map_err(|e| crate::utils::internal_err(e, "TOTP init"))?;
    let ok = totp.check_current(&payload.tfa_code).unwrap_or(false);
    if ok {
        tfa_coll
            .update_one(
                doc! {"_id": tfa[0].id.unwrap()},
                doc! {"$set": {"verified": true}},
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    crate::utils::db_err_json(e),
                )
            })?;
        // Only a bound pending login mints the real session here: the
        // settings flow already has one, and bare recovery proofs must not
        // create sessions at all (they only prove authenticator possession).
        if pending_owner.as_deref() == Some(payload.userId.as_str()) {
            let user = db
                .collection::<User>("users")
                .find_one(doc! {"_id": uid})
                .await
                .map_err(db_err)?
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"message": "User not found"})),
                ))?;
            let sub = JwtSub {
                _id: uid.to_hex(),
                name: user.name.clone(),
                googleAccount: user.googleAccount.unwrap_or(false),
            };
            let ua = headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("Unknown")
                .to_string();
            let meta = SessionMeta {
                ua,
                identifier: payload.identifier.clone(),
            };
            let geo = fetch_geo(&payload.identifier, &state.ipgeo_key).await;
            let token = mint_session(db, uid, sub, &meta, &geo, &state.jwt_secret).await?;
            let cfg = cookie_config(&state);
            let headers_out = set_cookie_headers(&[
                cookies::session_cookie(&token, cookies::SESSION_MAX_AGE_SECS, &cfg),
                cookies::clear_tfa_cookie(&cfg),
            ]);
            return Ok((
                StatusCode::OK,
                headers_out,
                Json(json!({"message": "Verified!"})),
            ));
        }
        Ok((
            StatusCode::OK,
            HeaderMap::new(),
            Json(json!({"message": "Verified!"})),
        ))
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Wrong code, please try again"})),
        ))
    }
}

pub async fn remove_2fa(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<Remove2FAReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    // Dual-use endpoint like change_password: live session or reset-token proof.
    let session_owner = bearer_session_user(&state, &headers).await;
    let authorized = match session_owner {
        Some(owner) => owner == payload.userId,
        None => payload
            .resetToken
            .as_deref()
            .and_then(|t| verify_reset_token(t, &state.jwt_secret))
            .map(|uid| uid == payload.userId)
            .unwrap_or(false),
    };
    if !authorized {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Access denied, sign in again"})),
        ));
    }
    let db = &state.db;
    let uid = ObjectId::parse_str(&payload.userId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid userId"})),
        )
    })?;
    let tfa_coll = db.collection::<Tfa>("2fa");
    let tfas: Vec<Tfa> = tfa_coll
        .find(doc! {"userId": uid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?
        .try_collect()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    if tfas.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "This account doesn't have 2FA enabled!"})),
        ));
    }
    tfa_coll
        .delete_one(doc! {"_id": tfas[0].id.unwrap()})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    db.collection::<User>("users")
        .update_one(doc! {"_id": uid}, doc! {"$set": {"TFAStatus": Bson::Null}})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    // unset instead
    db.collection::<User>("users")
        .update_one(doc! {"_id": uid}, doc! {"$unset": {"TFAStatus": ""}})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    Ok((
        StatusCode::OK,
        Json(json!({"message": "2FA removed successfuly!"})),
    ))
}

pub async fn sign_out(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
) -> Result<(StatusCode, HeaderMap, Json<Value>), (StatusCode, Json<Value>)> {
    // The owner comes from the verified session itself (cookie or Bearer);
    // no body credentials needed.
    let uid = ObjectId::parse_str(&claims.sub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    if let Some((token, _)) = request_session_token(&headers) {
        // Best effort: the session row may already be gone (e.g. after
        // "terminate all sessions"); logout still succeeds and clears cookies.
        let coll = state.db.collection::<Session>("sessions");
        if let Err(e) = coll.delete_one(doc! {"userId": uid, "token": token.as_str()}).await {
            tracing::warn!("sign-out session cleanup failed: {}", e);
        }
    }
    let cfg = cookie_config(&state);
    let headers_out = set_cookie_headers(&[
        cookies::clear_session_cookie(&cfg),
        cookies::clear_tfa_cookie(&cfg),
    ]);
    Ok((
        StatusCode::OK,
        headers_out,
        Json(json!({"message": "Success"})),
    ))
}

pub async fn convert_into_normal(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<ConvertNormalReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_owner(&claims, &payload.id)?;
    validate_password(&payload.password)?;
    let db = &state.db;
    let uid = ObjectId::parse_str(&payload.id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "User not found!"})),
        )
    })?;
    let coll = db.collection::<User>("users");
    let exists = coll.find_one(doc! {"_id": uid}).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    if exists.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "User not found!"})),
        ));
    }
    let hashed = bcrypt::hash(&payload.password, 10)
        .map_err(|e| crate::utils::internal_err(e, "bcrypt hash"))?;
    coll.update_one(
        doc! {"_id": uid},
        doc! {"$set": {"password": hashed, "googleAccount": false}},
    )
    .await
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    Ok((
        StatusCode::OK,
        Json(json!({"message": "Account was converted, please sign in again!"})),
    ))
}

pub async fn convert_into_google(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    // payload contains _id, email, name, id (googleId)
    let _id = payload.get("_id").and_then(|v| v.as_str()).unwrap_or("");
    require_owner(&claims, _id)?;
    let email = payload.get("email").and_then(|v| v.as_str()).unwrap_or("");
    let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let google_id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let uid = ObjectId::parse_str(_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "User not found!"})),
        )
    })?;
    let db = &state.db;
    let coll = db.collection::<User>("users");
    let exists = coll.find_one(doc! {"_id": uid}).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    if exists.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "User not found!"})),
        ));
    }
    let existing_by_email = coll.find_one(doc! {"email": email}).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    if let Some(u) = existing_by_email {
        if !u.googleAccount.unwrap_or(false) && u.email != exists.unwrap().email {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "User already exists!"})),
            ));
        }
    }
    coll.update_one(doc!{"_id": uid}, doc!{"$set": {"password": Bson::Null, "googleAccount": true, "googleId": google_id, "name": name, "email": email}}).await.map_err(|e| (StatusCode::BAD_REQUEST, crate::utils::db_err_json(e)))?;
    // unset password null -> keep null
    Ok((
        StatusCode::OK,
        Json(json!({"message": "Google account was linked, please sign in again!"})),
    ))
}

pub async fn last_opened_note(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<LastOpenedReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_owner(&claims, &id)?;
    if id.is_empty() || payload.lastOpenedNote.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Invalid request!"})),
        ));
    }
    let uid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    let note_oid = ObjectId::parse_str(&payload.lastOpenedNote).unwrap_or_else(|_| ObjectId::new());
    state
        .db
        .collection::<User>("users")
        .update_one(
            doc! {"_id": uid},
            doc! {"$set": {"lastOpenedNote": note_oid}},
        )
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    Ok((StatusCode::OK, Json(json!({"message": "Updated!"}))))
}

pub async fn change_theme(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<ThemeReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_owner(&claims, &id)?;
    let uid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    let coll = state.db.collection::<User>("users");
    let user = coll
        .find_one(doc! {"_id": uid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?
        .ok_or((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "User not found"})),
        ))?;
    let mut settings = user.settings.unwrap_or_default();
    settings.theme = Some(payload.theme);
    coll.update_one(
        doc! {"_id": uid},
        doc! {"$set": {"settings": bson::to_bson(&settings).unwrap()}},
    )
    .await
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    Ok((StatusCode::OK, Json(json!({"message": "Updated!"}))))
}

pub async fn note_text_expanded(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<ConditionReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_owner(&claims, &id)?;
    let uid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    let coll = state.db.collection::<User>("users");
    let user = coll
        .find_one(doc! {"_id": uid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?
        .ok_or((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "User not found"})),
        ))?;
    let mut settings = user.settings.unwrap_or_default();
    settings.noteTextExpanded = Some(payload.condition);
    coll.update_one(
        doc! {"_id": uid},
        doc! {"$set": {"settings": bson::to_bson(&settings).unwrap()}},
    )
    .await
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    Ok((StatusCode::OK, Json(json!({"message": "Updated!"}))))
}

pub async fn show_pinned_in_folder(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<ConditionReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_owner(&claims, &id)?;
    let uid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    let coll = state.db.collection::<User>("users");
    let user = coll
        .find_one(doc! {"_id": uid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?
        .ok_or((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "User not found"})),
        ))?;
    let mut settings = user.settings.unwrap_or_default();
    settings.showPinnedNotesInFolder = Some(payload.condition);
    coll.update_one(
        doc! {"_id": uid},
        doc! {"$set": {"settings": bson::to_bson(&settings).unwrap()}},
    )
    .await
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    Ok((StatusCode::OK, Json(json!({"message": "Updated!"}))))
}

pub async fn change_visualization(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<VisualizationReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_owner(&claims, &id)?;
    let uid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    let coll = state.db.collection::<User>("users");
    let user = coll
        .find_one(doc! {"_id": uid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?
        .ok_or((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "User not found"})),
        ))?;
    let mut settings = user.settings.unwrap_or_default();
    settings.noteVisualization = Some(payload.visualization);
    coll.update_one(
        doc! {"_id": uid},
        doc! {"$set": {"settings": bson::to_bson(&settings).unwrap()}},
    )
    .await
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    Ok((StatusCode::OK, Json(json!({"message": "Updated!"}))))
}

pub async fn on_login_go_to_last(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<OnLoginReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_owner(&claims, &id)?;
    let uid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    let coll = state.db.collection::<User>("users");
    let user = coll
        .find_one(doc! {"_id": uid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?
        .ok_or((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "User not found"})),
        ))?;
    let mut settings = user.settings.unwrap_or_default();
    settings.onLoginGoToLastOpenedNote = Some(payload.onLoginGoToLastOpenedNote);
    coll.update_one(
        doc! {"_id": uid},
        doc! {"$set": {"settings": bson::to_bson(&settings).unwrap()}},
    )
    .await
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    Ok((StatusCode::OK, Json(json!({"message": "Updated!"}))))
}

pub async fn change_global_bg(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<GlobalBgReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_owner(&claims, &id)?;
    let uid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    let coll = state.db.collection::<User>("users");
    let user = coll
        .find_one(doc! {"_id": uid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?
        .ok_or((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "User not found"})),
        ))?;
    let mut settings = user.settings.unwrap_or_default();
    settings.globalNoteBackgroundColor = Some(payload.globalNoteBackgroundColor);
    coll.update_one(
        doc! {"_id": uid},
        doc! {"$set": {"settings": bson::to_bson(&settings).unwrap()}},
    )
    .await
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    Ok((StatusCode::OK, Json(json!({"message": "Updated!"}))))
}
