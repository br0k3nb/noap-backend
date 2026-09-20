use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use bson::doc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use mongodb::Database;
use serde_json::json;
use std::sync::Arc;

use crate::{
    models::Session,
    utils::{
        cookies::{self, SESSION_COOKIE},
        crypto::Claims,
    },
    AppState,
};

/// Extracts the session token from the request: `Authorization: Bearer`
/// header first (API clients / tooling), then the HttpOnly session cookie
/// (browsers). Returns the token and whether it came from the cookie.
pub fn request_session_token(headers: &HeaderMap) -> Option<(String, bool)> {
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if auth.len() > 7 {
            let scheme = &auth[0..6.min(auth.len())];
            if scheme.eq_ignore_ascii_case("Bearer") {
                let token = auth[7..].trim();
                if !token.is_empty() {
                    return Some((token.to_string(), false));
                }
            }
        }
    }
    let cookie_header = headers.get("cookie")?.to_str().ok()?;
    let token = cookies::get_cookie(cookie_header, SESSION_COOKIE)?;
    Some((token, true))
}

/// CSRF guard for cookie-authenticated requests.
///
/// `SameSite=None` cookies are attached to cross-site requests, so a forged
/// top-level form POST from an attacker's page would otherwise reach us with
/// the victim's session. Browsers always send `Origin` on fetch POSTs (and
/// modern ones on form posts too), so for cookie-authenticated state-changing
/// requests we require the origin — or the referer's origin as fallback — to
/// be in the CORS allowlist. Header-authenticated (Bearer) requests are
/// exempt: a cross-site attacker cannot know the token to put it there.
fn cookie_request_origin_ok(headers: &HeaderMap, allowed: &[String], method: &axum::http::Method) -> bool {
    use axum::http::Method;
    match *method {
        Method::GET | Method::HEAD | Method::OPTIONS => return true,
        _ => {}
    }
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        return allowed.iter().any(|a| a.as_str() == origin.trim());
    }
    if let Some(referer) = headers.get("referer").and_then(|v| v.to_str().ok()) {
        // Reduce "https://host:port/path?q" to "https://host:port".
        if let Some(scheme_end) = referer.find("://") {
            let rest = &referer[scheme_end + 3..];
            let host_end = rest.find('/').unwrap_or(rest.len());
            let origin = format!("{}://{}", &referer[..scheme_end], &rest[..host_end]);
            return allowed.iter().any(|a| *a == origin);
        }
        return false;
    }
    // No Origin/Referer on a state-changing request: reject. Real browsers
    // always send one; curl/API clients should use Bearer auth instead.
    false
}

pub async fn verify_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    // Skip auth for CORS preflight
    if req.method() == axum::http::Method::OPTIONS {
        return Ok(next.run(req).await);
    }
    let (token, via_cookie) = match request_session_token(&headers) {
        Some(t) => t,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"message": "Authentication token wasn't found", "code": 1})),
            ))
        }
    };

    // CSRF check for cookie-authenticated state-changing requests.
    if via_cookie && !cookie_request_origin_ok(&headers, &state.allowed_origins, req.method()) {
        tracing::warn!("Blocked possible CSRF: cookie-authenticated {} without allowed origin", req.method());
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"message": "Access denied"})),
        ));
    }

    // Verify JWT
    let mut validation = Validation::new(Algorithm::HS512);
    let token_data = jsonwebtoken::decode::<Claims>(
        token.as_str(),
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &validation,
    );

    let claims = match token_data {
        Ok(d) => d.claims,
        Err(e) => {
            tracing::error!("JWT decode failed: {:?}", e);
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"message": "Access denied, sign in again"})),
            ));
        }
    };

    // Check exp
    let now = chrono::Utc::now().timestamp() as usize;
    if claims.exp < now {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Session expired, please sign in again"})),
        ));
    }

    // Check session exists
    let coll = state.db.collection::<Session>("sessions");
    let user_oid = match bson::oid::ObjectId::parse_str(&claims.sub) {
        Ok(oid) => oid,
        Err(e) => {
            tracing::error!(
                "Failed to parse sub as ObjectId: {} err: {:?}",
                claims.sub,
                e
            );
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"message": "Access denied, sign in again"})),
            ));
        }
    };
    tracing::info!("Checking sessions for userId {}", user_oid);
    tracing::info!("Token sub: {:?} exp: {}", claims.sub, claims.exp);
    let mut cursor = coll.find(doc! { "userId": user_oid }).await.map_err(|e| {
        tracing::error!("DB find sessions error: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"message": "DB error"})),
        )
    })?;
    let mut sessions: Vec<Session> = Vec::new();
    use futures::StreamExt;
    while let Some(doc) = cursor.next().await {
        match doc {
            Ok(s) => {
                tracing::info!(
                    "Found session for user {} token prefix {}",
                    s.userId,
                    &s.token[..20.min(s.token.len())]
                );
                sessions.push(s)
            }
            Err(e) => {
                tracing::error!("DB cursor error: {:?}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"message": "DB error"})),
                ));
            }
        }
    }
    tracing::info!("Found {} sessions for user", sessions.len());

    // If no sessions for this user, check by string userId fallback (some sessions store userId as string)
    // Also check if token matches any session
    let matching = sessions.iter().find(|s| s.token == token);
    tracing::info!("Matching session by token: {}", matching.is_some());
    if matching.is_none() {
        tracing::info!(
            "No matching session in user sessions, trying by_token fallback for token prefix {}",
            &token[..20.min(token.len())]
        );
        // Legacy rows may store userId as a string, invisible to the
        // ObjectId query above. Accept the row ONLY if it belongs to this
        // subject and hasn't expired server-side.
        let by_token = coll.find_one(doc! { "token": token.as_str() }).await.map_err(|e| {
            tracing::error!("DB find_one by_token error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "DB error"})),
            )
        })?;
        tracing::info!("by_token found: {}", by_token.is_some());
        match by_token {
            Some(row) if row.userId.to_hex() == claims.sub => {
                tracing::warn!("Accepted legacy string-userId session row for {}", claims.sub);
                let now = chrono::Utc::now().timestamp();
                if row.expAt < now {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(json!({"message": "Session expired, please sign in again"})),
                    ));
                }
                req.extensions_mut().insert(claims.clone());
                return Ok(next.run(req).await);
            }
            Some(_) => {
                tracing::warn!("Denying request: token row belongs to another user");
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"message": "Access denied, sign in again"})),
                ));
            }
            None => {
                tracing::warn!("No session found for token, returning 401");
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"message": "Access denied, sign in again"})),
                ));
            }
        }
    }

    // Insert claims into request extensions for handlers if needed
    req.extensions_mut().insert(claims.clone());

    // Enforce server-side session expiry (sessions carry their own expAt).
    if let Some(matching) = matching {
        let now = chrono::Utc::now().timestamp();
        if matching.expAt < now {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"message": "Session expired, please sign in again"})),
            ));
        }
    }

    Ok(next.run(req).await)
}

/// Ensures the caller only touches their own resources.
/// Every protected handler that receives a user id / author id from the URL
/// or body must call this with the subject of the verified session, otherwise
/// any authenticated user could read or mutate another user's data (IDOR).
/// Returns 403 (not 401) so clients don't mistake it for an expired session.
pub fn require_owner(
    claims: &Claims,
    owner_id: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if claims.sub != owner_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"message": "Access denied"})),
        ));
    }
    Ok(())
}

/// Validates the request session outside the middleware chain (for dual-use
/// public endpoints such as `/change-pass` and `/2fa/remove`, which accept
/// either a live session or a reset token). Accepts both the Bearer header
/// and the HttpOnly session cookie.
/// Returns the session owner's user id when the session is valid.
pub async fn bearer_session_user(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Option<String> {
    let (token, _) = request_session_token(headers)?;

    let validation = Validation::new(Algorithm::HS512);
    let claims = jsonwebtoken::decode::<Claims>(
        token.as_str(),
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &validation,
    )
    .ok()?
    .claims;

    let now = chrono::Utc::now().timestamp() as usize;
    if claims.exp < now {
        return None;
    }

    let coll = state.db.collection::<Session>("sessions");
    // Fast path: direct token lookup.
    let session = coll.find_one(doc! { "token": token }).await.ok()??;
    if session.expAt < chrono::Utc::now().timestamp() {
        return None;
    }
    // The session must belong to the token's subject.
    if session.userId.to_hex() != claims.sub {
        return None;
    }
    Some(claims.sub)
}
