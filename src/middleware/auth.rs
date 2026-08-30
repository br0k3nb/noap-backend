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

use crate::{models::Session, utils::crypto::Claims, AppState};

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
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if auth.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Authentication token wasn't found", "code": 1})),
        ));
    }

    let scheme = &auth[0..6.min(auth.len())];
    if !scheme.starts_with("Bearer") {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Authentication error"})),
        ));
    }

    // Extract token after "Bearer "
    let token = if auth.len() > 7 { &auth[7..] } else { "" };
    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Invalid token"})),
        ));
    }

    // Verify JWT
    let mut validation = Validation::new(Algorithm::HS512);
    let token_data = jsonwebtoken::decode::<Claims>(
        token,
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
        // Try string userId collections (OTP userId is string)
        // Also fallback to find by token directly
        let by_token = coll.find_one(doc! { "token": token }).await.map_err(|e| {
            tracing::error!("DB find_one by_token error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "DB error"})),
            )
        })?;
        tracing::info!("by_token found: {}", by_token.is_some());
        if by_token.is_none() {
            tracing::warn!("No session found for token, returning 401");
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"message": "Access denied, sign in again"})),
            ));
        }
    }

    // Insert claims into request extensions for handlers if needed
    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}
