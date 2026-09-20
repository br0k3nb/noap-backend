use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use bson::{doc, oid::ObjectId};
use futures::TryStreamExt;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::{
    middleware::auth::{request_session_token, require_owner},
    models::Session,
    utils::crypto::Claims,
    AppState,
};

pub async fn view(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
    Path(userId): Path<String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_owner(&claims, &userId)?;
    let uid = ObjectId::parse_str(&userId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid userId"})),
        )
    })?;
    let coll = state.db.collection::<Session>("sessions");
    // Match BOTH userId forms: current rows store an ObjectId, but legacy
    // rows store the hex string. Querying only one form yields a falsely
    // empty list (HTTP 500) while the user is demonstrably authenticated.
    let sessions: Vec<Session> = coll
        .find(doc! {"$or": [{"userId": uid}, {"userId": userId}]})
        .await
        .map_err(|e| {
            tracing::error!("DB error listing sessions: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?
        .try_collect()
        .await
        .map_err(|e| {
            tracing::error!("DB cursor error listing sessions: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?;
    if sessions.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"message": "Error, no sessions found"})),
        ));
    }
    // The frontend can no longer read the JWT (HttpOnly cookie), so the
    // backend marks which session row belongs to the calling request.
    // Raw tokens are stripped: with cookie auth the client never needs them,
    // and shipping them would re-expose session secrets to page JavaScript.
    let current_token = request_session_token(&headers).map(|(t, _)| t);
    let mut out = Vec::with_capacity(sessions.len());
    for s in sessions {
        let mut v = serde_json::to_value(&s).unwrap_or(json!({}));
        v["current"] = json!(current_token.as_deref() == Some(s.token.as_str()));
        if let Some(obj) = v.as_object_mut() {
            obj.remove("token");
        }
        out.push(v);
    }
    Ok((StatusCode::OK, Json(json!(out))))
}

pub async fn delete_one(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path((userId, sessionId)): Path<(String, String)>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_owner(&claims, &userId)?;
    if userId.is_empty() || sessionId.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Invalid request"})),
        ));
    }
    let uid = ObjectId::parse_str(&userId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid userId"})),
        )
    })?;
    let sid = ObjectId::parse_str(&sessionId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid sessionId"})),
        )
    })?;
    state
        .db
        .collection::<Session>("sessions")
        .delete_one(doc! {"_id": sid, "$or": [{"userId": uid}, {"userId": userId}]})
        .await
        .map_err(|e| {
            tracing::error!("DB error deleting session: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?;
    Ok((
        StatusCode::OK,
        Json(json!({"message": "Session was terminated successfully!"})),
    ))
}

pub async fn delete_all(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(userId): Path<String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_owner(&claims, &userId)?;
    if userId.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Invalid request"})),
        ));
    }
    let uid = ObjectId::parse_str(&userId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid userId"})),
        )
    })?;
    state
        .db
        .collection::<Session>("sessions")
        // Both userId forms: otherwise legacy string-keyed rows survive a
        // "terminate all" and stay valid while the user believes they're dead.
        .delete_many(doc! {"$or": [{"userId": uid}, {"userId": userId}]})
        .await
        .map_err(|e| {
            tracing::error!("DB error deleting sessions: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?;
    Ok((
        StatusCode::OK,
        Json(
            json!({"message": "All sessions (including yours), were terminated, please sign in again!"}),
        ),
    ))
}
