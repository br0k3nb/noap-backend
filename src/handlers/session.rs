use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use bson::{doc, oid::ObjectId};
use futures::TryStreamExt;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::{models::Session, AppState};

pub async fn view(
    State(state): State<Arc<AppState>>,
    Path(userId): Path<String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let uid = ObjectId::parse_str(&userId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid userId"})),
        )
    })?;
    let coll = state.db.collection::<Session>("sessions");
    let sessions: Vec<Session> = coll
        .find(doc! {"userId": uid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": e.to_string()})),
            )
        })?
        .try_collect()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": e.to_string()})),
            )
        })?;
    if sessions.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"message": "Error, no sessions found"})),
        ));
    }
    Ok((StatusCode::OK, Json(json!(sessions))))
}

pub async fn delete_one(
    State(state): State<Arc<AppState>>,
    Path((userId, sessionId)): Path<(String, String)>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
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
        .delete_one(doc! {"_id": sid, "userId": uid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": e.to_string()})),
            )
        })?;
    Ok((
        StatusCode::OK,
        Json(json!({"message": "Session was terminated successfully!"})),
    ))
}

pub async fn delete_all(
    State(state): State<Arc<AppState>>,
    Path(userId): Path<String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
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
        .delete_many(doc! {"userId": uid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": e.to_string()})),
            )
        })?;
    Ok((
        StatusCode::OK,
        Json(
            json!({"message": "All sessions (including yours), were terminated, please sign in again!"}),
        ),
    ))
}
