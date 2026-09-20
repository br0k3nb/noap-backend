use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    Json,
};
use bson::{doc, oid::ObjectId, Bson};
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};

use crate::{middleware::auth::require_owner, models::Label, utils::crypto::Claims, AppState};

#[derive(Deserialize)]
pub struct ViewQuery {
    pub search: Option<String>,
    pub page: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Deserialize)]
pub struct AddReq {
    pub name: String,
    pub color: String,
    pub fontColor: Option<String>,
    pub selectedStyle: Option<String>,
    #[serde(rename = "type")]
    pub label_type: Option<String>,
}

#[derive(Deserialize)]
pub struct EditReq {
    pub _id: String,
    pub name: String,
    pub color: String,
    #[serde(rename = "type")]
    pub label_type: String,
}

pub async fn view(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(userId): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_owner(&claims, &userId)?;
    let uid = ObjectId::parse_str(&userId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid userId"})),
        )
    })?;
    let search = query.get("search").cloned().unwrap_or_default();
    let page: i64 = query
        .get("page")
        .and_then(|p| p.parse().ok())
        .unwrap_or(1)
        .max(1);
    let limit: i64 = query
        .get("limit")
        .and_then(|p| p.parse().ok())
        .unwrap_or(10)
        .max(1);
    let regex = bson::Regex {
        pattern: search.clone(),
        options: "i".to_string(),
    };
    let filter = if search.is_empty() {
        doc! {"userId": uid}
    } else {
        doc! {"userId": uid, "name": {"$regex": regex}}
    };
    let coll = state.db.collection::<Label>("labels");
    let total = coll.count_documents(filter.clone()).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })? as i64;
    let skip = ((page - 1) * limit).max(0) as u64;
    let filter2 = if search.is_empty() {
        doc! {"userId": uid}
    } else {
        let regex2 = bson::Regex {
            pattern: search,
            options: "i".to_string(),
        };
        doc! {"userId": uid, "name": {"$regex": regex2}}
    };
    let mut cursor2 = coll
        .find(filter2)
        .skip(skip as u64)
        .limit(limit)
        .sort(doc! {"_id": 1})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    let docs: Vec<Label> = cursor2.try_collect().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    let total_pages = (total + limit - 1) / limit;
    let has_next = page < total_pages;
    let has_prev = page > 1;
    Ok((
        StatusCode::OK,
        Json(json!({
            "docs": docs,
            "totalDocs": total,
            "limit": limit,
            "page": page,
            "totalPages": total_pages,
            "hasNextPage": has_next,
            "hasPrevPage": has_prev,
            "nextPage": if has_next { Some(page+1) } else { None::<i64> },
            "prevPage": if has_prev { Some(page-1) } else { None::<i64> },
        })),
    ))
}

pub async fn add(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(userId): Path<String>,
    Json(payload): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_owner(&claims, &userId)?;
    let uid = ObjectId::parse_str(&userId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid userId"})),
        )
    })?;
    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let color = payload
        .get("color")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let font_color = payload
        .get("fontColor")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let selected_style = payload
        .get("selectedStyle")
        .and_then(|v| v.as_str())
        .or_else(|| payload.get("type").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();
    let label = Label {
        id: None,
        name,
        color,
        fontColor: font_color,
        label_type: selected_style,
        userId: uid,
        createdAt: Some(chrono::Utc::now()),
        updatedAt: None,
    };
    state
        .db
        .collection::<Label>("labels")
        .insert_one(label)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Error, please try again later!"})),
            )
        })?;
    Ok((
        StatusCode::OK,
        Json(json!({"message": "Label was created!"})),
    ))
}

pub async fn edit(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(_userId): Path<String>,
    Json(payload): Json<EditReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let oid = ObjectId::parse_str(&payload._id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    // Labels are owned via their userId: fetch first so one user cannot
    // rename another user's labels by id.
    let label = state
        .db
        .collection::<Label>("labels")
        .find_one(doc! {"_id": oid})
        .await
        .map_err(|e| {
            tracing::error!("DB error loading label: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Label not found"})),
        ))?;
    require_owner(&claims, &label.userId.to_hex())?;
    state.db.collection::<Label>("labels").update_one(doc!{"_id": oid}, doc!{"$set": {"name": payload.name, "color": payload.color, "type": payload.label_type, "updatedAt": Bson::DateTime(bson::DateTime::now())}}).await.map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"message": "Error, please try again later!"}))))?;
    Ok((StatusCode::OK, Json(json!({"message": "Label updated!"}))))
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let oid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    let label = state
        .db
        .collection::<Label>("labels")
        .find_one(doc! {"_id": oid})
        .await
        .map_err(|e| {
            tracing::error!("DB error loading label: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Label not found"})),
        ))?;
    require_owner(&claims, &label.userId.to_hex())?;
    state
        .db
        .collection::<Label>("labels")
        .delete_one(doc! {"_id": oid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Error, please try again later!"})),
            )
        })?;
    Ok((StatusCode::OK, Json(json!({"message": "Label deleted!"}))))
}
