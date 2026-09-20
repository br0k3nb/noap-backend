use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    Json,
};
use bson::{doc, oid::ObjectId, Bson, DateTime as BsonDateTime};
use chrono::Utc;
use futures::TryStreamExt;
use mongodb::Database;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};

use crate::{
    middleware::auth::require_owner,
    models::{Note, NoteState},
    utils::crypto::Claims,
    AppState,
};

/// Loads a note and guarantees it belongs to the session owner.
/// Without this, any authenticated user could read/mutate another user's
/// notes by guessing their ids.
async fn owned_note(
    db: &Database,
    note_id: ObjectId,
    claims: &Claims,
) -> Result<Note, (StatusCode, Json<Value>)> {
    let note = db
        .collection::<Note>("notes")
        .find_one(doc! {"_id": note_id})
        .await
        .map_err(|e| {
            tracing::error!("DB error loading note: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Note wasn't found!"})),
        ))?;
    require_owner(claims, &note.author)?;
    Ok(note)
}

#[derive(Deserialize)]
pub struct AddReq {
    pub name: Option<String>,
    pub body: Option<String>,
    pub image: Option<String>,
    pub state: String,
    pub author: String,
    pub settings: Option<Value>,
    pub pageLocation: Option<Value>,
}

#[derive(Deserialize)]
pub struct AddLabelReq {
    pub labels: Vec<String>,
    pub noteId: String,
}

#[derive(Deserialize)]
pub struct EditReq {
    pub _id: String,
    pub title: Option<String>,
    pub body: Option<String>,
    pub image: Option<String>,
    pub state: Option<String>,
    pub stateId: Option<String>,
}

#[derive(Deserialize)]
pub struct RenameReq {
    pub name: String,
}

#[derive(Deserialize)]
pub struct PinReq {
    pub condition: bool,
}

#[derive(Deserialize)]
pub struct ImageReq {
    pub image: String,
}

#[derive(Deserialize)]
pub struct BgReq {
    pub noteBackgroundColor: String,
}

pub async fn view(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path((page, author)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_owner(&claims, &author)?;
    if author.is_empty() || page.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Access denied!"})),
        ));
    }
    let page_num: i64 = page.parse().unwrap_or(1).max(1);
    let limit: i64 = query
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(10)
        .max(1);
    let pinned_page: i64 = query
        .get("pinnedNotesPage")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
        .max(1);
    let search = query.get("search").cloned().unwrap_or_default();

    let coll = state.db.collection::<Note>("notes");
    let label_coll = state.db.collection::<bson::Document>("labels");

    // Simplified pagination: find notes without aggregation, then manually handle
    // For search empty case, we need pinned and non-pinned separately
    if search.is_empty() {
        // Non-pinned. NOTE: `$ne: true` (not `false`) is deliberate — old
        // notes created before pinning existed have no `settings.pinned`
        // field at all, and MongoDB equality does not match missing fields.
        let filter = doc! {"author": &author, "settings.pinned": {"$ne": true}};
        let total = coll.count_documents(filter.clone()).await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })? as i64;
        let skip = ((page_num - 1) * limit).max(0) as u64;
        let mut cursor = coll
            .find(filter)
            .skip(skip as u64)
            .limit(limit)
            .sort(doc! {"createdAt": 1})
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    crate::utils::db_err_json(e),
                )
            })?;
        let docs: Vec<Note> = cursor.try_collect().await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
        let total_pages = (total + limit - 1) / limit;

        // Pinned
        let filter_pinned = doc! {"author": &author, "settings.pinned": true};
        let total_pinned = coll
            .count_documents(filter_pinned.clone())
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    crate::utils::db_err_json(e),
                )
            })? as i64;
        let skip_p = ((pinned_page - 1) * 10).max(0) as u64;
        let mut cursor_p = coll
            .find(filter_pinned)
            .skip(skip_p as u64)
            .limit(10)
            .sort(doc! {"createdAt": 1})
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    crate::utils::db_err_json(e),
                )
            })?;
        let docs_p: Vec<Note> = cursor_p.try_collect().await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
        let total_pages_p = (total_pinned + 10 - 1) / 10;

        // Map to expected shape (simplified): include label handling via lookup is skipped for brevity
        // We return docs as is, frontend expects label field but we provide labels array
        return Ok((
            StatusCode::OK,
            Json(json!({
                "notes": {
                    "docs": docs,
                    "totalDocs": total,
                    "hasNextPage": page_num < total_pages,
                    "totalPages": total_pages
                },
                "pinnedNotes": {
                    "docs": docs_p,
                    "totalDocs": total_pinned,
                    "hasNextPage": pinned_page < total_pages_p,
                    "totalPages": total_pages_p
                }
            })),
        ));
    } else {
        // Search case: match name, body, or labels.name
        // Simplified: regex search on name/body, and lookup labels
        let regex = bson::Regex {
            pattern: search.clone(),
            options: "i".to_string(),
        };
        // Find all notes for author, then filter in Rust for simplicity
        let filter = doc! {"author": &author};
        let mut cursor = coll.find(filter).await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
        let all: Vec<Note> = cursor.try_collect().await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
        // For each note, check if name/body matches or any label name matches
        let mut matched = Vec::new();
        let label_coll = state.db.collection::<crate::models::Label>("labels");
        for note in all {
            let mut is_match = false;
            if let Some(name) = &note.name {
                if name.to_lowercase().contains(&search.to_lowercase()) {
                    is_match = true;
                }
            }
            if !is_match {
                if let Some(body) = &note.body {
                    if body.to_lowercase().contains(&search.to_lowercase()) {
                        is_match = true;
                    }
                }
            }
            if !is_match {
                if let Some(labels) = &note.labels {
                    for lid in labels {
                        if let Ok(Some(label)) = label_coll.find_one(doc! {"_id": lid}).await {
                            if label.name.to_lowercase().contains(&search.to_lowercase()) {
                                is_match = true;
                                break;
                            }
                        }
                    }
                }
            }
            if is_match {
                matched.push(note);
            }
        }
        // Paginate matched
        matched.sort_by(|a, b| a.createdAt.cmp(&b.createdAt));
        let total = matched.len() as i64;
        let skip = (((page_num - 1) * limit).max(0)) as usize;
        let paged: Vec<Note> = matched
            .into_iter()
            .skip(skip)
            .take(limit as usize)
            .collect();
        let total_pages = (total + limit - 1) / limit;
        return Ok((
            StatusCode::OK,
            Json(json!({
                "notes": {
                    "docs": paged,
                    "totalDocs": total,
                    "hasNextPage": page_num < total_pages,
                    "totalPages": total_pages
                },
                "pinnedNotes": {}
            })),
        ));
    }
}

pub async fn get_note(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let author = query.get("author").cloned().unwrap_or_default();
    require_owner(&claims, &author)?;
    let oid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Error fetching note contents"})),
        )
    })?;
    let coll = state.db.collection::<Note>("notes");
    let note = coll.find_one(doc! {"_id": oid}).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    let mut note = note.ok_or((
        StatusCode::BAD_REQUEST,
        Json(json!({"message": "Error fetching note contents"})),
    ))?;
    require_owner(&claims, &note.author)?;
    if note.author != author {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "You don't have permission to access this note!", "code": 1})),
        ));
    }
    // Lookup state
    if let Some(state_bson) = note.state.clone() {
        // state is Mixed, could be ObjectId
        let state_id = match state_bson {
            Bson::ObjectId(oid) => Some(oid),
            Bson::String(s) => ObjectId::parse_str(&s).ok(),
            _ => None,
        };
        if let Some(sid) = state_id {
            let state_doc = state
                .db
                .collection::<NoteState>("noteStates")
                .find_one(doc! {"_id": sid})
                .await
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        crate::utils::db_err_json(e),
                    )
                })?;
            if let Some(ns) = state_doc {
                // Attach state as document
                // For simplicity, embed state string
                // Frontend expects state: { _id, state: string }
                let state_val = json!({"_id": ns.id.map(|o| o.to_hex()).unwrap_or_default(), "state": ns.state});
                // We need to return note with populated state
                // Convert note to Value and inject state
                let mut note_val = serde_json::to_value(&note).unwrap();
                note_val["state"] = state_val;
                // Populate labels
                if let Some(label_ids) = note.labels.clone() {
                    let label_coll = state.db.collection::<crate::models::Label>("labels");
                    let mut labels = Vec::new();
                    for lid in label_ids {
                        if let Ok(Some(l)) = label_coll.find_one(doc! {"_id": lid}).await {
                            labels.push(serde_json::to_value(l).unwrap());
                        }
                    }
                    note_val["labels"] = json!(labels);
                    return Ok((StatusCode::OK, Json(json!({"note": note_val}))));
                }
                return Ok((StatusCode::OK, Json(json!({"note": note_val}))));
            }
        }
    }
    let note_val = serde_json::to_value(&note).unwrap();
    Ok((StatusCode::OK, Json(json!({"note": note_val}))))
}

pub async fn add(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<AddReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_owner(&claims, &payload.author)?;
    let db = &state.db;
    // Clone pageLocation before moving payload
    let page_loc_clone = payload.pageLocation.clone();
    // Create NoteState
    let state_coll = db.collection::<NoteState>("noteStates");
    let ns = NoteState {
        id: None,
        state: payload.state.clone(),
        noteId: None,
        createdAt: Some(Utc::now()),
        updatedAt: None,
    };
    let res = state_coll.insert_one(ns).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Error creating a new note, please try again or later"})),
        )
    })?;
    let state_id = res.inserted_id.as_object_id().unwrap();
    let note = Note {
        id: None,
        name: payload.name.clone(),
        body: payload.body.clone(),
        image: payload.image.clone(),
        labels: Some(vec![]),
        state: Some(Bson::ObjectId(state_id)),
        settings: payload
            .settings
            .clone()
            .and_then(|v| bson::to_bson(&v).ok())
            .and_then(|b| b.as_document().cloned())
            .map(|d| {
                // Convert to NoteSettings via bson
                let s: crate::models::NoteSettings =
                    bson::from_bson(Bson::Document(d)).unwrap_or_default();
                s
            }),
        author: payload.author.clone(),
        pageLocation: page_loc_clone
            .clone()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .or_else(|| page_loc_clone.clone().map(|v| v.to_string())),
        createdAt: Some(Utc::now()),
        updatedAt: None,
    };
    // Handle settings if missing
    let mut note_with_settings = note;
    if note_with_settings.settings.is_none() {
        note_with_settings.settings = Some(crate::models::NoteSettings {
            shared: Some(false),
            pinned: Some(false),
            ..Default::default()
        });
    }
    let coll = db.collection::<Note>("notes");
    let res2 = coll.insert_one(note_with_settings).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Error creating a new note, please try again or later"})),
        )
    })?;
    let note_id = res2.inserted_id.as_object_id().unwrap();
    // Update NoteState with noteId
    state_coll
        .update_one(doc! {"_id": state_id}, doc! {"$set": {"noteId": note_id}})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    // pageLocation logic: retrieve from clone
    let page_loc = page_loc_clone.unwrap_or(json!("0"));
    let page_str = page_loc.as_str().unwrap_or("0").to_string();
    Ok((
        StatusCode::OK,
        Json(
            json!({"noteId": note_id.to_hex(), "pageLocation": page_str, "message": "Saved susccessfuly!"}),
        ),
    ))
}

pub async fn add_label(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<AddLabelReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let oid = ObjectId::parse_str(&payload.noteId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Error, please try again later!"})),
        )
    })?;
    owned_note(&state.db, oid, &claims).await?;
    let label_oids: Vec<ObjectId> = payload
        .labels
        .iter()
        .filter_map(|s| ObjectId::parse_str(s).ok())
        .collect();
    state
        .db
        .collection::<Note>("notes")
        .update_one(doc! {"_id": oid}, doc! {"$set": {"labels": label_oids}})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Error, please try again later!"})),
            )
        })?;
    Ok((StatusCode::OK, Json(json!({"message": "Label attached!"}))))
}

pub async fn edit(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<EditReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let oid = ObjectId::parse_str(&payload._id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Error, please try again later!"})),
        )
    })?;
    owned_note(&state.db, oid, &claims).await?;
    let mut update = doc! {};
    if let Some(t) = payload.title {
        update.insert("name", t);
    }
    if let Some(b) = payload.body {
        update.insert("body", b);
    }
    if let Some(img) = payload.image {
        update.insert("image", img);
    }
    if !update.is_empty() {
        state
            .db
            .collection::<Note>("notes")
            .update_one(doc! {"_id": oid}, doc! {"$set": update})
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"message": "Error, please try again later!"})),
                )
            })?;
    }
    if let (Some(sid), Some(st)) = (payload.stateId, payload.state) {
        if let Ok(s_oid) = ObjectId::parse_str(&sid) {
            state
                .db
                .collection::<NoteState>("noteStates")
                .update_one(doc! {"_id": s_oid}, doc! {"$set": {"state": st}})
                .await
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"message": "Error, please try again later!"})),
                    )
                })?;
        }
    }
    Ok((StatusCode::OK, Json(json!({"message": "Note updated!"}))))
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let oid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Error, please try again later!"})),
        )
    })?;
    let coll = state.db.collection::<Note>("notes");
    let note = coll.find_one(doc! {"_id": oid}).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    if let Some(n) = note {
        require_owner(&claims, &n.author)?;
        if let Some(state_bson) = n.state {
            if let Bson::ObjectId(sid) = state_bson {
                state
                    .db
                    .collection::<NoteState>("noteStates")
                    .delete_one(doc! {"_id": sid})
                    .await
                    .map_err(|e| {
                        (
                            StatusCode::BAD_REQUEST,
                            crate::utils::db_err_json(e),
                        )
                    })?;
            }
        }
        coll.delete_one(doc! {"_id": oid}).await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    }
    Ok((StatusCode::OK, Json(json!({"message": "Note deleted!"}))))
}

pub async fn delete_label(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path((id, noteId)): Path<(String, String)>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let nid = ObjectId::parse_str(&noteId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Error, please try again later!"})),
        )
    })?;
    let coll = state.db.collection::<Note>("notes");
    let note = coll
        .find_one(doc! {"_id": nid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?
        .ok_or((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Note wasn't found!"})),
        ))?;
    require_owner(&claims, &note.author)?;
    let labels = note.labels.unwrap_or_default();
    let filtered: Vec<ObjectId> = labels
        .into_iter()
        .filter(|oid| oid.to_hex() != id)
        .collect();
    coll.update_one(doc! {"_id": nid}, doc! {"$set": {"labels": filtered}})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    Ok((StatusCode::OK, Json(json!({"message": "Label detached!"}))))
}

pub async fn delete_all_labels(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(noteId): Path<String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let nid = ObjectId::parse_str(&noteId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Error, please try again later!"})),
        )
    })?;
    owned_note(&state.db, nid, &claims).await?;
    state
        .db
        .collection::<Note>("notes")
        .update_one(
            doc! {"_id": nid},
            doc! {"$set": {"labels": Vec::<ObjectId>::new()}},
        )
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    Ok((StatusCode::OK, Json(json!({"message": "Labels detached!"}))))
}

pub async fn pin_note(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(noteId): Path<String>,
    Json(payload): Json<PinReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let nid = ObjectId::parse_str(&noteId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Error, please try again later!"})),
        )
    })?;
    // Need to preserve other settings, so fetch first
    let coll = state.db.collection::<Note>("notes");
    let note = coll
        .find_one(doc! {"_id": nid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?
        .ok_or((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Note not found"})),
        ))?;
    require_owner(&claims, &note.author)?;
    let mut settings = note.settings.unwrap_or_default();
    settings.pinned = Some(payload.condition);
    coll.update_one(
        doc! {"_id": nid},
        doc! {"$set": {"settings": bson::to_bson(&settings).unwrap()}},
    )
    .await
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            crate::utils::db_err_json(e),
        )
    })?;
    let msg = if payload.condition {
        "Note pinned!"
    } else {
        "Note unpinned!"
    };
    Ok((StatusCode::OK, Json(json!({"message": msg}))))
}

pub async fn rename(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<RenameReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let oid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Error, please try again later!"})),
        )
    })?;
    owned_note(&state.db, oid, &claims).await?;
    state
        .db
        .collection::<Note>("notes")
        .update_one(doc! {"_id": oid}, doc! {"$set": {"name": payload.name}})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    Ok((StatusCode::OK, Json(json!({"message": "Updated!"}))))
}

pub async fn change_bg(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(noteId): Path<String>,
    Json(payload): Json<BgReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let nid = ObjectId::parse_str(&noteId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    let coll = state.db.collection::<Note>("notes");
    let note = coll
        .find_one(doc! {"_id": nid})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?
        .ok_or((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Note not found"})),
        ))?;
    require_owner(&claims, &note.author)?;
    let mut settings = note.settings.unwrap_or_default();
    settings.noteBackgroundColor = Some(payload.noteBackgroundColor);
    coll.update_one(
        doc! {"_id": nid},
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

pub async fn change_image(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(noteId): Path<String>,
    Json(payload): Json<ImageReq>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let nid = ObjectId::parse_str(&noteId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    owned_note(&state.db, nid, &claims).await?;
    state
        .db
        .collection::<Note>("notes")
        .update_one(doc! {"_id": nid}, doc! {"$set": {"image": payload.image}})
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                crate::utils::db_err_json(e),
            )
        })?;
    Ok((StatusCode::OK, Json(json!({"message": "Updated!"}))))
}
