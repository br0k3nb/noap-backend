use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use bson::{doc, oid::ObjectId, Bson};
use futures::TryStreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::{
    middleware::auth::require_owner,
    models::{Activity, ActivityTrigger},
    utils::crypto::Claims,
    AppState,
};

/// Trigger kinds this server can validate (and the frontend scheduler can
/// fire): "daily" (every day at `trigger.time`) and "once" (one-shot at
/// `trigger.date` + `trigger.time`). Future kinds (weekly, interval, ...) add
/// a validation arm in `validate_trigger`, their own optional config fields on
/// `models::ActivityTrigger`, and a registry entry + `shouldTrigger` case on
/// the frontend (`noap/src/services/activityNotifications.ts`).
const SUPPORTED_TRIGGER_TYPES: [&str; 2] = ["daily", "once"];

type HandlerResult = Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)>;

/// Parses a 24-hour time string ("H:MM" / "HH:MM") and normalizes it to
/// zero-padded "HH:MM". Returns `None` for anything malformed or out of range.
fn normalize_hhmm(time: &str) -> Option<String> {
    let (hours, minutes) = time.trim().split_once(':')?;
    if hours.is_empty() || minutes.is_empty() || hours.len() > 2 || minutes.len() > 2 {
        return None;
    }
    let hours: u32 = hours.parse().ok()?;
    let minutes: u32 = minutes.parse().ok()?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some(format!("{:02}:{:02}", hours, minutes))
}

/// Parses a date string and normalizes it to "DD/MM/YYYY". Days and months
/// may have 1-2 digits (zero-padded on output); the year must have 4 digits.
/// Returns `None` for anything malformed or not a real calendar date.
fn normalize_dd_mm_yyyy(date: &str) -> Option<String> {
    let (day, rest) = date.trim().split_once('/')?;
    let (month, year) = rest.split_once('/')?;
    if day.is_empty() || day.len() > 2 || month.is_empty() || month.len() > 2 || year.len() != 4 {
        return None;
    }
    let day: u32 = day.parse().ok()?;
    let month: u32 = month.parse().ok()?;
    let year: i32 = year.parse().ok()?;
    // Rejects impossible days (31/02, 29/02 on non-leap years, ...).
    chrono::NaiveDate::from_ymd_opt(year, month, day)?;
    Some(format!("{:02}/{:02}/{:04}", day, month, year))
}

/// Validates the trigger config of `trigger_type` and returns it normalized
/// ("HH:MM" zero-padded; `date` as "DD/MM/YYYY" zero-padded for "once").
/// New trigger types only extend this match.
fn validate_trigger(
    trigger_type: &str,
    trigger: &ActivityTrigger,
) -> Result<ActivityTrigger, (StatusCode, Json<Value>)> {
    let bad_time = || {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "message": "Trigger time must be a valid 24-hour \"HH:MM\" time" })),
        )
    };
    match trigger_type {
        "daily" => Ok(ActivityTrigger {
            time: normalize_hhmm(&trigger.time).ok_or_else(bad_time)?,
            date: None,
            weekdays: trigger.weekdays.clone(),
        }),
        "once" => Ok(ActivityTrigger {
            time: normalize_hhmm(&trigger.time).ok_or_else(bad_time)?,
            date: Some(
                normalize_dd_mm_yyyy(trigger.date.as_deref().unwrap_or_default()).ok_or_else(
                    || {
                        (
                            StatusCode::BAD_REQUEST,
                            Json(json!({ "message": "Trigger date must be a valid \"DD/MM/YYYY\" date" })),
                        )
                    },
                )?,
            ),
            weekdays: trigger.weekdays.clone(),
        }),
        other => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "message": format!(
                "Unsupported trigger type \"{}\" (supported: {})",
                other,
                SUPPORTED_TRIGGER_TYPES.join(", ")
            ) })),
        )),
    }
}

fn clean_title(title: &str) -> Result<String, (StatusCode, Json<Value>)> {
    let title = title.trim().to_string();
    if title.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "message": "Activity title is required" })),
        ));
    }
    if title.chars().count() > 120 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "message": "Activity title must be at most 120 characters" })),
        ));
    }
    Ok(title)
}

fn clean_description(
    description: Option<String>,
) -> Result<Option<String>, (StatusCode, Json<Value>)> {
    match description
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
    {
        Some(d) if d.chars().count() > 500 => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "message": "Activity description must be at most 500 characters" })),
        )),
        other => Ok(other),
    }
}

/// Normalizes an incoming linked-note id: trims, treats missing/empty as
/// "no link", otherwise requires a valid ObjectId hex string and returns it
/// canonicalized (lowercase hex). Never touches the DB (see
/// `ensure_note_owned` for the ownership check).
fn clean_note_id(raw: Option<String>) -> Result<Option<String>, (StatusCode, Json<Value>)> {
    match raw.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => ObjectId::parse_str(&s)
            .map(|oid| oid.to_hex())
            .map(Some)
            .map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"message": "Linked note id is invalid"})),
                )
            }),
    }
}

/// Guarantees the linked note exists and belongs to the session owner.
/// Without this, any authenticated user could link someone else's note to
/// their own activity (IDOR + information leak via the activity payload).
async fn ensure_note_owned(
    db: &mongodb::Database,
    note_id_hex: &str,
    claims: &Claims,
) -> Result<ObjectId, (StatusCode, Json<Value>)> {
    let oid = ObjectId::parse_str(note_id_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Linked note id is invalid"})),
        )
    })?;
    let note = db
        .collection::<crate::models::Note>("notes")
        .find_one(doc! {"_id": oid})
        .await
        .map_err(|e| {
            tracing::error!("DB error loading linked note: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Linked note wasn't found!"})),
        ))?;
    require_owner(claims, &note.author)?;
    Ok(oid)
}

/// Today in the app timezone (America/Recife = UTC-3 year-round, no DST) as
/// "DD/MM/YYYY". Used as the default `doneDates` entry when the client does
/// not send an explicit date.
fn today_recife_br() -> String {
    let now = chrono::Utc::now() - chrono::Duration::hours(3);
    now.format("%d/%m/%Y").to_string()
}

fn parse_br_date_to_naive(date: &str) -> Option<chrono::NaiveDate> {
    let normalized = normalize_dd_mm_yyyy(date)?;
    chrono::NaiveDate::parse_from_str(&normalized, "%d/%m/%Y").ok()
}

/// Current consecutive-day streak + total completions from `doneDates`.
/// `doneDates` holds "DD/MM/YYYY" keys, newest last, deduped on write.
/// The streak counts back from today when today is done, otherwise from
/// yesterday (a habit done every day so far but not yet today still shows
/// its streak instead of dropping to zero on every morning).
fn streak_stats(done_dates: &[String]) -> (i64, i64) {
    use std::collections::HashSet;
    let mut set: HashSet<chrono::NaiveDate> = HashSet::new();
    for d in done_dates {
        if let Some(nd) = parse_br_date_to_naive(d) {
            set.insert(nd);
        }
    }
    let total = set.len() as i64;
    if total == 0 {
        return (0, 0);
    }
    let today = parse_br_date_to_naive(&today_recife_br()).unwrap_or_else(|| chrono::Utc::now().date_naive());
    // Start counting from today if done, else from yesterday.
    let mut cursor = if set.contains(&today) {
        today
    } else {
        today - chrono::Duration::days(1)
    };
    let mut streak: i64 = 0;
    // If neither today nor yesterday is done, the streak is broken (0) even
    // though older completions still count toward the total.
    if !set.contains(&cursor) {
        return (0, total);
    }
    while set.contains(&cursor) {
        streak += 1;
        cursor = cursor - chrono::Duration::days(1);
    }
    (streak, total)
}

/// Loads an activity and guarantees it belongs to the session owner.
/// Without this, any authenticated user could read/mutate another user's
/// activities by guessing their ids (IDOR).
async fn owned_activity(
    db: &mongodb::Database,
    activity_id: ObjectId,
    claims: &Claims,
) -> Result<Activity, (StatusCode, Json<Value>)> {
    let activity = db
        .collection::<Activity>("activities")
        .find_one(doc! {"_id": activity_id})
        .await
        .map_err(|e| {
            tracing::error!("DB error loading activity: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Activity wasn't found!"})),
        ))?;
    require_owner(claims, &activity.userId.to_hex())?;
    Ok(activity)
}

#[derive(Deserialize)]
pub struct AddReq {
    pub title: String,
    pub description: Option<String>,
    pub triggerType: String,
    pub trigger: ActivityTrigger,
    pub enabled: Option<bool>,
    /// Optional hex id of the note acting as this activity's recurring todo
    /// list. Empty/missing means "no linked note".
    #[serde(default)]
    pub noteId: Option<String>,
}

#[derive(Deserialize)]
pub struct EditReq {
    pub _id: String,
    pub title: String,
    pub description: Option<String>,
    pub triggerType: String,
    pub trigger: ActivityTrigger,
    /// Same semantics as `AddReq.noteId`: `Some(id)` links, `None`/empty
    /// unlinks. `edit` always applies it so the frontend can link/unlink in
    /// the same form that edits the schedule.
    #[serde(default)]
    pub noteId: Option<String>,
}

#[derive(Deserialize)]
pub struct ToggleReq {
    pub enabled: bool,
}

#[derive(Deserialize)]
pub struct LinkReq {
    pub noteId: String,
}

#[derive(Deserialize)]
pub struct CompleteReq {
    /// "DD/MM/YYYY" occurrence to mark done. Defaults to today in
    /// America/Recife (UTC-3, no DST) when missing/empty.
    #[serde(default)]
    pub date: Option<String>,
}

#[derive(Deserialize)]
pub struct SeenReq {
    /// Occurrence key the client rolled over (e.g. "YYYY-MM-DD" for daily,
    /// "DD/MM/YYYY" for once). Stored verbatim, deduped.
    #[serde(default)]
    pub occurrenceKey: Option<String>,
    /// Legacy/alternate field name accepted for the same value.
    #[serde(default)]
    pub occurrence: Option<String>,
}

/// Lists every activity of the user as `{ activities: [...] }`, ordered as a
/// daily agenda (by time of day, then creation).
pub async fn view(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(userId): Path<String>,
) -> HandlerResult {
    require_owner(&claims, &userId)?;
    let uid = ObjectId::parse_str(&userId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid userId"})),
        )
    })?;

    // Match BOTH userId forms: documents written through the Rust models land
    // with `userId` as the hex string (`object_id_hex` serializes ObjectIds to
    // strings on BSON inserts), while older rows carry a real ObjectId.
    // Querying only one form yields a falsely empty list (same reason the
    // codebase already handles in `session.rs`).
    let mut cursor = state
        .db
        .collection::<Activity>("activities")
        .find(doc! {"$or": [{"userId": uid}, {"userId": userId}]})
        .sort(doc! {"trigger.time": 1, "_id": 1})
        .await
        .map_err(|e| {
            tracing::error!("DB error listing activities: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?;
    let activities = cursor.try_collect::<Vec<Activity>>().await.map_err(|e| {
        tracing::error!("DB cursor error listing activities: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"message": "Database error, please try again later"})),
        )
    })?;

    Ok((StatusCode::OK, Json(json!({ "activities": activities }))))
}

pub async fn add(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(userId): Path<String>,
    Json(payload): Json<AddReq>,
) -> HandlerResult {
    require_owner(&claims, &userId)?;
    let uid = ObjectId::parse_str(&userId).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid userId"})),
        )
    })?;

    let title = clean_title(&payload.title)?;
    let description = clean_description(payload.description)?;
    let trigger = validate_trigger(&payload.triggerType, &payload.trigger)?;
    let note_id = clean_note_id(payload.noteId)?;
    if let Some(ref nid) = note_id {
        ensure_note_owned(&state.db, nid, &claims).await?;
    }

    let activity = Activity {
        id: None,
        userId: uid,
        title,
        description,
        triggerType: payload.triggerType.clone(),
        trigger,
        enabled: payload.enabled.unwrap_or(true),
        lastPushKey: None,
        noteId: note_id,
        seenOccurrences: None,
        doneDates: None,
        lastTriggeredAt: None,
        createdAt: Some(chrono::Utc::now()),
        updatedAt: None,
    };

    state
        .db
        .collection::<Activity>("activities")
        .insert_one(activity)
        .await
        .map_err(|e| {
            tracing::error!("DB error inserting activity: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Error, please try again later!"})),
            )
        })?;

    Ok((
        StatusCode::OK,
        Json(json!({"message": "Activity created!"})),
    ))
}

pub async fn edit(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(_userId): Path<String>,
    Json(payload): Json<EditReq>,
) -> HandlerResult {
    let oid = ObjectId::parse_str(&payload._id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    // Ownership comes from the stored activity (never from body/path ids).
    owned_activity(&state.db, oid, &claims).await?;

    let title = clean_title(&payload.title)?;
    let description = clean_description(payload.description)?;
    let trigger = validate_trigger(&payload.triggerType, &payload.trigger)?;
    let note_id = clean_note_id(payload.noteId)?;
    if let Some(ref nid) = note_id {
        ensure_note_owned(&state.db, nid, &claims).await?;
    }
    let trigger_bson = bson::to_bson(&trigger)
        .map_err(|e| crate::utils::internal_err(e, "activity trigger serialisation"))?;

    // `noteId` is always applied (link or unlink) so one form covers both.
    let mut set_doc = doc! {
        "title": title,
        "description": description.map_or(Bson::Null, Bson::String),
        "triggerType": payload.triggerType,
        "trigger": trigger_bson,
        "updatedAt": Bson::DateTime(bson::DateTime::now()),
    };
    let mut unset_doc = doc! {};
    match note_id {
        Some(nid) => {
            set_doc.insert("noteId", nid);
        }
        None => {
            unset_doc.insert("noteId", "");
        }
    }
    let mut update_doc = doc! {"$set": set_doc};
    if !unset_doc.is_empty() {
        update_doc.insert("$unset", unset_doc);
    }

    state
        .db
        .collection::<Activity>("activities")
        .update_one(doc! {"_id": oid}, update_doc)
        .await
        .map_err(|e| {
            tracing::error!("DB error updating activity: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Error, please try again later!"})),
            )
        })?;

    Ok((
        StatusCode::OK,
        Json(json!({"message": "Activity updated!"})),
    ))
}

/// Quick enable/disable of an activity without resending the whole document.
pub async fn toggle(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<ToggleReq>,
) -> HandlerResult {
    let oid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    owned_activity(&state.db, oid, &claims).await?;

    state
        .db
        .collection::<Activity>("activities")
        .update_one(
            doc! {"_id": oid},
            doc! {"$set": {
                "enabled": payload.enabled,
                "updatedAt": Bson::DateTime(bson::DateTime::now()),
            }},
        )
        .await
        .map_err(|e| {
            tracing::error!("DB error toggling activity: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Error, please try again later!"})),
            )
        })?;

    let message = if payload.enabled {
        "Activity enabled!"
    } else {
        "Activity disabled!"
    };
    Ok((StatusCode::OK, Json(json!({ "message": message }))))
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> HandlerResult {
    let oid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    owned_activity(&state.db, oid, &claims).await?;

    state
        .db
        .collection::<Activity>("activities")
        .delete_one(doc! {"_id": oid})
        .await
        .map_err(|e| {
            tracing::error!("DB error deleting activity: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Error, please try again later!"})),
            )
        })?;

    Ok((
        StatusCode::OK,
        Json(json!({"message": "Activity deleted!"})),
    ))
}

/// Records that a client just fired a notification for this activity
/// (`lastTriggeredAt`). Bookkeeping for cross-device visibility and future
/// server-side push — the client already guarantees one notification per
/// activity per day per device via its own dedup.
pub async fn mark_triggered(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> HandlerResult {
    let oid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    owned_activity(&state.db, oid, &claims).await?;

    let now = bson::DateTime::now();
    state
        .db
        .collection::<Activity>("activities")
        .update_one(
            doc! {"_id": oid},
            doc! {"$set": {
                "lastTriggeredAt": Bson::DateTime(now),
                "updatedAt": Bson::DateTime(now),
            }},
        )
        .await
        .map_err(|e| {
            tracing::error!("DB error recording activity trigger: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Error, please try again later!"})),
            )
        })?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "message": "Activity trigger recorded!",
            "lastTriggeredAt": now.to_chrono().to_rfc3339(),
        })),
    ))
}

/// Links an existing note as this activity's recurring todo list. The note
/// must belong to the same user; otherwise the link is rejected (IDOR guard).
pub async fn link_note(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<LinkReq>,
) -> HandlerResult {
    let oid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    owned_activity(&state.db, oid, &claims).await?;
    let note_id = clean_note_id(Some(payload.noteId))?.ok_or((
        StatusCode::BAD_REQUEST,
        Json(json!({"message": "Linked note id is required"})),
    ))?;
    ensure_note_owned(&state.db, &note_id, &claims).await?;

    state
        .db
        .collection::<Activity>("activities")
        .update_one(
            doc! {"_id": oid},
            doc! {"$set": {
                "noteId": note_id,
                "updatedAt": Bson::DateTime(bson::DateTime::now()),
            }},
        )
        .await
        .map_err(|e| {
            tracing::error!("DB error linking activity note: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Error, please try again later!"})),
            )
        })?;

    Ok((
        StatusCode::OK,
        Json(json!({"message": "Note linked to activity!"})),
    ))
}

/// Removes the linked note (the note itself is untouched). The activity keeps
/// its `doneDates` history so a re-linked note still shows the old streak.
pub async fn unlink_note(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> HandlerResult {
    let oid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    owned_activity(&state.db, oid, &claims).await?;

    state
        .db
        .collection::<Activity>("activities")
        .update_one(
            doc! {"_id": oid},
            doc! {"$unset": {"noteId": ""},
                  "$set": {"updatedAt": Bson::DateTime(bson::DateTime::now())}},
        )
        .await
        .map_err(|e| {
            tracing::error!("DB error unlinking activity note: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Error, please try again later!"})),
            )
        })?;

    Ok((
        StatusCode::OK,
        Json(json!({"message": "Note unlinked from activity!"})),
    ))
}

fn progress_payload(activity: &Activity) -> Value {
    let done_dates = activity.doneDates.clone().unwrap_or_default();
    let seen = activity.seenOccurrences.clone().unwrap_or_default();
    let (streak, total) = streak_stats(&done_dates);
    let today = today_recife_br();
    let done_today = done_dates.iter().any(|d| {
        normalize_dd_mm_yyyy(d).as_deref() == Some(today.as_str())
    });
    json!({
        "noteId": activity.noteId,
        "doneDates": done_dates,
        "seenOccurrences": seen,
        "currentStreak": streak,
        "totalCompletions": total,
        "doneToday": done_today,
        "today": today,
        "lastDone": done_dates.last(),
    })
}

/// Returns the answered/completion state of the note attached to the
/// activity: `doneDates` history, `currentStreak`, `totalCompletions`,
/// `doneToday` and the `today` key the client should use. Powers the streak
/// badge + "answered?" UI without the client reimplementing date math.
pub async fn progress(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> HandlerResult {
    let oid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    let activity = owned_activity(&state.db, oid, &claims).await?;
    Ok((StatusCode::OK, Json(progress_payload(&activity))))
}

/// Marks the current occurrence as done ("the user answered the attached
/// note"). Appends the "DD/MM/YYYY" day to `doneDates` (deduped via
/// `$addToSet` — one entry per occurrence no matter how many devices
/// report it) and returns the fresh streak so the UI updates instantly.
/// The frontend resets the linked note's checkboxes right after this
/// succeeds, making the same note reusable as a recurring todo list.
pub async fn complete(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<CompleteReq>,
) -> HandlerResult {
    let oid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    owned_activity(&state.db, oid, &claims).await?;

    let date = match payload.date.map(|d| d.trim().to_string()).filter(|d| !d.is_empty()) {
        Some(d) => normalize_dd_mm_yyyy(&d).ok_or((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Completion date must be a valid \"DD/MM/YYYY\" date"})),
        ))?,
        None => today_recife_br(),
    };

    state
        .db
        .collection::<Activity>("activities")
        .update_one(
            doc! {"_id": oid},
            doc! {"$addToSet": {"doneDates": &date},
                  "$set": {"updatedAt": Bson::DateTime(bson::DateTime::now())}},
        )
        .await
        .map_err(|e| {
            tracing::error!("DB error completing activity: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Error, please try again later!"})),
            )
        })?;

    let activity = owned_activity(&state.db, oid, &claims).await?;
    let mut out = progress_payload(&activity);
    out["message"] = Value::String("Activity marked as done!".to_string());
    out["date"] = Value::String(date);
    Ok((StatusCode::OK, Json(out)))
}

/// Records that the client rolled the linked note over to a new occurrence
/// (i.e. it reset the note's checkboxes for `occurrenceKey`). Stored in
/// `seenOccurrences` (deduped, newest last is approximated by `$addToSet`
/// insertion order) so every device knows which occurrences were already
/// rolled over and never resets the same occurrence twice.
pub async fn record_seen(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<SeenReq>,
) -> HandlerResult {
    let oid = ObjectId::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Invalid id"})),
        )
    })?;
    owned_activity(&state.db, oid, &claims).await?;

    let key = payload
        .occurrenceKey
        .or(payload.occurrence)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "occurrenceKey is required"})),
        ))?;
    if key.chars().count() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "occurrenceKey is too long"})),
        ));
    }

    state
        .db
        .collection::<Activity>("activities")
        .update_one(
            doc! {"_id": oid},
            doc! {"$addToSet": {"seenOccurrences": &key},
                  "$set": {"updatedAt": Bson::DateTime(bson::DateTime::now())}},
        )
        .await
        .map_err(|e| {
            tracing::error!("DB error recording activity occurrence: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Error, please try again later!"})),
            )
        })?;

    Ok((
        StatusCode::OK,
        Json(json!({"message": "Occurrence recorded!", "occurrenceKey": key})),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trigger(time: &str) -> ActivityTrigger {
        ActivityTrigger {
            time: time.to_string(),
            date: None,
            weekdays: None,
        }
    }

    fn once_trigger(time: &str, date: &str) -> ActivityTrigger {
        ActivityTrigger {
            time: time.to_string(),
            date: Some(date.to_string()),
            weekdays: None,
        }
    }

    #[test]
    fn activity_round_trips_the_shape_stored_in_mongo() {
        // Mirrors a real stored document: nested `trigger` subdocument, no
        // `weekdays`, no `description`/`updatedAt`/`lastTriggeredAt`, and a
        // sub-second RFC3339 `createdAt` string (chrono `to_rfc3339` output).
        let doc = bson::doc! {
            "_id": bson::oid::ObjectId::parse_str("6ab290bf9c189ae12d54b155").unwrap(),
            "userId": bson::oid::ObjectId::parse_str("648a173ca6d551d5ee99e897").unwrap(),
            "title": "teste",
            "triggerType": "once",
            "trigger": { "time": "11:30", "date": "22/09/2026" },
            "enabled": true,
            "createdAt": "2026-09-22T14:29:19.563439220+00:00"
        };
        let activity: Activity = bson::from_document(doc).expect("stored shape must deserialize");
        assert_eq!(activity.title, "teste");
        assert_eq!(activity.trigger.time, "11:30");
        assert_eq!(activity.trigger.date.as_deref(), Some("22/09/2026"));
        let out = serde_json::to_value(&activity).expect("must serialize to JSON");
        assert_eq!(out["userId"], "648a173ca6d551d5ee99e897");
    }

    #[test]
    fn normalize_hhmm_accepts_and_pads() {
        assert_eq!(normalize_hhmm("9:05").as_deref(), Some("09:05"));
        assert_eq!(normalize_hhmm("23:59").as_deref(), Some("23:59"));
        assert_eq!(normalize_hhmm("00:00").as_deref(), Some("00:00"));
        assert_eq!(normalize_hhmm(" 8:30 ").as_deref(), Some("08:30"));
    }

    #[test]
    fn normalize_hhmm_rejects_malformed_times() {
        assert_eq!(normalize_hhmm("24:00"), None);
        assert_eq!(normalize_hhmm("12:60"), None);
        assert_eq!(normalize_hhmm("1200"), None);
        assert_eq!(normalize_hhmm(""), None);
        assert_eq!(normalize_hhmm("ab:cd"), None);
        assert_eq!(normalize_hhmm("1:2:3"), None);
        assert_eq!(normalize_hhmm("123:45"), None);
    }

    #[test]
    fn normalize_dd_mm_yyyy_accepts_and_pads() {
        assert_eq!(normalize_dd_mm_yyyy("1/5/2026").as_deref(), Some("01/05/2026"));
        assert_eq!(normalize_dd_mm_yyyy("25/12/2026").as_deref(), Some("25/12/2026"));
    }

    #[test]
    fn normalize_dd_mm_yyyy_rejects_invalid_dates() {
        assert_eq!(normalize_dd_mm_yyyy("31/02/2026"), None);
        assert_eq!(normalize_dd_mm_yyyy("2026/05/01"), None);
        assert_eq!(normalize_dd_mm_yyyy("32/01/2026"), None);
        assert_eq!(normalize_dd_mm_yyyy("01/13/2026"), None);
        assert_eq!(normalize_dd_mm_yyyy("garbage"), None);
        assert_eq!(normalize_dd_mm_yyyy(""), None);
    }

    #[test]
    fn validate_trigger_daily_normalizes_time() {
        let normalized = validate_trigger("daily", &trigger("8:30")).unwrap();
        assert_eq!(normalized.time, "08:30");
        assert!(normalized.date.is_none());
    }

    #[test]
    fn validate_trigger_once_normalizes_time_and_date() {
        let normalized = validate_trigger("once", &once_trigger("7:5", "3/4/2027")).unwrap();
        assert_eq!(normalized.time, "07:05");
        assert_eq!(normalized.date.as_deref(), Some("03/04/2027"));
    }

    #[test]
    fn validate_trigger_once_requires_a_valid_date() {
        assert!(validate_trigger("once", &trigger("10:00")).is_err());
        assert!(validate_trigger("once", &once_trigger("10:00", "31/02/2026")).is_err());
        // 29/02 only exists in leap years.
        assert!(validate_trigger("once", &once_trigger("10:00", "29/02/2026")).is_err());
        assert!(validate_trigger("once", &once_trigger("10:00", "29/02/2028")).is_ok());
    }

    #[test]
    fn validate_trigger_rejects_bad_times_and_unknown_types() {
        assert!(validate_trigger("daily", &trigger("25:00")).is_err());
        assert!(validate_trigger("daily", &trigger("")).is_err());
        assert!(validate_trigger("weekly", &trigger("10:00")).is_err());
        assert!(validate_trigger("interval", &trigger("10:00")).is_err());
    }

    #[test]
    fn clean_note_id_treats_missing_and_empty_as_no_link() {
        assert_eq!(clean_note_id(None).unwrap(), None);
        assert_eq!(clean_note_id(Some("".to_string())).unwrap(), None);
        assert_eq!(clean_note_id(Some("   ".to_string())).unwrap(), None);
    }

    #[test]
    fn clean_note_id_accepts_valid_hex_and_rejects_garbage() {
        let hex = "648a173ca6d551d5ee99e897";
        assert_eq!(
            clean_note_id(Some(hex.to_string())).unwrap(),
            Some(hex.to_string())
        );
        assert!(clean_note_id(Some("not-an-id".to_string())).is_err());
    }

    #[test]
    fn streak_stats_counts_consecutive_days_back_from_today() {
        let today = parse_br_date_to_naive(&today_recife_br()).unwrap();
        let fmt = |d: chrono::NaiveDate| d.format("%d/%m/%Y").to_string();
        let done = vec![
            fmt(today - chrono::Duration::days(2)),
            fmt(today - chrono::Duration::days(1)),
            fmt(today),
        ];
        assert_eq!(streak_stats(&done), (3, 3));
    }

    #[test]
    fn streak_stats_keeps_streak_when_today_not_done_yet() {
        let today = parse_br_date_to_naive(&today_recife_br()).unwrap();
        let fmt = |d: chrono::NaiveDate| d.format("%d/%m/%Y").to_string();
        let done = vec![
            fmt(today - chrono::Duration::days(1)),
            fmt(today - chrono::Duration::days(2)),
        ];
        assert_eq!(streak_stats(&done), (2, 2));
    }

    #[test]
    fn streak_stats_breaks_on_gaps_and_ignores_bad_dates() {
        let today = parse_br_date_to_naive(&today_recife_br()).unwrap();
        let fmt = |d: chrono::NaiveDate| d.format("%d/%m/%Y").to_string();
        // Gap yesterday -> streak 0, but total still counts older days.
        let done = vec![fmt(today - chrono::Duration::days(2)), "garbage".to_string()];
        assert_eq!(streak_stats(&done), (0, 1));
        // Empty history -> no streak, no total.
        assert_eq!(streak_stats(&[]), (0, 0));
    }
}