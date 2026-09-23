//! Server-side Web Push (RFC8030) for activity reminders.
//!
//! The in-tab scheduler only fires while a Noap tab is open. Server push
//! closes the gap: each device subscribes once via the Push API, and
//! `POST /cron/push-due` (Vercel Cron, every minute) fans out to every
//! subscribed device even when no tab is open anywhere.
//!
//! Flow: `GET /push/vapid-key` (public) -> `POST /push/subscribe/:userId`
//! (auth) -> `POST /cron/push-due` (CRON_SECRET bearer). `endpoint` is the
//! idempotency key: re-subscribing upserts. Push crypto uses the `web-push`
//! crate; HTTP delivery reuses the app reqwest client — the crate only builds
//! the `http 0.2` request which we translate header-by-header (hence the
//! explicit `http = "0.2"` dep: reqwest 0.12 speaks `http 1.x`).

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Extension, Json,
};
use bson::{doc, oid::ObjectId};
use chrono::Timelike;
use futures::TryStreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::{
    middleware::auth::require_owner, models::{Activity, PushSubscription},
    utils::crypto::Claims, AppState,
};

type HandlerResult = Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)>;

/// Minutes after the scheduled time a cron tick still pushes. Mirrors the
/// frontend grace window so both channels agree on "due".
pub const PUSH_GRACE_MINUTES: i32 = 5;

#[derive(serde::Serialize)]
struct PushPayload<'a> {
    title: &'a str,
    body: &'a str,
    tag: &'a str,
    url: &'a str,
    #[serde(rename = "activityId")]
    activity_id: &'a str,
    #[serde(rename = "occurrenceKey")]
    occurrence_key: &'a str,
}

/// Public VAPID key for `pushManager.subscribe({ applicationServerKey })`.
/// Public by design (like a TLS public key): identifies the server, grants
/// nothing. 503 while VAPID_PRIVATE_KEY is unset.
pub async fn vapid_key(State(state): State<Arc<AppState>>) -> HandlerResult {
    match &state.vapid_public_key {
        Some(key) => Ok((StatusCode::OK, Json(json!({ "publicKey": key })))),
        None => Err((StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"message": "Push notifications are not configured on this server"})))),
    }
}

#[derive(Deserialize, Clone)]
pub struct SubscribeReq {
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
    #[serde(default, rename = "userAgent")]
    pub user_agent: Option<String>,
}

fn bad(msg: &str) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({ "message": msg })))
}

fn validate_subscription(req: &SubscribeReq) -> Result<(), (StatusCode, Json<Value>)> {
    let endpoint = req.endpoint.trim();
    if endpoint.is_empty() || endpoint.len() > 2048 {
        return Err(bad("Invalid push subscription endpoint"));
    }
    if !endpoint.to_lowercase().starts_with("https://") {
        return Err(bad("Push subscription endpoint must be an https URL"));
    }
    if req.p256dh.trim().is_empty() || req.p256dh.len() > 256 {
        return Err(bad("Invalid push subscription p256dh key"));
    }
    if req.auth.trim().is_empty() || req.auth.len() > 256 {
        return Err(bad("Invalid push subscription auth key"));
    }
    Ok(())
}

/// Links one device to server-side reminders. Idempotent per endpoint:
/// re-subscribing updates keys/owner instead of duplicating. A device that
/// changes owner transfers to the latest subscriber so reminders never leak
/// to the previous account.
pub async fn subscribe(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(userId): Path<String>,
    Json(payload): Json<SubscribeReq>,
) -> HandlerResult {
    require_owner(&claims, &userId)?;
    if state.vapid_private_key.is_none() {
        return Err((StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"message": "Push notifications are not configured on this server"}))));
    }
    validate_subscription(&payload)?;
    let uid = ObjectId::parse_str(&userId).map_err(|_| bad("Invalid userId"))?;
    let now = chrono::Utc::now();
    state.db.collection::<PushSubscription>("push_subscriptions")
        .update_one(
            doc! { "endpoint": payload.endpoint.trim() },
            doc! {
                "$set": {
                    "userId": uid,
                    "p256dh": payload.p256dh.trim(),
                    "auth": payload.auth.trim(),
                    "userAgent": payload.user_agent.unwrap_or_default(),
                    "updatedAt": now,
                },
                "$setOnInsert": { "createdAt": now },
            },
        )
        .upsert(true).await
        .map_err(|e| { tracing::error!("DB error saving push subscription: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"message": "Database error, please try again later"}))) })?;
    Ok((StatusCode::OK, Json(json!({ "message": "Device subscribed to push notifications!" }))))
}

/// Removes one device by endpoint. Unknown endpoints still return OK.
pub async fn unsubscribe(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(userId): Path<String>,
    Json(payload): Json<Value>,
) -> HandlerResult {
    require_owner(&claims, &userId)?;
    let endpoint = payload.get("endpoint").and_then(|v| v.as_str()).unwrap_or_default().trim().to_string();
    if endpoint.is_empty() { return Err(bad("Missing subscription endpoint")); }
    let uid = ObjectId::parse_str(&userId).map_err(|_| bad("Invalid userId"))?;
    state.db.collection::<PushSubscription>("push_subscriptions")
        .delete_one(doc! { "endpoint": endpoint, "userId": uid }).await
        .map_err(|e| { tracing::error!("DB error deleting push subscription: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"message": "Database error, please try again later"}))) })?;
    Ok((StatusCode::OK, Json(json!({ "message": "Device unsubscribed!" }))))
}

/// "Your devices" list. Never exposes p256dh/auth (push-service secrets).
pub async fn list(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(userId): Path<String>,
) -> HandlerResult {
    require_owner(&claims, &userId)?;
    let uid = ObjectId::parse_str(&userId).map_err(|_| bad("Invalid userId"))?;
    let mut cursor = state.db.collection::<PushSubscription>("push_subscriptions")
        .find(doc! { "userId": uid }).sort(doc! { "createdAt": 1 }).await
        .map_err(|e| { tracing::error!("DB error listing push subscriptions: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"message": "Database error, please try again later"}))) })?;
    let mut out = Vec::new();
    while let Some(sub) = cursor.try_next().await.map_err(|e| {
        tracing::error!("DB cursor error listing push subscriptions: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"message": "Database error, please try again later"})))
    })? {
        out.push(json!({
            "endpoint": sub.endpoint,
            "userAgent": sub.userAgent,
            "createdAt": sub.createdAt.map(|d| d.to_rfc3339()),
            "updatedAt": sub.updatedAt.map(|d| d.to_rfc3339()),
        }));
    }
    Ok((StatusCode::OK, Json(json!({ "subscriptions": out }))))
}
// ---------------------------------------------------------------------------
// Cron fan-out: POST /cron/push-due
// ---------------------------------------------------------------------------

/// Today (DD/MM/YYYY), minutes-of-day, and occurrence key (YYYY-MM-DD) as
/// wall-clock in America/Recife (UTC-3, no DST: fixed offset, no tz database
/// needed on the serverless runtime).
fn recife_now() -> (String, i32, String) {
    let now = chrono::Utc::now() - chrono::Duration::hours(3);
    let date = now.date_naive();
    (
        date.format("%d/%m/%Y").to_string(),
        now.time().hour() as i32 * 60 + now.time().minute() as i32,
        date.format("%Y-%m-%d").to_string(),
    )
}

/// Server-side mirror of frontend shouldTriggerActivity + grace window.
/// Returns the occurrence key (lastPushKey) when due: "daily:<YYYY-MM-DD>"
/// or "once:<DD/MM/YYYY>".
fn due_occurrence_key(activity: &Activity, today_br: &str, now_minutes: i32, today_key: &str) -> Option<String> {
    if !activity.enabled { return None; }
    let (hours, minutes) = activity.trigger.time.split_once(':')?;
    let hours: i32 = hours.parse().ok()?;
    let minutes: i32 = minutes.parse().ok()?;
    let trigger_minutes: i32 = hours * 60 + minutes;
    let diff = now_minutes - trigger_minutes;
    if !(0..=PUSH_GRACE_MINUTES).contains(&diff) { return None; }
    match activity.triggerType.as_str() {
        "daily" => Some(format!("daily:{}", today_key)),
        "once" => {
            if activity.trigger.date.as_deref() == Some(today_br) {
                Some(format!("once:{}", today_br))
            } else { None }
        }
        _ => None,
    }
}

/// Sends one RFC8030 push via state.http. web-push builds + encrypts the
/// http-0.2 request; we translate it onto reqwest (http-1.x types differ).
/// Returns true when the row must be deleted (410/404: dead subscription).
async fn send_push(state: &AppState, sub: &PushSubscription, payload_json: &str) -> Result<bool, String> {
    let vapid_key = state.vapid_private_key.as_deref().ok_or_else(|| "push disabled".to_string())?;
    let subscription = web_push::SubscriptionInfo::new(sub.endpoint.clone(), sub.p256dh.clone(), sub.auth.clone());
    let partial = web_push::VapidSignatureBuilder::from_base64_no_sub(vapid_key)
        .map_err(|e| format!("bad VAPID key: {}", e))?;
    let mut sig_builder = partial.add_sub_info(&subscription);
    sig_builder.add_claim("sub", state.vapid_subject.clone());
    let signature = sig_builder.build().map_err(|e| format!("vapid sign: {}", e))?;
    let mut msg_builder = web_push::WebPushMessageBuilder::new(&subscription);
    msg_builder.set_urgency(web_push::Urgency::High);
    msg_builder.set_ttl(86_400);
    msg_builder.set_payload(web_push::ContentEncoding::Aes128Gcm, payload_json.as_bytes());
    msg_builder.set_vapid_signature(signature);
    let message = msg_builder.build().map_err(|e| format!("build message: {}", e))?;
    let request: http::Request<Vec<u8>> = web_push::request_builder::build_request(message);
    let (parts, body) = request.into_parts();
    let mut req = state.http.post(parts.uri.to_string()).body(body);
    for (name, value) in parts.headers.iter() {
        req = req.header(name.as_str(), value.as_bytes());
    }
    let response = req.send().await.map_err(|e| format!("push send: {}", e))?;
    let status = response.status();
    if status.is_success() { return Ok(false); }
    let body_text = response.text().await.unwrap_or_default();
    if status == reqwest::StatusCode::GONE || status == reqwest::StatusCode::NOT_FOUND {
        tracing::info!("Pruning dead push subscription {}", sub.endpoint);
        return Ok(true);
    }
    Err(format!("push service {}: {}", status, body_text.chars().take(200).collect::<String>()))
}
/// Vercel Cron fans out every due activity to all devices of its owner. Auth
/// is `Authorization: Bearer <CRON_SECRET>` — this route sits OUTSIDE the
/// session middleware (cron has no user session). Unset CRON_SECRET leaves it
/// open (local dev only); production must set it.
///
/// Cost guard: activities without any subscription are skipped before sending;
/// lastPushKey is still written, so a later-subscribing device never receives
/// an already-fired occurrence as "new".
pub async fn cron_push_due(State(state): State<Arc<AppState>>, headers: HeaderMap) -> HandlerResult {
    if let Some(secret) = state.cron_secret.as_deref() {
        let presented = headers.get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok()).unwrap_or_default();
        let expected = format!("Bearer {}", secret);
        let ok = presented.len() == expected.len() && subtle_time_eq(presented.as_bytes(), expected.as_bytes());
        if !ok {
            return Err((StatusCode::UNAUTHORIZED, Json(json!({ "message": "Invalid cron secret" }))));
        }
    }
    if state.vapid_private_key.is_none() {
        return Err((StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"message": "Push notifications are not configured on this server"}))));
    }
    let (today_br, now_minutes, today_key) = recife_now();
    let activity_coll = state.db.collection::<Activity>("activities");
    let sub_coll = state.db.collection::<PushSubscription>("push_subscriptions");
    // Only enabled activities whose clock-time already passed today can be
    // due. Legacy rows may lack `enabled` (predates the toggle): $ne:false
    // keeps them firing, mirroring frontend `enabled !== false`.
    let mut cursor = activity_coll.find(doc! {
        "$and": [
            { "enabled": { "$ne": false } },
            { "trigger.time": { "$lte": minutes_to_hhmm(now_minutes) } },
        ]
    }).await.map_err(|e| { tracing::error!("DB error scanning due activities: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"message": "Database error, please try again later"}))) })?;
    let mut pushed = 0u32;
    let mut checked = 0u32;
    while let Some(activity) = cursor.try_next().await.map_err(|e| {
        tracing::error!("DB cursor error scanning due activities: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"message": "Database error, please try again later"})))
    })? {
        checked += 1;
        let Some(occurrence) = due_occurrence_key(&activity, &today_br, now_minutes, &today_key) else { continue; };
        if activity.lastPushKey.as_deref() == Some(occurrence.as_str()) { continue; }
        let Some(activity_id) = activity.id else { continue; };
        // Claim FIRST (atomic compare-and-set) so overlapping ticks never
        // double-push. A lost race only skips: the winner still sends.
        let claimed = activity_coll.update_one(
            doc! { "_id": activity_id,
                "$or": [ { "lastPushKey": { "$exists": false } }, { "lastPushKey": { "$ne": occurrence.clone() } } ] },
            doc! { "$set": { "lastPushKey": occurrence.clone(), "lastTriggeredAt": chrono::Utc::now() } },
        ).await.map(|r| r.modified_count > 0).unwrap_or(false);
        if !claimed { continue; }
        // Devices of this owner: tolerant of BOTH userId forms (legacy
        // ObjectId vs hex-string duality, same as activity::view).
        let owner_hex = activity.userId.to_hex();
        let mut subs = sub_coll.find(doc! {
            "$or": [ { "userId": activity.userId }, { "userId": owner_hex.clone() } ]
        }).await.map_err(|e| { tracing::error!("DB error listing subscriber devices: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"message": "Database error, please try again later"}))) })?;
        let mut devices: Vec<PushSubscription> = Vec::new();
        while let Some(s) = subs.try_next().await.map_err(|e| {
            tracing::error!("DB cursor error listing subscriber devices: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"message": "Database error, please try again later"})))
        })? { devices.push(s); }
        if devices.is_empty() { continue; }
        let url = activity.noteId.as_deref()
            .map(|nid| format!("/notes/page/1/note/{}", nid))
            .unwrap_or_else(|| "/".to_string());
        // Same tag shape as the in-tab scheduler (noap-activity-<id>-<key>)
        // so a server push arriving with a tab open replaces — not doubles —
        // the local notification, and vice versa.
        let short_key = occurrence.split_once(':').map(|(_, k)| k).unwrap_or(occurrence.as_str());
        let tag = format!("noap-activity-{}-{}", activity_id.to_hex(), short_key);
        let payload = PushPayload {
            title: &activity.title,
            body: activity.description.as_deref().unwrap_or("Scheduled activity"),
            tag: &tag, url: &url,
            activity_id: &activity_id.to_hex(), occurrence_key: &occurrence,
        };
        let payload_json = serde_json::to_string(&payload).unwrap_or_else(|_| {
            format!(r#"{{"title":{}}}"#, serde_json::to_string(&activity.title).unwrap_or_default())
        });
        let mut any_sent = false;
        for sub in &devices {
            match send_push(&state, sub, &payload_json).await {
                Ok(prune) => {
                    any_sent = true;
                    if prune {
                        if let Err(e) = sub_coll.delete_one(doc! { "endpoint": sub.endpoint.clone() }).await {
                            tracing::warn!("Failed pruning dead push subscription: {}", e);
                        }
                    }
                }
                Err(e) => tracing::warn!("Push to {} failed: {}", sub.endpoint, e),
            }
        }
        if any_sent { pushed += 1; }
    }
    Ok((StatusCode::OK, Json(json!({ "message": "Push sweep done", "checked": checked, "pushed": pushed }))))
}

fn subtle_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..a.len() { diff |= a[i] ^ b[i]; }
    diff == 0
}

fn minutes_to_hhmm(minutes: i32) -> String {
    format!("{:02}:{:02}", minutes / 60, minutes % 60)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ActivityTrigger;

    fn activity(trigger_type: &str, time: &str, date: Option<&str>, enabled: bool) -> Activity {
        Activity {
            id: None,
            userId: ObjectId::new(),
            title: "Test".to_string(),
            description: None,
            triggerType: trigger_type.to_string(),
            trigger: ActivityTrigger { time: time.to_string(), date: date.map(|d| d.to_string()), weekdays: None },
            enabled,
            lastPushKey: None,
            noteId: None,
            seenOccurrences: None,
            doneDates: None,
            lastTriggeredAt: None,
            createdAt: None,
            updatedAt: None,
        }
    }

    #[test]
    fn daily_is_due_at_trigger_and_inside_grace() {
        let a = activity("daily", "09:00", None, true);
        assert_eq!(due_occurrence_key(&a, "22/09/2026", 9 * 60, "2026-09-22"), Some("daily:2026-09-22".to_string()));
        assert_eq!(due_occurrence_key(&a, "22/09/2026", 9 * 60 + 5, "2026-09-22"), Some("daily:2026-09-22".to_string()));
    }

    #[test]
    fn daily_not_due_before_trigger_or_after_grace() {
        let a = activity("daily", "09:00", None, true);
        assert_eq!(due_occurrence_key(&a, "22/09/2026", 9 * 60 - 1, "2026-09-22"), None);
        assert_eq!(due_occurrence_key(&a, "22/09/2026", 9 * 60 + 6, "2026-09-22"), None);
    }

    #[test]
    fn once_fires_only_on_its_day() {
        let a = activity("once", "09:00", Some("22/09/2026"), true);
        assert_eq!(due_occurrence_key(&a, "22/09/2026", 9 * 60 + 2, "2026-09-22"), Some("once:22/09/2026".to_string()));
        assert_eq!(due_occurrence_key(&a, "23/09/2026", 9 * 60 + 2, "2026-09-23"), None);
        assert_eq!(due_occurrence_key(&a, "21/09/2026", 9 * 60 + 2, "2026-09-21"), None);
    }

    #[test]
    fn disabled_or_unknown_never_due() {
        assert_eq!(due_occurrence_key(&activity("daily", "09:00", None, false), "22/09/2026", 9 * 60, "2026-09-22"), None);
        assert_eq!(due_occurrence_key(&activity("weekly", "09:00", None, true), "22/09/2026", 9 * 60, "2026-09-22"), None);
    }

    #[test]
    fn subscription_validation_rejects_non_https_and_blank_keys() {
        let mk = |endpoint: &str, p256dh: &str| SubscribeReq {
            endpoint: endpoint.to_string(), p256dh: p256dh.to_string(),
            auth: "EvcWjEgzr4rbvhfi3yds0A".to_string(), user_agent: None,
        };
        assert!(validate_subscription(&mk("https://fcm.googleapis.com/fcm/send/abc", "BGa4N1PI79lboMR_YrwCiCsgp35DRvedt7opHcf0yM3iOBTSoQYqQLwWxAfRKE6tsDnReWmhsImkhDF_DBdkNSU")).is_ok());
        assert!(validate_subscription(&mk("http://evil.example/sub", "BGa4N1PI79lboMR_YrwCiCsgp35DRvedt7opHcf0yM3iOBTSoQYqQLwWxAfRKE6tsDnReWmhsImkhDF_DBdkNSU")).is_err());
        assert!(validate_subscription(&mk("https://fcm.googleapis.com/fcm/send/abc", "  ")).is_err());
        assert!(validate_subscription(&mk("", "BGa4N1PI79lboMR_YrwCiCsgp35DRvedt7opHcf0yM3iOBTSoQYqQLwWxAfRKE6tsDnReWmhsImkhDF_DBdkNSU")).is_err());
    }
}
