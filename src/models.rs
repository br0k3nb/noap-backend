use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// Helper for RFC3339 string for JSON, but BSON DateTime for MongoDB
pub mod rfc3339_option {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};
    use serde::{de::Error as DeError, Deserialize, Deserializer, Serializer};
    use serde_json::Value;

    pub fn serialize<S>(opt: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(dt) => serializer.serialize_str(&dt.to_rfc3339()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<Value>::deserialize(deserializer)?;
        match value {
            Some(Value::String(s)) => {
                let dt = DateTime::parse_from_rfc3339(&s)
                    .map_err(DeError::custom)?
                    .with_timezone(&Utc);
                Ok(Some(dt))
            }
            Some(Value::Object(mut map)) => {
                // Handle Extended JSON {"$date": "..."} or {"$date": {"$numberLong": "..."}}
                if let Some(v) = map.remove("$date") {
                    match v {
                        Value::String(s) => {
                            let dt = DateTime::parse_from_rfc3339(&s)
                                .map_err(DeError::custom)?
                                .with_timezone(&Utc);
                            Ok(Some(dt))
                        }
                        Value::Object(inner) => {
                            if let Some(Value::String(num)) = inner.get("$numberLong") {
                                let millis: i64 = num.parse().map_err(DeError::custom)?;
                                Ok(Some(Utc.timestamp_millis_opt(millis).unwrap()))
                            } else if let Some(Value::Number(n)) = inner.get("$numberLong") {
                                let millis = n
                                    .as_i64()
                                    .ok_or_else(|| DeError::custom("invalid number"))?;
                                Ok(Some(Utc.timestamp_millis_opt(millis).unwrap()))
                            } else {
                                Err(DeError::custom("invalid $date"))
                            }
                        }
                        Value::Number(n) => {
                            let millis = n
                                .as_i64()
                                .ok_or_else(|| DeError::custom("invalid number"))?;
                            Ok(Some(Utc.timestamp_millis_opt(millis).unwrap()))
                        }
                        _ => Err(DeError::custom("invalid $date")),
                    }
                } else {
                    Err(DeError::custom("expected $date"))
                }
            }
            Some(Value::Null) | None => Ok(None),
            _ => {
                // Try direct BSON DateTime deserialization via bson::DateTime
                let s = serde_json::to_string(&value.unwrap()).unwrap();
                Err(DeError::custom(format!("invalid date value: {}", s)))
            }
        }
    }
}

// Helper for Option<DateTime> that handles BSON DateTime and RFC3339 string
pub mod bson_rfc3339_option {
    use super::*;
    use chrono::TimeZone;
    use serde::{de::Error as DeError, Deserialize, Deserializer, Serializer};
    pub fn serialize<S>(opt: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(dt) => serializer.serialize_str(&dt.to_rfc3339()),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        // First try to deserialize directly as bson::DateTime (for BSON)
        // Use a Value intermediate to handle both BSON and JSON
        let value = match bson::Bson::deserialize(deserializer) {
            Ok(bson_val) => {
                match bson_val {
                    bson::Bson::DateTime(bdt) => return Ok(Some(bdt.to_chrono())),
                    bson::Bson::Null => return Ok(None),
                    bson::Bson::String(s) => {
                        if let Ok(dt) = DateTime::parse_from_rfc3339(&s) {
                            return Ok(Some(dt.with_timezone(&Utc)));
                        } else if let Ok(millis) = s.parse::<i64>() {
                            return Ok(Some(Utc.timestamp_millis_opt(millis).unwrap()));
                        } else {
                            return Err(DeError::custom(format!("invalid date string: {}", s)));
                        }
                    }
                    bson::Bson::Int64(n) => {
                        let millis = n;
                        return Ok(Some(Utc.timestamp_millis_opt(millis).unwrap()));
                    }
                    bson::Bson::Int32(n) => {
                        let millis = n as i64;
                        return Ok(Some(Utc.timestamp_millis_opt(millis).unwrap()));
                    }
                    bson::Bson::Document(doc) => {
                        // Handle Extended JSON {"$date": ...} when coming from JSON Value
                        let json_val = serde_json::to_value(&doc).map_err(DeError::custom)?;
                        return deserialize_json_value(json_val).map_err(DeError::custom);
                    }
                    _ => return Err(DeError::custom("invalid date type")),
                }
            }
            Err(e) => return Err(e),
        };
    }

    fn deserialize_json_value(value: serde_json::Value) -> Result<Option<DateTime<Utc>>, String> {
        match value {
            serde_json::Value::Null => Ok(None),
            serde_json::Value::String(s) => {
                if let Ok(dt) = DateTime::parse_from_rfc3339(&s) {
                    Ok(Some(dt.with_timezone(&Utc)))
                } else if let Ok(millis) = s.parse::<i64>() {
                    Ok(Some(Utc.timestamp_millis_opt(millis).unwrap()))
                } else {
                    Err(format!("invalid date string: {}", s))
                }
            }
            serde_json::Value::Object(map) => {
                if let Some(v) = map.get("$date") {
                    match v {
                        serde_json::Value::String(s) => {
                            let dt = DateTime::parse_from_rfc3339(s)
                                .map_err(|e| e.to_string())?
                                .with_timezone(&Utc);
                            Ok(Some(dt))
                        }
                        serde_json::Value::Object(inner) => {
                            if let Some(serde_json::Value::String(num)) = inner.get("$numberLong") {
                                let millis: i64 = num.parse().map_err(|e| format!("{}", e))?;
                                Ok(Some(Utc.timestamp_millis_opt(millis).unwrap()))
                            } else if let Some(serde_json::Value::Number(n)) =
                                inner.get("$numberLong")
                            {
                                let millis = n.as_i64().ok_or("invalid number".to_string())?;
                                Ok(Some(Utc.timestamp_millis_opt(millis).unwrap()))
                            } else {
                                Err("invalid $date".to_string())
                            }
                        }
                        serde_json::Value::Number(n) => {
                            let millis = n.as_i64().ok_or("invalid number".to_string())?;
                            Ok(Some(Utc.timestamp_millis_opt(millis).unwrap()))
                        }
                        _ => Err("invalid $date value".to_string()),
                    }
                } else {
                    Err("expected $date".to_string())
                }
            }
            serde_json::Value::Number(n) => {
                let millis = n.as_i64().ok_or("invalid number".to_string())?;
                Ok(Some(Utc.timestamp_millis_opt(millis).unwrap()))
            }
            _ => Err("invalid date type".to_string()),
        }
    }
}

// Helper to serialize ObjectId as hex string for JSON (frontend) but as ObjectId in BSON
// Handles both BSON ObjectId and hex string / {"$oid": "..."} from Extended JSON
pub mod object_id_hex {
    use super::*;
    use bson::oid::ObjectId;
    use serde::de::IntoDeserializer;
    use serde::{de::Error as DeError, Deserialize, Deserializer, Serializer};
    use serde_json::Value;
    pub fn serialize<S>(oid: &ObjectId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&oid.to_hex())
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<ObjectId, D::Error>
    where
        D: Deserializer<'de>,
    {
        // First try to deserialize directly as ObjectId (handles BSON ObjectId)
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::String(s) => ObjectId::parse_str(&s).map_err(DeError::custom),
            Value::Object(mut map) => {
                if let Some(Value::String(s)) = map.remove("$oid") {
                    ObjectId::parse_str(&s).map_err(DeError::custom)
                } else {
                    // Try to deserialize as ObjectId via bson (for BSON)
                    let de = Value::Object(map).into_deserializer();
                    ObjectId::deserialize(de).map_err(DeError::custom)
                }
            }
            _ => Err(DeError::custom(
                "expected ObjectId as hex string or {$oid: string}",
            )),
        }
    }
    pub mod option {
        use super::*;
        pub fn serialize<S>(opt: &Option<ObjectId>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match opt {
                Some(oid) => serializer.serialize_str(&oid.to_hex()),
                None => serializer.serialize_none(),
            }
        }
        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<ObjectId>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let value = Option::<Value>::deserialize(deserializer)?;
            match value {
                Some(Value::String(s)) => {
                    Ok(Some(ObjectId::parse_str(&s).map_err(DeError::custom)?))
                }
                Some(Value::Object(mut map)) => {
                    if let Some(Value::String(s)) = map.remove("$oid") {
                        Ok(Some(ObjectId::parse_str(&s).map_err(DeError::custom)?))
                    } else {
                        let de = Value::Object(map).into_deserializer();
                        let oid = bson::oid::ObjectId::deserialize(de).map_err(DeError::custom)?;
                        Ok(Some(oid))
                    }
                }
                Some(v) => {
                    // Try direct ObjectId deserialization (for BSON)
                    let de = v.into_deserializer();
                    let oid = bson::oid::ObjectId::deserialize(de).map_err(DeError::custom)?;
                    Ok(Some(oid))
                }
                None => Ok(None),
            }
        }
    }
}

pub mod vec_object_id_hex {
    use super::*;
    use bson::oid::ObjectId;
    use serde::de::IntoDeserializer;
    use serde::{de::Error as DeError, Deserializer, Serializer};
    use serde_json::Value;
    pub fn serialize<S>(vec: &Option<Vec<ObjectId>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match vec {
            Some(v) => {
                let hexes: Vec<String> = v.iter().map(|oid| oid.to_hex()).collect();
                hexes.serialize(serializer)
            }
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<ObjectId>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<Value>::deserialize(deserializer)?;
        match value {
            Some(Value::Array(arr)) => {
                let mut out = Vec::new();
                for v in arr {
                    match v {
                        Value::String(s) => {
                            out.push(ObjectId::parse_str(&s).map_err(DeError::custom)?)
                        }
                        Value::Object(mut map) => {
                            if let Some(Value::String(s)) = map.remove("$oid") {
                                out.push(ObjectId::parse_str(&s).map_err(DeError::custom)?);
                            } else {
                                let de = Value::Object(map).into_deserializer();
                                let oid = bson::oid::ObjectId::deserialize(de)
                                    .map_err(DeError::custom)?;
                                out.push(oid);
                            }
                        }
                        _ => {
                            let de = v.into_deserializer();
                            let oid =
                                bson::oid::ObjectId::deserialize(de).map_err(DeError::custom)?;
                            out.push(oid);
                        }
                    }
                }
                Ok(Some(out))
            }
            Some(Value::Null) | None => Ok(None),
            _ => Err(DeError::custom("expected array of ObjectIds")),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(
        rename = "_id",
        skip_serializing_if = "Option::is_none",
        with = "object_id_hex::option"
    )]
    pub id: Option<ObjectId>,
    pub email: String,
    pub name: String,
    pub password: Option<String>,
    pub verified: Option<bool>,
    pub googleId: Option<String>,
    #[serde(
        rename = "TFAStatus",
        with = "object_id_hex::option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub tfa_status: Option<ObjectId>,
    pub googleAccount: Option<bool>,
    #[serde(
        with = "object_id_hex::option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub lastOpenedNote: Option<ObjectId>,
    pub settings: Option<UserSettings>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct UserSettings {
    pub showPinnedNotesInFolder: Option<bool>,
    pub noteTextExpanded: Option<bool>,
    pub globalNoteBackgroundColor: Option<String>,
    pub onLoginGoToLastOpenedNote: Option<bool>,
    pub noteVisualization: Option<String>,
    pub theme: Option<String>,
    pub language: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Note {
    #[serde(
        rename = "_id",
        skip_serializing_if = "Option::is_none",
        with = "object_id_hex::option"
    )]
    pub id: Option<ObjectId>,
    pub name: Option<String>,
    pub body: Option<String>,
    #[serde(
        with = "vec_object_id_hex",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub labels: Option<Vec<ObjectId>>,
    pub image: Option<String>,
    pub state: Option<bson::Bson>, // Mixed
    // Old notes may predate the settings object entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<NoteSettings>,
    pub author: String,
    pub pageLocation: Option<String>,
    #[serde(
        with = "bson_rfc3339_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub createdAt: Option<DateTime<Utc>>,
    #[serde(
        with = "bson_rfc3339_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub updatedAt: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct NoteSettings {
    pub shared: Option<bool>,
    pub permissions: Option<bson::Bson>,
    pub pinned: Option<bool>,
    pub noteBackgroundColor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NoteState {
    #[serde(
        rename = "_id",
        skip_serializing_if = "Option::is_none",
        with = "object_id_hex::option"
    )]
    pub id: Option<ObjectId>,
    pub state: String,
    #[serde(
        with = "object_id_hex::option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub noteId: Option<ObjectId>,
    #[serde(
        with = "bson_rfc3339_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub createdAt: Option<DateTime<Utc>>,
    #[serde(
        with = "bson_rfc3339_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub updatedAt: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Label {
    #[serde(
        rename = "_id",
        skip_serializing_if = "Option::is_none",
        with = "object_id_hex::option"
    )]
    pub id: Option<ObjectId>,
    pub name: String,
    pub color: String,
    pub fontColor: Option<String>,
    #[serde(rename = "type")]
    pub label_type: String,
    #[serde(with = "object_id_hex")]
    pub userId: ObjectId,
    #[serde(
        with = "bson_rfc3339_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub createdAt: Option<DateTime<Utc>>,
    #[serde(
        with = "bson_rfc3339_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub updatedAt: Option<DateTime<Utc>>,
}

/// A recurring activity ("schedule"): at each trigger occurrence the frontend
/// scheduler fires a browser notification about it.
///
/// `triggerType` is the extension point for future recurrence kinds ("daily"
/// today; weekly, interval, ... later): add the new kind to
/// `handlers/activity.rs::validate_trigger`, give it its own optional config
/// fields on [`ActivityTrigger`] (optional so stored documents never need a
/// migration) and register it in the frontend trigger registry
/// (`noap/src/services/activityNotifications.ts`).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Activity {
    #[serde(
        rename = "_id",
        skip_serializing_if = "Option::is_none",
        with = "object_id_hex::option"
    )]
    pub id: Option<ObjectId>,
    #[serde(with = "object_id_hex")]
    pub userId: ObjectId,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Recurrence kind of `trigger`: "daily" (every day at `time`) or "once"
    /// (one-shot at `trigger.date` + `time`); more kinds later.
    pub triggerType: String,
    pub trigger: ActivityTrigger,
    pub enabled: bool,
    /// Dedupe key of the last occurrence this server pushed to the user's
    /// devices ("YYYY-MM-DD" for daily, "DD/MM/YYYY" for once). The due-check
    /// claims an occurrence atomically (`lastPushKey != key`) before sending,
    /// so overlapping cron invocations can never double-notify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lastPushKey: Option<String>,
    /// Optional note linked to this activity. When set, the note acts as the
    /// activity's recurring todo list: checking items off + "Mark done"
    /// records the current occurrence, and the note resets its checkboxes at
    /// the next occurrence. Stored as the hex string (see the `view` comment
    /// about BOTH id forms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noteId: Option<String>,
    /// "DD/MM/YYYY" (daily) or "DD/MM/YYYY HH:MM" (once) keys of the
    /// occurrences already rolled over, newest last. The note resets its
    /// checkboxes the first time the scheduler sees a newer occurrence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seenOccurrences: Option<Vec<String>>,
    /// "DD/MM/YYYY" keys of the occurrences the user marked done, newest
    /// last. Drives the streak + "answered?" state, never shrinks. One entry
    /// per occurrence per device report (deduped).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doneDates: Option<Vec<String>>,
    /// Last time a client fired a notification for this activity. Bookkeeping
    /// for cross-device visibility and future server-side push.
    #[serde(
        with = "bson_rfc3339_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub lastTriggeredAt: Option<DateTime<Utc>>,
    #[serde(
        with = "bson_rfc3339_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub createdAt: Option<DateTime<Utc>>,
    #[serde(
        with = "bson_rfc3339_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub updatedAt: Option<DateTime<Utc>>,
}

/// Trigger configuration of an [`Activity`]. Each trigger kind only relies on
/// the fields it needs; the remaining fields are reserved for future kinds so
/// existing documents keep deserializing without migrations.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ActivityTrigger {
    /// 24-hour "HH:MM" time of day the notification fires, in the app
    /// timezone (America/Recife).
    pub time: String,
    /// "DD/MM/YYYY" day of the one-shot "once" trigger (ignored by "daily").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// Reserved for a future "weekly" trigger: 0 (Sunday) - 6 (Saturday).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weekdays: Option<Vec<u8>>,
}

/// One device subscribed to server-side Web Push reminders (RFC8030).
/// A user links every device they own (phone, PC, ...) so a due activity
/// notifies all of them even when no Noap tab is open anywhere. The
/// `endpoint` is globally unique per browser/device and acts as the
/// idempotency key: re-subscribing the same device upserts instead of
/// duplicating. Stored in the `push_subscriptions` collection.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PushSubscription {
    #[serde(
        rename = "_id",
        skip_serializing_if = "Option::is_none",
        with = "object_id_hex::option"
    )]
    pub id: Option<ObjectId>,
    #[serde(with = "object_id_hex")]
    pub userId: ObjectId,
    /// Push service URL (FCM / Mozilla autopush / Apple / ...). Unique per
    /// device; a 404/410 from it means the subscription died and the row is
    /// deleted on the next send attempt.
    pub endpoint: String,
    /// Base64url (no pad) client keys from `pushSubscription.toJSON()`.
    pub p256dh: String,
    pub auth: String,
    /// Best-effort device label for the "your devices" list (`navigator.userAgent`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userAgent: Option<String>,
    #[serde(
        with = "bson_rfc3339_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub createdAt: Option<DateTime<Utc>>,
    #[serde(
        with = "bson_rfc3339_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub updatedAt: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Session {
    #[serde(
        rename = "_id",
        skip_serializing_if = "Option::is_none",
        with = "object_id_hex::option"
    )]
    pub id: Option<ObjectId>,
    #[serde(with = "object_id_hex")]
    pub userId: ObjectId,
    pub token: String,
    pub expAt: i64,
    pub ip: String,
    pub browserData: String,
    pub location: String,
    pub countryFlag: String,
    pub deviceData: bson::Bson,
    pub clientData: String,
    #[serde(
        with = "bson_rfc3339_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub createdAt: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Otp {
    #[serde(
        rename = "_id",
        skip_serializing_if = "Option::is_none",
        with = "object_id_hex::option"
    )]
    pub id: Option<ObjectId>,
    pub userId: String, // stored as String in original (userId)
    pub otp: String,
    #[serde(
        with = "bson_rfc3339_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub createdAt: Option<DateTime<Utc>>,
    #[serde(
        with = "bson_rfc3339_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expiresAt: Option<DateTime<Utc>>,
    #[serde(
        with = "bson_rfc3339_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub spam: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Tfa {
    #[serde(
        rename = "_id",
        skip_serializing_if = "Option::is_none",
        with = "object_id_hex::option"
    )]
    pub id: Option<ObjectId>,
    pub qrcode: String,
    #[serde(with = "object_id_hex")]
    pub userId: ObjectId,
    pub secret: String,
    pub options: Option<TfaOptions>,
    pub verified: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TfaOptions {
    pub useToResetPass: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PasskeyCredential {
    #[serde(
        rename = "_id",
        skip_serializing_if = "Option::is_none",
        with = "object_id_hex::option"
    )]
    pub id: Option<ObjectId>,
    #[serde(with = "object_id_hex")]
    pub userId: ObjectId,
    /// base64url credential ID (global lookup key).
    pub cred_id: String,
    /// Serialized webauthn_rs::Passkey (JSON string: immune to BSON quirks
    /// in third-party key material, trivially re-parsed on use).
    pub passkey_json: String,
    pub label: Option<String>,
    #[serde(
        with = "bson_rfc3339_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub createdAt: Option<DateTime<Utc>>,
    #[serde(
        with = "bson_rfc3339_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub lastUsedAt: Option<DateTime<Utc>>,
}

// Helper for pagination response
#[derive(Debug, Serialize, Deserialize)]
pub struct PaginateResponse<T> {
    pub docs: Vec<T>,
    pub totalDocs: i64,
    pub limit: i64,
    pub page: i64,
    pub totalPages: i64,
    pub hasNextPage: bool,
    pub hasPrevPage: bool,
    pub nextPage: Option<i64>,
    pub prevPage: Option<i64>,
}
