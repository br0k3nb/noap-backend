//! Passkey ceremonies use expiring, atomically consumed MongoDB state.

use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bson::{doc, oid::ObjectId};
use chrono::Utc;
use futures::TryStreamExt;
use mongodb::Database;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::ResidentKeyRequirement;

use super::user::{
    cookie_config, enforce_rate_limit, enforce_rate_limit_key, mint_session, set_cookie_headers,
    SessionMeta,
};
use crate::{
    models::{PasskeyCredential, User},
    utils::{
        cookies,
        crypto::{Claims, JwtSub},
        geo::fetch_geo,
    },
    AppState,
};

/// base64url (unpadded) string form of a credential ID — the global lookup key.
fn cred_id_string(id: &CredentialID) -> String {
    serde_json::to_value(id)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}

type ApiResult<T> = Result<T, (StatusCode, Json<Value>)>;

fn bad_request(msg: &str) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({"message": msg})))
}

fn unauthorized() -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"message": "Access denied, sign in again"})),
    )
}

fn internal() -> (StatusCode, Json<Value>) {
    tracing::error!("passkey handler internal failure");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"message": "Internal error, please try again later"})),
    )
}

/// Builds the Webauthn relying-party instance from environment config.
/// Passkeys are bound to (rp_id, origin): localhost values for dev, the
/// deployed frontend host for production. Registrations do NOT transfer
/// between the two — by WebAuthn design, not a bug.
fn webauthn(state: &AppState) -> ApiResult<Webauthn> {
    let origin = Url::parse(&state.webauthn_rp_origin).map_err(|e| {
        tracing::error!("Invalid WEBAUTHN_ORIGIN: {}", e);
        internal()
    })?;
    WebauthnBuilder::new(&state.webauthn_rp_id, &origin)
        .map_err(|e| {
            tracing::error!("Invalid WebAuthn RP config: {:?}", e);
            internal()
        })?
        .rp_name(&state.webauthn_rp_name)
        .build()
        .map_err(|e| {
            tracing::error!("WebAuthn builder failed: {:?}", e);
            internal()
        })
}

/// Deterministic per-user handle: stable across logins without migration.
fn user_uuid(user_id_hex: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_URL, user_id_hex.as_bytes())
}

/// All stored credentials of a user, with parsed passkeys.
/// Unparseable rows are skipped with a warning (never fail the whole set).
async fn load_passkeys(
    db: &Database,
    uid: ObjectId,
) -> ApiResult<Vec<(PasskeyCredential, Passkey)>> {
    let coll = db.collection::<PasskeyCredential>("passkey_credentials");
    let docs: Vec<PasskeyCredential> = coll
        .find(doc! {"userId": uid})
        .await
        .map_err(|e| {
            tracing::error!("DB error loading passkeys: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?
        .try_collect()
        .await
        .map_err(|e| {
            tracing::error!("DB cursor error loading passkeys: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?;
    let mut out = Vec::new();
    for doc in docs {
        match serde_json::from_str::<Passkey>(&doc.passkey_json) {
            Ok(pk) => out.push((doc, pk)),
            Err(e) => tracing::warn!("Skipping unparseable passkey row: {}", e),
        }
    }
    Ok(out)
}

const PK_REG_PURPOSE: &str = "pk-reg";
const PK_AUTH_PURPOSE: &str = "pk-auth";
const CEREMONY_TTL_SECS: i64 = 600;

#[derive(Serialize, Deserialize)]
struct Ceremony {
    #[serde(rename = "_id")]
    token: String,
    purpose: String,
    subject: String,
    state_json: String,
    expires_at: bson::DateTime,
}

/// These indexes are correctness requirements, not optional query optimizations.
pub async fn ensure_indexes(db: &Database) -> mongodb::error::Result<()> {
    use mongodb::{options::IndexOptions, IndexModel};
    db.collection::<PasskeyCredential>("passkey_credentials")
        .create_index(
            IndexModel::builder()
                .keys(doc! {"cred_id": 1})
                .options(IndexOptions::builder().unique(true).build())
                .build(),
        )
        .await?;
    db.collection::<Ceremony>("passkey_ceremonies")
        .create_index(
            IndexModel::builder()
                .keys(doc! {"expires_at": 1})
                .options(
                    IndexOptions::builder()
                        .expire_after(std::time::Duration::ZERO)
                        .build(),
                )
                .build(),
        )
        .await?;
    Ok(())
}

async fn store_ceremony<T: Serialize>(
    db: &Database,
    subject: &str,
    purpose: &str,
    state: &T,
) -> ApiResult<String> {
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let token = URL_SAFE_NO_PAD.encode(random);
    let ceremony = Ceremony {
        token: token.clone(),
        subject: subject.to_owned(),
        purpose: purpose.to_owned(),
        state_json: serde_json::to_string(state).map_err(|_| internal())?,
        expires_at: bson::DateTime::from_chrono(
            Utc::now() + chrono::Duration::seconds(CEREMONY_TTL_SECS),
        ),
    };
    db.collection::<Ceremony>("passkey_ceremonies")
        .insert_one(ceremony)
        .await
        .map_err(|_| internal())?;
    Ok(token)
}

fn ceremony_filter(token: &str, purpose: &str, subject: &str) -> bson::Document {
    doc! {"_id": token, "purpose": purpose, "subject": subject,
    "expires_at": {"$gt": bson::DateTime::now()}}
}

async fn consume_ceremony<T: serde::de::DeserializeOwned>(
    db: &Database,
    token: &str,
    purpose: &str,
    subject: &str,
) -> ApiResult<T> {
    // Expiry is checked here: MongoDB TTL cleanup is asynchronous.
    let ceremony = db
        .collection::<Ceremony>("passkey_ceremonies")
        .find_one_and_delete(ceremony_filter(token, purpose, subject))
        .await
        .map_err(|_| internal())?
        .ok_or_else(|| bad_request("Passkey request expired or already used; please try again"))?;
    serde_json::from_str(&ceremony.state_json).map_err(|_| internal())
}

// ---------- Registration (session required) ----------

pub async fn register_start(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let db = &state.db;
    let uid = ObjectId::parse_str(&claims.sub).map_err(|_| bad_request("Invalid id"))?;
    let user = db
        .collection::<User>("users")
        .find_one(doc! {"_id": uid})
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?
        .ok_or_else(|| bad_request("User not found"))?;

    enforce_rate_limit_key(&state, format!("pk-register:{}", uid), 10, 600).await?;
    let existing = load_passkeys(db, uid).await?;
    let exclude: Vec<CredentialID> = existing
        .iter()
        .map(|(_, pk)| pk.cred_id().clone())
        .collect();

    let wn = webauthn(&state)?;
    let (mut ccr, reg_state) = wn
        .start_passkey_registration(
            user_uuid(&uid.to_hex()),
            &user.email,
            &user.name,
            Some(exclude),
        )
        .map_err(|e| {
            tracing::warn!("passkey registration start failed: {:?}", e);
            bad_request("Could not start passkey registration, please try again")
        })?;

    // A usernameless sign-in needs a credential discoverable by the authenticator.
    if let Some(selection) = ccr.public_key.authenticator_selection.as_mut() {
        selection.resident_key = Some(ResidentKeyRequirement::Required);
        selection.require_resident_key = true;
    }
    let state_token = store_ceremony(db, &uid.to_hex(), PK_REG_PURPOSE, &reg_state).await?;

    Ok((
        StatusCode::OK,
        Json(json!({"options": ccr.public_key, "stateToken": state_token})),
    ))
}

#[derive(Deserialize)]
pub struct RegisterFinishReq {
    pub credential: RegisterPublicKeyCredential,
    #[serde(default)]
    pub stateToken: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

pub async fn register_finish(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<RegisterFinishReq>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let db = &state.db;
    let uid = ObjectId::parse_str(&claims.sub).map_err(|_| bad_request("Invalid id"))?;

    let token = payload.stateToken.as_deref().unwrap_or_default();
    let reg_state: PasskeyRegistration =
        consume_ceremony(db, token, PK_REG_PURPOSE, &claims.sub).await?;

    let wn = webauthn(&state)?;
    let passkey = wn
        .finish_passkey_registration(&payload.credential, &reg_state)
        .map_err(|e| {
            tracing::warn!("passkey registration finish failed: {:?}", e);
            bad_request("Passkey verification failed, please try again")
        })?;

    // Docs requirement: a credential must not be registered to two accounts.
    let cred_id_str = cred_id_string(passkey.cred_id());
    let coll = db.collection::<PasskeyCredential>("passkey_credentials");
    let taken = coll
        .find_one(doc! {"cred_id": &cred_id_str})
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?;
    if taken.is_some() {
        return Err(bad_request(
            "This passkey is already registered to an account",
        ));
    }

    let label: String = payload
        .label
        .unwrap_or_else(|| "Passkey".to_string())
        .trim()
        .chars()
        .take(64)
        .collect();
    let doc = PasskeyCredential {
        id: None,
        userId: uid,
        cred_id: cred_id_str,
        passkey_json: serde_json::to_string(&passkey).map_err(|_| internal())?,
        label: Some(if label.is_empty() {
            "Passkey".to_string()
        } else {
            label
        }),
        createdAt: Some(Utc::now()),
        lastUsedAt: None,
    };
    coll.insert_one(doc).await.map_err(|e| {
        if e.contains_label("DuplicateKey") || e.to_string().contains("E11000") {
            bad_request("This passkey is already registered to an account")
        } else {
            internal()
        }
    })?;

    Ok((
        StatusCode::OK,
        Json(json!({"message": "Passkey registered!"})),
    ))
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let db = &state.db;
    let uid = ObjectId::parse_str(&claims.sub).map_err(|_| bad_request("Invalid id"))?;
    let coll = db.collection::<PasskeyCredential>("passkey_credentials");
    let docs: Vec<PasskeyCredential> = coll
        .find(doc! {"userId": uid})
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?
        .try_collect()
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?;
    // Metadata only: key material never leaves the server.
    let out: Vec<Value> = docs
        .into_iter()
        .map(|d| {
            json!({
                "cred_id": d.cred_id,
                "label": d.label,
                "createdAt": d.createdAt.map(|dt| dt.to_rfc3339()),
                "lastUsedAt": d.lastUsedAt.map(|dt| dt.to_rfc3339()),
            })
        })
        .collect();
    Ok((StatusCode::OK, Json(json!(out))))
}

pub async fn remove(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(cred_id): Path<String>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let db = &state.db;
    let uid = ObjectId::parse_str(&claims.sub).map_err(|_| bad_request("Invalid id"))?;
    // Ownership is inherent in the filter (user + credential must match).
    let res = db
        .collection::<PasskeyCredential>("passkey_credentials")
        .delete_one(doc! {"userId": uid, "cred_id": &cred_id})
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?;
    if res.deleted_count == 0 {
        return Err(bad_request("Passkey not found"));
    }
    Ok((StatusCode::OK, Json(json!({"message": "Passkey removed"}))))
}

// ---------- Authentication (public) ----------

pub async fn auth_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<(StatusCode, Json<Value>)> {
    enforce_rate_limit(&state, &headers, "pk-auth-start", 20, 600).await?;
    let wn = webauthn(&state)?;
    let (rcr, auth_state) = wn
        .start_discoverable_authentication()
        .map_err(|_| internal())?;
    let state_token = store_ceremony(&state.db, "", PK_AUTH_PURPOSE, &auth_state).await?;
    // Return PublicKeyCredentialRequestOptions, without conditional mediation:
    // this endpoint is used by an explicit sign-in button.
    Ok((
        StatusCode::OK,
        Json(json!({"options": rcr.public_key, "stateToken": state_token})),
    ))
}

#[derive(Deserialize)]
pub struct AuthFinishReq {
    pub assertion: PublicKeyCredential,
    #[serde(default)]
    pub stateToken: Option<String>,
    #[serde(default)]
    pub identifier: String,
}

pub async fn auth_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<AuthFinishReq>,
) -> ApiResult<(StatusCode, HeaderMap, Json<Value>)> {
    enforce_rate_limit(&state, &headers, "pk-auth-finish", 10, 600).await?;
    let db = &state.db;

    let token = payload.stateToken.as_deref().unwrap_or_default();
    let auth_state: DiscoverableAuthentication =
        consume_ceremony(db, token, PK_AUTH_PURPOSE, "").await?;
    let wn = webauthn(&state)?;
    let (handle, credential_id) = wn
        .identify_discoverable_authentication(&payload.assertion)
        .map_err(|_| unauthorized())?;
    // The client-provided ID only selects a candidate; verification follows.
    let cred_id_str = URL_SAFE_NO_PAD.encode(credential_id);
    let coll = db.collection::<PasskeyCredential>("passkey_credentials");
    let mut doc = coll
        .find_one(doc! {"cred_id": &cred_id_str})
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?
        .ok_or_else(unauthorized)?;
    if handle != user_uuid(&doc.userId.to_hex()) {
        return Err(unauthorized());
    }
    let mut passkey: Passkey =
        serde_json::from_str(&doc.passkey_json).map_err(|_| unauthorized())?;
    let result = wn
        .finish_discoverable_authentication(
            &payload.assertion,
            auth_state,
            &[DiscoverableKey::from(&passkey)],
        )
        .map_err(|e| {
            tracing::warn!("passkey authentication failed: {:?}", e);
            unauthorized()
        })?;
    if !result.user_verified() {
        return Err(unauthorized());
    }
    let previous_json = doc.passkey_json.clone();
    // Persist counter / backup-state changes (clone detection bookkeeping).
    let changed = passkey.update_credential(&result).unwrap_or(false);
    let now = Utc::now();
    doc.lastUsedAt = Some(now);
    if changed {
        doc.passkey_json = serde_json::to_string(&passkey).map_err(|_| internal())?;
    }
    let updated = coll.update_one(
        doc! {"cred_id": &cred_id_str, "passkey_json": previous_json},
        doc! {"$set": {"passkey_json": &doc.passkey_json, "lastUsedAt": bson::DateTime::from_chrono(now)}},
    )
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"message": "Database error, please try again later"})),
        )
    })?;

    // Reject a removed credential or a concurrent counter update; do not mint a session.
    if updated.matched_count != 1 {
        return Err(unauthorized());
    }
    let uid = doc.userId;
    let user = db
        .collection::<User>("users")
        .find_one(doc! {"_id": uid})
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "Database error, please try again later"})),
            )
        })?
        .ok_or_else(unauthorized)?;

    let cfg = cookie_config(&state);

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
    let sub_jwt = JwtSub {
        _id: uid.to_hex(),
        name: user.name.clone(),
        googleAccount: user.googleAccount.unwrap_or(false),
    };
    let token = mint_session(db, uid, sub_jwt, &meta, &geo, &state.jwt_secret).await?;
    let headers_out = set_cookie_headers(&[
        cookies::session_cookie(&token, cookies::SESSION_MAX_AGE_SECS, &cfg),
        cookies::clear_tfa_cookie(&cfg),
    ]);
    Ok((
        StatusCode::OK,
        headers_out,
        Json(json!({
            "_id": uid.to_hex(),
            "name": user.name,
            "TFAEnabled": false,
            "googleAccount": user.googleAccount.unwrap_or(false),
            "settings": user.settings,
            "lastOpenedNote": user.lastOpenedNote.map(|o| o.to_hex())
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        sign::Signer,
    };
    use serde_cbor_2::Value as Cbor;
    use std::collections::BTreeMap;

    fn relying_party() -> Webauthn {
        WebauthnBuilder::new("localhost", &Url::parse("http://localhost:5173").unwrap())
            .unwrap()
            .build()
            .unwrap()
    }

    #[test]
    fn ceremony_filter_binds_account_purpose_and_expiry() {
        let filter = ceremony_filter("opaque", PK_REG_PURPOSE, "account");
        assert_eq!(filter.get_str("_id").unwrap(), "opaque");
        assert_eq!(filter.get_str("subject").unwrap(), "account");
        assert_eq!(filter.get_str("purpose").unwrap(), PK_REG_PURPOSE);
        assert!(filter
            .get_document("expires_at")
            .unwrap()
            .get_datetime("$gt")
            .is_ok());
    }

    // Exercise actual registration and signed authentication using a software
    // authenticator. No browser, production secrets, or database are required.
    #[test]
    fn discoverable_ceremony_verifies_signature_challenge_origin_and_uv() {
        let wn = relying_party();
        let handle = user_uuid("0123456789abcdef01234567");
        let credential_id = vec![42u8; 32];
        let id = URL_SAFE_NO_PAD.encode(&credential_id);
        let (options, registration) = wn
            .start_passkey_registration(handle, "test@example.com", "Test", None)
            .unwrap();
        let options = serde_json::to_value(options.public_key).unwrap();
        assert!(options["challenge"].is_string());
        assert_eq!(
            options["authenticatorSelection"]["userVerification"],
            "required"
        );
        let ec =
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let point = ec
            .public_key()
            .to_bytes(
                ec.group(),
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )
            .unwrap();
        let cose = Cbor::Map(BTreeMap::from([
            (Cbor::Integer(1), Cbor::Integer(2)),
            (Cbor::Integer(3), Cbor::Integer(-7)),
            (Cbor::Integer(-1), Cbor::Integer(1)),
            (Cbor::Integer(-2), Cbor::Bytes(point[1..33].to_vec())),
            (Cbor::Integer(-3), Cbor::Bytes(point[33..].to_vec())),
        ]));
        let mut auth_data = openssl::sha::sha256(b"localhost").to_vec();
        auth_data.push(0x45); // user present, verified, attested credential data
        auth_data.extend(0u32.to_be_bytes());
        auth_data.extend([0u8; 16]);
        auth_data.extend((credential_id.len() as u16).to_be_bytes());
        auth_data.extend(&credential_id);
        auth_data.extend(serde_cbor_2::to_vec(&cose).unwrap());
        let attestation = Cbor::Map(BTreeMap::from([
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new())),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
        ]));
        let client = json!({"type": "webauthn.create", "challenge": options["challenge"], "origin": "http://localhost:5173", "crossOrigin": false});
        let credential: RegisterPublicKeyCredential = serde_json::from_value(json!({
            "id": id, "rawId": id, "type": "public-key", "extensions": {},
            "response": {"attestationObject": URL_SAFE_NO_PAD.encode(serde_cbor_2::to_vec(&attestation).unwrap()),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(serde_json::to_vec(&client).unwrap())}
        })).unwrap();
        let passkey = wn
            .finish_passkey_registration(&credential, &registration)
            .unwrap();
        let key = PKey::from_ec_key(ec).unwrap();
        let (options, state) = wn.start_discoverable_authentication().unwrap();
        let options = serde_json::to_value(options.public_key).unwrap();
        assert_eq!(options["userVerification"], "required");
        let assertion = |origin: &str, challenge: Value, flags: u8| {
            let client = serde_json::to_vec(&json!({"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": false})).unwrap();
            let mut data = openssl::sha::sha256(b"localhost").to_vec();
            data.push(flags);
            data.extend(1u32.to_be_bytes());
            let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
            signer.update(&data).unwrap();
            signer.update(&openssl::sha::sha256(&client)).unwrap();
            serde_json::from_value::<PublicKeyCredential>(json!({
                "id": id, "rawId": id, "type": "public-key", "extensions": {},
                "response": {"authenticatorData": URL_SAFE_NO_PAD.encode(data),
                    "clientDataJSON": URL_SAFE_NO_PAD.encode(client),
                    "signature": URL_SAFE_NO_PAD.encode(signer.sign_to_vec().unwrap()),
                    "userHandle": URL_SAFE_NO_PAD.encode(handle.as_bytes())}
            }))
            .unwrap()
        };
        let good = assertion("http://localhost:5173", options["challenge"].clone(), 5);
        let (actual_handle, actual_id) = wn.identify_discoverable_authentication(&good).unwrap();
        assert_eq!(actual_handle, handle);
        assert_eq!(actual_id, credential_id);
        let creds = [DiscoverableKey::from(&passkey)];
        assert!(wn
            .finish_discoverable_authentication(&good, state.clone(), &creds)
            .unwrap()
            .user_verified());
        for bad in [
            assertion("https://attacker.example", options["challenge"].clone(), 5),
            assertion(
                "http://localhost:5173",
                json!(URL_SAFE_NO_PAD.encode([7u8; 32])),
                5,
            ),
            assertion("http://localhost:5173", options["challenge"].clone(), 1),
        ] {
            assert!(wn
                .finish_discoverable_authentication(&bad, state.clone(), &creds)
                .is_err());
        }
        let mut tampered = serde_json::to_value(&good).unwrap();
        tampered["response"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0u8; 64]));
        let tampered = serde_json::from_value(tampered).unwrap();
        assert!(wn
            .finish_discoverable_authentication(&tampered, state.clone(), &creds)
            .is_err());
        let result = wn
            .finish_discoverable_authentication(&good, state.clone(), &creds)
            .unwrap();
        let mut updated = passkey.clone();
        assert_eq!(updated.update_credential(&result), Some(true));
        assert!(wn
            .finish_discoverable_authentication(
                &good,
                state.clone(),
                &[DiscoverableKey::from(&updated)]
            )
            .is_err());
        assert!(wn
            .finish_discoverable_authentication(&good, state, &[])
            .is_err());
    }
}
