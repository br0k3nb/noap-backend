use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwtSub {
    #[serde(rename = "_id")]
    pub _id: String,
    pub name: String,
    pub googleAccount: bool,
}

// Custom Claims that handles both old tokens (sub as object) and new tokens (sub as string + user as object)
// jsonwebtoken crate fails to deserialize sub as object when using `sub` as registered claim string, so we work around
// by using a different claim name for the user object and keeping sub as string.
#[derive(Debug, Serialize, Clone)]
pub struct Claims {
    pub iss: String,
    pub sub: String, // always user ID as string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<JwtSub>,
    pub exp: usize,
}

// Custom Deserialize to handle both old (sub as object) and new (sub as string + user) tokens
impl<'de> Deserialize<'de> for Claims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let obj = value
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("expected object"))?;
        let iss = obj
            .get("iss")
            .and_then(|v| v.as_str())
            .unwrap_or("login-form")
            .to_string();
        let exp = obj.get("exp").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        // Try sub as string first
        let mut sub_id = String::new();
        let mut user_opt: Option<JwtSub> = None;
        if let Some(sub_val) = obj.get("sub") {
            match sub_val {
                Value::String(s) => {
                    sub_id = s.clone();
                    // Try to get user from separate "user" field for new tokens
                    if let Some(user_val) = obj.get("user") {
                        if let Ok(u) = serde_json::from_value::<JwtSub>(user_val.clone()) {
                            user_opt = Some(u);
                            // If sub is string, ensure it matches user._id if user present, otherwise use sub
                            if sub_id.is_empty() {
                                if let Some(u) = &user_opt {
                                    sub_id = u._id.clone();
                                }
                            }
                        }
                    }
                }
                Value::Object(map) => {
                    // Old token: sub is object like {"_id": "...", "name": "...", "googleAccount": false}
                    if let Ok(u) = serde_json::from_value::<JwtSub>(sub_val.clone()) {
                        sub_id = u._id.clone();
                        user_opt = Some(u);
                    } else {
                        return Err(serde::de::Error::custom("invalid sub object"));
                    }
                }
                _ => return Err(serde::de::Error::custom("invalid sub type")),
            }
        }
        // Also handle case where sub is missing but user is present (should not happen)
        if sub_id.is_empty() {
            if let Some(user_val) = obj.get("user") {
                if let Ok(u) = serde_json::from_value::<JwtSub>(user_val.clone()) {
                    sub_id = u._id.clone();
                    user_opt = Some(u);
                }
            }
        }
        if sub_id.is_empty() {
            return Err(serde::de::Error::custom("missing sub"));
        }
        Ok(Claims {
            iss,
            sub: sub_id,
            user: user_opt,
            exp,
        })
    }
}

impl Claims {
    pub fn sub_id(&self) -> &str {
        &self.sub
    }
    pub fn sub_obj(&self) -> Option<&JwtSub> {
        self.user.as_ref()
    }
    // For backward compat, provide JwtSub via sub field when user is None but sub was originally object
    pub fn jwt_sub(&self) -> JwtSub {
        if let Some(u) = &self.user {
            u.clone()
        } else {
            // Fallback: construct minimal JwtSub from sub string (should not happen for old tokens, as user will be Some)
            JwtSub {
                _id: self.sub.clone(),
                name: "".to_string(),
                googleAccount: false,
            }
        }
    }
}

pub fn create_token(sub: JwtSub, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let header = Header::new(Algorithm::HS512);
    let exp = (Utc::now().timestamp() as usize) + 604800; // 7 days
                                                          // Store sub as string (user ID) and user as full object for jsonwebtoken compatibility
                                                          // This makes sub a string per JWT spec, so jsonwebtoken can handle it
    let claims = Claims {
        iss: "login-form".to_string(),
        sub: sub._id.clone(),
        user: Some(sub),
        exp,
    };
    jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

pub fn decode_token(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::HS512);
    validation.validate_exp = false; // we check manually
                                     // Allow sub as string, user as object
    let data = jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?;
    Ok(data.claims)
}

// ---------- Password-reset / 2FA-reset tokens ----------
// Short-lived, single-purpose JWTs issued by verify_otp as proof of email
// ownership. They authorize /change-pass and /2fa/remove when the caller
// has no session (account-recovery flow). Authenticated callers instead use
// their normal session, so a stolen reset token is useless after 15 min.

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ResetClaims {
    iss: String,
    sub: String, // user id
    purpose: String,
    exp: usize,
}

const RESET_ISSUER: &str = "noap-reset";
const RESET_PURPOSE: &str = "password-reset";
/// Reset tokens live 15 minutes.
const RESET_TTL_SECS: i64 = 15 * 60;

pub fn create_reset_token(user_id: &str, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let header = Header::new(Algorithm::HS512);
    let claims = ResetClaims {
        iss: RESET_ISSUER.to_string(),
        sub: user_id.to_string(),
        purpose: RESET_PURPOSE.to_string(),
        exp: (Utc::now().timestamp() + RESET_TTL_SECS) as usize,
    };
    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(secret.as_bytes()))
}

/// Returns the user id if `token` is a valid, unexpired reset token.
pub fn verify_reset_token(token: &str, secret: &str) -> Option<String> {
    let mut validation = Validation::new(Algorithm::HS512);
    validation.set_issuer(&[RESET_ISSUER]);
    let data = jsonwebtoken::decode::<ResetClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .ok()?;
    if data.claims.purpose != RESET_PURPOSE {
        return None;
    }
    Some(data.claims.sub)
}

// ---------- 2FA-pending tokens ----------
// Issued (as an HttpOnly cookie, never in JS) after a correct password when
// the account has 2FA enabled. It proves "password OK, 2FA still pending" and
// is the ONLY credential accepted to mint the real session in /2fa/verify.
// Lifetime is 10 minutes; it can never be used as a session itself.

const TFA_ISSUER: &str = "noap-tfa";
const TFA_PURPOSE: &str = "tfa-pending";
/// 2FA-pending tokens live 10 minutes.
pub const TFA_TTL_SECS: i64 = 10 * 60;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TfaClaims {
    iss: String,
    sub: String, // user id
    purpose: String,
    exp: usize,
}

pub fn create_tfa_token(user_id: &str, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let header = Header::new(Algorithm::HS512);
    let claims = TfaClaims {
        iss: TFA_ISSUER.to_string(),
        sub: user_id.to_string(),
        purpose: TFA_PURPOSE.to_string(),
        exp: (Utc::now().timestamp() + TFA_TTL_SECS) as usize,
    };
    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(secret.as_bytes()))
}

/// Returns the user id if `token` is a valid, unexpired 2FA-pending token.
pub fn verify_tfa_token(token: &str, secret: &str) -> Option<String> {
    let mut validation = Validation::new(Algorithm::HS512);
    validation.set_issuer(&[TFA_ISSUER]);
    let data = jsonwebtoken::decode::<TfaClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .ok()?;
    if data.claims.purpose != TFA_PURPOSE {
        return None;
    }
    Some(data.claims.sub)
}
