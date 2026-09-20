//! HttpOnly cookie helpers for session authentication.
//!
//! The session JWT is stored in an HttpOnly cookie (`noap_session`) so that
//! page JavaScript — and therefore injected XSS payloads — can never read it.
//! Because the cookie is sent cross-site (`SameSite=None; Secure` in
//! production), all cookie-authenticated state-changing requests additionally
//! pass an Origin/Referer allowlist check (see middleware::auth).

use std::collections::HashMap;

pub const SESSION_COOKIE: &str = "noap_session";
/// Short-lived cookie proving "password OK, 2FA still pending".
pub const TFA_COOKIE: &str = "noap_tfa";

/// 7 days, matching the session JWT lifetime.
pub const SESSION_MAX_AGE_SECS: i64 = 604800;
/// 10 minutes to complete the 2FA step.
pub const TFA_MAX_AGE_SECS: i64 = 10 * 60;

#[derive(Debug, Clone)]
pub struct CookieConfig {
    pub secure: bool,
    pub same_site: String,
}

impl CookieConfig {
    /// Browsers reject `SameSite=None` without `Secure`; downgrade
    /// defensively so local http dev keeps working instead of silently
    /// dropping the cookie.
    pub fn normalized(&self) -> (bool, String) {
        if !self.secure && self.same_site.eq_ignore_ascii_case("none") {
            (false, "Lax".to_string())
        } else {
            (self.secure, self.same_site.clone())
        }
    }
}

/// Parses a `Cookie` request header into name → value pairs.
pub fn parse_cookies(header_value: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for part in header_value.split(';') {
        let mut kv = part.splitn(2, '=');
        if let (Some(name), Some(value)) = (kv.next(), kv.next()) {
            let name = name.trim();
            if !name.is_empty() {
                out.insert(name.to_string(), value.trim().to_string());
            }
        }
    }
    out
}

/// Reads one cookie value from a `Cookie` header, if present and non-empty.
pub fn get_cookie(header_value: &str, name: &str) -> Option<String> {
    let value = parse_cookies(header_value).remove(name)?;
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn build_cookie(name: &str, value: &str, max_age_secs: i64, cfg: &CookieConfig) -> String {
    let (secure, same_site) = cfg.normalized();
    format!(
        "{name}={value}; Path=/; HttpOnly; Max-Age={max_age_secs}; SameSite={same_site}{secure}",
        secure = if secure { "; Secure" } else { "" },
    )
}

pub fn session_cookie(token: &str, max_age_secs: i64, cfg: &CookieConfig) -> String {
    build_cookie(SESSION_COOKIE, token, max_age_secs, cfg)
}

pub fn tfa_cookie(token: &str, cfg: &CookieConfig) -> String {
    build_cookie(TFA_COOKIE, token, TFA_MAX_AGE_SECS, cfg)
}

pub fn clear_session_cookie(cfg: &CookieConfig) -> String {
    build_cookie(SESSION_COOKIE, "", 0, cfg)
}

pub fn clear_tfa_cookie(cfg: &CookieConfig) -> String {
    build_cookie(TFA_COOKIE, "", 0, cfg)
}
