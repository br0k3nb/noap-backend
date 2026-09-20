//! Minimal in-memory sliding-window rate limiter (no extra dependencies).
//!
//! Keyed per client IP (+ endpoint, by using separate limits per call site).
//! This raises the cost of credential stuffing and OTP/TOTP guessing to the
//! point of uselessness on a single instance. Note: counters are per
//! process, so on multi-instance deployments each instance enforces its own
//! budget — still a strict improvement over no limiting at all.

use axum::http::HeaderMap;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

pub struct RateLimiter {
    inner: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Records one attempt for `key`. Returns `Ok(())` when under budget,
    /// or `Err(retry_after_secs)` when the window is exhausted.
    pub async fn check(&self, key: String, max_attempts: u32, window: Duration) -> Result<(), u64> {
        let mut map = self.inner.lock().await;
        let now = Instant::now();

        // Opportunistic cleanup so the map can't grow without bound.
        if map.len() > 50_000 {
            map.retain(|_, hits| hits.iter().any(|t| now.duration_since(*t) < window));
            if map.len() > 50_000 {
                map.clear();
            }
        }

        let hits = map.entry(key).or_default();
        hits.retain(|t| now.duration_since(*t) < window);
        if hits.len() >= max_attempts as usize {
            let oldest = hits.first().copied().unwrap_or(now);
            let retry = window
                .checked_sub(now.duration_since(oldest))
                .map(|d| d.as_secs().max(1))
                .unwrap_or(1);
            return Err(retry);
        }
        hits.push(now);
        Ok(())
    }
}

/// Best-effort client identity for rate limiting: first `X-Forwarded-For`
/// entry (set by the hosting proxy), else `X-Real-Ip`, else "unknown".
/// Values are sanitized to plain printable tokens.
pub fn client_key(headers: &HeaderMap, scope: &str) -> String {
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("unknown");
    let clean: String = ip.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == ':' || *c == '_' || *c == '-').take(64).collect();
    format!("{scope}:{}", if clean.is_empty() { "unknown" } else { &clean })
}
