pub mod cookies;
pub mod crypto;
pub mod flag;
pub mod geo;
pub mod mail;
pub mod ratelimit;

pub fn object_id_from_str(s: &str) -> Result<bson::oid::ObjectId, bson::oid::Error> {
    bson::oid::ObjectId::parse_str(s)
}

/// Logging + generic client message for database failures. Use in `map_err`
/// instead of `e.to_string()`, which leaks driver internals to API clients.
pub fn db_err_json<E: std::fmt::Display>(e: E) -> axum::Json<serde_json::Value> {
    tracing::error!("Database error: {}", e);
    axum::Json(serde_json::json!({"message": "Database error, please try again later"}))
}

/// Logging + generic client message for non-DB internal failures (crypto,
/// TOTP, QR rendering, mail construction). Same leak rationale as above.
pub fn internal_err<E: std::fmt::Display>(
    e: E,
    ctx: &str,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    tracing::error!("{}: {}", ctx, e);
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({"message": "Internal error, please try again later"})),
    )
}
