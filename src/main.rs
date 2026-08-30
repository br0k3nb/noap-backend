#![allow(
    warnings,
    non_snake_case,
    dead_code,
    unused_imports,
    unused_variables,
    unused_mut
)]

mod handlers;
mod middleware;
mod models;
mod utils;

use axum::{
    http::Method,
    routing::{delete, get, patch, post},
    Router,
};
use mongodb::{Client, Database};
use std::{env, net::SocketAddr, sync::Arc};
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use handlers::{label, note, session, user};

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub jwt_secret: String,
    pub mail_host: String,
    pub mail_port: u16,
    pub mail_user: String,
    pub mail_pass: String,
    pub mail_from: String,
    pub ipgeo_key: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let mongodb_url = env::var("MONGODB_URL").expect("MONGODB_URL must be set");
    let jwt_secret = env::var("SECRET").unwrap_or_else(|_| "secret".to_string());
    let mail_host = env::var("MAIL_HOSTNAME").unwrap_or_default();
    let mail_port: u16 = env::var("MAIL_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(587);
    let mail_user = env::var("MAIL_USERNAME").unwrap_or_default();
    let mail_pass = env::var("MAIL_PASSWORD").unwrap_or_default();
    let mail_from = env::var("HOST_MAIL").unwrap_or_else(|_| mail_user.clone());
    let ipgeo_key = env::var("IPGEOLOCATION_KEY").unwrap_or_default();

    let client = Client::with_uri_str(&mongodb_url).await?;
    // Use default db from URL or fallback to "noap"
    let db = client
        .default_database()
        .unwrap_or_else(|| client.database("noap"));
    tracing::info!("Connected to MongoDB");

    let state = Arc::new(AppState {
        db,
        jwt_secret,
        mail_host,
        mail_port,
        mail_user,
        mail_pass,
        mail_from,
        ipgeo_key,
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(Any)
        .allow_private_network(true);

    // Public routes
    let public_routes = Router::new()
        .route("/sign-up", post(user::sign_up))
        .route("/sign-in", post(user::sign_in))
        .route("/sign-in/google", post(user::google_login))
        .route("/verify-otp", post(user::verify_otp))
        .route("/2fa/remove", post(user::remove_2fa))
        .route("/2fa/verify", post(user::verify_2fa_code))
        .route("/find-user", post(user::find_and_send_code))
        .route("/change-pass", patch(user::change_password))
        .route("/convert/account/email", patch(user::convert_into_normal))
        .route("/convert/account/google", patch(user::convert_into_google));

    // Protected routes (require auth middleware)
    let protected_routes = Router::new()
        .route("/sign-out", post(user::sign_out))
        .route("/verify-user", post(user::verify_user))
        .route("/2fa/qrcode", post(user::generate_2fa_qrcode))
        .route("/verify-token", post(user::verify_token))
        .route("/lastOpenedNote/:id", patch(user::last_opened_note))
        .route("/settings/change-theme/:id", patch(user::change_theme))
        .route("/settings/note-text/:id", post(user::note_text_expanded))
        .route(
            "/settings/pin-notes-folder/:id",
            post(user::show_pinned_in_folder),
        )
        .route(
            "/settings/note-visualization/:id",
            patch(user::change_visualization),
        )
        .route(
            "/settings/onLoginGoToLastOpenedNote/:id",
            patch(user::on_login_go_to_last),
        )
        .route(
            "/settings/global-note-background-color/:id",
            patch(user::change_global_bg),
        )
        .route("/get/sessions/:userId", get(session::view))
        .route(
            "/delete/session/:userId/:sessionId",
            delete(session::delete_one),
        )
        .route("/delete/all/sessions/:userId", delete(session::delete_all))
        .route("/add", post(note::add))
        .route("/edit", patch(note::edit))
        .route("/note/:id", get(note::get_note))
        .route("/delete/:id", delete(note::delete))
        .route("/notes/:page/:author", get(note::view))
        .route("/note/add/label", post(note::add_label))
        .route("/note/rename/:id", post(note::rename))
        .route("/note/pin-note/:noteId", post(note::pin_note))
        .route("/note/image/:noteId", post(note::change_image))
        .route("/note/delete/label/:id/:noteId", delete(note::delete_label))
        .route(
            "/note/delete-all/label/:noteId",
            delete(note::delete_all_labels),
        )
        .route(
            "/settings/note-background-color/:noteId",
            patch(note::change_bg),
        )
        .route("/labels/:userId", get(label::view))
        .route("/label/add/:userId", post(label::add))
        .route("/label/edit/:userId", patch(label::edit))
        .route("/label/delete/:id", delete(label::delete))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth::verify_user,
        ));

    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(cors)
        .with_state(state);

    // Health check
    let app = app.route("/", get(|| async { "Noap Rust API running" }));

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3002);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
