use tower::ServiceBuilder;
use vercel_runtime::{axum::VercelLayer, Error};

#[tokio::main]
async fn main() -> Result<(), Error> {
    noap_server::init_tracing();
    let router = noap_server::build_app().await?;
    let app = ServiceBuilder::new()
        .layer(VercelLayer::new())
        .service(router);

    vercel_runtime::run(app).await
}
