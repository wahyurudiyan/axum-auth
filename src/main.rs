use api::router::Routes;
use axum::Router;
use dotenv::dotenv;
use log::info;
use service::{auth_interface::AuthService, paseto_service::PasetoService};
use std::{env, fs, sync::Arc};

mod api;
mod models;
mod service;

#[tokio::main]
async fn main() {
    // Init some dependencies
    dotenv().ok();
    env_logger::init();

    let mut app_port = env::var("APP_PORT").unwrap();
    app_port = if app_port == "" {
        "3000".to_string()
    } else {
        app_port
    };

    // Just for example, not recommend for production
    let cert_path = env::var("CERTIFICATE_PATH").expect("Certificate path cannot empty");
    let pem = fs::read_to_string(cert_path).expect("Unable to read ed25519_key.pem");
    let local_secret = env::var("PASETO_LOCAL_SECRET").expect("Envar: local secret cannot empty");
    let hmac_secret = env::var("PASETO_HMAC_SECRET").expect("Envar: hmac secret cannot empty");

    // Init auth service as dependency for controller that passing over layer
    let paseto_service = PasetoService::new(pem, local_secret, hmac_secret);

    // Init REST Service
    let app_host = format!("0.0.0.0:{app_port}");
    let routes = Routes::new(paseto_service);
    let app = Router::new().nest("/api", routes.router());
    let listener = tokio::net::TcpListener::bind(app_host.clone())
        .await
        .unwrap();

    log::info!("🚀 Server running at host: {app_host}");
    if let Err(e) = axum::serve(listener, app.into_make_service()).await {
        panic!("Unable to run server, error occur: {}", e);
    }
}
