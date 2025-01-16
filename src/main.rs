use api::router::Routes;
use axum::Router;
use dotenv::dotenv;
use service::{auth_interface::AuthService, paseto_service::PasetoService};
use std::{env, sync::Arc};

mod api;
mod models;
mod service;

#[tokio::main]
async fn main() {
    dotenv().ok();
    let app_port = env::var("APP_PORT").expect("secret cannot empty");
    let secret_key = env::var("PASETO_SECRET").expect("secret cannot empty");
    let hmac_secret = env::var("PASETO_SECRET").expect("secret cannot empty");

    // Init auth service as dependency for controller that passing over layer
    let auth_service: Arc<dyn AuthService> = Arc::new(PasetoService::new(secret_key, hmac_secret));

    // Init REST Service
    let app_host = format!("0.0.0.0:{app_port}");
    let routes = Routes::new(auth_service);
    let app = Router::new().nest("/api", routes.router());
    let listener = tokio::net::TcpListener::bind(app_host).await.unwrap();

    println!("Server running on port: {app_port}");
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
