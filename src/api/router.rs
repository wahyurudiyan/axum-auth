use super::controller::auth_controller::{claim_token, verify_token};
use crate::service::{auth_interface::AuthService, paseto_service::PasetoService};
use axum::{routing::post, Extension, Router};
use std::sync::Arc;

pub struct Routes {
    auth_service: Arc<dyn AuthService>,
}

impl Routes {
    pub fn new(auth_service: Arc<dyn AuthService>) -> Self {
        Routes {
            auth_service: auth_service,
        }
    }

    pub fn router(&self) -> Router {
        Router::new().nest(
            "/auth/token",
            Router::new()
                .route("/claim", post(claim_token))
                .route("/verify", post(verify_token))
                .layer(Extension(self.auth_service.clone())),
        )
    }
}
