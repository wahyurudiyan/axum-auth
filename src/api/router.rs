use super::controller::auth_controller::{
    claim_local_token, claim_public_token, verify_local_token, verify_public_token,
};
use crate::service::auth_interface::AuthService;
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
                .route("/local/claim", post(claim_local_token))
                .route("/local/verify", post(verify_local_token))
                .route("/public/claim", post(claim_public_token))
                .route("/public/verify", post(verify_public_token))
                .layer(Extension(self.auth_service.clone())),
        )
    }
}
