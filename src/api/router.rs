use super::controller::auth_controller::{
    claim_local_token, claim_public_token, verify_local_token, verify_public_token,
};
use crate::service::auth_interface::AuthService;
use axum::{routing::post, Extension, Router};

pub struct Routes<T: AuthService + Clone> {
    auth_service: T,
}

impl <T: AuthService + Clone> Routes<T> {
    pub fn new(paseto_service: T) -> Self {
        Routes {
            auth_service: paseto_service,
        }
    }

    pub fn router(&self) -> Router {
        Router::new().nest(
            "/auth/token",
            Router::new()
                .route("/local/claim", post(claim_local_token::<T>))
                .route("/local/verify", post(verify_local_token::<T>))
                .route("/public/claim", post(claim_public_token::<T>))
                .route("/public/verify", post(verify_public_token::<T>))
                .layer(Extension(self.auth_service.clone())),
        )
    }
}
