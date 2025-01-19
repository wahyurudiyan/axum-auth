use crate::{
    models::{
        dto::auth::{
            PasetoClaimRequest, PasetoClaimResponse, PasetoVerifyRequest, PasetoVerifyResponse,
        },
        entities::auth::{PasetoToken, UserData},
    },
    service::auth_interface::AuthService,
};
use axum::{http::StatusCode, response::IntoResponse, Extension, Json};
use std::sync::Arc;

pub async fn claim_local_token(
    Extension(state): Extension<Arc<dyn AuthService>>,
    Json(body): Json<PasetoClaimRequest>,
) -> impl IntoResponse {
    let user_data = UserData { user: body.user };
    let claim_svc = state.claim_local_token(user_data);
    match claim_svc {
        Ok(result) => {
            log::info!("Local token claimed...");
            let response = PasetoClaimResponse::success(result);
            (StatusCode::OK, Json(response))
        }

        Err(e) => {
            log::error!("Error occur - claim local token: {}", e.to_string());
            let response = PasetoClaimResponse::failure("unable to claim token".to_string());
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
        }
    }
}

pub async fn verify_local_token(
    Extension(state): Extension<Arc<dyn AuthService>>,
    Json(body): Json<PasetoVerifyRequest>,
) -> impl IntoResponse {
    let token = PasetoToken {
        token: body.token,
        expired: body.expired,
    };
    let verified = state.verify_local_token(token);
    match verified {
        Ok(data) => {
            log::info!("Local token verified...");
            let response = PasetoVerifyResponse::success(data);
            (StatusCode::OK, Json(response))
        }

        Err(e) => {
            log::error!("Error occur - verify local token: {}", e.to_string());
            let response =
                PasetoVerifyResponse::failure("invalid local token, user unauthorized".to_string());
            (StatusCode::UNAUTHORIZED, Json(response))
        }
    }
}

pub async fn claim_public_token(
    Extension(state): Extension<Arc<dyn AuthService>>,
    Json(body): Json<PasetoClaimRequest>,
) -> impl IntoResponse {
    let user_data = UserData { user: body.user };
    let claim_svc = state.claim_public_token(user_data);
    match claim_svc {
        Ok(result) => {
            log::info!("Public token claimed...");
            let response = PasetoClaimResponse::success(result);
            (StatusCode::OK, Json(response))
        }

        Err(e) => {
            log::error!("Error occur - claim public token: {}", e.to_string());
            let response = PasetoClaimResponse::failure("unable to claim public token".to_string());
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
        }
    }
}

pub async fn verify_public_token(
    Extension(state): Extension<Arc<dyn AuthService>>,
    Json(body): Json<PasetoVerifyRequest>,
) -> impl IntoResponse {
    let token = PasetoToken {
        token: body.token,
        expired: body.expired,
    };
    let verified = state.verify_public_token(token);
    match verified {
        Ok(data) => {
            log::info!("Public token verified...");
            let response = PasetoVerifyResponse::success(data);
            (StatusCode::OK, Json(response))
        }

        Err(e) => {
            log::error!("Error occur - verify public token: {}", e.to_string());
            let response = PasetoVerifyResponse::failure(
                "invalid public token, user unauthorized".to_string(),
            );
            (StatusCode::UNAUTHORIZED, Json(response))
        }
    }
}
