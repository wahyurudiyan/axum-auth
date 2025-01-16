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

pub async fn claim_token(
    Extension(state): Extension<Arc<dyn AuthService>>,
    Json(body): Json<PasetoClaimRequest>,
) -> impl IntoResponse {
    let user_data = UserData { user: body.user };
    let claim_logic = state.claim_token(user_data);
    match claim_logic {
        Ok(result) => {
            let response = PasetoClaimResponse::success(result);
            (StatusCode::OK, Json(response))
        }

        Err(e) => {
            let response = PasetoClaimResponse::failure("unable to claim token".to_string());
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
        }
    }
}

pub async fn verify_token(
    Extension(state): Extension<Arc<dyn AuthService>>,
    Json(body): Json<PasetoVerifyRequest>,
) -> impl IntoResponse {
    let token = PasetoToken {
        token: body.token,
        expired: body.expired,
    };
    let verified = state.verify_token(token);
    match verified {
        Ok(data) => {
            let response = PasetoVerifyResponse::success(data);
            (StatusCode::OK, Json(response))
        }

        Err(e) => {
            let response =
                PasetoVerifyResponse::failure("invalid token, user unauthorized".to_string());
            (StatusCode::UNAUTHORIZED, Json(response))
        }
    }
}
