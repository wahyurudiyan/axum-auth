use crate::models::{
    dto::auth::PasetoVerifiedData,
    entities::auth::{PasetoToken, UserData},
};
use async_trait::async_trait;
use axum::Error;

#[async_trait]
pub trait AuthService: Send + Sync + 'static {
    fn claim_local_token(&self, user: UserData) -> Result<PasetoToken, Error>;
    fn verify_local_token(&self, token: PasetoToken) -> Result<PasetoVerifiedData, Error>;
    fn claim_public_token(&self, user: UserData) -> Result<PasetoToken, Error>;
    fn verify_public_token(&self, body: PasetoToken) -> Result<PasetoVerifiedData, Error>;
}
