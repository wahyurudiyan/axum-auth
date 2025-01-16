use crate::models::{
    dto::auth::PasetoVerifiedData,
    entities::auth::{PasetoToken, User, UserData},
};
use async_trait::async_trait;
use axum::Error;

#[async_trait]
pub trait AuthService: Send + Sync + 'static {
    fn claim_token(&self, user: UserData) -> Result<PasetoToken, Error>;
    fn verify_token(&self, token: PasetoToken) -> Result<PasetoVerifiedData, Error>;
}
