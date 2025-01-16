use crate::models::entities::auth::{PasetoToken, User};
use serde::{Deserialize, Serialize};

/// Represents a request to create a Paseto claim for a user.
#[derive(Serialize, Deserialize, Debug)]
pub struct PasetoClaimRequest {
    pub user: User, // Reuse the `User` struct for user-related details
}

impl PasetoClaimRequest {
    pub fn new(user: User) -> Self {
        Self { user }
    }
}

/// Represents the response after attempting to create a Paseto claim.
#[derive(Serialize, Deserialize, Debug)]
pub struct PasetoClaimResponse {
    pub message: String,
    pub data: Option<PasetoToken>,
}

impl PasetoClaimResponse {
    pub fn success(token: PasetoToken) -> Self {
        Self {
            message: "Claim successfully created.".to_string(),
            data: Some(token),
        }
    }

    pub fn failure(message: String) -> Self {
        Self {
            message,
            data: None,
        }
    }
}

/// Represents a request to verify a Paseto token.
#[derive(Serialize, Deserialize, Debug)]
pub struct PasetoVerifyRequest {
    pub token: String,
    pub expired: String,
}

impl PasetoVerifyRequest {
    pub fn new(token: String, expired: String) -> Self {
        Self { token, expired }
    }

    /// Validates the token expiration date.
    pub fn is_expired(&self) -> bool {
        // Basic example: you might want to parse and compare the `expired` field here.
        let now = chrono::Utc::now();
        match chrono::DateTime::parse_from_rfc3339(&self.expired) {
            Ok(dt) => {
                let duration = now.signed_duration_since(dt);
                return duration.num_hours() > 1;
            }
            Err(_) => {
                return false;
            }
        }
    }
}

/// Represents the response after verifying a Paseto token.
#[derive(Serialize, Deserialize, Debug)]
pub struct PasetoVerifyResponse {
    pub message: String,
    pub data: Option<PasetoVerifiedData>,
}

impl PasetoVerifyResponse {
    pub fn success(data: PasetoVerifiedData) -> Self {
        Self {
            message: "Token successfully verified.".to_string(),
            data: Some(data),
        }
    }

    pub fn failure(message: String) -> Self {
        Self {
            message,
            data: Some(PasetoVerifiedData::default()), // Return a default instance in case of failure
        }
    }
}

/// Represents the result of verifying the Paseto token data.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct PasetoVerifiedData {
    pub user: User,        // Reuse the `User` struct for consistency
    pub token_valid: bool, // Indicates if the token was successfully verified
}

impl PasetoVerifiedData {
    pub fn new(user: User, token_valid: bool) -> Self {
        Self { user, token_valid }
    }
}
