use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
pub struct PayloadClaim {
    pub user_data: UserData,
    pub nbf: String, // Using chrono for parsing the timestamp
    pub exp: String,
    pub iat: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserData {
    pub user: User,
}

/// Represents the basic user details.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct User {
    pub user_id: u64,
    pub username: String,
    pub role: String,
}

impl User {
    /// Creates a new User instance.
    pub fn new(user_id: u64, username: String, role: String) -> Self {
        Self {
            user_id,
            username,
            role,
        }
    }

    /// Returns a formatted string for the user.
    pub fn user_info(&self) -> String {
        format!(
            "{} (ID: {}) with role: {}",
            self.username, self.user_id, self.role
        )
    }
}

/// Represents a Paseto token with an expiration date.
#[derive(Serialize, Deserialize, Debug)]
pub struct PasetoToken {
    pub token: String,
    pub expired: String,
}

impl PasetoToken {
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
