use crate::models::{
    dto::auth::PasetoVerifiedData,
    entities::auth::{PasetoToken, PayloadClaim, User, UserData},
};
use async_trait::async_trait;
use axum::Error;
use pasetors::{
    claims::{Claims, ClaimsValidationRules},
    keys::SymmetricKey,
    local,
    token::UntrustedToken,
    version4::V4,
    Local,
};

use super::auth_interface::AuthService;

#[derive(Clone)]
pub struct PasetoService {
    pub secret_key: String,
    pub hmac_secret: String,
}

impl PasetoService {
    pub fn new(secret_key: String, hmac_secret: String) -> Self {
        PasetoService {
            secret_key: secret_key,
            hmac_secret: hmac_secret,
        }
    }
}

#[async_trait]
impl AuthService for PasetoService {
    fn claim_token(&self, user: UserData) -> Result<PasetoToken, Error> {
        let now = chrono::Utc::now();
        let expired_at = now + chrono::Duration::hours(12);

        // claim data
        let mut claims = Claims::new().unwrap();
        claims.expiration(&expired_at.to_rfc3339()).unwrap();
        claims
            .add_additional("user_data", serde_json::json!(user))
            .unwrap();

        if self.secret_key.len() != 32 {
            return Err(Error::new("invalid secret key length, must 32 bytes"));
        }

        let symmetric_key = SymmetricKey::<V4>::from(self.secret_key.as_bytes()).unwrap();
        let encrypted = local::encrypt(
            &symmetric_key,
            &claims,
            None,
            Some(self.hmac_secret.as_bytes()),
        );
        match encrypted {
            Ok(token) => {
                let data = PasetoToken {
                    token: token,
                    expired: expired_at.to_rfc3339(),
                };

                return Ok(data);
            }
            Err(err) => {
                return Err(Error::new(format!(
                    "error occur when encrypting token: {}",
                    err.to_string()
                )));
            }
        }
    }

    fn verify_token(&self, body: PasetoToken) -> Result<PasetoVerifiedData, Error> {
        let is_expired = body.is_expired();
        if is_expired {
            return Err(Error::new("expired token cannot claimed"));
        }

        if self.secret_key.len() != 32 {
            return Err(Error::new("invalid secret key length, must 32 bytes"));
        }

        let validation_rules = ClaimsValidationRules::new();
        let untrusted_token = UntrustedToken::<Local, V4>::try_from(&body.token).unwrap();

        let symetric_key = SymmetricKey::<V4>::from(self.secret_key.as_bytes()).unwrap();
        let trusted_token = local::decrypt(
            &symetric_key,
            &untrusted_token,
            &validation_rules,
            None,
            Some(self.hmac_secret.as_bytes()),
        )
        .unwrap();

        let payload = trusted_token.payload_claims().unwrap().to_string().unwrap();
        let p = serde_json::from_str::<PayloadClaim>(&payload).unwrap();
        let verified_data = PasetoVerifiedData::new(p.user_data.user, true);

        Ok(verified_data)
    }
}
