use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use crate::oidc::OidcConfig;

pub(crate) mod code_verifier_manager;
pub(crate) mod jwk_set_manager;
pub(crate) mod oidc_config_manager;
pub(crate) mod token_manager;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OidcConfigWithTimestamp {
    pub oidc_config: OidcConfig,
    #[serde(with = "time::serde::rfc3339")]
    pub retrieved: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwkSetWithTimestamp {
    pub jwk_set: jsonwebtoken::jwk::JwkSet,
    #[serde(with = "time::serde::rfc3339")]
    pub retrieved: OffsetDateTime,
}
