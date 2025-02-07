use crate::oidc::OidcConfig;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;

pub(crate) mod code_verifier_manager;
pub(crate) mod derived_urls;
pub(crate) mod jwk_set_manager;
pub(crate) mod oidc_config_manager;
pub(crate) mod token_manager;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OidcConfigWithTimestamp {
    pub oidc_config: OidcConfig,
    #[serde(with = "time::serde::rfc3339")]
    pub retrieved: OffsetDateTime,

    /// The discovery endpoint used to query this information.
    /// This OIDC config data immediately becomes invalid if we no longer work with that source,
    /// e.g. the app was reconfigured to use a different authentication provider!
    /// We see any change in the url, be it host, port, realm, ... as a potentially completely
    /// different provider for which the already known / cached information is no longer applicable.
    pub source: Url,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwkSetWithTimestamp {
    pub jwk_set: jsonwebtoken::jwk::JwkSet,
    #[serde(with = "time::serde::rfc3339")]
    pub retrieved: OffsetDateTime,

    /// The discovery endpoint used to query this information.
    /// This JWK set data immediately becomes invalid if we no longer work with that source,
    /// e.g. the app was reconfigured to use a different authentication provider!
    /// We see any change in the url, be it host, port, realm, ... as a potentially completely
    /// different provider for which the already known / cached information is no longer applicable.
    pub source: Url,
}
