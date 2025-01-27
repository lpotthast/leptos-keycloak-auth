use crate::token::LifeLeft;
use crate::DiscoveryEndpoint;
use std::time::Duration;
use url::Url;

/// Represents authentication parameters required for initializing the `Auth`
/// structure. These parameters include authentication and token endpoints,
/// client ID, and other related data.
#[derive(Debug)]
pub struct UseKeycloakAuthOptions {
    /// Url of your keycloak instance, E.g. "https://localhost:8443/"
    pub keycloak_server_url: Url,

    /// The keycloak realm you want to use.
    pub realm: String,

    /// The name of this client as configured inside your Keycloak admin area.
    pub client_id: String,

    /// Url to which you want to be redirected after a successful login.
    pub post_login_redirect_url: Url,

    /// Url to which you want to be redirected after a successful logout.
    pub post_logout_redirect_url: Url,

    pub scope: Option<String>,

    pub advanced: AdvancedOptions,
}

impl UseKeycloakAuthOptions {
    pub(crate) fn discovery_endpoint(&self) -> DiscoveryEndpoint {
        let mut url = self.keycloak_server_url.clone();
        url.path_segments_mut()
            .expect("no cannot-be-a-base url")
            .extend(&["realms", &self.realm, ".well-known", "openid-configuration"]);
        url
    }
}

#[derive(Debug)]
pub struct AdvancedOptions {
    /// Interval after which the access token should be checked for its age.
    /// This has to happen frequently in order to detect an access token becoming expired.
    /// Defaults to `Duration::from_millis(500)`.
    pub access_token_age_check_interval: Duration,

    /// Interval after which the refresh token should be checked for its age.
    /// This has to happen frequently in order to detect a refresh token becoming expired.
    /// Defaults to `Duration::from_millis(500)`.
    pub refresh_token_age_check_interval: Duration,

    /// Describes how much time must be left for the access token to not count as "nearly expired".
    /// If any token is nearly expired, a refresh is triggered.
    /// Defaults to `LifeLeft::Percentage(0.25)`.
    pub access_token_nearly_expired_having: LifeLeft,

    /// Describes how much time must be left for the refresh token to not count as "nearly expired".
    /// If any token is nearly expired, a refresh is triggered.
    /// Defaults to `LifeLeft::Percentage(0.25)`.
    pub refresh_token_nearly_expired_having: LifeLeft,

    /// Interval after which the oidc configuration should be checked for its age.
    /// Defaults to `Duration::from_secs(3)`.
    pub oidc_config_age_check_interval: Duration,

    /// Interval after which the jwk set should be checked for its age.
    /// Defaults to `Duration::from_secs(3)`.
    pub jwk_set_age_check_interval: Duration,

    /// Time after which a discovered OIDC config is considered too old.
    /// Defaults to `Duration::from_secs(60 * 5)`.
    pub max_oidc_config_age: Duration,

    /// Time after which the loaded JWK set is considered too old.
    /// After this age is reached, a new set of JWKs is queried for.
    /// If it didn't change, nothing will happen.
    /// Defaults to `Duration::from_secs(60 * 5)`.
    pub max_jwk_set_age: Duration,
}

impl Default for AdvancedOptions {
    fn default() -> Self {
        Self {
            access_token_age_check_interval: Duration::from_millis(500),
            refresh_token_age_check_interval: Duration::from_millis(500),
            access_token_nearly_expired_having: LifeLeft::Percentage(0.25),
            refresh_token_nearly_expired_having: LifeLeft::Percentage(0.25),
            oidc_config_age_check_interval: Duration::from_secs(3),
            jwk_set_age_check_interval: Duration::from_secs(3),
            max_oidc_config_age: Duration::from_secs(60 * 5),
            max_jwk_set_age: Duration::from_secs(60 * 5),
        }
    }
}
