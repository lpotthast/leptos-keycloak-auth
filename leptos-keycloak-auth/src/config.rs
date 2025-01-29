use crate::DiscoveryEndpoint;
use leptos::prelude::RwSignal;
use std::time::Duration as StdDuration;
use url::Url;

#[derive(Debug, Clone, Copy)]
pub enum LifeLeft {
    Percentage(f64),
    Duration(StdDuration),
}

impl LifeLeft {
    // TODO: Use time::Duration everywhere...
    pub fn nearly_expired(self, lifetime: StdDuration, left: StdDuration) -> bool {
        match self {
            LifeLeft::Percentage(p) => (left.as_millis() as f64 / lifetime.as_millis() as f64) <= p,
            LifeLeft::Duration(d) => left <= d,
        }
    }
}

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

#[derive(Debug, Clone)]
pub struct AdvancedOptions {
    /// Interval after which the access token should be checked for its age.
    /// This has to happen frequently in order to detect an access token becoming expired.
    /// Defaults to `Duration::from_millis(500)`.
    pub access_token_age_check_interval: StdDuration,

    /// Interval after which the refresh token should be checked for its age.
    /// This has to happen frequently in order to detect a refresh token becoming expired.
    /// Defaults to `Duration::from_millis(500)`.
    pub refresh_token_age_check_interval: StdDuration,

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
    pub oidc_config_age_check_interval: StdDuration,

    /// Interval after which the jwk set should be checked for its age.
    /// Defaults to `Duration::from_secs(3)`.
    pub jwk_set_age_check_interval: StdDuration,

    /// Time after which a discovered OIDC config is considered too old.
    /// Defaults to `Duration::from_secs(60 * 5)`.
    pub max_oidc_config_age: StdDuration,

    /// Time after which the loaded JWK set is considered too old.
    /// After this age is reached, a new set of JWKs is queried for.
    /// If it didn't change, nothing will happen.
    /// Defaults to `Duration::from_secs(60 * 5)`.
    pub max_jwk_set_age: StdDuration,
}

impl Default for AdvancedOptions {
    fn default() -> Self {
        Self {
            access_token_age_check_interval: StdDuration::from_millis(500),
            refresh_token_age_check_interval: StdDuration::from_millis(500),
            access_token_nearly_expired_having: LifeLeft::Percentage(0.25),
            refresh_token_nearly_expired_having: LifeLeft::Percentage(0.25),
            oidc_config_age_check_interval: StdDuration::from_secs(3),
            jwk_set_age_check_interval: StdDuration::from_secs(3),
            max_oidc_config_age: StdDuration::from_secs(60 * 5),
            max_jwk_set_age: StdDuration::from_secs(60 * 5),
        }
    }
}

/// Represents authentication parameters required for initializing the `Auth`
/// structure. These parameters include authentication and token endpoints,
/// client ID, and other related data.
#[derive(Debug, Clone)]
pub(crate) struct Options {
    /// Url of your keycloak instance, E.g. "https://localhost:8443/"
    pub(crate) keycloak_server_url: Url,

    /// The keycloak realm you want to use.
    pub(crate) realm: String,

    /// The name of this client as configured inside your Keycloak admin area.
    pub(crate) client_id: String,

    /// Url to which you want to be redirected after a successful login.
    pub(crate) post_login_redirect_url: RwSignal<Url>,

    /// Url to which you want to be redirected after a successful logout.
    pub(crate) post_logout_redirect_url: RwSignal<Url>,

    pub(crate) scope: Option<String>,

    pub(crate) advanced: AdvancedOptions,
}

impl Options {
    pub(crate) fn new(options: UseKeycloakAuthOptions) -> Self {
        Self {
            keycloak_server_url: options.keycloak_server_url,
            realm: options.realm,
            client_id: options.client_id,
            post_login_redirect_url: RwSignal::new(options.post_login_redirect_url),
            post_logout_redirect_url: RwSignal::new(options.post_logout_redirect_url),
            scope: options.scope,
            advanced: options.advanced,
        }
    }

    pub(crate) fn discovery_endpoint(&self) -> DiscoveryEndpoint {
        let mut url = self.keycloak_server_url.clone();
        url.path_segments_mut()
            .expect("no cannot-be-a-base url")
            .extend(&["realms", &self.realm, ".well-known", "openid-configuration"]);
        url
    }
}
