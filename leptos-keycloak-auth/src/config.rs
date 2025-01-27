use crate::{
    internal::OidcConfigWithTimestamp, token::LifeLeft, AuthorizationEndpoint, EndSessionEndpoint,
    JwkSetEndpoint, TokenEndpoint,
};
use leptos::prelude::*;
use snafu::{ResultExt, Snafu};
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

#[derive(Debug, Clone, Snafu)]
pub enum DerivedUrlError {
    #[snafu(display("DerivedUrlError: Could not parse"))]
    Parsing { source: url::ParseError },

    #[snafu(display("DerivedUrlError: No config data to read from"))]
    NoConfig,

    #[snafu(display("DerivedUrlError: oidc_config.standard_claims.token_endpoint is None"))]
    NoTokenEndpoint,

    #[snafu(display(
        "DerivedUrlError: oidc_config.rp_initialized_claims.end_session_endpoint is None"
    ))]
    NoEndSessionEndpoint,
}

pub(crate) struct DerivedUrls {
    pub(crate) jwks_endpoint: Signal<Result<JwkSetEndpoint, DerivedUrlError>>,
    pub(crate) authorization_endpoint: Signal<Result<AuthorizationEndpoint, DerivedUrlError>>,
    pub(crate) token_endpoint: Signal<Result<TokenEndpoint, DerivedUrlError>>,
    pub(crate) end_session_endpoint: Signal<Result<EndSessionEndpoint, DerivedUrlError>>,
}

impl DerivedUrls {
    pub(crate) fn new(oidc_config: Signal<Option<OidcConfigWithTimestamp>>) -> Self {
        let jwks_endpoint_url: Signal<Result<Url, DerivedUrlError>> =
            Signal::derive(move || match oidc_config.read().as_ref() {
                Some(oidc_config) => Url::parse(&oidc_config.oidc_config.standard_claims.jwks_uri)
                    .context(ParsingSnafu {}),
                None => Err(NoConfigSnafu {}.build()),
            });

        let authorization_endpoint_url: Signal<Result<Url, DerivedUrlError>> =
            Signal::derive(move || match oidc_config.read().as_ref() {
                Some(oidc_config) => Url::parse(
                    &oidc_config
                        .oidc_config
                        .standard_claims
                        .authorization_endpoint,
                )
                .context(ParsingSnafu {}),
                None => Err(NoTokenEndpointSnafu {}.build()),
            });

        let token_endpoint_url: Signal<Result<Url, DerivedUrlError>> =
            Signal::derive(move || match oidc_config.read().as_ref() {
                Some(oidc_config) => {
                    match oidc_config
                        .oidc_config
                        .standard_claims
                        .token_endpoint
                        .as_deref()
                    {
                        Some(token_endpoint) => Url::parse(token_endpoint).context(ParsingSnafu {}),
                        None => Err(NoConfigSnafu {}.build()),
                    }
                }
                None => Err(NoConfigSnafu {}.build()),
            });

        let end_session_endpoint_url: Signal<Result<Url, DerivedUrlError>> =
            Signal::derive(move || match oidc_config.read().as_ref() {
                Some(oidc_config) => {
                    match oidc_config
                        .oidc_config
                        .rp_initialized_claims
                        .end_session_endpoint
                        .as_deref()
                    {
                        Some(end_session_endpoint) => {
                            Url::parse(end_session_endpoint).context(ParsingSnafu {})
                        }
                        None => Err(NoEndSessionEndpointSnafu {}.build()),
                    }
                }
                None => Err(NoConfigSnafu {}.build()),
            });

        Self {
            jwks_endpoint: jwks_endpoint_url,
            authorization_endpoint: authorization_endpoint_url,
            token_endpoint: token_endpoint_url,
            end_session_endpoint: end_session_endpoint_url,
        }
    }
}
