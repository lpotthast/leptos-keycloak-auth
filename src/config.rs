use leptos::*;
use leptos_use::storage::StorageType;
use snafu::{ResultExt, Snafu};
use url::Url;

use crate::{
    token::LifeLeft, AuthorizationEndpoint, EndSessionEndpoint, JwkSetEndpoint,
    OidcConfigWithTimestamp, TokenEndpoint,
};

/// Represents authentication parameters required for initializing the `Auth`
/// structure. These parameters include authentication and token endpoints,
/// client ID, and other related data.
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

pub struct AdvancedOptions {
    /// This library persists information in order to regain knowledge after cold app startup.
    /// The storage pin the storage provided here.
    ///
    pub storage_type_provider: Callback<(), leptos_use::storage::StorageType>,

    pub access_token_expiration_check_interval_milliseconds: u64,

    pub access_token_nearly_expired_check_interval_milliseconds: u64,
    pub access_token_nearly_expired_having: LifeLeft,

    pub refresh_token_nearly_expired_check_interval_milliseconds: u64,
    pub refresh_token_nearly_expired_having: LifeLeft,

    /// Intervall in milliseconds after which the oidc configuration should be checked for its age.
    /// A
    pub oidc_config_age_check_interval_milliseconds: u64,

    pub jwk_set_age_check_interval_milliseconds: u64,

    /// Time in seconds after which a discovered OIDC config is considered too old.
    pub max_oidc_config_age_seconds: u32,

    /// Time in seconds after which the loaded JWK set is considered too old.
    pub max_jwk_set_age_seconds: u32,
}

impl Default for AdvancedOptions {
    fn default() -> Self {
        Self {
            storage_type_provider: Callback::new(|()| StorageType::Local),
            access_token_expiration_check_interval_milliseconds: 2000,
            access_token_nearly_expired_check_interval_milliseconds: 2000,
            access_token_nearly_expired_having: LifeLeft::Percentage(0.25),
            refresh_token_nearly_expired_check_interval_milliseconds: 2000,
            refresh_token_nearly_expired_having: LifeLeft::Percentage(0.25),
            oidc_config_age_check_interval_milliseconds: 2000,
            jwk_set_age_check_interval_milliseconds: 2000,
            max_oidc_config_age_seconds: 60 * 3,
            max_jwk_set_age_seconds: 60 * 3,
        }
    }
}

#[derive(Debug, Snafu)]
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
    pub(crate) fn new(oidc_config_wt: Signal<Option<OidcConfigWithTimestamp>>) -> Self {
        let jwks_endpoint_url: Signal<Result<Url, DerivedUrlError>> = Signal::derive(move || {
            oidc_config_wt.with(move |oidc_config| match oidc_config {
                Some(oidc_config) => Url::parse(&oidc_config.oidc_config.standard_claims.jwks_uri)
                    .context(ParsingSnafu {}),
                None => Err(NoConfigSnafu {}.build()),
            })
        });

        let authorization_endpoint_url: Signal<Result<Url, DerivedUrlError>> =
            Signal::derive(move || {
                oidc_config_wt.with(move |oidc_config| match oidc_config {
                    Some(oidc_config) => Url::parse(
                        &oidc_config
                            .oidc_config
                            .standard_claims
                            .authorization_endpoint,
                    )
                    .context(ParsingSnafu {}),
                    None => Err(NoTokenEndpointSnafu {}.build()),
                })
            });

        let token_endpoint_url: Signal<Result<Url, DerivedUrlError>> = Signal::derive(move || {
            oidc_config_wt.with(move |oidc_config| match oidc_config {
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
            })
        });

        let end_session_endpoint_url: Signal<Result<Url, DerivedUrlError>> =
            Signal::derive(move || {
                oidc_config_wt.with(move |oidc_config| match oidc_config {
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
                })
            });

        Self {
            jwks_endpoint: jwks_endpoint_url,
            authorization_endpoint: authorization_endpoint_url,
            token_endpoint: token_endpoint_url,
            end_session_endpoint: end_session_endpoint_url,
        }
    }
}
