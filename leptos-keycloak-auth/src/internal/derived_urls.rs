use leptos::prelude::{Signal, *};
use rootcause::{Report, markers::Cloneable, prelude::ResultExt};
use thiserror::Error;
use url::Url;

use crate::{
    AuthorizationEndpoint, EndSessionEndpoint, JwkSetEndpoint, TokenEndpoint,
    internal::OidcConfigWithTimestamp,
};

/// Error contexts of deriving an endpoint URL from the OIDC configuration.
///
/// The underlying `url` parsing error, if any, is a child report.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DerivedUrlError {
    /// The endpoint URL from the OIDC configuration could not be parsed.
    #[error("Failed to parse the endpoint URL.")]
    Parsing,

    /// No OIDC configuration is known yet.
    #[error("No OIDC configuration is known.")]
    NoConfig,

    /// The OIDC configuration does not specify a token endpoint.
    #[error("The OIDC configuration does not specify a token endpoint.")]
    NoTokenEndpoint,

    /// The OIDC configuration does not specify an end session endpoint.
    #[error("The OIDC configuration does not specify an end session endpoint.")]
    NoEndSessionEndpoint,
}

/// The outcome of deriving an endpoint URL.
pub(crate) type DerivedUrl<U = Url> = Result<U, Report<DerivedUrlError, Cloneable>>;

fn parse(url: &str) -> DerivedUrl {
    Url::parse(url)
        .context(DerivedUrlError::Parsing)
        .map_err(Report::into_cloneable)
}

fn derived_url_error(error: DerivedUrlError) -> DerivedUrl {
    Err(Report::new_sendsync(error).into_cloneable())
}

/// Reactive OIDC endpoint URLs derived from discovery configuration, automatically updating when
/// the OIDC configuration changes, such as after initial discovery or a configuration refresh.
/// These URLs are used throughout the authentication flow for various operations.
///
/// Endpoints include:
/// - **JWK Set Endpoint**: For fetching public keys to verify token signatures
/// - **Authorization Endpoint**: For initiating the authorization code flow
/// - **Token Endpoint**: For exchanging authorization codes and refreshing tokens
/// - **End Session Endpoint**: For logout operations
///
/// # Internal Use
/// This is an internal component exposed via the `internals` feature flag for advanced
/// use cases like testing or debugging.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_field_names)] // Allow all field names to end with `_endpoint`.
pub struct DerivedUrls {
    pub(crate) jwks_endpoint: Signal<DerivedUrl<JwkSetEndpoint>>,
    pub(crate) authorization_endpoint: Signal<DerivedUrl<AuthorizationEndpoint>>,
    pub(crate) token_endpoint: Signal<DerivedUrl<TokenEndpoint>>,
    pub(crate) end_session_endpoint: Signal<DerivedUrl<EndSessionEndpoint>>,
}

impl DerivedUrls {
    pub(crate) fn new(oidc_config: Signal<Option<OidcConfigWithTimestamp>>) -> Self {
        let jwks_endpoint_url: Signal<DerivedUrl> =
            Signal::derive(move || match oidc_config.read().as_ref() {
                Some(oidc_config) => parse(&oidc_config.oidc_config.standard_claims.jwks_uri),
                None => derived_url_error(DerivedUrlError::NoConfig),
            });

        let authorization_endpoint_url: Signal<DerivedUrl> =
            Signal::derive(move || match oidc_config.read().as_ref() {
                Some(oidc_config) => parse(
                    &oidc_config
                        .oidc_config
                        .standard_claims
                        .authorization_endpoint,
                ),
                None => derived_url_error(DerivedUrlError::NoConfig),
            });

        let token_endpoint_url: Signal<DerivedUrl> =
            Signal::derive(move || match oidc_config.read().as_ref() {
                Some(oidc_config) => {
                    match oidc_config
                        .oidc_config
                        .standard_claims
                        .token_endpoint
                        .as_deref()
                    {
                        Some(token_endpoint) => parse(token_endpoint),
                        None => derived_url_error(DerivedUrlError::NoTokenEndpoint),
                    }
                }
                None => derived_url_error(DerivedUrlError::NoConfig),
            });

        let end_session_endpoint_url: Signal<DerivedUrl> =
            Signal::derive(move || match oidc_config.read().as_ref() {
                Some(oidc_config) => {
                    match oidc_config
                        .oidc_config
                        .rp_initialized_claims
                        .end_session_endpoint
                        .as_deref()
                    {
                        Some(end_session_endpoint) => parse(end_session_endpoint),
                        None => derived_url_error(DerivedUrlError::NoEndSessionEndpoint),
                    }
                }
                None => derived_url_error(DerivedUrlError::NoConfig),
            });

        Self {
            jwks_endpoint: jwks_endpoint_url,
            authorization_endpoint: authorization_endpoint_url,
            token_endpoint: token_endpoint_url,
            end_session_endpoint: end_session_endpoint_url,
        }
    }
}
