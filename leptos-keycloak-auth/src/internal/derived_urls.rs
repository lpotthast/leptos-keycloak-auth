use leptos::prelude::{Signal, *};
use snafu::{ResultExt, Snafu};
use url::Url;

use crate::{
    AuthorizationEndpoint, EndSessionEndpoint, JwkSetEndpoint, TokenEndpoint,
    internal::OidcConfigWithTimestamp,
};

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
