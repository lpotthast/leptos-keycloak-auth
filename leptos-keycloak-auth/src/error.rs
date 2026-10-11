use thiserror::Error;
use url::Url;

use crate::response::ErrorResponse;

/// Error contexts of the authentication operations performed in the background.
///
/// Reported through [`NotAuthenticated::last_error`](crate::NotAuthenticated::last_error).
/// Underlying causes, like a [`RequestError`](crate::RequestError), are child reports.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum KeycloakAuthError {
    /// The OIDC configuration could not be retrieved through discovery.
    #[error("Failed to retrieve the OIDC configuration from {discovery_endpoint}.")]
    RetrieveOidcConfig {
        /// The discovery endpoint queried.
        discovery_endpoint: Url,
    },

    /// The JWK set, used to verify ID token signatures, could not be retrieved.
    #[error("Failed to retrieve the JWK set from {jwk_set_endpoint}.")]
    RetrieveJwkSet {
        /// The JWK set endpoint queried.
        jwk_set_endpoint: Url,
    },

    /// The authorization code received after a login could not be exchanged for a token.
    #[error("Failed to exchange the authorization code for a token at {token_endpoint}.")]
    ExchangeCodeForToken {
        /// The token endpoint queried.
        token_endpoint: Url,
    },

    /// The token could not be refreshed.
    #[error("Failed to refresh the token at {token_endpoint}.")]
    RefreshToken {
        /// The token endpoint queried.
        token_endpoint: Url,
    },

    /// Keycloak redirected back to the application with an error instead of an authorization
    /// code, e.g. because the user denied access.
    #[error("Keycloak responded to the authorization request with an error: {error_response}")]
    AuthorizationErrorResponse {
        /// The error Keycloak responded with.
        error_response: ErrorResponse,
    },

    /// The query parameters of a Keycloak callback could not be parsed.
    #[error("Failed to parse the query parameters of a Keycloak callback.")]
    ParseCallbackParams,
}
