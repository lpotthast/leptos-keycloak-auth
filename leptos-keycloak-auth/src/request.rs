use std::{collections::HashMap, time::Duration as StdDuration};

use reqwest::IntoUrl;
use rootcause::{Report, prelude::ResultExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    DiscoveryEndpoint,
    oidc::OidcConfig,
    response::{ErrorResponse, TokenResponse},
    token::TokenData,
};

/// Error contexts of the HTTP requests sent to Keycloak.
///
/// The underlying `reqwest` error, if any, is a child report.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RequestError {
    /// The request could not be sent, or no response was received.
    #[error("Failed to send the request.")]
    Send,

    /// The response body could not be decoded.
    #[error("Failed to decode the response.")]
    Decode,

    /// Keycloak responded with an OAuth error response.
    #[error("Received an error response: {error_response}")]
    ErrResponse {
        /// The error Keycloak responded with.
        error_response: ErrorResponse,
    },
}

pub(crate) async fn retrieve_jwk_set(
    jwk_set_endpoint: impl IntoUrl,
    timeout: StdDuration,
) -> Result<jsonwebtoken::jwk::JwkSet, Report<RequestError>> {
    #[derive(Deserialize)]
    pub struct RawJwkSet {
        pub keys: Vec<serde_json::Value>,
    }
    let raw_set = reqwest::Client::builder()
        .build()
        .expect("reqwest::Client builder should not fail")
        .get(jwk_set_endpoint)
        .timeout(timeout)
        .send()
        .await
        .context(RequestError::Send)?
        .json::<RawJwkSet>()
        .await
        .context(RequestError::Decode)?;
    let mut set = jsonwebtoken::jwk::JwkSet { keys: Vec::new() };
    for key in raw_set.keys {
        match serde_json::from_value::<jsonwebtoken::jwk::Jwk>(key) {
            Ok(parsed) => set.keys.push(parsed),
            Err(err) => tracing::warn!(?err, "Found non-decodable JWK"),
        }
    }
    Ok(set)
}

pub(crate) async fn retrieve_oidc_config(
    discovery_endpoint: impl IntoUrl,
    timeout: StdDuration,
) -> Result<OidcConfig, Report<RequestError>> {
    reqwest::Client::builder()
        .build()
        .expect("reqwest::Client builder should not fail")
        .get(discovery_endpoint)
        .timeout(timeout)
        .send()
        .await
        .context(RequestError::Send)?
        .json::<OidcConfig>()
        .await
        .context(RequestError::Decode)
}

/// The grant type used to request token data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantType {
    #[serde(rename = "authorization_code")]
    AuthorizationCode,

    #[serde(rename = "refresh_token")]
    RefreshToken,
}

impl GrantType {
    fn as_str(self) -> &'static str {
        match self {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::RefreshToken => "refresh_token",
        }
    }
}

/// Exchange a previously received authorization code for a token.
///
/// The fact that this is the initial token response is stored in `TokenDate`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn exchange_code_for_token(
    token_endpoint: impl IntoUrl,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    code_verifier: &str,
    session_state: Option<&str>,
    discovery_endpoint: DiscoveryEndpoint,
    timeout: StdDuration,
) -> Result<TokenData, Report<RequestError>> {
    let mut params: HashMap<&str, &str> = HashMap::new();
    params.insert("grant_type", GrantType::AuthorizationCode.as_str());
    params.insert("client_id", client_id);
    params.insert("redirect_uri", redirect_uri);
    params.insert("code", code);
    params.insert("code_verifier", code_verifier);
    if let Some(state) = session_state {
        params.insert("state", state);
    }
    request_token(
        token_endpoint,
        &params,
        GrantType::AuthorizationCode,
        discovery_endpoint,
        timeout,
    )
    .await
}

/// Perform a token refresh request.
///
/// The fact that this is NOT the initial token response, but a refresh response, is stored in
/// `TokenDate`.
pub(crate) async fn refresh_token(
    token_endpoint: impl IntoUrl,
    client_id: &str,
    refresh_token: &str,
    discovery_endpoint: DiscoveryEndpoint,
    timeout: StdDuration,
) -> Result<TokenData, Report<RequestError>> {
    let params = [
        ("grant_type", GrantType::RefreshToken.as_str()),
        ("client_id", client_id),
        ("refresh_token", refresh_token),
    ];
    request_token(
        token_endpoint,
        &params,
        GrantType::RefreshToken,
        discovery_endpoint,
        timeout,
    )
    .await
}

async fn request_token<T: Serialize + ?Sized>(
    token_endpoint: impl IntoUrl,
    params: &T,
    grant_type: GrantType,
    discovery_endpoint: DiscoveryEndpoint,
    timeout: StdDuration,
) -> Result<TokenData, Report<RequestError>> {
    match reqwest::Client::builder()
        .build()
        .expect("reqwest::Client builder should not fail")
        .post(token_endpoint)
        .form(&params)
        .timeout(timeout)
        .send()
        .await
        .context(RequestError::Send)?
        .json::<TokenResponse>()
        .await
        .context(RequestError::Decode)?
    {
        TokenResponse::Success(success_token_response) => Ok(TokenData::from_token_response(
            success_token_response,
            grant_type,
            discovery_endpoint,
        )),
        TokenResponse::Error(error_response) => {
            Err(Report::new(RequestError::ErrResponse { error_response }))
        }
    }
}
