use crate::{
    oidc::OidcConfig,
    response::{ErrorResponse, TokenResponse},
    token::TokenData,
    DiscoveryEndpoint,
};
use reqwest::IntoUrl;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use std::collections::HashMap;

#[derive(Debug, Snafu)]
pub enum RequestError {
    #[snafu(display("RequestError: Could not send request"))]
    Send { source: reqwest::Error },

    #[snafu(display("RequestError: Could not decode payload"))]
    Decode { source: reqwest::Error },

    #[snafu(display("RequestError: Received an error response"))]
    ErrResponse { error_response: ErrorResponse },
}

pub(crate) async fn retrieve_jwk_set(
    jwk_set_endpoint: impl IntoUrl,
) -> Result<jsonwebtoken::jwk::JwkSet, RequestError> {
    #[derive(Deserialize)]
    pub struct RawJwkSet {
        pub keys: Vec<serde_json::Value>,
    }
    let raw_set = reqwest::Client::new()
        .get(jwk_set_endpoint)
        .send()
        .await
        .context(SendSnafu {})?
        .json::<RawJwkSet>()
        .await
        .context(DecodeSnafu {})?;
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
) -> Result<OidcConfig, RequestError> {
    reqwest::Client::new()
        .get(discovery_endpoint)
        .send()
        .await
        .context(SendSnafu {})?
        .json::<OidcConfig>()
        .await
        .context(DecodeSnafu {})
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
pub(crate) async fn exchange_code_for_token(
    token_endpoint: impl IntoUrl,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    code_verifier: &str,
    session_state: Option<&str>,
    discovery_endpoint: DiscoveryEndpoint,
) -> Result<TokenData, RequestError> {
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
) -> Result<TokenData, RequestError> {
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
    )
    .await
}

async fn request_token<T: Serialize + ?Sized>(
    token_endpoint: impl IntoUrl,
    params: &T,
    grant_type: GrantType,
    discovery_endpoint: DiscoveryEndpoint,
) -> Result<TokenData, RequestError> {
    match reqwest::Client::new()
        .post(token_endpoint)
        .form(&params)
        .send()
        .await
        .context(SendSnafu {})?
        .json::<TokenResponse>()
        .await
        .context(DecodeSnafu {})?
    {
        TokenResponse::Success(success_token_response) => Ok(TokenData::from_token_response(
            success_token_response,
            grant_type,
            discovery_endpoint,
        )),
        TokenResponse::Error(error) => Err(ErrResponseSnafu {
            error_response: error,
        }
        .build()),
    }
}
