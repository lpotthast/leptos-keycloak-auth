use crate::{
    oidc::OidcConfig,
    response::{ErrorResponse, TokenResponse},
    token::TokenData,
};
use reqwest::IntoUrl;
use serde::Deserialize;
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

pub(crate) async fn exchange_code_for_token(
    client_id: impl AsRef<str>,
    redirect_uri: impl AsRef<str>,
    token_endpoint: impl IntoUrl,
    code: impl AsRef<str>,
    session_state: Option<impl AsRef<str>>,
) -> Result<TokenData, RequestError> {
    fn build_params<'a>(
        client_id: &'a str,
        redirect_uri: &'a str,
        code: &'a str,
    ) -> HashMap<&'static str, &'a str> {
        let mut params: HashMap<&str, &str> = HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("client_id", client_id);
        params.insert("redirect_uri", redirect_uri);
        params.insert("code", code);
        params
    }
    async fn inner(
        params: HashMap<&str, &str>,
        token_endpoint: impl IntoUrl,
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
            TokenResponse::Success(success) => Ok(success.into()),
            TokenResponse::Error(error) => Err(ErrResponseSnafu {
                error_response: error,
            }
            .build()),
        }
    }
    let mut params = build_params(client_id.as_ref(), redirect_uri.as_ref(), code.as_ref());
    if let Some(state) = &session_state {
        params.insert("state", state.as_ref());
    }
    inner(params, token_endpoint).await
}

pub(crate) async fn refresh_token(
    client_id: impl AsRef<str>,
    token_endpoint: impl IntoUrl,
    refresh_token: impl AsRef<str>,
) -> Result<TokenData, RequestError> {
    async fn inner(
        client_id: &str,
        token_endpoint: impl IntoUrl,
        refresh_token: &str,
    ) -> Result<TokenData, RequestError> {
        let params = [
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("refresh_token", refresh_token),
        ];
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
            TokenResponse::Success(success) => Ok(success.into()),
            TokenResponse::Error(error) => Err(ErrResponseSnafu {
                error_response: error,
            }
            .build()),
        }
    }
    inner(client_id.as_ref(), token_endpoint, refresh_token.as_ref()).await
}
