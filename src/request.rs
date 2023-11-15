use crate::{
    oidc_discovery::OidcConfig, response::TokenResponse, token::TokenData, KeycloakAuthError,
};
use reqwest::IntoUrl;
use serde::Deserialize;
use std::{collections::HashMap, rc::Rc};

pub async fn retrieve_jwk_set(
    jwk_set_endpoint: impl IntoUrl,
) -> Result<jsonwebtoken::jwk::JwkSet, KeycloakAuthError> {
    #[derive(Deserialize)]
    pub struct RawJwkSet {
        pub keys: Vec<serde_json::Value>,
    }
    let raw_set = reqwest::Client::new()
        .get(jwk_set_endpoint)
        .send()
        .await
        .map_err(|err| KeycloakAuthError::Request(Rc::new(err)))?
        .json::<RawJwkSet>()
        .await
        .map_err(|err| KeycloakAuthError::Request(Rc::new(err)))?;
    let mut set = jsonwebtoken::jwk::JwkSet { keys: Vec::new() };
    for key in raw_set.keys {
        match serde_json::from_value::<jsonwebtoken::jwk::Jwk>(key) {
            Ok(parsed) => set.keys.push(parsed),
            Err(err) => tracing::warn!(?err, "Found non-decodable JWK"),
        }
    }
    Ok(set)
}

pub async fn retrieve_oidc_config(
    discovery_endpoint: impl IntoUrl,
) -> Result<OidcConfig, KeycloakAuthError> {
    reqwest::Client::new()
        .get(discovery_endpoint)
        .send()
        .await
        .map_err(|err| KeycloakAuthError::Request(Rc::new(err)))?
        .json::<OidcConfig>()
        .await
        .map_err(|err| KeycloakAuthError::Request(Rc::new(err)))
}

pub async fn exchange_code_for_token(
    client_id: impl AsRef<str>,
    redirect_uri: impl AsRef<str>,
    token_endpoint: impl IntoUrl,
    code: impl AsRef<str>,
    session_state: Option<impl AsRef<str>>,
) -> Result<TokenData, KeycloakAuthError> {
    let mut params = HashMap::new();
    params.insert("grant_type", "authorization_code");
    params.insert("client_id", client_id.as_ref());
    params.insert("redirect_uri", redirect_uri.as_ref());
    params.insert("code", code.as_ref());
    if let Some(state) = &session_state {
        params.insert("state", state.as_ref());
    }
    match reqwest::Client::new()
        .post(token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(Rc::new)?
        .json::<TokenResponse>()
        .await
        .map_err(Rc::new)?
    {
        TokenResponse::Success(success) => Ok(success.into()),
        TokenResponse::Error(error) => Err(KeycloakAuthError::Provider(error)),
    }
}

pub async fn refresh_token(
    client_id: impl AsRef<str>,
    token_endpoint: impl IntoUrl,
    refresh_token: impl AsRef<str>,
) -> Result<TokenData, KeycloakAuthError> {
    let params = [
        ("grant_type", "refresh_token"),
        ("client_id", client_id.as_ref()),
        ("refresh_token", refresh_token.as_ref()),
    ];
    match reqwest::Client::new()
        .post(token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(Rc::new)?
        .json::<TokenResponse>()
        .await
        .map_err(Rc::new)?
    {
        TokenResponse::Success(success) => Ok(success.into()),
        TokenResponse::Error(error) => Err(KeycloakAuthError::Provider(error)),
    }
}
