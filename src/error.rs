use std::rc::Rc;

use thiserror::Error;

use crate::response::ErrorResponse;

/// An enumeration representing various authentication-related errors.
#[derive(Debug, Clone, Error)]
pub enum KeycloakAuthError {
    #[error("Provider error {0:?}")]
    Provider(ErrorResponse),

    #[error("Request error: {0}")]
    Request(#[from] Rc<reqwest::Error>),

    #[error("Could not handle parameters: {0}")]
    Params(#[from] leptos_router::ParamsError),

    #[error("Could not serialize or deserialize data: {0}")]
    Serde(#[from] Rc<serde_json::Error>),
}

#[derive(Debug, Clone, Error)]
pub enum UrlError {
    #[error("Dependencies are missing: {0}")]
    DependenciesMissing(&'static str),

    #[error("parse error: {0}")]
    Parsing(#[from] url::ParseError),
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum JwtValidationError {
    #[error("Could not decode JWT header. Input may have the wrong format: {0}")]
    DecodeHeader(jsonwebtoken::errors::Error),

    #[error("Could not find a JWK which would match the tokens 'kid': {0:?}")]
    NoMatchingJwk(Option<String>),

    #[error("Could not construct DecodingKey from JWK: {0}")]
    JwkToDecodingKey(jsonwebtoken::errors::Error),

    #[error("Could not decode JWT: {0}")]
    Decode(jsonwebtoken::errors::Error),
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum NoIdToken {
    #[error("Could not validate and decode JWT token: {0}")]
    JwtValidationError(JwtValidationError),

    #[error("Dependencies are missing: {0}")]
    DependenciesMissing(String),
}
