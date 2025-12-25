#![doc = include_str!("../README.md")]
#![allow(clippy::single_match_else)]
// Without this annotation, building with the `ssr` feature enabled would result in a multitude
// of "unused" warnings, as the main entrypoint, `init_keycloak_auth`, just returns a stub
// without touching much of this libraries code, leaving most code unused.
// But we are fine with that.
#![cfg_attr(feature = "ssr", allow(unused))]

mod action;
mod authenticated_client;
mod code_verifier;
pub mod components;
mod config;
mod csrf_token;
mod error;
mod hooks;
mod internal;
mod login;
mod logout;
mod nonce;
mod oidc;
mod request;
mod response;
mod state;
mod storage;
mod time_ext;
mod token;
mod token_claims;
mod token_validation;

// Library exports (additional to pub modules).
pub use authenticated_client::*;
pub use config::*;
pub use hooks::*;
pub use leptos_use::storage::StorageType;
pub use state::*;
pub mod url {
    pub use url::Url;
}
pub mod reqwest {
    pub use reqwest::*;
}

#[cfg(feature = "internals")]
pub mod internals {
    pub use crate::code_verifier::CodeChallenge;
    pub use crate::code_verifier::CodeVerifier;
    pub use crate::internal::code_verifier_manager::CodeVerifierManager;
    pub use crate::internal::csrf_token_manager::CsrfTokenManager;
    pub use crate::internal::derived_urls::DerivedUrls;
    pub use crate::internal::jwk_set_manager::JwkSetManager;
    pub use crate::internal::nonce_manager::NonceManager;
    pub use crate::internal::oidc_config_manager::OidcConfigManager;
    pub use crate::internal::token_manager::TokenManager;
    pub use crate::nonce::Nonce;
    pub use crate::token::TokenData;
}

type DiscoveryEndpoint = url::Url;
type JwkSetEndpoint = url::Url;
type AuthorizationEndpoint = url::Url;
type TokenEndpoint = url::Url;
type EndSessionEndpoint = url::Url;

type AuthorizationCode = String;
type SessionState = String;
type AccessToken = String;
type RefreshToken = String;
