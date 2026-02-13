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
    pub use crate::{
        code_verifier::{CodeChallenge, CodeVerifier},
        internal::{
            code_verifier_manager::CodeVerifierManager, csrf_token_manager::CsrfTokenManager,
            derived_urls::DerivedUrls, jwk_set_manager::JwkSetManager, nonce_manager::NonceManager,
            oidc_config_manager::OidcConfigManager, token_manager::TokenManager,
        },
        nonce::Nonce,
        token::TokenData,
    };
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
