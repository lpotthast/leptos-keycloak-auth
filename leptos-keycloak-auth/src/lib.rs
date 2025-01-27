mod action;
mod code_verifier;
pub mod components;
mod config;
mod error;
mod hooks;
mod internal;
mod login;
mod logout;
mod oidc;
mod request;
mod response;
mod state;
mod time_ext;
mod token;
mod token_validation;

type DiscoveryEndpoint = Url;
type JwkSetEndpoint = Url;
type AuthorizationEndpoint = Url;
type TokenEndpoint = Url;
type EndSessionEndpoint = Url;

type AuthorizationCode = String;
type SessionState = String;
type AccessToken = String;
type RefreshToken = String;

// Library exports (additional to pub modules).
pub use config::*;
pub use hooks::*;
pub use leptos_use::storage::StorageType;
pub use state::*;
pub use token::*;
pub use url::Url;

#[cfg(feature = "internals")]
pub use code_verifier::CodeChallenge;
#[cfg(feature = "internals")]
pub use code_verifier::CodeVerifier;
// Additional (feature-gated) library exports.
#[cfg(feature = "internals")]
pub use internal::code_verifier_manager::CodeVerifierManager;
#[cfg(feature = "internals")]
pub use internal::jwk_set_manager::JwkSetManager;
#[cfg(feature = "internals")]
pub use internal::oidc_config_manager::OidcConfigManager;
#[cfg(feature = "internals")]
pub use internal::token_manager::TokenManager;
