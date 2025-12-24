#![allow(clippy::single_match_else)]

//! Protect parts of your Leptos application using Keycloak.
//!
//! ## Example
//!
//! ```
//! use leptos::prelude::*;
//! use leptos_router::{path, components::*};
//! use leptos_keycloak_auth::components::{AuthProvider, MaybeAuthenticated};
//! use leptos_keycloak_auth::url::Url;
//! use leptos_keycloak_auth::{use_authenticated, use_keycloak_auth};
//!
//! #[component]
//! pub fn App() -> impl IntoView {
//!     view! {
//!         <Router>
//!             <AuthProvider
//!                 keycloak_server_url=Url::parse("http://localhost:8443").unwrap()
//!                 realm="test-realm"
//!                 client="test-client"
//!             >
//!                 <Routes fallback=|| view! { "Page not found." }>
//!                     <Route path=path!("/") view=HomePage/>
//!                     <Route path=path!("/protected") view=ProtectedPage/>
//!                 </Routes>
//!             </AuthProvider>
//!         </Router>
//!     }
//! }
//!
//! #[component]
//! pub fn HomePage() -> impl IntoView {
//!     view! {
//!         <h1>"Welcome"</h1>
//!         <MaybeAuthenticated
//!             authenticated=|auth| view! {
//!                 <p>"Hello, " { auth.id_token_claims.read().name.clone() }</p>
//!             }
//!             unauthenticated=|_| view! { "You are not logged in." }
//!         />
//!         <a href="/protected">"Go to Protected Area"</a>
//!     }
//! }
//!
//! #[component]
//! pub fn ProtectedPage() -> impl IntoView {
//!     view! {
//!         <MaybeAuthenticated
//!             authenticated=|auth| view! {
//!                 <h1>"Protected Area"</h1>
//!                 <p>"Welcome, " { auth.id_token_claims.read().name.clone() }</p>
//!                 <SecretContent/>
//!             }
//!             unauthenticated=|_| view! { <LoginButton/> }
//!         />
//!     }
//! }
//!
//! #[component]
//! pub fn SecretContent() -> impl IntoView {
//!     // Safe to call, as our parent ensures this is only rendered when authenticated.
//!     let _auth = use_authenticated();
//!     view! { <div>"This is secret content!"</div> }
//! }
//!
//! #[component]
//! pub fn LoginButton() -> impl IntoView {
//!     let auth = use_keycloak_auth();
//!     let login_url = move || auth.login_url.get().map(|u| u.to_string()).unwrap_or_default();
//!     let login_url_unavailable = move || auth.login_url.get().is_none();
//!     view! {
//!         <a href=login_url aria-disabled=login_url_unavailable>"Log In"</a>
//!     }
//! }
//! ```

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
