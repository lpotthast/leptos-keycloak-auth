//!
//! ```
//! use leptos::prelude::*;
//! use leptos_router::{path, components::{Route, Router, Routes}};
//! use leptos_keycloak_auth::{components::ShowWhenAuthenticated, url::Url, use_keycloak_auth, Authenticated, UseKeycloakAuthOptions, ValidationOptions};
//!
//! #[component]
//! pub fn App() -> impl IntoView {
//!     // Meta tags excluded...
//!     view! {
//!         <main>
//!             <Router>
//!                 <Routes fallback=|| view! { "Page not found." }>
//!                     <Route path=path!("/") view=|| view! {
//!                         <Protected>
//!                             <ConfidentialArea/>
//!                         </Protected>
//!                     }/>
//!                 </Routes>
//!             </Router>
//!         </main>
//!     }
//! }
//!
//! #[component]
//! pub fn Protected(children: ChildrenFn) -> impl IntoView {
//!     // Note: These values should be served from environment variables to be overwritten in production.
//!     // Note: Redirect URLs should match the route path at which you render this component.
//!     //       If this component is rendered at `/admin`, the redirects should also go to that route,
//!     //       or we end up in a place where `use_keycloak_auth` is not rendered/active
//!     //       and any login attempt can never be completed.
//!     let keycloak_server_url = "http://localhost:8443".to_owned();
//!     let auth = use_keycloak_auth(UseKeycloakAuthOptions {
//!         keycloak_server_url: Url::parse(&keycloak_server_url).unwrap(),
//!         realm: "test-realm".to_owned(),
//!         client_id: "test-client".to_owned(),
//!         post_login_redirect_url: Url::parse("http://127.0.0.1:3000").unwrap(),
//!         post_logout_redirect_url: Url::parse("http://127.0.0.1:3000").unwrap(),
//!         scope: vec![],
//!         id_token_validation: ValidationOptions {
//!             expected_audiences: Some(vec!["test-client".to_owned()]),
//!             expected_issuers: Some(vec![format!("{keycloak_server_url}/realms/test-realm")]),
//!         },
//!         advanced: Default::default(),
//!     });
//!
//!     view! {
//!         <ShowWhenAuthenticated fallback=move || view! { <a href={ auth.login_url.get().unwrap_or_default() }>"Login"</a> }>
//!             { children }
//!         </ShowWhenAuthenticated>
//!     }
//! }
//!
//! #[component]
//! pub fn ConfidentialArea() -> impl IntoView {
//!     // We can expect this context, as we only render this component under `ShowWhenAuthenticated`.
//!     // It gives direct access to the users decoded ID token.
//!     let auth = expect_context::<Authenticated>();
//!
//!     view! {
//!         <div>
//!             "Hello, " { move || auth.id_token_claims.read().name }
//!         </div>
//!     }
//! }
//! ```
//!

mod action;
mod authenticated_client;
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
mod token_claims;
mod token_validation;

// Library exports (additional to pub modules).
pub use authenticated_client::*;
pub use config::*;
pub use hooks::*;
pub use leptos_use::storage::StorageType;
pub use state::*;
pub use state::to_current_url;
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
    pub use crate::internal::jwk_set_manager::JwkSetManager;
    pub use crate::internal::oidc_config_manager::OidcConfigManager;
    pub use crate::internal::token_manager::TokenManager;
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
