#![allow(clippy::single_match_else)]

//! Protect parts of your Leptos application using Keycloak.
//!
//! ## Example
//!
//! ```
//! use leptos::prelude::*;
//! use leptos_router::path;
//! use leptos_router::components::*;
//! use leptos_keycloak_auth::{to_current_url, init_keycloak_auth, Authenticated, KeycloakAuth, UseKeycloakAuthOptions, ValidationOptions};
//! use leptos_keycloak_auth::components::*;
//! use leptos_keycloak_auth::url::Url;
//!
//! #[component]
//! pub fn Init(children: Children) -> impl IntoView {
//!     // Note: These values should be served from environment variables to be overwritten in production.
//!     // Note: Redirect URLs should match the route path at which you render this component.
//!     //       If this component is rendered at `/admin`, the redirects should also go to that route,
//!     //       or we end up in a place where `use_keycloak_auth` is not rendered/active
//!     //       and any login attempt can never be completed.
//!     //       Using `to_current_url()` allows us to render `<Protected>` anywhere we want.
//!     let keycloak_server_url = "http://localhost:8443".to_owned();
//!     let _auth = init_keycloak_auth(UseKeycloakAuthOptions {
//!         keycloak_server_url: Url::parse(&keycloak_server_url).unwrap(),
//!         realm: "test-realm".to_owned(),
//!         client_id: "test-client".to_owned(),
//!         post_login_redirect_url: to_current_url(),
//!         post_logout_redirect_url: to_current_url(),
//!         scope: vec![],
//!         id_token_validation: ValidationOptions {
//!             expected_audiences: Some(vec!["test-client".to_owned()]),
//!             expected_issuers: Some(vec![format!("{keycloak_server_url}/realms/test-realm")]),
//!         },
//!         delay_during_hydration: true,
//!         advanced: Default::default(),
//!     });
//!
//!     children()
//! }
//!
//! #[component]
//! pub fn App() -> impl IntoView {
//!     // Meta tags excluded...
//!     view! {
//!         <main>
//!             <Router>
//!                 <Init>
//!                     <Routes fallback=|| view! { "Page not found." }>
//!                         <Route path=path!("/") view=|| view! {
//!                             <Protected>
//!                                 <ConfidentialArea/>
//!                             </Protected>
//!                         }/>
//!                     </Routes>
//!                 </Init>
//!             </Router>
//!         </main>
//!     }
//! }
//!
//! #[component]
//! pub fn Protected(children: ChildrenFn) -> impl IntoView {
//!     view! {
//!         <ShowWhenAuthenticated fallback=|| view! { <Login/> }>
//!             { children() }
//!         </ShowWhenAuthenticated>
//!     }
//! }
//!
//! #[component]
//! pub fn Login() -> impl IntoView {
//!     let auth = expect_context::<KeycloakAuth>();
//!     let login_url_unavailable = Signal::derive(move || auth.login_url.get().is_none());
//!     let login_url = Signal::derive(move || {
//!         auth.login_url
//!             .get()
//!             .map(|url| url.to_string())
//!             .unwrap_or_default()
//!     });
//!
//!     view! {
//!        <h1>"Unauthenticated"</h1>
//!
//!         <a href=move || login_url.get() aria_disabled=login_url_unavailable>
//!             "Log in"
//!         </a>
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
//!             "Hello, " { move || auth.id_token_claims.read().name.clone() }
//!         </div>
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
mod error;
mod hooks;
mod internal;
mod login;
mod logout;
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
    pub use crate::internal::derived_urls::DerivedUrls;
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
