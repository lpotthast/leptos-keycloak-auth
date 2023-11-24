# leptos-keycloak-auth

Secure Leptos applications using Keycloak.

## Features

- OpenID Connect discovery
- Authorization code flow
- ID token verification
- ID token introspection
- Automatic refresh token renewal

## Usage

```rust
use leptos::*;
use leptos_keycloak_auth::{use_keycloak_auth, Authenticated, Url, UseKeycloakAuthOptions};

#[component]
pub fn Protected(children: ChildrenFn) -> impl IntoView {
    // Note: These values should be served from environment variables to be overwritten in production.
    let _auth = use_keycloak_auth(UseKeycloakAuthOptions {
        keycloak_server_url: "http://localhost:8443/",
        realm: "your-realm-name".to_owned(),
        client_id: "your-client-name".to_owned(),
        post_login_redirect_url: "http://127.0.0.1:4000/".to_owned(),
        post_logout_redirect_url: "http://127.0.0.1:4000/".to_owned(),
        scope: Some("openid".to_string()),
        advanced: Default::default(),
    });

    let user_name = Signal::derive(move || {
        auth.id_token_claims
            .get()
            .map(|claims| claims.name.clone())
            .unwrap_or_default()
    });

    view! {
        <Authenticated unauthenticated=move || view! { <PageUnauthenticated /> }>
            <div>
                "Hello, " {move || user_name.get()}
            </div>
            { children }
        </Authenticated>
    }
}

#[component]
pub fn Login() -> impl IntoView {
    let auth = expect_context::<KeycloakAuth>();
    let login_url = Signal::derive(move || {
        auth.login_url
            .get()
            .map(|url| url.to_string())
            .unwrap_or_default()
    });
    let login_disabled = Signal::derive(move || auth.login_url.get().is_none());

    view! {
        <H1>"Unauthenticated"</H1>

        view! {
            <a href={ move || login_url.get() } target="self" disabled={ move || login_disabled.get() }>
                "Log in"
            </a>
        }
    }
}

```
