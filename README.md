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
use leptos::prelude::*;
use leptos_keycloak_auth::{use_keycloak_auth, Authenticated, Url, UseKeycloakAuthOptions};

#[component]
pub fn Protected(children: ChildrenFn) -> impl IntoView {
    // Note: These values should be served from environment variables to be overwritten in production.
    let keycloak_server_url = "http://localhost:8443".to_owned();
    let _auth = use_keycloak_auth(UseKeycloakAuthOptions {
        keycloak_server_url: Url::parse(&keycloak_server_url).unwrap(),
        realm: "test-realm".to_owned(),
        client_id: "test-client".to_owned(),
        post_login_redirect_url: Url::parse("http://127.0.0.1:3000").unwrap(),
        post_logout_redirect_url: Url::parse("http://127.0.0.1:3000").unwrap(),
        scope: vec![],
        id_token_validation: ValidationOptions {
           expected_audiences: Some(vec!["test-client".to_owned()]),
           expected_issuers: Some(vec![format!("{keycloak_server_url}/realms/test-realm")]),
        },
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
s
        view! {
            <a href={ move || login_url.get() } target="self" disabled={ move || login_disabled.get() }>
                "Log in"
            </a>
        }
    }
}
```

## Leptos compatibility

| Crate version | Compatible Leptos version |
|---------------|---------------------------|
| 0.1           | 0.6                       |
| 0.2           | 0.6                       |
| 0.3           | 0.7                       |

## MSRV

The minimum supported rust version is `1.76.0`

## Troubleshooting

Q: My app no longer compiles using an Apple Silicon chip (M1 or upwards) after including this crate.

A: This crate depends on `jsonwebtoken` which depends on `ring` which needs to compile C code in its build-script.
   MacOS comes with its own (rather quirky) version of Clang, which often leads to weird issues. Make sure to use Clang
   provided through the `llvm` installation. Follow these instructions: https://github.com/briansmith/ring/issues/1824#issuecomment-2059955073
      
      brew install llvm

      echo 'export PATH="/opt/homebrew/opt/llvm/bin:$PATH"' >> ~/.zshrc

## Acknowledgements

The crate was initially based on the fantastic work of [leptos_oidc](https://gitlab.com/kerkmann/leptos_oidc).
Definitely check this out as well if you do not want a Keycloak specific dependency.
