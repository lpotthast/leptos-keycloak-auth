# leptos-keycloak-auth

Secure Leptos applications using Keycloak.

## Features

- OpenID Connect discovery
- Authorization code flow wik PKCE
- ID token verification
- ID token introspection
- Automatic refresh token renewal
- Automatic access token usage and 401 response handling when using the provided `reqwest`-based `AuthenticatedClient`
- Programmatic logout
- SSR support (auth flow still on client only)

## Installation

This library has to create random numbers. It uses the `rand` crate for this. `rand` depends on `getrandom`.
For `wasm32-unknown-unknown`, the target of our hydrating client, a special `getrandom` wasm backend must be specified.

1. Add `getrandom` to the dependency section ouf your final application to include the wasm backend
   when compiling the hydrating client.
   ```toml
   [dependencies]
   getrandom = { version = "0.3", features = ["wasm_js"], optional = true }
   
   [features]
   hydrate = [
       "dep:getrandom",
       # ...
   ]
   ```
2. Add the following content to `.cargo/config.toml` to actually enable this backend when building for the wasm target (
   client).
   ```toml
   [target.wasm32-unknown-unknown]
   rustflags = ['--cfg', 'getrandom_backend="wasm_js"']
   ```
3. Finally, add `leptos-keycloak-auth` as a dependency and enable its `ssr` feature when running on the server.
   ```toml
   [dependencies]
   leptos-keycloak-auth = "0.4"
   
   [features]
   hydrate = [ 
     #...
   ]
   ssr = [
     "leptos/ssr",
     "leptos-keycloak-auth/ssr",
     #...
   ]
   ```

## Usage

```rust
use leptos::prelude::*;
use leptos_router::path;
use leptos_router::components::*;
use leptos_keycloak_auth::{to_current_url, init_keycloak_auth, Authenticated, KeycloakAuth, UseKeycloakAuthOptions, ValidationOptions};
use leptos_keycloak_auth::components::*;
use leptos_keycloak_auth::url::Url;

#[component]
pub fn Init(children: Children) -> impl IntoView {
    // Note: These values should be served from environment variables to be overwritten in production.
    // Note: Redirect URLs should match the route path at which you render this component.
    //       If this component is rendered at `/admin`, the redirects should also go to that route,
    //       or we end up in a place where `use_keycloak_auth` is not rendered/active
    //       and any login attempt can never be completed.
    //       Using `to_current_url()` allows us to render `<Protected>` anywhere we want.
    let keycloak_server_url = "http://localhost:8443".to_owned();
    let _auth = init_keycloak_auth(UseKeycloakAuthOptions {
        keycloak_server_url: Url::parse(&keycloak_server_url).unwrap(),
        realm: "test-realm".to_owned(),
        client_id: "test-client".to_owned(),
        post_login_redirect_url: to_current_url(),
        post_logout_redirect_url: to_current_url(),
        scope: vec![],
        id_token_validation: ValidationOptions {
            expected_audiences: Some(vec!["test-client".to_owned()]),
            expected_issuers: Some(vec![format!("{keycloak_server_url}/realms/test-realm")]),
        },
        delay_during_hydration: true,
        advanced: Default::default(),
    });

    children()
}

#[component]
pub fn App() -> impl IntoView {
    // Meta tags excluded...
    view! {
        <main>
            <Router>
                <Init>
                    <Routes fallback=|| view! { "Page not found." }>
                        <Route path=path!("/") view=|| view! {
                            <Protected>
                                <ConfidentialArea/>
                            </Protected>
                        }/>
                    </Routes>
                </Init>
            </Router>
        </main>
    }
}

#[component]
pub fn Protected(children: ChildrenFn) -> impl IntoView {
    view! {
        <ShowWhenAuthenticated fallback=|| view! { <Login/> }>
            { children() }
        </ShowWhenAuthenticated>
    }
}

#[component]
pub fn Login() -> impl IntoView {
    let auth = expect_context::<KeycloakAuth>();
    let login_url_unavailable = Signal::derive(move || auth.login_url.get().is_none());
    let login_url = Signal::derive(move || {
        auth.login_url
            .get()
            .map(|url| url.to_string())
            .unwrap_or_default()
    });

    view! {
       <h1>"Unauthenticated"</h1>

        <a href=move || login_url.get() aria_disabled=login_url_unavailable>
            "Log in"
        </a>
    }
}

#[component]
pub fn ConfidentialArea() -> impl IntoView {
    // We can expect this context, as we only render this component under `ShowWhenAuthenticated`.
    // It gives direct access to the users decoded ID token.
    let auth = expect_context::<Authenticated>();

    view! {
        <div>
            "Hello, " { move || auth.id_token_claims.read().name.clone() }
        </div>
    }
}
```

## Test

Make sure that

1. Docker is running
2. `cargo-leptos` is up to date 

Start the tests (including the integration test) with

      cargo test -- --nocapture

This allows you to see the output from `Keycloak` as well as our `test-frontend` (build and running server) 
when running the integration tests.

You can set `DELAY_TEST_EXECUTION` to `true` in `integration_test.rs` to play around with the test application.
You can than still run the UI test by entering `y` and pressing enter or canceling the test with `n`.

## Leptos compatibility

| Crate version | Compatible Leptos version |
|---------------|---------------------------|
| 0.1           | 0.6                       |
| 0.2           | 0.6                       |
| 0.3 - 0.5     | 0.7                       |

## MSRV

- Starting from version `0.6.0`, the minimum supported rust version is `1.85.0`
- Starting from version `0.3.0`, the minimum supported rust version is `1.81.0`

## Troubleshooting

Q: My app no longer compiles using an Apple Silicon chip (M1 or upwards) after including this crate.

A: This crate depends on `jsonwebtoken` which depends on `ring` which needs to compile C code in its build-script.
MacOS comes with its own (rather quirky) version of Clang, which often leads to weird issues. Make sure to use Clang
provided through the `llvm` installation. Follow these
instructions: https://github.com/briansmith/ring/issues/1824#issuecomment-2059955073

      brew install llvm

      echo 'export PATH="/opt/homebrew/opt/llvm/bin:$PATH"' >> ~/.zshrc

## Acknowledgements

The crate was initially based on the fantastic work of [leptos_oidc](https://gitlab.com/kerkmann/leptos_oidc).
Definitely check this out as well if you do not want a Keycloak specific dependency.
