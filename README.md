# leptos-keycloak-auth

Secure Leptos applications using Keycloak.

## Features

- `OpenID Connect` discovery
- Authorization code flow with PKCE, Nonce validation, and Logout validation
- ID token verification
- ID token introspection
- Automatic refresh token renewal
- Automatic access token usage and 401 response handling when using the provided `reqwest`-based `AuthenticatedClient`
- Programmatic logout
- SSR support (auth flow still on client only)

## Installation

This library has to create random numbers. It uses the `rand` crate for this. `rand` depends on `getrandom`.
For `wasm32-unknown-unknown`, the target of our hydrating client, a special `getrandom` wasm backend must be specified.

1. With the current set of dependencies, two versions of `getrandom` will be in the dependency tree. We have to enable
   `getrandom`s WASM related features on all versions used (check with `cargo tree`) to mitigate any compile errors.
   Add this to the Cargo.toml of your application.
   ```toml
   [target.'cfg(target_arch = "wasm32")'.dependencies]
   js-sys = "0.3"
   getrandom_02 = { package = "getrandom", version = "0.2", features = ["js"] }
   getrandom_03 = { package = "getrandom", version = "0.3", features = ["wasm_js"] }
   getrandom_04 = { package = "getrandom", version = "0.4", features = ["wasm_js"] }
   ```
2. Add `leptos-keycloak-auth` as a dependency and enable its `ssr` feature when running on the server.
   ```toml
   [dependencies]
   leptos-keycloak-auth = "0.13"
   
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

Initialize auth at the root of your application with the `<AuthProvider>` component.

**Note:** `expected_audiences` defaults to `["<client>"]` and `expected_issuers` defaults to
`["<realm>"]`, so you don't need to specify them for standard setups. Redirect URLs automatically track
the current page, so wherever you display a login link the user will be redirected to automatically once the login was
completed on the Keycloak side.

This should happen between `Router` and `Routes`, so that initialization runs on all pages but has access ot the router
hook.

Use the `MaybeAuthenticated`, `Authenticated` and `Unauthenticated` component to conditionally render content based on
the current authentication status. These give you immediate access to the relevant state.

Use `use_keycloak_auth` or `try_use_keycloak_auth` to access `leptos-keycloak-auth`'s main state. The try variant can
be used when you don't use the `<AuthProvider>` on all pages are unsure whether the library was initialized.

Use `use_authenticated` or `try_use_authenticated` to directly access the `Authenticated` state, providing information
about the user. The try variant can be used if you are unsure whether the user is currently logged in.

```rust
use leptos::prelude::*;
use leptos_router::{path, components::*};
use leptos_keycloak_auth::components::*;
use leptos_keycloak_auth::url::Url;
use leptos_keycloak_auth::use_keycloak_auth;

#[component]
pub fn App() -> impl IntoView {
    view! {
        <Router>
            <AuthProvider
                keycloak_server_url=Url::parse("http://localhost:8443").unwrap()
                realm="my-realm"
                client="my-client"
            >
                <Routes fallback=|| view! { "Page not found." }>
                    <Route path=path!("/") view=HomePage/>
                </Routes>
            </AuthProvider>
        </Router>
    }
}

#[component]
pub fn HomePage() -> impl IntoView {
    view! {
        <h1>"Welcome"</h1>
        <MaybeAuthenticated
            authenticated=|auth| view! {
                <p>"Hello, " { auth.id_token_claims.read().name.clone() }</p>
                <LogoutButton/>
            }
            unauthenticated=|_| view! { 
                <LoginButton/>
            }
        />
    }
}

#[component]
pub fn LoginButton() -> impl IntoView {
    let auth = use_keycloak_auth();
    let login_url = move || auth.login_url.get().map(|url: Url| url.to_string()).unwrap_or_default();
    let login_url_unavailable = move || auth.login_url.get().is_none();
    view! {
        <a href=login_url aria-disabled=login_url_unavailable>"Log In"</a>
    }
}

#[component]
pub fn LogoutButton() -> impl IntoView {
    let auth = use_keycloak_auth();
    let logout_url = move || auth.logout_url.get().map(|url: Url| url.to_string()).unwrap_or_default();
    let logout_url_unavailable = move || auth.login_url.get().is_none();
    view! {
        <a href=logout_url aria-disabled=logout_url_unavailable>"Log out"</a>
    }
}
```

## Test

Make sure that

1. Podman is running
2. `cargo-leptos` is up to date

Start the tests (including the integration test) with

```sh
cd leptos-keycloak-auth
cargo test -- --nocapture
```

This allows you to see the output from `Keycloak` as well as our `test-frontend` (build and running server)
when running the integration tests.

You can set `DELAY_TEST_EXECUTION` to `true` in `integration_test.rs` to play around with the test application.
You can than still run the UI test by entering `y` and pressing enter or canceling the test with `n`.

## Leptos compatibility

| Crate version | Compatible Leptos version |
|---------------|---------------------------|
| 0.1           | 0.6                       |
| 0.2           | 0.6                       |
| 0.3 - 0.6     | 0.7                       |
| 0.7 - 0.13    | 0.8                       |

## MSRV

- Starting from version `0.8.0`, the minimum supported rust version is `1.88.0`
- Starting from version `0.6.0`, the minimum supported rust version is `1.85.0`
- Starting from version `0.3.0`, the minimum supported rust version is `1.81.0`

## Troubleshooting

Q: My app does not compile due to `getrandom` not compiling for the WASM target.

A: Add this to your projects Cargo.toml

```toml
[target.'cfg(target_arch = "wasm32")'.dependencies]
js-sys = "0.3"
getrandom_02 = { package = "getrandom", version = "0.2", features = ["js"] }
getrandom_03 = { package = "getrandom", version = "0.3", features = ["wasm_js"] }
getrandom_04 = { package = "getrandom", version = "0.4", features = ["wasm_js"] }
```

Q: My app no longer compiles using an Apple Silicon chip (M1 or upwards) after including this crate.

A: This crate depends on `jsonwebtoken` which depends on `ring` which needs to compile C code in its build-script.
macOS comes with its own (rather quirky) version of Clang, which often leads to weird issues. Make sure to use Clang
provided through the `llvm` installation. Follow these
instructions: <https://github.com/briansmith/ring/issues/1824#issuecomment-2059955073>

```shell
brew install llvm

echo 'export PATH="/opt/homebrew/opt/llvm/bin:$PATH"' >> ~/.zshrc
```

## Acknowledgements

The crate was initially based on the fantastic work of [leptos_oidc](https://gitlab.com/kerkmann/leptos_oidc).
Definitely check this out as well if you do not want a Keycloak specific dependency.
