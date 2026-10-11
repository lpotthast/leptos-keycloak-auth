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

## Crate Features

- `ssr`: Enable when building for the server. The auth flow still runs on the client only.
- `internals`: Exposes the internal manager types and the `<DebugState>` component, for advanced use and debugging.
- `rustls` *(default)*: Sends requests through `rustls` with the `aws-lc-rs` crypto provider.
- `rustls-no-provider`: Sends requests through `rustls` with the process-default crypto provider, which you must install
  before any request is made.
- `native-tls`: Sends requests through the platform's native TLS implementation.

The TLS features are forwarded to `reqwest` and only affect native (non-WASM) targets. In the browser, `reqwest` uses
the Fetch API, leaving TLS to the browser. Since the auth flow runs client-side only, your server makes no requests
through this crate. You can therefore disable the default features entirely, unless you use the re-exported
`leptos_keycloak_auth::reqwest` from native code to reach HTTPS endpoints.

To use the `ring` crypto provider instead of `aws-lc-rs`, select `rustls-no-provider` and install `ring` as the
process-default provider. No crate in your dependency graph may enable `reqwest/rustls`.

```toml
[dependencies]
leptos-keycloak-auth = { version = "0.14", default-features = false, features = ["rustls-no-provider"] }
rustls = { version = "0.23", default-features = false, features = ["ring", "std"] }
```

```rust,ignore
// Once per process, before any request is made. Fails harmlessly if a provider is already installed.
let _ = rustls::crypto::ring::default_provider().install_default();
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
3. the installed `wasm-bindgen` CLI matches the version locked by the test-frontend (`just install-tools` installs the
   latest CLI, `just update` locks the latest crate)

Start the tests (including the integration test) with

```sh
just test
```

Run only the browser-driven integration test with `just browser-test`, or with `just browser-test-visible` to watch the
browser. Output from `Keycloak` and the `test-frontend` (build and running server) is shown as the tests run.

Set `BROWSER_TEST_PAUSE=1` to pause before the browser tests start, e.g. to play around with the running test
application. Answer `y` to continue with the tests or `n` to end the run.

## Leptos compatibility

| Crate version | Compatible Leptos version |
|---------------|---------------------------|
| 0.1           | 0.6                       |
| 0.2           | 0.6                       |
| 0.3 - 0.6     | 0.7                       |
| 0.7 - 0.13    | 0.8                       |

## MSRV

- Starting from version `0.14.0`, the minimum supported rust version is `1.89.0`
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
