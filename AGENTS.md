# AGENTS.md

## Building, Testing, Formatting

- The root is not a cargo workspace. Prefer the `Justfile` recipes. When running cargo directly, pass`--manifest-path`,
  and for the test-frontend also `--config ./test-frontend/.cargo/config.toml`, since cargo only picks up that file
  (`--cfg=web_sys_unstable_apis`, required by leptonic) when run in the test-frontend's directory.
- `just verify` runs the full non-mutating suite. Formatting requires nightly rustfmt (`rustfmt.toml` sets unstable
  options) plus `leptosfmt` for `view!` macros.
- `cargo test --lib --manifest-path ./leptos-keycloak-auth/Cargo.toml` runs the unit tests only. All other tests are
  integration tests, which need Podman running (Keycloak via testcontainers), an up-to-date `cargo-leptos` and a
  `wasm-bindgen` CLI exactly matching the `wasm-bindgen` crate locked by the test-frontend (otherwise: "different
  bindgen format"). `just install-tools` installs the latest CLI, `just update` locks the latest crate.
- `BROWSER_TEST_VISIBLE=1` shows the browser. `BROWSER_TEST_PAUSE=1` pauses before the browser tests run, e.g. to
  manually play around with the fully running test application.
- On Apple Silicon, `ring` (via `jsonwebtoken`) needs LLVM's Clang (`brew install llvm`, added to PATH).

## Integration Tests

Tests receive a `Page` (`tests/pages/mod.rs`, provided by `harness::with_page`), which holds the shared lookups, clicks,
navigation and waits, each timed as a browser-test step. Page objects for single pages wrap a `Page`. Page objects and
helpers panic on failure instead of returning `Result`s. The browser-test runner reports panicking tests.

`Page` finds elements with `WebDriver::query(..).first()`, polling with the runner's element-query wait, and checks
values with assertr's thirtyfour support: `assert_that!(element).text().await` for the current text, eventual assertions
(`eventually_ok`, timing from the global `Patience` set in `integration_test.rs`) for values that settle later. Don't use
`WebDriver::find`: it doesn't wait (the implicit wait is zero) and fails during navigations. After navigating to a
test-frontend page, wait for its hydration (`Page::wait_for_hydration`, the frontend sets `data-hydrated` on `<body>`).

The test-frontend records panics, uncaught errors, `console.error` and `console.warn` (script in its `shell`). `Page`
fails the test when a test-frontend page reported any of them: before every click and navigation (which may leave the
page), and after the test. `tracing` events don't count: `tracing-wasm` logs all of them with `console.log`.

The test-frontend uses leptonic's unstyled atoms and hooks only, without a leptonic theme. All styling lives in
`test-frontend/style/main.scss`.

## Library Conventions

- With the `ssr` feature, `init_keycloak_auth` returns an `Indeterminate` stub. The entire auth flow runs client-side,
  and browser-only logic is gated by `#[cfg(not(feature = "ssr"))]`.
- The `Effect` in `hooks.rs:real()` watching `url_state` (the parsed callback query parameters) drives the login/logout
  state transitions.
- `Authenticated` and `NotAuthenticated` hold inner signals, so that token refreshes don't rerender everything below
  them. Keep it that way.
- Errors are `rootcause` reports with `thiserror`-derived, context-only error enums. Underlying errors become child
  reports via `.context(..)`. Errors of background operations reach users as cloneable reports through reactive signals
  (`NotAuthenticated::last_error`, `NotAuthenticated::last_id_token_error`).
- All flow state (tokens, PKCE code verifier, nonce, logout CSRF token) lives in localStorage, observed across tabs.
  Never use sessionStorage for it: all tabs share the tokens, so they must share the values validating them. Every tab
  validates the shared ID token against the nonce, and a logout regenerates these values only in the tab receiving the
  logout callback.
