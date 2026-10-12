# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.14.0] - 2026-08-11

### Added

- Export the error types `KeycloakAuthError`, `RequestError`, `ErrorResponse`, `OidcErrorCode`, `KnownOidcErrorCode`,
  `IdTokenClaimsError` and `JwtValidationError`, so that the errors reported through `NotAuthenticated::last_error` and
  `NotAuthenticated::last_id_token_error` can be inspected.
- `Display` implementations for `ErrorResponse` and `OidcErrorCode`, and `KnownOidcErrorCode::as_str`.
- TLS backend features `rustls` (default), `rustls-no-provider` and `native-tls`, forwarded to `reqwest`. They choose
  how requests from native targets are secured, e.g. with the `ring` crypto provider instead of `aws-lc-rs`. See the
  README.

### Changed

- **Breaking**: `reqwest`'s `rustls` feature is no longer always enabled. Only the selected TLS feature enables a TLS
  backend now, so dependents disabling the default features get none on native targets. WASM builds are unaffected.
- **Breaking**: Switch error handling from `snafu` to `rootcause` reports with `thiserror`-derived error types. The
  error types only describe the failed operation (e.g. `KeycloakAuthError::RefreshToken { token_endpoint }`). Underlying
  errors (e.g. a `RequestError`, a `reqwest` or `jsonwebtoken` error) are children of the rootcause `Report`.
- `KeycloakAuthError` names the operation that failed (OIDC discovery, JWK set retrieval, code exchange, token refresh,
  an error response from Keycloak, unparsable callback parameters) instead of only distinguishing request and parameter
  errors.
- **Breaking**: Bump `leptos-use` to 0.19 (`StorageType` is re-exported from it).
- **Breaking**: Bump `jsonwebtoken` to 11 (its `Algorithm` and `KeyAlgorithm` appear in `JwtValidationError`).
- **Breaking**: Raise the MSRV to 1.89.0 (required by `rootcause`).
- Bump `sha2` to 0.11 and `base64` to 0.23 (both used internally for PKCE, not exposed in the public API).
- Bump `itertools` to 0.15 and the other dependencies to their latest compatible versions.
- **Breaking**: `<DebugState>` renders error reports as readable trees, and its state element is now identified as
  `leptos-keycloak-auth-debug-state` instead of `auth-state`, which easily clashed with ids of an application.
- Migrate the integration tests to new versions of `browser-test`, `leptos-browser-test`, `rootcause` and `assertr` and
  switch to assertr's native thirtyfour assertions. A failing browser test now fails `cargo test`.
- Rebuild the test-frontend's UI with leptonic's atoms and hooks (`hooks` branch) and custom styles, and adopt
  leptonic's recommended build profiles for it.
- Reformat sources.

### Fixed

- Store the PKCE code verifier, the nonce and the logout CSRF token in local storage instead of session storage. Chrome
  could hand a page a stale session storage (values from earlier in the session) when pages of the redirect to Keycloak
  and back were kept in its back/forward cache. Logging in after a logout then failed with "PKCE verification failed:
  Code mismatch", and the nonce validation and the logout CSRF detection were affected alike.
- Opening the application in another tab after logging in no longer ends the session. All tabs share the token data,
  but each tab had a nonce of its own, so the other tab rejected the ID token received with the login.
- `IdTokenValidationOptions::expected_audiences: None` now skips audience validation, as documented. Previously, every
  ID token issued by Keycloak was rejected (it always carries an `aud` claim), ending the session right after login.
- Refresh tokens without a known expiry no longer trigger an endless loop of token refreshes. Keycloak reports
  `refresh_expires_in: 0` for offline tokens (requested through the `offline_access` scope). Such refresh tokens are now
  never considered (nearly) expired.
- Refetch the JWK set when an ID token references an unknown key (`kid`), e.g. after Keycloak rotated its keys, instead
  of ending the session while the cached JWK set (up to `max_jwk_set_age` old) lacks the new key.
- Only interpret `code` and `error` query parameters as a login callback on the path of the `post_login_redirect_url`.
  Application routes using such query parameters no longer trigger a token exchange and redirect.
- `NotAuthenticated::last_error` is no longer overwritten with a parameter-parsing error on every page load without
  callback query parameters.
- `AuthenticatedClient`: Concurrent requests receiving a 401 now share a single token refresh instead of each refreshing
  with the same refresh token, which fails for all but one request when refresh token rotation is enabled in Keycloak.
  Requests are also retried when another refresh already provided a new access token.
- `AuthenticatedClient` and `Authenticated::handle_http_error`: A failed token refresh after a 401 only drops the token
  when Keycloak reports the session as ended (`invalid_grant`), no longer on network errors.
- `AuthenticatedClient`: A failed token refresh after a 401 is now reported through `NotAuthenticated::last_error`, like
  failures of the automatic background refresh.
- A missing authorization endpoint was reported as a missing token endpoint, and a missing token endpoint as a missing
  OIDC configuration.

### Security

- Only verify ID tokens using asymmetric algorithms and, should the JWK declare one, using the algorithm of the JWK. The
  algorithm was previously taken from the (untrusted) token header alone. Algorithm confusion was already prevented by
  `jsonwebtoken` rejecting keys of the wrong type though.

## [0.13.0] - 2026-02-13

Re-release of `0.12.1`, which was yanked from crates.io. The set of changes is identical to `0.12.1` - see that section
for details.

## [0.12.1] - 2026-02-13 [YANKED]

### Added

- `AdvancedOptions::request_timeout` (default: 30 s) controlling the timeout for internal HTTP requests (OIDC discovery,
  JWK set retrieval, token exchange, token refresh). Does not affect requests issued through `AuthenticatedClient`,
  where the user owns the `reqwest::Client`.
- Additional unit tests covering `LifeLeft::nearly_expired`, `TokenData` helpers, error-response classification and
  ID-token validation.

### Changed

- **Breaking**: Add field `request_timeout` to `AdvancedOptions`. Code that constructed `AdvancedOptions` field-by-field
  (rather than using `..Default::default()`) needs to supply the new field.
- **Breaking**: Upgrade `rand` to 0.10. The `getrandom` 0.4 feature wiring required for `wasm32-unknown-unknown` changes
  accordingly; downstream `Cargo.toml`s targeting wasm need to add the corresponding `getrandom` feature (see updated
  installation instructions in the README).
- Upgrade `jsonwebtoken` to 10.3 and `time` to 0.3.47.
- Always go through `update_token` when persisting tokens (consistency).
- Format `use` declarations using nightly grouping; reorder imports.

### Fixed

- Automatic token refresh.

## [0.12.0] - 2026-01-15

### Changed

- **Breaking**: Upgrade `reqwest` from 0.12.x to 0.13.x. Consumers that interact with `AuthenticatedClient`'s underlying
  `reqwest::Client` or share types with `reqwest` must update to the same major version.
- **Breaking**: Upgrade `leptos-use` from 0.17.x to 0.18.x.
- Specify all dependency features explicitly so each downstream build pulls in only the minimum feature set required.
- Relax tracing severity: do not warn on missing optional ID-token claims.
- Upgrade `leptos`, `leptos_router`, `serde`, `serde_json`, `time`, `tracing`, `url` and assorted dev-dependencies.

## [0.11.2] - 2025-12-27

### Added

- `ssr`-feature-gated `new` constructor variants on the manager types `TokenManager`, `OidcConfigManager`,
  `JwkSetManager`, and `CodeVerifierManager` so the `ssr_stub` and any `internals`-using code can build them in `ssr`
  mode without the client-only dependencies.
- Internal **auth session version** counter that invalidates stale asynchronous operations when their `session_version`
  no longer matches the current one (e.g. a logout/relogin completed while a token-refresh request was in flight).

### Changed

- Consistently store action-triggering callbacks (instead of mixing `Action` and `Callback`-shaped fields) for a uniform
  internal model.
- Fix various clippy lints.

## [0.11.1] - 2025-12-26

### Added

- README is now symlinked into the library crate so `crates.io` and `lib.rs` show the project README.
- README content is reused as the crate-level rustdoc.

### Changed

- A `keycloak_server_url` that is a "cannot-be-a-base" URL is now rejected immediately during initialization (via an
  internal `BaseUrl` conversion) instead of surfacing as a panic later when discovery URLs are constructed. The public
  `UseKeycloakAuthOptions::keycloak_server_url` field type is unchanged (`url::Url`); only the timing of failure
  changes.
- Read extended ID-token claims via `serde_json::Value::get` plus `serde_json::from_value`, warning when a claim is
  missing or has the wrong shape.
- Differentiate between distinct logout-validation error variants instead of collapsing them into one.
- Pre-allocate the `code_verifier` `String` to avoid intermediate allocations.
- Document why no panic is raised when (re-)constructing a URL via `use_url`.

### Fixed

- Prevent a potential divide-by-zero in `LifeLeft::nearly_expired` when the access-token lifetime is zero.
- Many README/doc-comment typos, including a typo in the `keywords` array in `Cargo.toml`. End all error messages with a
  period.
- Documentation example in the README.

## [0.11.0] - 2025-12-24

### Added

- New high-level components that drastically simplify usage:
    - `<AuthProvider>` - wraps `init_keycloak_auth` with sensible defaults (post-login/post-logout redirect to the
      current
      URL, expected audience/issuer derived from the configured client and realm).
    - `<MaybeAuthenticated>` - render different views for authenticated versus unauthenticated states.
    - `<Unauthenticated>` - counterpart to `<Authenticated>`.
    - `<WithAuth render=…>` - convenience for accessing the auth handle inside a render closure.

### Changed

- **Breaking**: Rename component `ShowWhenAuthenticated` to `Authenticated`. The previous rename (introduced in 0.3.0 to
  avoid clashing with the `Authenticated` *struct*) is reverted now that the struct lives in `crate::state` and the
  component name is reclaimed.
- Updated the bundled `test-frontend` to reflect the new components.

## [0.10.0] - 2025-12-20

### Added

- ID-token **nonce validation**. The `nonce` claim is now validated against the value generated for the authorization
  request, providing protection against ID-token replay attacks. Controlled via the new
  `AdvancedOptions::nonce_validation` field (default: `true`).

### Changed

- **Breaking**: Rename `ValidationOptions` to `IdTokenValidationOptions`. Downstream code referencing
  `ValidationOptions` (or importing it from the crate root) must be updated.
- **Breaking**: Add field `nonce_validation` to `AdvancedOptions`. Code constructing the struct field-by-field must
  supply the new field.

## [0.9.0] - 2025-12-19

### Added

- **CSRF-protected logout flow**. The library now generates a CSRF token before navigating to Keycloak's `end-session`
  endpoint and verifies it on the post-logout redirect. If the redirect does not carry the expected token (i.e. the user
  was logged out by something other than this client), `KeycloakAuth::suspicious_logout: Signal<bool>` is set. The
  accompanying `dismiss_suspicious_logout_warning: Callback<()>` lets applications acknowledge and clear the warning.
- `AdvancedOptions::logout_csrf_detection` (default: `true`) to opt out of the new behaviour.
- `csrf_token_manager()` accessor on `KeycloakAuth` (under the `internals` feature).
- A helper that detects Keycloak error-shaped responses, used in several places that previously parsed errors ad-hoc.

### Changed

- **Breaking**: `KeycloakAuth::end_session_and_go_to` now takes `url::Url` instead of `&str`.
- **Breaking**: Add field `logout_csrf_detection` to `AdvancedOptions`.
- **Breaking**: Add fields `suspicious_logout` and `dismiss_suspicious_logout_warning` to `KeycloakAuth`.
  Pattern-matching or constructing this type breaks accordingly. (Use through methods is unaffected.)
- Refactor internal storage usage; refactor and extend integration tests; update dependencies.

## [0.8.4] - 2025-12-19

> Released to crates.io but not tagged in this repository. The same change set is included in `0.9.0`.

### Changed

- Refactor Keycloak error-response detection into a helper function (no user-visible API change).

## [0.8.3] - 2025-12-18

### Fixed

- Fix deserialization of OIDC `error` codes received from Keycloak. The set of known codes is now properly modelled and
  unknown codes are preserved as `OidcErrorCode::Unknown(String)`.

## [0.8.2] - 2025-12-18

### Changed

- Update documentation across the public API.
- Fix clippy lints.

## [0.8.1] - 2025-12-17

### Fixed

- Prevent accidental rerendering of `<ShowWhenAuthenticated>` (and other consumers) on token refresh by avoiding tracked
  access where unnecessary.

## [0.8.0] - 2025-12-16

### Changed

- **Breaking**: Bump MSRV to 1.88.0.
- **Breaking**: Upgrade `jsonwebtoken` from 9.x to 10.x (with the `rust_crypto` feature). Downstreams that re-export or
  interact with `jsonwebtoken` types need to follow.
- **Breaking**: Update many other dependencies to new majors/minors, including `codee` 0.3.5, `http` 1.4, `leptos`
  0.8.14, `leptos-use` 0.16.3, `leptos_router` 0.8.10, `rand` 0.9.2, `reqwest` 0.12.26, `time` 0.3.44, `url` 2.5.7.
  Library types interacting with these crates inherit their semver implications.
- `AuthenticatedClient` no longer accesses the user's current `access_token` in a tracked manner, eliminating spurious
  re-evaluations of surrounding reactive scopes.
- Tested against Keycloak 26.4.0.
- Updated README.

## [0.7.0] - 2025-06-01

### Changed

- **Breaking**: Migrate to Leptos 0.8 (`leptos`, `leptos_router`, and `leptos-use` 0.16). Consumer projects must update
  accordingly.
- Mark the bundled `test-frontend` crate `publish = false` so it can never accidentally be uploaded to crates.io.

## [0.6.2] - 2025-03-25

> Re-release of `0.6.1`. The `v0.6.1` and `v0.6.2` Git tags point to the same commit; `0.6.2` was published from the
> same source tree with only the `Cargo.toml` version bump (which was not committed back to the repository).

## [0.6.1] - 2025-03-25

### Changed

- Update `codee` to 0.3 (used internally for storage codecs; no public API impact).

## [0.6.0] - 2025-02-23

### Changed

- **Breaking**: Switch to Rust **edition 2024**.
- **Breaking**: Bump MSRV to **1.85.0**.
- **Breaking**: Update `leptos-routes` to 0.3.0.
- Add empty `use<>` annotations where required to preserve 2021-edition capture semantics.
- Drop the now-unused direct `reqwest` dependency in `dev-dependencies`.
- Sort imports; assorted housekeeping.

## [0.5.4] - 2025-02-07

### Changed

- Gracefully handle the situation where the type of values stored in local/session storage changes between releases by
  capturing storage decode errors and dropping the offending entries. All unhandled storage errors are now logged.

## [0.5.3] - 2025-02-06

### Changed

- Limit enabled `leptos-use` features to the minimum required (`use_interval`, `storage`). This removes a number of
  transitive dependencies from downstream builds.

## [0.5.2] - 2025-02-06

### Fixed

- Use an always-accessible path to `DerivedUrls`; fixes a build error when the `internals` feature is *not* enabled.
- Update the README's feature list.

## [0.5.1] - 2025-02-05

### Changed

- Drop all cached state when `init_keycloak_auth` is called with a config that resolves to a different OIDC discovery
  endpoint than the one cached state was issued for. The assumption is that a different discovery endpoint implies a
  different identity provider whose tokens cannot be reused.
- Determine source-mismatch synchronously (without going through an effect), so stale data is dropped immediately on
  init.
- *Internal*: even with the `internals` feature enabled, state-changing fields are now hidden behind a smaller surface.
  Technically breaking for `internals` consumers but not advertised as such.

## [0.5.0] - 2025-02-05

### Added

- **`ssr` feature**. With `ssr` enabled, `init_keycloak_auth` returns an `Indeterminate`-state stub on the server; the
  entire OIDC flow runs client-side only. Avoids hydration errors when the auth UI would otherwise render different
  content on server and client.
- `KeycloakAuthState::Indeterminate` variant, returned during SSR/hydration and while a Keycloak callback redirect is
  being processed. Eliminates the "state-flickering" issues reported when the unauthenticated branch rendered briefly
  before cached tokens were rehydrated.
- `delay_during_hydration` option on `UseKeycloakAuthOptions` to defer initialization until after hydration completes.
- `expect_keycloak_auth()` and `expect_authenticated()` context-lookup helpers.
- The new `init_keycloak_auth` entry point is usable without an existing `Signal<KeycloakAuth>` context, simplifying
  setup.

### Changed

- **Breaking**: Rename `use_keycloak_auth` to `init_keycloak_auth`. The new name better reflects that this function
  initializes the auth handle and registers it as a Leptos context; subsequent reads use `expect_keycloak_auth()`.
- **Breaking**: Add variant `KeycloakAuthState::Indeterminate` to the state enum. Exhaustive `match`es over
  `KeycloakAuthState` need a new arm.
- **Breaking**: Add `delay_during_hydration` field to `UseKeycloakAuthOptions`. Code constructing the struct
  field-by-field must supply the new field.
- Logout URL is now updated on the page when redirect URLs change.
- Simplified internal initialization logic.

## [0.4.1] - 2025-02-01

### Added

- Utilities for performing **programmatic logouts**:
    - `KeycloakAuth::end_session()` and `end_session_and_go_to(...)`.
    - `<EndSession and_route_to=…>` component.
- `<DebugState>` component (gated on the `internals` feature) that renders the values of the internal manager types -
  useful for diagnosing OIDC flow issues.

### Changed

- Documentation updated to make explicit that `use_keycloak_auth` must be rendered on the client only (for now).

## [0.4.0] - 2025-02-01

### Changed

- **Breaking**: Update `rand` to 0.9. Because `rand` 0.9 changes its `getrandom` dependency story, downstream
  applications targeting `wasm32-unknown-unknown` must now declare both `getrandom = "0.2"` (with the `js` feature) and
  `getrandom = "0.3"` (with the `wasm_js` feature) themselves. See the README's new "Installation" section for details.

## [0.3.1] - 2025-02-01

### Added

- `to_current_url_untracked` - non-reactive sibling of `to_current_url`, useful when capturing the current URL without
  re-running on navigation.

### Changed

- Logging: use `tracing-subscriber` on the server and `tracing-wasm` on the client.
- Allow the `state_pretty_printer` to be invoked from a potentially reactive context.

### Fixed

- Reactive access in non-reactive contexts.

## [0.3.0] - 2025-01-30

> First Git-tagged release.

### Added

- **Migration to Leptos 0.7**. The library now targets `leptos = "0.7"`.
- `expected_audiences` and `expected_issuers` fields on the validation options, allowing applications to constrain
  ID-token validation to their own audiences and issuers.
- `scope` may now be supplied as a `Vec<String>`; the `openid` scope is always appended automatically.
- `AuthenticatedClient` - a `reqwest::Client` wrapper that injects the `Authorization: Bearer …` header and
  transparently retries once on `401 UNAUTHORIZED` after refreshing the token.
- `internals` feature, exposing the manager types (`TokenManager`, `OidcConfigManager`, `JwkSetManager`, …) for advanced
  use cases.
- PKCE: `code_verifier`/`code_challenge` are now used during the authorization-code → token exchange.
- Decoding the ID token tries both the previous and the freshly-fetched JWK sets, smoothing key-rotation transitions.
- `set_post_login_redirect_url` / `set_post_logout_redirect_url` for reactive redirect-URL updates.
- Comprehensive documentation, examples and tests (`tests/` now spins up a real Keycloak via testcontainers + Selenium).

### Changed

- **Breaking**: Big API overhaul to follow Leptos 0.7 idioms (signals, memos, owners). Most public types changed shape;
  review imports against the new `lib.rs` re-exports.
- **Breaking**: Public access is now structured around `KeycloakAuth` and `KeycloakAuthState`. The full token data is no
  longer exposed on the state - `NotAuthenticated` carries `last_error`/ `last_id_token_error` signals; `Authenticated`
  exposes `id_token_claims`, `access_token`, and `client()`.
- **Breaking**: Move state types to their own module. Most `pub` items moved out of `lib.rs`.
- **Breaking**: Many items previously `pub` are now `pub(crate)`. They can be re-acquired through the new `internals`
  feature where applicable.
- **Breaking**: Component `Authenticated` was renamed to `ShowWhenAuthenticated` to avoid clashing with the new
  `Authenticated` *state* struct. (Reverted in 0.11.0.)
- **Breaking**: `Duration` types in the configuration are now `std::time::Duration` (re-exported as `StdDuration`
  internally for clarity).
- Drop the current token when the JWK set changes. Drop the current token when refresh fails with "Invalid refresh
  token". Validate `expected_issuers`. Stop expecting `?session_state=…` to remain in the browser URL.
- Numerous internal refactors: separated the library and the `test-frontend`; reduced cloning; lowered tracing event
  levels; consolidated request helpers.

### Fixed

- Authorization code being exchanged twice; consumed state is now removed from the URL.
- JWK-set retrieval timestamp not being updated, which caused the current JWK set to always be considered outdated
  despite being fetched.
- CORS setup uses `.allow_credentials(true)`.
- Various small bugs uncovered while bringing up the integration tests.

## [0.2.0] - 2024-09-12

### Added

- `codee` 0.2 dependency providing the `JsonSerdeCodec` storage codec.

### Changed

- **Breaking**: Migrate to `leptos` / `leptos_router` 0.6 (was 0.5). Consumers must update accordingly.
- **Breaking**: Update `leptos-use` from 0.8.x to 0.13.x and adopt the new `codee`-based serialization for storage
  hooks.
- **Breaking**: Replace `thiserror` with `snafu` for error handling. Error types exposed by the library now use
  `snafu`-derived types; downstreams pattern-matching errors must update.
- **Breaking**: Update `reqwest` from 0.11 to 0.12; drop the `serde_json` reqwest feature that is no longer available.
- Drop the now-unused direct `web-sys` dependency.
- Mostly-non-generic inner functions in generic contexts (smaller monomorphization footprint).
- Specify a minimal `include` set for the published crate (`src/**/*`, `LICENSE-*`, `README.md`).
- Relax the `time` version requirement.
- Update MIT license header and README.

## [0.1.0] - 2023-12-20

### Changed

- **Breaking**: Switch `jsonwebtoken` from a git dependency on the upstream `master` branch to a regular crates.io
  dependency at `9.2.0`. The pre-`0.1.0` release depended on an unreleased patch of `jsonwebtoken`; with 9.2 out, the
  dependency could finally be expressed normally, allowing this crate to be published to crates.io as `0.1.0`.

## [0.0.1] - 2023-11-15

### Added

- Initial release. OIDC authorization-code flow against a Keycloak realm from a Leptos client, including discovery, JWK
  retrieval, ID token validation, automatic refresh, and login/logout helpers.

[Unreleased]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.14.0...HEAD
[0.13.0]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.12.0...v0.13.0
[0.12.1]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.11.2...v0.12.0
[0.11.2]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.11.1...v0.11.2
[0.11.1]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.8.3...v0.9.0
[0.8.4]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.8.3...v0.9.0
[0.8.3]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.8.2...v0.8.3
[0.8.2]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.6.2...v0.7.0
[0.6.2]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.5.4...v0.6.0
[0.5.4]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/lpotthast/leptos-keycloak-auth/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/lpotthast/leptos-keycloak-auth/releases/tag/v0.3.0
[0.2.0]: https://crates.io/crates/leptos-keycloak-auth/0.2.0
[0.1.0]: https://crates.io/crates/leptos-keycloak-auth/0.1.0
[0.0.1]: https://crates.io/crates/leptos-keycloak-auth/0.0.1
