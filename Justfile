# List all available commands.
list:
  just --list

# Install dependencies for maintenance work, profiling and more...
install-tools:
  rustup toolchain add nightly
  cargo +stable install --locked cargo-edit
  cargo +stable install --locked cargo-expand
  cargo +stable install --locked cargo-hack
  cargo +stable install --locked cargo-minimal-versions
  cargo +stable install --locked cargo-msrv
  cargo +stable install --locked cargo-upgrades
  cargo +stable install --locked cargo-whatfeatures
  cargo +stable install --locked leptosfmt
  cargo +stable install --locked wasm-bindgen-cli

# Check that the library crate still compiles when its direct dependencies are resolved to the lowest versions its
# Cargo.toml allows, i.e. that the declared lower version bounds are not too low.
minimal-versions:
  cargo minimal-versions check --manifest-path ./leptos-keycloak-auth/Cargo.toml --direct

# Find the minimum supported Rust version of the library crate.
find-msrv:
  cargo msrv find --manifest-path ./leptos-keycloak-auth/Cargo.toml

# Run `cargo sort` for every crate.
sort:
  cargo sort ./leptos-keycloak-auth/Cargo.toml --workspace --grouped
  cargo sort ./test-frontend/Cargo.toml --workspace --grouped

# Check that `cargo fmt` would not change any code. Uses nightly rustfmt, as `rustfmt.toml` sets unstable options.
fmt-check:
  cargo +nightly fmt --manifest-path ./leptos-keycloak-auth/Cargo.toml --check
  cargo +nightly fmt --manifest-path ./test-frontend/Cargo.toml --check

# Run `cargo fmt` for every crate. Uses nightly rustfmt, as `rustfmt.toml` sets unstable options.
fmt:
  cargo +nightly fmt --manifest-path ./leptos-keycloak-auth/Cargo.toml
  cargo +nightly fmt --manifest-path ./test-frontend/Cargo.toml

# Check that `leptosfmt` would not change any code.
leptosfmt-check:
  leptosfmt --check ./leptos-keycloak-auth/src/*
  leptosfmt --check ./test-frontend/src/*

# Run `leptosfmt` for every crate.
leptosfmt:
  leptosfmt ./leptos-keycloak-auth/src/*
  leptosfmt ./test-frontend/src/*

# Run all tests of the library crate, including browser-/integration-tests.
test:
  cargo test --manifest-path ./leptos-keycloak-auth/Cargo.toml -- --nocapture

# Run browser-/integration-tests.
browser-test:
  cargo test --manifest-path ./leptos-keycloak-auth/Cargo.toml -- --nocapture test_integration

# Run browser-/integration-tests in a visible browser window.
browser-test-visible:
  BROWSER_TEST_VISIBLE=1 cargo test --manifest-path ./leptos-keycloak-auth/Cargo.toml -- --nocapture test_integration

# Run browser-/integration-tests in a visible browser window. Pauses before test execution and waits for approval. Gives time to interact with the test frontend manually.
browser-test-paused:
  BROWSER_TEST_VISIBLE=1 BROWSER_TEST_PAUSE=1 cargo test --manifest-path ./leptos-keycloak-auth/Cargo.toml -- --nocapture test_integration

# Run `cargo update` for every crate, updating the dependencies of all crates to the latest non-breaking version.
# Rewrites Cargo.lock files.
update:
  cargo update --manifest-path ./leptos-keycloak-auth/Cargo.toml
  cargo update --manifest-path ./test-frontend/Cargo.toml

# Run `cargo upgrades` for every crate, checking if new crate versions including potentially breaking changes are
# available.
upgrades: # "-" prefixes allow for non-zero status codes!
  -cargo upgrades --manifest-path ./leptos-keycloak-auth/Cargo.toml
  -cargo upgrades --manifest-path ./test-frontend/Cargo.toml

# Run `cargo upgrade` for every crate, automatically bumping all dependencies to their latest versions.
upgrade: # "-" prefixes allow for non-zero status codes!
  -cargo upgrade --manifest-path ./leptos-keycloak-auth/Cargo.toml
  -cargo upgrade --manifest-path ./test-frontend/Cargo.toml

# Compile all crates. Cargo only picks up the test-frontend's `.cargo/config.toml` when run in its directory, so
# test-frontend commands pass it explicitly using `--config`.
check:
  cargo check --manifest-path ./leptos-keycloak-auth/Cargo.toml --tests
  cargo check --manifest-path ./leptos-keycloak-auth/Cargo.toml --tests --features ssr
  cargo check --manifest-path ./test-frontend/Cargo.toml --config ./test-frontend/.cargo/config.toml --tests
  cargo check --manifest-path ./test-frontend/Cargo.toml --config ./test-frontend/.cargo/config.toml --tests --features ssr

# Run `cargo clippy --tests` for every crate. The crates deny `clippy::all` and `clippy::pedantic` in their `[lints]`.
# Runs all lints, even if one fails, but fails at the end should any of them have failed.
clippy:
  #!/usr/bin/env bash
  status=0
  cargo clippy --manifest-path ./leptos-keycloak-auth/Cargo.toml --tests || status=1
  cargo clippy --manifest-path ./leptos-keycloak-auth/Cargo.toml --tests --features ssr || status=1
  cargo clippy --manifest-path ./test-frontend/Cargo.toml --config ./test-frontend/.cargo/config.toml --tests || status=1
  cargo clippy --manifest-path ./test-frontend/Cargo.toml --config ./test-frontend/.cargo/config.toml --tests --features ssr || status=1
  exit $status

# Build the library's documentation.
docs:
  cargo doc --manifest-path ./leptos-keycloak-auth/Cargo.toml --no-deps

# Update all dependencies, sort all Cargo.toml dependencies and format all code.
tidy:
  just update
  just sort
  just fmt
  just leptosfmt

# Run the full non-mutating validation suite: format checks, check, lint, all tests and docs.
verify:
  just fmt-check
  just leptosfmt-check
  just check
  just clippy
  just test # includes browser-test
  just docs
