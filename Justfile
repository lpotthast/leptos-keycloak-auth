# Lists all available commands.
list:
  just --list

# Install dependencies for maintenance work, profiling and more...
install-tools:
  cargo install --locked leptosfmt
  cargo install --locked cargo-expand
  cargo install --locked cargo-whatfeatures
  cargo install --locked cargo-upgrades
  cargo install --locked cargo-edit
  cargo install --locked cargo-msrv
  cargo install -f wasm-bindgen-cli --version 0.2.108

# Find the minimum supported rust version
find-msrv:
    cd leptos-keycloak-auth && cargo msrv find

# Run `cargo sort` for every crate.
sort:
  cargo sort ./leptos-keycloak-auth/Cargo.toml -w -g
  cargo sort ./test-frontend/Cargo.toml -w -g

# Run `cargo fmt` for every crate.
fmt:
  cargo fmt --all --manifest-path ./leptos-keycloak-auth/Cargo.toml
  cargo fmt --all --manifest-path ./test-frontend/Cargo.toml

leptosfmt:
  leptosfmt ./leptos-keycloak-auth/src/*
  leptosfmt ./test-frontend/src/*

# Run `cargo test` for every crate.
test:
  cargo test --manifest-path ./leptos-keycloak-auth/Cargo.toml -- --nocapture

# Run `cargo update` for every crate, updating the dependencies of all crates to the latest non-breaking version. Rewrites Cargo.lock files.
update:
  cargo update --manifest-path ./leptos-keycloak-auth/Cargo.toml
  cargo update --manifest-path ./test-frontend/Cargo.toml

# Run `cargo upgrades` for every crate, checking if new crate versions including potentially breaking changes are available.
upgrades: # "-" prefixes allow for non-zero status codes!
  -cargo upgrades --manifest-path ./leptos-keycloak-auth/Cargo.toml
  -cargo upgrades --manifest-path ./test-frontend/Cargo.toml

# Run `cargo upgrade` for every crate, automatically bumping all dependencies to their latest versions.
upgrade: # "-" prefixes allow for non-zero status codes!
  -cargo upgrade --manifest-path ./leptos-keycloak-auth/Cargo.toml
  -cargo upgrade --manifest-path ./test-frontend/Cargo.toml

# Run `cargo clippy --tests -- -Dclippy::all -Dclippy::pedantic` for every crate.
clippy: # "-" prefixes allow for non-zero status codes!
  -cargo clippy --tests --manifest-path ./leptos-keycloak-auth/Cargo.toml -- -Dclippy::all -Dclippy::pedantic
  -cargo clippy --tests --manifest-path ./test-frontend/Cargo.toml -- -Dclippy::all -Dclippy::pedantic
  -cargo clippy --tests --manifest-path ./leptos-keycloak-auth/Cargo.toml --features ssr -- -Dclippy::all -Dclippy::pedantic
  -cargo clippy --tests --manifest-path ./test-frontend/Cargo.toml --features ssr -- -Dclippy::all -Dclippy::pedantic
