# Lists all available commands.
list:
  just --list

# Install dependencies for maintenance work, profiling and more...
install-tools:
  cargo install leptosfmt
  cargo install cargo-expand
  cargo install cargo-whatfeatures
  cargo install cargo-upgrades
  cargo install cargo-edit

# Find the minimum supported rust version
msrv:
    cargo install cargo-msrv
    cargo msrv --min "2021"

# Run `cargo sort` for every crate.
sort:
  cargo sort ./ -w -g

# Run `cargo fmt` for every crate.
fmt:
  cargo fmt --all --manifest-path ./Cargo.toml

leptosfmt:
  leptosfmt ./src/*

# Run `cargo update` for every crate, updating the dependencies of all crates to the latest non-breaking version. Rewrites Cargo.lock files.
update:
  cargo update --manifest-path ./Cargo.toml

# Run `cargo test` for every crate.
test:
  cargo test --manifest-path ./Cargo.toml

# Run `cargo upgrades` for every crate, checking if new crate versions including potentially breaking changes are available.
upgrades: # "-" prefixes allow for non-zero status codes!
  -cargo upgrades --manifest-path ./Cargo.toml

# Run `cargo upgrade` for every crate, automatically bumping all dependencies to their latest versions
upgrade: # "-" prefixes allow for non-zero status codes!
  -cargo upgrade --manifest-path ./Cargo.toml

# Run `cargo clippy --tests -- -Dclippy::all -Dclippy::pedantic` for every crate.
clippy: # "-" prefixes allow for non-zero status codes!
  -cargo clippy --tests --manifest-path ./Cargo.toml -- -Dclippy::all -Dclippy::pedantic
