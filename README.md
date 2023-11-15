# leptos-keycloak-auth

**Important notice:**

This crate awaits a mew release of its `jsonwebtoken` dependency. Taken from the dependency definition`Cargo.toml`:

The "master" branch contains an unreleased wasm fix, fixing a "time is not implemented..." bug when decoding a JWT. TODO: Update, as soon as a version newer than 9.1.0 is out! This crate might not work as intended when used from crates.io.
