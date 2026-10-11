use std::path::{Path, PathBuf};

/// Where cargo-leptos serves the test-frontend. Must match `site-addr` in its `Cargo.toml`.
pub const ADDR: &str = "127.0.0.1:3000";

/// The test-frontend's origin. Must match `BASE_URL` in its `routes.rs`.
pub fn origin() -> String {
    format!("http://{ADDR}")
}

/// Resolve the absolute path to the `test-frontend` crate directory.
pub fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../test-frontend")
        .canonicalize()
        .expect("Resolving the test-frontend directory")
}

/// Materialize a `.env` file in the test-frontend directory from `.env.template`, substituting
/// `{kc_port_placeholder}` with the running Keycloak container port.
///
/// The frontend's `dotenv_codegen::dotenv!` macro reads this file at compile time, so it must
/// exist on disk before `cargo leptos serve` is invoked. Changes don't trigger a recompilation, so
/// the frontend's server reads the Keycloak port at runtime instead.
pub fn write_dotenv(fe_dir: &Path, keycloak_port: u16) {
    let template = fe_dir.join(".env.template");
    let dotenv = fe_dir.join(".env");

    let rendered = std::fs::read_to_string(&template)
        .unwrap_or_else(|err| panic!("Reading {}: {err:?}", template.display()))
        .replace("{kc_port_placeholder}", &keycloak_port.to_string());

    std::fs::write(&dotenv, rendered)
        .unwrap_or_else(|err| panic!("Writing {}: {err:?}", dotenv.display()));
}
