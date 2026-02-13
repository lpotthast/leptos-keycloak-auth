use snafu::Snafu;

use crate::request::RequestError;

/// An enumeration representing various authentication-related errors.
#[derive(Debug, Snafu)]
pub enum KeycloakAuthError {
    #[snafu(display("KeycloakAuthError: Request error"))]
    Request { source: RequestError },

    #[snafu(display("KeycloakAuthError: Could not handle parameters: {err}"))]
    Params {
        err: leptos_router::params::ParamsError,
    },

    #[snafu(display("KeycloakAuthError: Could not serialize or deserialize data: {source}"))]
    Serde { source: serde_json::Error },
}
