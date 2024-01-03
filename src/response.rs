use leptos_router::{Params, ParamsError, ParamsMap};
use serde::{Deserialize, Serialize};

/// An enumeration representing different callback responses during the
/// authentication process.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) enum CallbackResponse {
    SuccessLogin(SuccessCallbackResponse),
    SuccessLogout(SuccessLogoutResponse),
    Error(ErrorResponse),
}

/// A structure representing a successful login callback response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct SuccessCallbackResponse {
    pub session_state: Option<String>,
    pub code: String,
}

/// A structure representing a successful logout callback response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct SuccessLogoutResponse {
    pub destroy_session: bool,
}

/// An enumeration representing the response to token requests, including
/// success and error responses.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum TokenResponse {
    Success(SuccessTokenResponse),
    Error(ErrorResponse),
}

/// A structure representing a successful token response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct SuccessTokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub refresh_expires_in: Option<i64>,
    pub refresh_token: String,
    pub token_type: Option<String>,
    pub id_token: String,
    #[serde(rename = "not-before-policy")]
    pub not_before_policy: Option<i64>,
    pub session_state: Option<String>,
    pub scope: Option<String>,
}

/// A structure representing an error response during the authentication
/// process.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
}

/// A trait for converting parameters from a map to a structure for
/// `SuccessCallbackResponse`.
impl Params for SuccessCallbackResponse {
    fn from_map(map: &ParamsMap) -> Result<Self, ParamsError> {
        if let (session_state, Some(code)) = (map.get("session_state"), map.get("code")) {
            return Ok(SuccessCallbackResponse {
                session_state: session_state.cloned(),
                code: code.clone(),
            });
        }
        Err(ParamsError::MissingParam(
            "Missing parameter 'code'".to_string(),
        ))
    }
}

/// A trait for converting parameters from a map to a structure for
/// `SuccessLogoutResponse`.
impl Params for SuccessLogoutResponse {
    fn from_map(map: &ParamsMap) -> Result<Self, ParamsError> {
        if let Some(destroy_session) = map.get("destroy_session") {
            return Ok(SuccessLogoutResponse {
                destroy_session: destroy_session.parse().unwrap_or_default(),
            });
        }
        Err(ParamsError::MissingParam(
            "Missing parameter 'destroy_session'".to_string(),
        ))
    }
}

/// A trait for converting parameters from a map to a structure for
/// `ErrorResponse`.
impl Params for ErrorResponse {
    fn from_map(map: &ParamsMap) -> Result<Self, ParamsError> {
        if let (Some(error), Some(error_description)) =
            (map.get("error"), map.get("error_description"))
        {
            return Ok(ErrorResponse {
                error: error.clone(),
                error_description: error_description.clone(),
            });
        }
        Err(ParamsError::MissingParam(
            "Missing parameter 'error' and 'error_description'".to_string(),
        ))
    }
}

/// A trait for converting parameters from a map to a structure for
/// `CallbackResponse`.
impl Params for CallbackResponse {
    fn from_map(map: &ParamsMap) -> Result<Self, ParamsError> {
        if let Ok(response) = SuccessCallbackResponse::from_map(map) {
            return Ok(CallbackResponse::SuccessLogin(response));
        } else if let Ok(response) = SuccessLogoutResponse::from_map(map) {
            return Ok(CallbackResponse::SuccessLogout(response));
        } else if let Ok(response) = ErrorResponse::from_map(map) {
            return Ok(CallbackResponse::Error(response));
        }

        Err(ParamsError::MissingParam(
            "Missing parameter 'session_state' and 'code' or 'error' and 'error_description'"
                .to_string(),
        ))
    }
}
