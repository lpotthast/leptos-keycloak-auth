use leptos_router::params::{ParamsError, ParamsMap};
use serde::{Deserialize, Serialize};

/// An enumeration representing different callback responses during the
/// authentication process.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) enum CallbackResponse {
    SuccessfulLogin(SuccessLoginResponse),
    SuccessfulLogout(SuccessLogoutResponse),
    Error(ErrorResponse),
}

/// A structure representing a successful login callback response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct SuccessLoginResponse {
    pub code: String,
    pub session_state: Option<String>,
}

/// A structure representing a successful logout callback response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct SuccessLogoutResponse {
    pub destroy_session: bool,

    /// Should contain the csrf token that we sent as part of our `post_logout_redirect_uri`.
    pub state: Option<String>,
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

/// See [RFC 6749 Section 5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2) for details.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum KnownOidcErrorCode {
    /// The request is missing a required parameter, includes an unsupported parameter value
    /// (other than grant type), repeats a parameter, includes multiple credentials,
    /// utilizes more than one mechanism for authenticating the client, or is otherwise malformed.
    #[serde(rename = "invalid_request")]
    InvalidRequest,

    /// Client authentication failed (e.g., unknown client, no client authentication included,
    /// or unsupported authentication method). The authorization server MAY return an HTTP 401
    /// (Unauthorized) status code to indicate which HTTP authentication schemes are supported.
    /// If the client attempted to authenticate via the "Authorization" request header field, the
    /// authorization server MUST respond with an HTTP 401 (Unauthorized) status code and include
    /// the "WWW-Authenticate" response header field matching the authentication scheme used by the
    /// client.
    #[serde(rename = "invalid_client")]
    InvalidClient,

    /// The provided authorization grant (e.g., authorization code, resource owner credentials) or
    /// refresh token is invalid, expired, revoked, does not match the redirection URI used in the
    /// authorization request, or was issued to another client.
    #[serde(rename = "invalid_grant")]
    InvalidGrant,

    /// The authenticated client is not authorized to use this authorization grant type.
    #[serde(rename = "unauthorized_client")]
    UnauthorizedClient,

    /// The authorization grant type is not supported by the authorization server.
    #[serde(rename = "unsupported_grant_type")]
    UnsupportedGrantType,

    /// The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the
    /// resource owner.
    #[serde(rename = "invalid_scope")]
    InvalidScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum OidcErrorCode {
    Known(KnownOidcErrorCode),
    Unknown(String),
}

/// OAuth/OIDC error response received from Keycloak.
///
/// This structure represents error responses returned by Keycloak during
/// authentication, token exchange, or token refresh operations. Errors follow
/// the OAuth 2.0 error response format.
///
/// # Common Error Codes
/// - `access_denied`: The user or authorization server denied the request
/// - `server_error`: The authorization server encountered an error
///
/// See [RFC 6749 Section 5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2) for details.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ErrorResponse {
    /// The error code (e.g., `invalid_client` or `invalid_grant`).
    pub error: OidcErrorCode,

    /// OPTIONAL. Human-readable ASCII [US-ASCII] text providing additional information, used to
    /// assist the client developer in understanding the error that occurred. Values for the
    /// `error_description` parameter MUST NOT include characters outside the set
    /// `%x20-21 / %x23-5B / %x5D-7E`.
    pub error_description: Option<String>,

    /// OPTIONAL. A URI identifying a human-readable web page with information about the error,
    /// used to provide the client developer with additional information about the error. Values
    /// for the `error_uri` parameter MUST conform to the URI-reference syntax and thus MUST NOT
    /// include characters outside the set `%x21 / %x23-5B / %x5D-7E`.
    pub error_uri: Option<String>,
}

impl ErrorResponse {
    /// Check if this represents an invalid or expired refresh token.
    pub fn is_invalid_refresh_token(&self) -> bool {
        self.error == OidcErrorCode::Known(KnownOidcErrorCode::InvalidGrant)
            && self
                .error_description
                .as_deref()
                .unwrap_or_default()
                .eq_ignore_ascii_case("Invalid refresh token")
    }

    /// Check if this represents a "Session not active" error.
    /// In that case, any still known refresh token can be dropped, as the user was logged out.
    pub fn is_session_not_active(&self) -> bool {
        self.error == OidcErrorCode::Known(KnownOidcErrorCode::InvalidGrant)
            && self
                .error_description
                .as_deref()
                .unwrap_or_default()
                .eq_ignore_ascii_case("Session not active")
    }

    /// Check if this error likely indicates the session has ended, regardless of the specific
    /// error description. Any `invalid_grant` error suggests the session or token is no longer
    /// valid. Use this as a fallback when the specific error description is not recognized.
    pub fn is_likely_session_ended(&self) -> bool {
        self.error == OidcErrorCode::Known(KnownOidcErrorCode::InvalidGrant)
    }
}

/// A trait for converting parameters from a map to a structure for
/// `SuccessCallbackResponse`.
impl leptos_router::params::Params for SuccessLoginResponse {
    fn from_map(map: &ParamsMap) -> Result<Self, ParamsError> {
        let Some(code) = map.get("code") else {
            return Err(ParamsError::MissingParam(
                "Missing query parameter 'code'.".to_string(),
            ));
        };

        let session_state = map.get("session_state");

        Ok(SuccessLoginResponse {
            code,
            session_state,
        })
    }
}

/// A trait for converting parameters from a map to a structure for
/// `SuccessLogoutResponse`.
impl leptos_router::params::Params for SuccessLogoutResponse {
    fn from_map(map: &ParamsMap) -> Result<Self, ParamsError> {
        let Some(destroy_session) = map.get("destroy_session") else {
            return Err(ParamsError::MissingParam(
                "Missing query parameter 'destroy_session'.".to_string(),
            ));
        };
        let destroy_session: bool = destroy_session
            .parse()
            .inspect_err(|err| {
                tracing::error!("Could not parse `destroy_session` query parameter as bool: {err}");
            })
            .unwrap_or_default();

        // Parse optional state parameter
        let state = map.get("state");

        Ok(SuccessLogoutResponse {
            destroy_session,
            state,
        })
    }
}

/// A trait for converting parameters from a map to a structure for
/// `ErrorResponse`.
impl leptos_router::params::Params for ErrorResponse {
    fn from_map(map: &ParamsMap) -> Result<Self, ParamsError> {
        let Some(error) = map.get("error") else {
            return Err(ParamsError::MissingParam(
                "Missing query parameter 'error'.".to_string(),
            ));
        };
        let Ok(error) = serde_json::from_str::<OidcErrorCode>(&format!("\"{error}\"")) else {
            return Err(ParamsError::MissingParam(
                "Could not parse query parameter 'error' as `OidcErrorCode`.".to_string(),
            ));
        };

        let error_description = map.get("error_description");
        let error_uri = map.get("error_uri");

        Ok(ErrorResponse {
            error,
            error_description,
            error_uri,
        })
    }
}

/// A trait for converting parameters from a map to a structure for `CallbackResponse`.
impl leptos_router::params::Params for CallbackResponse {
    fn from_map(map: &ParamsMap) -> Result<Self, ParamsError> {
        match SuccessLoginResponse::from_map(map) {
            Ok(response) => Ok(CallbackResponse::SuccessfulLogin(response)),
            Err(_) => match SuccessLogoutResponse::from_map(map) {
                Ok(response) => Ok(CallbackResponse::SuccessfulLogout(response)),
                Err(_) => match ErrorResponse::from_map(map) {
                    Ok(response) => Ok(CallbackResponse::Error(response)),
                    Err(err) => {
                        // Note: This is the expected code path when there are no query parameters!
                        // We therefore do not log anything error here.
                        Err(ParamsError::MissingParam(format!(
                            "Could not parse query parameters into any expected Keycloak response: {err}"
                        )))
                    }
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use assertr::{assert_that, prelude::*};

    use crate::response::{ErrorResponse, KnownOidcErrorCode, OidcErrorCode};

    #[test]
    fn deserialize_known_error_code() {
        let error = "invalid_grant";
        let parsed = serde_json::from_str::<OidcErrorCode>(&format!("\"{error}\"")).unwrap();
        assert_that(parsed).is_equal_to(OidcErrorCode::Known(KnownOidcErrorCode::InvalidGrant));
    }

    #[test]
    fn deserialize_unknown_error_code() {
        let error = "some_unknown_error";
        let parsed = serde_json::from_str::<OidcErrorCode>(&format!("\"{error}\"")).unwrap();
        assert_that(parsed).is_equal_to(OidcErrorCode::Unknown(error.to_owned()));
    }

    fn make_error_response(description: &str) -> ErrorResponse {
        ErrorResponse {
            error: OidcErrorCode::Known(KnownOidcErrorCode::InvalidGrant),
            error_description: Some(description.to_string()),
            error_uri: None,
        }
    }

    #[test]
    fn is_invalid_refresh_token_exact_match() {
        let err = make_error_response("Invalid refresh token");
        assert_that(err.is_invalid_refresh_token()).is_true();
    }

    #[test]
    fn is_invalid_refresh_token_case_insensitive() {
        let err = make_error_response("invalid refresh token");
        assert_that(err.is_invalid_refresh_token()).is_true();

        let err = make_error_response("INVALID REFRESH TOKEN");
        assert_that(err.is_invalid_refresh_token()).is_true();

        let err = make_error_response("Invalid Refresh Token");
        assert_that(err.is_invalid_refresh_token()).is_true();
    }

    #[test]
    fn is_invalid_refresh_token_wrong_description() {
        let err = make_error_response("Token is not active");
        assert_that(err.is_invalid_refresh_token()).is_false();
    }

    #[test]
    fn is_invalid_refresh_token_no_description() {
        let err = ErrorResponse {
            error: OidcErrorCode::Known(KnownOidcErrorCode::InvalidGrant),
            error_description: None,
            error_uri: None,
        };
        assert_that(err.is_invalid_refresh_token()).is_false();
    }

    #[test]
    fn is_invalid_refresh_token_wrong_error_code() {
        let err = ErrorResponse {
            error: OidcErrorCode::Known(KnownOidcErrorCode::InvalidClient),
            error_description: Some("Invalid refresh token".to_string()),
            error_uri: None,
        };
        assert_that(err.is_invalid_refresh_token()).is_false();
    }

    #[test]
    fn is_session_not_active_exact_match() {
        let err = make_error_response("Session not active");
        assert_that(err.is_session_not_active()).is_true();
    }

    #[test]
    fn is_session_not_active_case_insensitive() {
        let err = make_error_response("session not active");
        assert_that(err.is_session_not_active()).is_true();

        let err = make_error_response("SESSION NOT ACTIVE");
        assert_that(err.is_session_not_active()).is_true();
    }

    #[test]
    fn is_session_not_active_wrong_description() {
        let err = make_error_response("Invalid refresh token");
        assert_that(err.is_session_not_active()).is_false();
    }

    #[test]
    fn is_likely_session_ended_any_invalid_grant() {
        let err = make_error_response("Some completely unknown message");
        assert_that(err.is_likely_session_ended()).is_true();
    }

    #[test]
    fn is_likely_session_ended_false_for_other_codes() {
        let err = ErrorResponse {
            error: OidcErrorCode::Known(KnownOidcErrorCode::InvalidClient),
            error_description: Some("whatever".to_string()),
            error_uri: None,
        };
        assert_that(err.is_likely_session_ended()).is_false();
    }

    #[test]
    fn is_likely_session_ended_false_for_unknown_codes() {
        let err = ErrorResponse {
            error: OidcErrorCode::Unknown("custom_error".to_string()),
            error_description: Some("whatever".to_string()),
            error_uri: None,
        };
        assert_that(err.is_likely_session_ended()).is_false();
    }
}
