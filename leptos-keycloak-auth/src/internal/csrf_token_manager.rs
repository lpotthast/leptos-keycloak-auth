use crate::csrf_token::CsrfToken;
use crate::storage::{use_storage_with_options_and_error_handler, UseStorageReturn};
use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos_use::storage::StorageType;

/// Manages CSRF tokens for operations to detect CSRF attacks.
///
/// This enables detection of CSRF logout attacks. Note though that such attacks cannot be prevented
/// (Keycloak will process the logout before returning control to the application).
///
/// # Internal Use
/// This is an internal component exposed via the `internals` feature flag for advanced
/// use cases like testing or debugging.
#[derive(Clone, Copy, Debug)]
pub struct CsrfTokenManager {
    /// The currently active logout token.
    logout_token: Signal<CsrfToken>,

    /// Setter for the logout token.
    set_logout_token: Callback<CsrfToken>,
}

impl CsrfTokenManager {
    /// Create a new CSRF manager.
    pub fn new() -> Self {
        // We keep the logout_token, used for the logout source verification in session storage.
        // We cannot keep it completely in-memory, as our logout flow includes
        // navigating away from our Leptos application to the Keycloak logout URL and then
        // being redirected back to our application, meaning that we do a full page reload!
        // We have to compare the logout_token that we put into the logout request and which
        // is going to be relayed by Keycloak back to us without accidentally generating a new
        // logout_token on reload.
        let UseStorageReturn {
            read: logout_token,
            write: set_logout_token,
            remove: _remove_logout_token_from_storage,
            ..
        } = use_storage_with_options_and_error_handler::<CsrfToken, JsonSerdeCodec>(
            // Forcing session storage, because this data point must be as secure as possible,
            // and we do not care that we may lose the code from a page-refresh or tab-close.
            StorageType::Session,
            "leptos_keycloak_auth__logout_token",
            move || {
                tracing::trace!("Create initial logout csrf token");
                CsrfToken::new()
            },
        );

        Self {
            logout_token,
            set_logout_token,
        }
    }

    pub fn logout_token(&self) -> Signal<CsrfToken> {
        self.logout_token
    }

    /// Validates that a seen logout csrf token is the same as the one we are currently storing.
    ///
    /// # Parameters
    /// - `received`: The state parameter received in the logout callback.
    ///
    /// # Returns
    /// - `true` if the token matches the expected value.
    /// - `false` if the token doesn't match.
    pub fn validate_logout_token(&self, received_token: Option<&str>) -> bool {
        let expected_token = self.logout_token().read_untracked();
        let expected_token = expected_token.as_str();

        if expected_token.is_empty() {
            tracing::warn!(
                "Logout token validation must not be triggered when we can't expect anything."
            );
            return false;
        }

        if received_token.is_none() {
            tracing::warn!(
                expected_token,
                "Logout CSRF token validation failed. No token was present in logout response. User was logged out via potential CSRF attack."
            );
            return false;
        }
        let received_token = received_token.unwrap();

        // Although we compare secret tokens, this does not need to be time-attack safe.
        // Attackers hav no way to repeatedly trigger this validation without `expected` changing.
        let is_valid = expected_token == received_token;
        if is_valid {
            tracing::trace!("Validation of the logout CSRF token succeeded.");
        } else {
            tracing::warn!(
                expected_token,
                received_token,
                "Logout CSRF token validation failed. Tokens are not equal. User was logged out via potential CSRF attack."
            );
        }
        is_valid
    }

    pub fn regenerate(&self) {
        self.set_logout_token.run(CsrfToken::new());
    }
}

impl Default for CsrfTokenManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assertr::assert_that;
    use assertr::prelude::*;

    fn cut() -> CsrfTokenManager {
        let (token, set_token) = signal(CsrfToken::new());

        CsrfTokenManager {
            logout_token: token.into(),
            set_logout_token: Callback::new(move |new| set_token.set(new)),
        }
    }

    #[test]
    fn validate_correct_logout_token() {
        let manager = cut();
        assert_that(
            manager.validate_logout_token(Some(manager.logout_token().get_untracked().as_str())),
        )
        .is_true();
    }

    #[test]
    fn validate_no_logout_token() {
        let manager = cut();
        assert_that(manager.validate_logout_token(None)).is_false();
    }

    #[test]
    fn validate_unknown_logout_token() {
        let manager = cut();
        assert_that(manager.validate_logout_token(Some("some_unknown_token"))).is_false();
    }

    #[test]
    fn regenerate_creates_new_logout_token() {
        let manager = cut();
        let initial_token = manager.logout_token().get_untracked();
        assert_that(manager.validate_logout_token(Some(initial_token.as_str()))).is_true();
        manager.regenerate();
        let new_token = manager.logout_token().get_untracked();
        assert_that(manager.validate_logout_token(Some(initial_token.as_str()))).is_false();
        assert_that(manager.validate_logout_token(Some(new_token.as_str()))).is_true();
        assert_that(initial_token.as_str()).is_not_equal_to(new_token.as_str());
    }
}
