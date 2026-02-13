use std::time::Duration as StdDuration;

use leptos::prelude::{RwSignal, Signal};
use snafu::Snafu;
use url::{PathSegmentsMut, Url};

use crate::DiscoveryEndpoint;

/// Specifies how much lifetime must remain for a token to not be considered "nearly expired".
///
/// This is used to determine when tokens should be refreshed proactively, before they actually
/// expire.
/// Refreshing tokens before expiration provides a better user experience by avoiding authentication
/// errors during active sessions. (An expired token would still potentially be handled by a retry
/// when our [`AuthenticatedClient`](crate::authenticated_client::AuthenticatedClient) is used.)
///
/// # Variants
/// - **Percentage**: Token is nearly expired if remaining lifetime is ≤ this percentage of total lifetime
///   (e.g., `Percentage(0.25)` means refresh when 25% or less of lifetime remains)
/// - **Duration**: Token is nearly expired if remaining lifetime is ≤ this duration
///   (e.g., `Duration(Duration::from_secs(60))` means refresh when 60 seconds or less remain)
#[derive(Debug, Clone, Copy)]
pub enum LifeLeft {
    /// Token is nearly expired when remaining lifetime ≤ this percentage of total lifetime.
    ///
    /// Value should be between 0.0 and 1.0 (e.g., 0.25 = 25%).
    Percentage(f64),

    /// Token is nearly expired when remaining lifetime ≤ this absolute duration.
    Duration(StdDuration),
}

impl LifeLeft {
    /// Check if a token is nearly expired based on the configured threshold.
    ///
    /// # Parameters
    /// - `lifetime`: The total lifetime of the token (time between issued-at and expiration).
    /// - `left`: The remaining lifetime of the token (time until expiration).
    ///
    /// # Returns
    /// `true` if the token should be considered nearly expired and should be refreshed.
    ///
    /// # Example
    /// ```
    /// use std::time::Duration;
    /// use leptos_keycloak_auth::LifeLeft;
    ///
    /// let lifetime = Duration::from_hours(1);
    /// let left = Duration::from_mins(10);
    ///
    /// // Check with percentage threshold (25% = 15 minutes). But 10 min < 15 min!
    /// let by_percentage = LifeLeft::Percentage(0.25);
    /// assert!(by_percentage.nearly_expired(lifetime, left));
    ///
    /// // Check with absolute duration threshold (5 minutes). But 10 min < 15 min!
    /// let by_duration = LifeLeft::Duration(Duration::from_mins(15));
    /// assert!(by_duration.nearly_expired(lifetime, left));
    /// ```
    #[must_use]
    pub fn nearly_expired(self, lifetime: StdDuration, left: StdDuration) -> bool {
        match self {
            LifeLeft::Percentage(p) => {
                let lifetime = lifetime.as_secs_f64();
                if lifetime == 0.0 {
                    true
                } else {
                    (left.as_secs_f64() / lifetime) <= p
                }
            }
            LifeLeft::Duration(d) => left <= d,
        }
    }
}

/// Configuration for ID token validation.
///
/// These options control how the ID token received from Keycloak is validated.
/// Proper validation ensures that tokens are only accepted from trusted issuers and are intended
/// for your application.
///
/// # Security Note
/// It's recommended to set both `expected_audiences` and `expected_issuers` for production
/// applications to prevent token replay attacks and ensure tokens are only accepted from your
/// Keycloak instance.
#[derive(Debug, Clone)]
pub struct IdTokenValidationOptions {
    /// Expected audience(s) (`aud` claim) in the ID token.
    ///
    /// Set this to your client ID to ensure the token was issued for your application.
    /// If `None`, audience validation is skipped (not recommended for production).
    ///
    /// # Example
    /// ```
    /// use leptos_keycloak_auth::IdTokenValidationOptions;
    ///
    /// let validation = IdTokenValidationOptions {
    ///     expected_audiences: Some(vec!["my-client-id".to_string()]),
    ///     expected_issuers: Some(vec![
    ///         "https://keycloak.example.com/realms/myrealm".to_string()
    ///     ]),
    /// };
    /// ```
    pub expected_audiences: Option<Vec<String>>,

    /// Expected issuer(s) (`iss` claim) in the ID token.
    ///
    /// Set this to your Keycloak realm's issuer URL to ensure the token came from
    /// your Keycloak instance. The issuer URL typically follows the pattern:
    /// `https://your-keycloak.example.com/realms/your-realm`
    ///
    /// If `None`, issuer validation is skipped (not recommended for production).
    ///
    /// # Example
    /// ```
    /// use leptos_keycloak_auth::IdTokenValidationOptions;
    ///
    /// let validation = IdTokenValidationOptions {
    ///     expected_audiences: Some(vec!["my-client-id".to_string()]),
    ///     expected_issuers: Some(vec![
    ///         "https://keycloak.example.com/realms/myrealm".to_string()
    ///     ]),
    /// };
    /// ```
    pub expected_issuers: Option<Vec<String>>,
}

/// Represents authentication parameters required for initializing the `Auth`
/// structure. These parameters include authentication and token endpoints,
/// client ID, and other related data.
#[derive(Debug, Clone)]
pub struct UseKeycloakAuthOptions {
    /// Url of your keycloak instance, E.g. <https://localhost:8443>
    pub keycloak_server_url: Url,

    /// The keycloak realm you want to use.
    pub realm: String,

    /// The name of this client as configured inside your Keycloak admin area.
    pub client_id: String,

    /// Url to which you want to be redirected after a successful login.
    ///
    /// It is MANDATORY that this redirects to a URL where `init_keycloak_auth` is called in order
    /// to be able to complete the login flow.
    pub post_login_redirect_url: Signal<Url>,

    /// Url to which you want to be redirected after a successful logout.
    ///
    /// It is MANDATORY that this redirects to a URL where `init_keycloak_auth` is called in order
    /// to be able to complete the login flow.
    pub post_logout_redirect_url: Signal<Url>,

    /// The additional scopes (permissions / access-levels) requested from Keycloak.
    ///
    /// We will always make sure that the mandatory `openid` scope is present,
    /// so you can use an empty Vec as a starting point.
    pub scope: Vec<String>,

    /// Configuration for the validation of the ID token.
    pub id_token_validation: IdTokenValidationOptions,

    /// It is recommended to just use `Default::default()` here.
    pub advanced: AdvancedOptions,
}

#[derive(Debug, Clone)]
pub struct AdvancedOptions {
    /// Interval after which the access token should be checked for its age.
    /// This has to happen frequently in order to detect an access token becoming expired.
    ///
    /// Defaults to `Duration::from_millis(500)`.
    pub access_token_age_check_interval: StdDuration,

    /// Interval after which the refresh token should be checked for its age.
    /// This has to happen frequently in order to detect a refresh token becoming expired.
    ///
    /// Defaults to `Duration::from_millis(500)`.
    pub refresh_token_age_check_interval: StdDuration,

    /// Describes how much time must be left for the access token to not count as "nearly expired".
    /// If any token is nearly expired, a refresh is triggered.
    ///
    /// Defaults to `LifeLeft::Percentage(0.25)`.
    pub access_token_nearly_expired_having: LifeLeft,

    /// Describes how much time must be left for the refresh token to not count as "nearly expired".
    /// If any token is nearly expired, a refresh is triggered.
    ///
    /// Defaults to `LifeLeft::Percentage(0.25)`.
    pub refresh_token_nearly_expired_having: LifeLeft,

    /// Interval after which the oidc configuration should be checked for its age.
    ///
    /// Defaults to `Duration::from_secs(3)`.
    pub oidc_config_age_check_interval: StdDuration,

    /// Interval after which the jwk set should be checked for its age.
    ///
    /// Defaults to `Duration::from_secs(3)`.
    pub jwk_set_age_check_interval: StdDuration,

    /// Time after which a discovered OIDC config is considered too old.
    ///
    /// Defaults to `Duration::from_secs(60 * 5)`.
    pub max_oidc_config_age: StdDuration,

    /// Time after which the loaded JWK set is considered too old.
    /// After this age is reached, a new set of JWKs is queried for.
    /// If it didn't change, nothing will happen.
    ///
    /// Defaults to `Duration::from_secs(60 * 5)`.
    pub max_jwk_set_age: StdDuration,

    /// Enable CSRF detection for the logout flow.
    ///
    /// When enabled (default), logout URLs will include a `state` parameter that is validated
    /// on the logout callback to detect potential CSRF logout attacks.
    ///
    /// **Note**: This detects CSRF attacks but does not prevent them. Keycloak processes the
    /// logout before returning control to our application. However, detection is valuable for:
    /// - Notifying users about suspicious logouts.
    /// - Security monitoring and incident response.
    ///
    /// Defaults to `true`.
    pub logout_csrf_detection: bool,

    /// Enable nonce validation for ID tokens.
    ///
    /// Nonce validation protects against ID token replay attacks by ensuring each ID token is bound
    /// to a specific authorization request. The nonce is a cryptographically random value that is:
    /// - Generated by the client before redirecting to Keycloak's authorization endpoint.
    /// - Included in the authorization request.
    /// - Returned by Keycloak in the ID token's `nonce` claim.
    /// - Validated by the client to match the original value.
    ///
    /// Defaults to `true`.
    pub nonce_validation: bool,
}

impl Default for AdvancedOptions {
    fn default() -> Self {
        Self {
            access_token_age_check_interval: StdDuration::from_millis(500),
            refresh_token_age_check_interval: StdDuration::from_millis(500),
            access_token_nearly_expired_having: LifeLeft::Percentage(0.25),
            refresh_token_nearly_expired_having: LifeLeft::Percentage(0.25),
            oidc_config_age_check_interval: StdDuration::from_secs(3),
            jwk_set_age_check_interval: StdDuration::from_secs(3),
            max_oidc_config_age: StdDuration::from_secs(60 * 5),
            max_jwk_set_age: StdDuration::from_secs(60 * 5),
            logout_csrf_detection: true,
            nonce_validation: true,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ValidationOptionsInternal {
    pub(crate) expected_audiences: RwSignal<Option<Vec<String>>>,
    pub(crate) expected_issuers: RwSignal<Option<Vec<String>>>,
}

/// Represents authentication parameters required for initializing the `Auth`
/// structure. These parameters include authentication and token endpoints,
/// client ID, and other related data.
#[derive(Debug, Clone)]
pub(crate) struct Options {
    pub(crate) keycloak_server_url: BaseUrl,
    pub(crate) realm: String,
    pub(crate) client_id: String,
    pub(crate) post_login_redirect_url: Signal<Url>,
    pub(crate) post_logout_redirect_url: Signal<Url>,
    pub(crate) scope: Vec<String>,
    pub(crate) id_token_validation: ValidationOptionsInternal,
    pub(crate) advanced: AdvancedOptions,
}

impl Options {
    pub(crate) fn new(options: UseKeycloakAuthOptions) -> Self {
        Self {
            keycloak_server_url: options
                .keycloak_server_url
                .expect_base_url()
                .expect("`keycloak_server_url` to be a base URL."),
            realm: options.realm,
            client_id: options.client_id,
            post_login_redirect_url: options.post_login_redirect_url,
            post_logout_redirect_url: options.post_logout_redirect_url,
            scope: options.scope,
            id_token_validation: ValidationOptionsInternal {
                expected_audiences: RwSignal::new(options.id_token_validation.expected_audiences),
                expected_issuers: RwSignal::new(options.id_token_validation.expected_issuers),
            },
            advanced: options.advanced,
        }
    }

    pub(crate) fn discovery_endpoint(&self) -> DiscoveryEndpoint {
        let mut url = self.keycloak_server_url.clone();
        url.path_segments_mut().extend(&[
            "realms",
            &self.realm,
            ".well-known",
            "openid-configuration",
        ]);
        url.into_inner()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BaseUrl(Url);

impl BaseUrl {
    pub fn path_segments_mut(&mut self) -> PathSegmentsMut<'_> {
        self.0
            .path_segments_mut()
            .expect("Unreachable. This type is only constructed with base URLs.")
    }

    pub fn into_inner(self) -> Url {
        self.0
    }
}

#[derive(Debug, Snafu)]
#[snafu(display(
    "'{}' must not be a cannot-be-a-base URL. This URL must be usable as a base to prefix other relative urls with. Did you specify a 'data:' or 'mailto:' address?",
    url.as_str()
))]
pub struct NotABaseUrlError {
    url: Url,
}

trait UrlExt {
    fn expect_base_url(self) -> Result<BaseUrl, NotABaseUrlError>;
}

impl UrlExt for Url {
    fn expect_base_url(self) -> Result<BaseUrl, NotABaseUrlError> {
        if self.cannot_be_a_base() {
            return Err(NotABaseUrlError { url: self });
        }
        Ok(BaseUrl(self))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use assertr::prelude::*;

    use crate::LifeLeft;

    mod life_left {
        use super::*;

        #[test]
        fn nearly_expired_can_handle_zero_lifetime_when_computing_percentage() {
            let ll = LifeLeft::Percentage(0.25);
            let result = ll.nearly_expired(Duration::ZERO, Duration::from_secs(10));
            assert_that(result).is_true();
        }
    }
}
