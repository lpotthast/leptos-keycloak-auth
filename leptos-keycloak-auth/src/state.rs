use std::{fmt::Debug, ops::Deref, time::Duration as StdDuration};

use leptos::prelude::*;
use leptos_router::{
    NavigateOptions,
    hooks::{use_navigate, use_url},
};
use url::Url;

use crate::{
    AccessToken, TokenEndpoint, action,
    authenticated_client::AuthenticatedClient,
    config::Options,
    error::KeycloakAuthError,
    internal::{derived_urls::DerivedUrlError, token_manager::SessionVersion},
    logout,
    request::RequestError,
    token::TokenData,
    token_claims::KeycloakIdTokenClaims,
    token_validation::IdTokenClaimsError,
};

/// The global state this library tracks for you. Gives access to `login_url` and `logout_url`
/// as well as the current authentication `state`.
///
/// Provided as context. Use
/// ```no_run
/// use leptos::prelude::expect_context;
/// use leptos_keycloak_auth::KeycloakAuth;
///
/// let auth = expect_context::<KeycloakAuth>();
/// ```
/// to get access to the authentication state in any component rendered below the component that
/// performed the `use_keycloak_auth` call.
///
/// What you may want instead is to `expect_context::<Authenticated>()` when in any component
/// rendered under `ShowWhenAuthenticated` and you just want information about the
/// authenticated user. Please also check the documentation for `Authenticated`.
#[derive(Debug, Clone, Copy)]
pub struct KeycloakAuth {
    /// Configuration used to initialize this Keycloak auth provider.
    pub(crate) options: StoredValue<Options>,

    /// URL for initiating the authentication process,
    /// directing the user to the authentication provider's login page.
    /// It may be None until OIDC discovery happened and the URL could be computed.
    pub login_url: Signal<Option<Url>>,

    /// URL for initiating the logout process.
    /// It may be None until OIDC discovery happened and the URL could be computed.
    pub logout_url: Signal<Option<Url>>,

    pub(crate) state: Signal<KeycloakAuthState>,

    /// Derived signal stating `true` when `state` is of the `Authenticated` variant.
    pub is_authenticated: Signal<bool>,

    /// Signal indicating whether the last logout was suspicious (a potential CSRF attack).
    ///
    /// Applications can read this signal to show a warning message to users, such as:
    /// "You may have been logged out by a malicious website."
    ///
    /// This signal resets to `false` on the next successful login.
    pub suspicious_logout: Signal<bool>,

    /// Call this function to dismiss/acknowledge the `suspicious_logout` warning.
    /// This will reset `suspicious_logout` to `false`.
    pub dismiss_suspicious_logout_warning: Callback<()>,

    pub(crate) derived_urls: crate::internal::derived_urls::DerivedUrls,

    #[allow(unused)]
    pub(crate) oidc_config_manager: crate::internal::oidc_config_manager::OidcConfigManager,

    #[allow(unused)]
    pub(crate) jwk_set_manager: crate::internal::jwk_set_manager::JwkSetManager,

    #[allow(unused)]
    pub(crate) code_verifier_manager: crate::internal::code_verifier_manager::CodeVerifierManager,

    pub(crate) token_manager: crate::internal::token_manager::TokenManager,

    #[allow(unused)]
    pub(crate) csrf_token_manager: crate::internal::csrf_token_manager::CsrfTokenManager,

    #[allow(unused)]
    pub(crate) nonce_manager: crate::internal::nonce_manager::NonceManager,

    #[allow(unused)]
    pub(crate) hydration_manager: crate::internal::hydration_manager::HydrationManager,
}

/// Get the current URL (origin + path). Uses a tracking access to the current url.
///
/// # Returns
/// A [`Url`] representing the current page's origin and path (query and fragment are excluded).
///
/// # Panics
/// Panics if the current URL cannot be parsed as a valid URL. This should not occur
/// in normal usage as the URL is constructed from the current route.
#[must_use]
pub fn current_url() -> Url {
    let current = use_url().get();
    // TODO: Why ignore search() / hash()?
    let current = format!("{}{}", current.origin(), current.path());
    Url::parse(&current).expect("Valid url constructed from `use_url` information.")
}

impl KeycloakAuth {
    /// Update the `expected_audiences` used when validating the ID token.
    ///
    /// This will lead to a reactive re-validation of the ID token.
    pub fn set_expected_audiences_for_id_token_validation(
        &self,
        expected_audiences: Option<Vec<String>>,
    ) {
        self.options.with_value(|it| {
            it.id_token_validation
                .expected_audiences
                .set(expected_audiences);
        });
    }

    /// Update the `expected_issuers` used when validating the ID token.
    ///
    /// This will lead to a reactive re-validation of the ID token.
    pub fn set_expected_issuers_for_id_token_validation(
        &self,
        expected_issuers: Option<Vec<String>>,
    ) {
        self.options.with_value(|it| {
            it.id_token_validation
                .expected_issuers
                .set(expected_issuers);
        });
    }

    /// Returns a reactive function that pretty prints the current authentication state.
    ///
    /// Useful for debugging purposes.
    pub fn state_pretty_printer(&self) -> impl Fn() -> String + use<> {
        let state = self.state();
        move || state.read().pretty_printer()()
    }

    /// End the current session of the user by programmatically performing a logout against the
    /// Keycloak server on behalf of the user.
    ///
    /// See also `end_session_and_go_to` if you want to immediately move to a different path after
    /// the logout was performed.
    pub fn end_session(&self) {
        self.end_session_and_go_to(
            self.options
                .read_value()
                .post_logout_redirect_url
                .get_untracked(),
        );
    }

    /// End the current session and navigate to a specified path.
    ///
    /// Performs a logout against the Keycloak server (when OIDC discovery is complete and a token
    /// exists) and then navigates to the specified path. The logout includes the ID token hint and
    /// sets `destroy_session=true` to ensure the Keycloak session is terminated.
    ///
    /// If OIDC discovery hasn't completed or no token exists, this will simply navigate to the path
    /// without performing a server-side logout.
    ///
    /// # Parameters
    /// - `path`: The path to navigate to after logout (e.g., "/login", "/", etc.)
    ///
    /// # Example
    /// ```no_run
    /// use url::Url;
    /// use leptos_keycloak_auth::{use_keycloak_auth};
    ///
    /// let auth = use_keycloak_auth();
    /// auth.end_session_and_go_to(Url::parse("/").unwrap());
    /// ```
    pub fn end_session_and_go_to(&self, path: Url) {
        let navigation_target = match (
            self.derived_urls.end_session_endpoint.get_untracked(),
            // We MUST clone here, as the `token_manager.forget()` will later clear the token data!
            self.token_manager.token.get_untracked(),
        ) {
            (Ok(end_session_endpoint), Some(token)) => logout::create_logout_url(
                end_session_endpoint,
                path,
                Some(token.id_token.as_str()),
                &self.csrf_token_manager.logout_token().read_untracked(),
            ),
            _ => {
                self.forget_session();
                path
            }
        };
        #[cfg(feature = "ssr")]
        {
            unimplemented!(
                "The `end_session` and `end_session_and_go_to` fn's are not implemented in SSR yet. Ensure that these are only called on the client. If you see this in your logs, there is a bug."
            );

            // Note: When full SSR support is implemented:
            // // Let's use the redirect utility from our specific server integration,
            // // e.g., leptos_axum::redirect.
            // tracing::trace!(
            //     "Redirecting to '{}' using leptos_axum.",
            //     navigation_target.as_str()
            // );
            // leptos_axum::redirect(navigation_target.as_str());
        }
        #[cfg(not(feature = "ssr"))]
        {
            let navigate = use_navigate();
            tracing::trace!(
                "Redirecting to '{}' using leptos_router.",
                navigation_target.as_str()
            );
            navigate(navigation_target.as_str(), NavigateOptions::default());
        }
    }

    /// Forget any known token. This is a local operation, not hitting Keycloak in any way.
    /// It immediately locks the user out of protected areas, but does not perform a logout on the
    /// OIDC server. If the user tried to log in again, his session would most likely be restored.
    ///
    /// Unless you have a specific use case for this, it is, in almost all cases, strongly preferred
    /// to either show the user an interactable logout link or use `end_session` to instead perform
    /// a full logout!
    pub fn forget_session(&self) {
        self.token_manager.forget();
    }

    #[cfg(feature = "internals")]
    pub fn derived_urls(&self) -> &crate::internal::derived_urls::DerivedUrls {
        &self.derived_urls
    }

    #[cfg(feature = "internals")]
    pub fn oidc_config_manager(&self) -> &crate::internal::oidc_config_manager::OidcConfigManager {
        &self.oidc_config_manager
    }

    #[cfg(feature = "internals")]
    pub fn jwk_set_manager(&self) -> &crate::internal::jwk_set_manager::JwkSetManager {
        &self.jwk_set_manager
    }

    #[cfg(feature = "internals")]
    pub fn code_verifier_manager(
        &self,
    ) -> &crate::internal::code_verifier_manager::CodeVerifierManager {
        &self.code_verifier_manager
    }

    #[cfg(feature = "internals")]
    pub fn token_manager(&self) -> &crate::internal::token_manager::TokenManager {
        &self.token_manager
    }

    #[cfg(feature = "internals")]
    pub fn csrf_token_manager(&self) -> &crate::internal::csrf_token_manager::CsrfTokenManager {
        &self.csrf_token_manager
    }

    #[cfg(feature = "internals")]
    pub fn nonce_manager(&self) -> &crate::internal::nonce_manager::NonceManager {
        &self.nonce_manager
    }

    /// Returns the authentication state signal.
    ///
    /// This signal is hydration-safe - during the hydration window (on client before hydration
    /// completes), it returns `KeycloakAuthState::Indeterminate`. After hydration completes,
    /// it returns the true authentication state.
    ///
    /// # Example
    /// ```no_run
    /// use leptos::prelude::*;
    /// use leptos_keycloak_auth::{use_keycloak_auth, KeycloakAuthState};
    ///
    /// #[component]
    /// fn Component() -> impl IntoView {
    ///     let auth = use_keycloak_auth();
    ///     view! {
    ///         { move || match auth.state().get() {
    ///             KeycloakAuthState::Authenticated(_) => view! { <p>"Logged in"</p> },
    ///             KeycloakAuthState::NotAuthenticated(_)
    ///                 | KeycloakAuthState::Indeterminate => view! { <p>"Not logged in"</p> },
    ///         }}
    ///     }
    /// }
    /// ```
    #[must_use]
    pub fn state(&self) -> Signal<KeycloakAuthState> {
        self.state
    }
}

/// The current state of authentication.
///
/// - Will be of variant `KeycloakAuthState::Authenticated` if the user was deemed authenticated
///   (which implies him having a validated, non-expired token).
/// - Will be of variant `KeycloakAuthState::NotAuthenticated` if the user was deemed not authenticated.
///   This can be of several reasons:
///      - the library did not receive the OIDC config and JWK set yet.
///      - there is no token, the user did not go through the authentication flow.
///      - the token data contains an expired access token.
///      - the token data contains a non-validatable id token.
///      - ...
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeycloakAuthState {
    /// The Authenticated state is only entered when there is a valid token which did not yet expire.
    /// If you encounter this state, be ensured that the access token can be used to access your API.
    ///
    /// The contained `Authenticated` state provides you:
    /// - An `AuthenticatedClient` (through `client()`) which uses the access token automatically.
    /// - The plain `access_token`, for when you need manual access to it.
    /// - The verified and decoded `id_token_claims`, ready for inspection. These include the users
    ///   id, name, email, roles, ...
    Authenticated(Authenticated),

    /// The user is logged out (no token data is available) or an error occurred during token
    /// introspection.
    NotAuthenticated(NotAuthenticated),

    /// The `Indeterminate` state is entered on two scenarios.
    ///
    /// 1. `use_keycloak_auth` was used on the server (in an SSR context).
    /// 2. We run on the client, received an authorization code (through a redirect from Keycloak)
    ///    but are still pending precessing this authorization code (exchanging it with a token).
    ///
    /// Having this additional state, in contrast to simply falling back to `NotAuthenticated` in
    /// both cases just mentioned, allows our `<ShowWhenAuthenticated>` component to render
    /// nothing (NOT using the fallback!) in such cases, which is desired as the fallback will
    /// mostly show some "login page". Showing that always when not authenticated would lead to:
    ///
    /// 1. On SSR: Rendering "login page" regardless, even though the client may/will promptly
    ///    replace it with the real/guarded content, assuming the user is already authenticated,
    ///    leading to a small flicker of the page.
    /// 1. On the client when authenticating: After getting the redirect from Keycloak
    ///    (containing the "to be processed" authorization code), showing the `fallback` of
    ///    `<ShowWhenAuthenticated>` even though we assume that the guarded content will be shown
    ///    in a few milliseconds, ultimately leading to a small unnecessary flicker of the page.
    ///
    /// Therefore, `<ShowWhenAuthenticated>` simply renders nothing in these case.
    Indeterminate,
}

impl KeycloakAuthState {
    /// Returns a reactive function that pretty prints the current authentication state.
    /// Useful for debugging purposes.
    pub fn pretty_printer(&self) -> impl Fn() -> String {
        let this = *self;

        move || match this {
            KeycloakAuthState::Authenticated(Authenticated {
                access_token,
                id_token_claims,
                on_http_error: _,
                refresh_context: _,
            }) => {
                #[derive(Debug)]
                #[expect(unused)]
                struct Pretty<'a> {
                    access_token: &'a AccessToken,
                    id_token_claims: &'a KeycloakIdTokenClaims,
                }
                format!(
                    "KeycloakAuthState::Authenticated {:#?}",
                    Pretty {
                        access_token: access_token.read().deref(),
                        id_token_claims: id_token_claims.read().deref(),
                    }
                )
            }
            KeycloakAuthState::NotAuthenticated(NotAuthenticated {
                has_token_data,
                last_id_token_error,
                last_error,
            }) => {
                #[derive(Debug)]
                #[expect(unused)]
                struct Pretty {
                    has_token_data: bool,
                    last_id_token_error: Option<String>,
                    last_error: Option<String>,
                }
                format!(
                    "KeycloakAuthState::NotAuthenticated {:#?}",
                    Pretty {
                        has_token_data: has_token_data.get(),
                        last_id_token_error: last_id_token_error
                            .read()
                            .as_ref()
                            .map(|err| format!("{err:?}")),
                        last_error: last_error.read().as_ref().map(|err| format!("{err:?}")),
                    }
                )
            }
            KeycloakAuthState::Indeterminate => "KeycloakAuthState::Indeterminate".to_string(),
        }
    }
}

/// Context needed by `AuthenticatedClient` to perform a direct token refresh.
#[derive(Clone, Copy)]
pub(crate) struct RefreshContext {
    pub(crate) token_data: Signal<Option<TokenData>>,
    pub(crate) token_endpoint: Signal<Result<TokenEndpoint, DerivedUrlError>>,
    pub(crate) options: StoredValue<Options>,
    pub(crate) update_token: Callback<Option<TokenData>>,
    pub(crate) request_timeout: StdDuration,
    pub(crate) session_version: Signal<SessionVersion>,
}

impl Debug for RefreshContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshContext")
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}

impl RefreshContext {
    /// Attempt to refresh the token using the current refresh token and token endpoint. Automatically publishes the new token data (when refresh succeeded to the reactive system).
    ///
    /// Returns `None` when a refresh is impossible (no refresh token or no token endpoint),
    /// or when the session version changed during the refresh (stale response).
    /// Returns `Some(Ok(()))` on success and `Some(Err(..))` when the refresh request fails.
    pub(crate) async fn try_refresh(&self) -> Option<Result<(), RequestError>> {
        let refresh_token = self
            .token_data
            .read_untracked()
            .as_ref()
            .map(|t| t.refresh_token.clone())?;

        let new_token = action::refresh_token_with_session_check(
            self.token_endpoint.read_untracked().as_ref().ok()?.clone(),
            &self.options.read_value().client_id,
            &refresh_token,
            self.options.read_value().discovery_endpoint(),
            self.request_timeout,
            self.session_version.get_untracked(),
            self.session_version,
        )
        .await;

        match new_token {
            None => None,
            Some(new_token) => match new_token {
                Ok(new_token) => {
                    self.update_token.run(Some(new_token));
                    Some(Ok(()))
                }
                Err(err) => Some(Err(err)),
            },
        }
    }
}

/// State only accessible when the user is authenticated.
///
/// You can call `client` to receive an `AuthenticatedClient` (using a `reqwest::Client` in
/// the background) that automatically (and reactively) attaches the `access_token` to your requests
/// and handles potential failure codes by performing a retry of the request if applicable.
#[derive(Debug, Clone, Copy)]
pub struct Authenticated {
    /// Claims from the verified and decoded ID token.
    /// Contains user information like name, email and roles.
    ///
    /// NOTE: Roles will only be contained if activated in the Keycloak admin UI!
    pub id_token_claims: Memo<KeycloakIdTokenClaims>,

    /// Access token to be used in an authorization header.
    /// Guaranteed to not be expired.
    /// This is a signal, as we refresh the token regularly and automatically in the background.
    pub access_token: Memo<AccessToken>,

    /// Callback invoked when an HTTP request fails. Triggers a background token refresh
    /// on 401 responses (with debouncing to prevent rapid-fire refreshes).
    /// Always returns `Fail` — the `AuthenticatedClient` handles retry internally.
    pub(crate) on_http_error: Callback<http::StatusCode>,

    /// Context for direct token refresh in `AuthenticatedClient`.
    pub(crate) refresh_context: RefreshContext,
}

impl PartialEq for Authenticated {
    fn eq(&self, other: &Self) -> bool {
        // Excluding on_http_error and refresh_context (not relevant for equality).
        self.id_token_claims == other.id_token_claims && self.access_token == other.access_token
    }
}

impl Eq for Authenticated {}

impl Authenticated {
    /// Create an authenticated HTTP client with automatic token injection.
    ///
    /// Returns an [`AuthenticatedClient`] that automatically attaches the access token to all
    /// requests and handles 401 responses by attempting to refresh the token and retry the request.
    ///
    /// This creates a new `reqwest::Client` internally. If you need to customize the underlying
    /// client (e.g., for custom timeouts or middleware), use [`client_from`](Self::client_from)
    /// instead.
    ///
    /// # Returns
    /// An [`AuthenticatedClient`] configured with a default `reqwest::Client`.
    ///
    /// # Example
    /// ```no_run
    /// use leptos_keycloak_auth::{use_authenticated};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let authenticated = use_authenticated();
    /// let client = authenticated.client();
    /// let response = client.get("https://api.example.com/protected-resource").await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn client(&self) -> AuthenticatedClient {
        AuthenticatedClient::new(reqwest::Client::new(), *self)
    }

    /// Create an authenticated HTTP client from an existing `reqwest::Client`.
    ///
    /// Returns an [`AuthenticatedClient`] that wraps your provided `reqwest::Client` and
    /// automatically attaches the access token to all requests. Use this when you need to
    /// customize the underlying client configuration.
    ///
    /// # Parameters
    /// - `client`: A configured `reqwest::Client` to use for making requests.
    ///
    /// # Returns
    /// An [`AuthenticatedClient`] wrapping the provided client.
    ///
    /// # Example
    /// ```no_run
    /// use std::time::Duration;
    /// use leptos_keycloak_auth::use_authenticated;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let authenticated = use_authenticated();
    /// let custom_client = reqwest::Client::builder()
    ///     .timeout(Duration::from_secs(30))
    ///     .build()?;
    /// let client = authenticated.client_from(custom_client);
    /// let response = client.get("https://api.example.com/protected-resource").await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn client_from(&self, client: reqwest::Client) -> AuthenticatedClient {
        AuthenticatedClient::new(client, *self)
    }

    /// Report a failed HTTP request to trigger a background token refresh.
    ///
    /// Call this method when you receive a 401 Unauthorized response from your API. This triggers
    /// a background refresh of the access token (with debouncing to prevent rapid-fire refreshes).
    ///
    /// Note: This does NOT retry the request. The `AuthenticatedClient` handles retry internally.
    /// For manual request handling, call this to trigger the refresh, then re-read `access_token`
    /// for subsequent requests.
    ///
    /// # Parameters
    /// - `status_code`: The HTTP status code received from the failed request.
    ///
    /// # Example
    /// ```no_run
    /// use leptos_keycloak_auth::use_authenticated;
    ///
    /// let authenticated = use_authenticated();
    /// authenticated.handle_http_error(http::StatusCode::UNAUTHORIZED);
    /// ```
    pub fn handle_http_error(&self, status_code: http::StatusCode) {
        self.on_http_error.run(status_code);
    }
}

/// State when the user is not authenticated.
///
/// This state is entered when:
/// - No token data exists (user hasn't logged in).
/// - The access token has expired and cannot be refreshed.
/// - The ID token failed validation.
/// - OIDC discovery hasn't completed yet.
/// - Any other authentication error occurred.
///
/// Use the signals within this struct to access error information and debug why authentication
/// failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotAuthenticated {
    /// Reactive signal indicating whether any token data exists in local storage.
    ///
    /// `true` means token data was found but authentication failed for some other reason
    /// (e.g., token expired, validation failed). `false` means no token data exists.
    pub has_token_data: Signal<bool>,

    /// Reactive signal containing the last ID token validation error, if any.
    ///
    /// Use this to debug why ID token validation failed (e.g., invalid signature, wrong audience,
    /// expired token, etc.).
    pub last_id_token_error: Signal<Option<IdTokenClaimsError>>,

    /// Reactive signal containing the last general authentication error, if any.
    ///
    /// This includes errors from OIDC discovery, token exchange, token refresh, and other
    /// authentication operations.
    pub last_error: Signal<Option<KeycloakAuthError>>,
}
