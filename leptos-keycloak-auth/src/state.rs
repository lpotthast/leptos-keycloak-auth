use crate::authenticated_client::AuthenticatedClient;
use crate::config::Options;
use crate::error::KeycloakAuthError;
use crate::token_claims::KeycloakIdTokenClaims;
use crate::token_validation::KeycloakIdTokenClaimsError;
use crate::AccessToken;
use leptos::prelude::*;
use std::ops::Deref;
use url::Url;

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

    pub state: Signal<KeycloakAuthState>,

    /// Derived signal stating `true` when `state` is of the `Authenticated` variant.
    pub is_authenticated: Signal<bool>,

    #[cfg(feature = "internals")]
    pub oidc_config_manager: crate::internal::oidc_config_manager::OidcConfigManager,

    #[cfg(feature = "internals")]
    pub jwk_set_manager: crate::internal::jwk_set_manager::JwkSetManager,

    #[cfg(feature = "internals")]
    pub code_verifier_manager: crate::internal::code_verifier_manager::CodeVerifierManager,

    #[cfg(feature = "internals")]
    pub token_manager: crate::internal::token_manager::TokenManager,
}

impl KeycloakAuth {
    /// Update the URL to which you want to be redirected after a successful login.
    ///
    /// This will lead to a reactive change in the `login_url` signal.
    pub fn set_post_login_redirect_url(&mut self, url: Url) {
        self.options
            .with_value(|it| it.post_login_redirect_url.set(url));
    }

    /// Update the URL to which you want to be redirected after a successful logout.
    ///
    /// This will lead to a reactive change in the `logout_url` signal.
    pub fn set_post_logout_redirect_url(&mut self, url: Url) {
        self.options
            .with_value(|it| it.post_logout_redirect_url.set(url));
    }

    /// Returns a reactive function that pretty prints the current authentication state.
    ///
    /// Useful for debugging purposes.
    pub fn state_pretty_printer(&self) -> impl Fn() -> String {
        self.state.read().deref().pretty_printer()
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
    /// The Authenticated state is only used when there is a valid token which did not yet expire.
    /// If you encounter this state, be ensured that the token can be used to access your api.
    Authenticated(Authenticated),

    NotAuthenticated(NotAuthenticated),
}

impl KeycloakAuthState {
    /// Returns a reactive function that pretty prints the current authentication state.
    /// Useful for debugging purposes.
    pub fn pretty_printer(&self) -> impl Fn() -> String {
        let this = self.clone();

        move || match this {
            KeycloakAuthState::Authenticated(Authenticated {
                access_token,
                id_token_claims,
                auth_error_reporter: _,
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
                            .map(|err| format!("{:?}", err)),
                        last_error: last_error.read().as_ref().map(|err| format!("{:?}", err)),
                    }
                )
            }
        }
    }
}

/// State only accessible when the user is authenticated.
///
/// You can call `client` to receive an `AuthenticatedClient` (using a `reqwest::Client` in
/// the background) that automatically (and reactively) attaches the access_token to your requests
/// and handles potential failure codes by performing a retry of the request if applicable.
#[derive(Debug, Clone, Copy)]
pub struct Authenticated {
    /// Claims from the verified and decoded ID token.
    /// Contains user information like name, email and roles.
    ///
    /// NOTE: Roles will only be contained if activated in the Keycloak admin UI!
    pub id_token_claims: Signal<KeycloakIdTokenClaims>,

    /// Access token to be used in an authorization header.
    /// Guaranteed to not be expired.
    /// This is a signal, as we refresh the token regularly and automatically in the background.
    pub access_token: Signal<AccessToken>,

    pub(crate) auth_error_reporter: Callback<http::StatusCode, RequestAction>,
}

impl PartialEq for Authenticated {
    fn eq(&self, other: &Self) -> bool {
        // Only excluding auth_error_reporter.
        self.id_token_claims == other.id_token_claims && self.access_token == other.access_token
    }
}

impl Eq for Authenticated {}

pub enum RequestAction {
    /// Indicates that the request should be retried as updated tokens are now available.
    Retry,

    /// Indicates that the request should be marked as ultimately failed.
    Fail,
}

impl Authenticated {
    pub fn client(&self) -> AuthenticatedClient {
        AuthenticatedClient::new(reqwest::Client::new(), self.clone())
    }

    pub fn client_from(&self, client: reqwest::Client) -> AuthenticatedClient {
        AuthenticatedClient::new(client, self.clone())
    }

    pub fn report_failed_http_request(&self, status_code: http::StatusCode) -> RequestAction {
        self.auth_error_reporter.run(status_code)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotAuthenticated {
    pub has_token_data: Signal<bool>,
    pub last_id_token_error: Signal<Option<KeycloakIdTokenClaimsError>>,
    pub last_error: Signal<Option<KeycloakAuthError>>,
}
