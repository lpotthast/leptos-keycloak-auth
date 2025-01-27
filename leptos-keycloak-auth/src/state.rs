use crate::error::KeycloakAuthError;
use crate::token::{KeycloakIdTokenClaims, TokenData};
use crate::token_validation::KeycloakIdTokenClaimsError;
use crate::{AccessToken, UseKeycloakAuthOptions};
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
    pub options: StoredValue<UseKeycloakAuthOptions>,

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
    pub oidc_config_manager: crate::OidcConfigManager,

    #[cfg(feature = "internals")]
    pub jwk_set_manager: crate::JwkSetManager,

    #[cfg(feature = "internals")]
    pub code_verifier_manager: crate::CodeVerifierManager,

    #[cfg(feature = "internals")]
    pub token_manager: crate::TokenManager,
}

impl KeycloakAuth {
    /// This can be used to set the `post_login_redirect_url` dynamically. It's helpful if
    /// you would like to be redirected to the current page.
    // TODO: Decide whether this should be a signal and if this should be in our options... Or should this overwrite a signal internally?!!
    pub fn set_post_login_redirect_url(&mut self, url: Url) {
        self.options
            .update_value(|parameters| parameters.post_login_redirect_url = url);
    }

    /// Returns a reactive function that pretty prints the current authentication state.
    /// Useful for debugging purposes.
    pub fn state_pretty_printer(&self) -> impl Fn() -> String {
        self.state.read().deref().pretty_printer()
    }
}

/// The current state of authentication.
/// Prefer using this to determine if a user is already authenticated.
/// Will be of AuthState::Undetermined variant if neither a token nor any error were received.
/// Will be of AuthState::NotAuthenticated variant if the token data contains an expired access token or an error was received.
#[derive(Debug, Clone, PartialEq)]
pub enum KeycloakAuthState {
    /// The Authenticated state is only used when there is a valid token which did not jet expire.
    /// If you encounter this state, be ensured that the token can be used to access your api.
    Authenticated(Authenticated),

    NotAuthenticated {
        last_token_data: Signal<Option<TokenData>>,
        last_token_id_error: Signal<Option<KeycloakIdTokenClaimsError>>,
        last_error: Signal<Option<KeycloakAuthError>>,
    },
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
            KeycloakAuthState::NotAuthenticated {
                last_token_data,
                last_token_id_error,
                last_error,
            } => {
                #[derive(Debug)]
                #[expect(unused)]
                struct Pretty<'a> {
                    last_token_data: Option<&'a TokenData>,
                    last_token_id_error: Option<&'a KeycloakIdTokenClaimsError>,
                    last_error: Option<String>,
                }
                format!(
                    "KeycloakAuthState::NotAuthenticated {:#?}",
                    Pretty {
                        last_token_data: last_token_data.read().deref().as_ref(),
                        last_token_id_error: last_token_id_error.read().deref().as_ref(),
                        last_error: last_error.read().as_ref().map(|err| format!("{:?}", err)),
                    }
                )
            }
        }
    }
}

/// Authentication handler responsible for handling user authentication and
/// token management.
#[derive(Debug, Clone, Copy, PartialEq)]
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
}
