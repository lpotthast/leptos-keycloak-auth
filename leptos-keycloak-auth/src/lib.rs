use crate::code_verifier::{CodeChallenge, CodeVerifier};
use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_query};
use leptos_router::NavigateOptions;
use leptos_use::{
    storage::{use_storage_with_options, UseStorageOptions},
    use_interval, UseIntervalReturn,
};
use oidc::OidcConfig;
use request::RequestError;
use response::CallbackResponse;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::ops::Deref;
use time::OffsetDateTime;
use token::{KeycloakIdTokenClaims, TokenData};

mod action;
mod code_verifier;
pub mod components;
pub mod config;
mod login;
mod logout;
mod oidc;
mod request;
mod response;
pub mod token;
mod token_validation;

pub use components::*;
pub use config::*;
pub use leptos_use::storage::StorageType;
use token_validation::KeycloakIdTokenClaimsError;
pub use url::Url;

type DiscoveryEndpoint = Url;
type JwkSetEndpoint = Url;
type AuthorizationEndpoint = Url;
type TokenEndpoint = Url;
type EndSessionEndpoint = Url;

type AuthorizationCode = String;
type SessionState = String;
//type AccessToken = String;
type RefreshToken = String;

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
#[derive(Debug, Clone, Copy, PartialEq)]
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
                token,
                access_token_nearly_expired,
                refresh_token_nearly_expired,
                id_token_claims,
            }) => {
                #[derive(Debug)]
                #[expect(unused)]
                struct Pretty {
                    token: TokenData,
                    access_token_nearly_expired: bool,
                    refresh_token_nearly_expired: bool,
                    id_token_claims: KeycloakIdTokenClaims,
                }
                format!(
                    "KeycloakAuthState::Authenticated {:#?}",
                    Pretty {
                        token: token.get(),
                        access_token_nearly_expired: access_token_nearly_expired.get(),
                        refresh_token_nearly_expired: refresh_token_nearly_expired.get(),
                        id_token_claims: id_token_claims.get(),
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
                struct Pretty {
                    last_token_data: Option<TokenData>,
                    last_token_id_error: Option<KeycloakIdTokenClaimsError>,
                    last_error: Option<String>,
                }
                format!(
                    "KeycloakAuthState::NotAuthenticated {:#?}",
                    Pretty {
                        last_token_data: last_token_data.get(),
                        last_token_id_error: last_token_id_error.get(),
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
    /// Last known token data. Single source of truth of token information.
    /// May contain an expired access and / or refresh token.
    pub token: Signal<TokenData>,

    /// Derived signal, updating in regular time intervals or when the token data changes,
    /// stating if the access token is about to expire.
    pub access_token_nearly_expired: Signal<bool>,

    /// Derived signal, updating in regular time intervals or when the token data changes,
    /// stating if the access token is about to expire.
    pub refresh_token_nearly_expired: Signal<bool>,

    /// Claims from the verified ID token. Contains user information like name, email and roles.
    /// Will contain an error if the ID token was not yet verified or could not be verified.
    /// Note: Roles will only be contained if activated in the Keycloak admin UI!
    pub id_token_claims: Signal<KeycloakIdTokenClaims>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct LastUsedCode {
    session_state: Option<SessionState>,
    code: AuthorizationCode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct OidcConfigWithTimestamp {
    oidc_config: OidcConfig,
    #[serde(with = "time::serde::rfc3339")]
    retrieved: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct JwkSetWithTimestamp {
    jwk_set: jsonwebtoken::jwk::JwkSet,
    #[serde(with = "time::serde::rfc3339")]
    retrieved: OffsetDateTime,
}

struct OidcManager {
    oidc_config: Signal<Option<OidcConfigWithTimestamp>>,
}

impl OidcManager {
    pub(crate) fn new(
        discovery_endpoint: DiscoveryEndpoint,
        storage_type_provider: Callback<(), StorageType>,
        options: StoredValue<UseKeycloakAuthOptions>,
        handle_req_error: Callback<Option<RequestError>>,
    ) -> Self {
        let (oidc_config, set_oidc_config, _remove_oidc_config_from_storage) =
            use_storage_with_options::<Option<OidcConfigWithTimestamp>, JsonSerdeCodec>(
                storage_type_provider.run(()),
                "leptos_keycloak_auth__oidc_config",
                UseStorageOptions::default().initial_value(None),
            );

        let oidc_config_too_old = {
            let UseIntervalReturn { counter, .. } = use_interval(
                options.with_value(|o| o.advanced.oidc_config_age_check_interval_milliseconds),
            );
            Memo::new(move |_| {
                let _count = counter.get();
                oidc_config
                    .get()
                    .map(|it| {
                        (OffsetDateTime::now_utc() - it.retrieved).whole_seconds()
                            > options
                                .with_value(|o| o.advanced.max_oidc_config_age_seconds)
                                .into()
                    })
                    .unwrap_or(true)
            })
        };

        // Fetch a token from the OIDC provider using an authorization code and an optional session state.
        let retrieve_oidc_config_action = action::create_retrieve_oidc_config_action(
            discovery_endpoint.clone(),
            Callback::new(move |val| set_oidc_config.set(val)),
            handle_req_error,
        );

        // Obtain the OIDC configuration. Updating any previously stored config.
        Effect::new(move |_| {
            if oidc_config_too_old.get() {
                retrieve_oidc_config_action.dispatch(());
            }
        });

        Self { oidc_config }
    }
}

struct JwkSetManager {
    jwk_set: Signal<Option<JwkSetWithTimestamp>>,
}

impl JwkSetManager {
    pub(crate) fn new(
        jwk_set_endpoint: Signal<Result<JwkSetEndpoint, DerivedUrlError>>,
        storage_type_provider: Callback<(), StorageType>,
        options: StoredValue<UseKeycloakAuthOptions>,
        handle_req_error: Callback<Option<RequestError>>,
    ) -> Self {
        // TODO: Store old JWK set alongside newly fetched (changed) keys.
        let (jwk_set, set_jwk_set, _remove_jwk_set_from_storage) =
            use_storage_with_options::<Option<JwkSetWithTimestamp>, JsonSerdeCodec>(
                storage_type_provider.run(()),
                "leptos_keycloak_auth__jwk_set",
                UseStorageOptions::default().initial_value(None),
            );

        // This callback is called whenever an updated JWK set is available.
        let handle_jwk_set = Callback::new(move |val: Option<JwkSetWithTimestamp>| {
            // If the JWK set changed, the Keycloak realm rolled its keys.
            // Note that this is done automatically in a certain interval.
            // New tokens must be validated against the new JWK set.
            // But old tokens, which may still be relevant because they didn't expire yet,
            // should still be validatable. We therefore need to also track any `previous`
            // JWK set.
            // TODO:
            //if jwk_set.read_untracked().as_ref().map(|it| &it.jwk_set)
            //    != val.as_ref().map(|it| &it.jwk_set)
            //{
            //    tracing::debug!("JWK set changed, forgetting current token...");
            //    handle_token.run(None);
            //}

            set_jwk_set.set(val)
        });

        // Fetch a token from the OIDC provider using an authorization code and an optional session state.
        let retrieve_jwk_set_action =
            action::create_retrieve_jwk_set_action(handle_jwk_set, handle_req_error);

        let jwk_set_too_old = {
            let UseIntervalReturn { counter, .. } = use_interval(
                options.with_value(|o| o.advanced.jwk_set_age_check_interval_milliseconds),
            );
            Memo::new(move |_| {
                let _count = counter.get();
                jwk_set
                    .get()
                    .map(|it| {
                        (OffsetDateTime::now_utc() - it.retrieved).whole_seconds()
                            > options
                                .with_value(|o| o.advanced.max_jwk_set_age_seconds)
                                .into()
                    })
                    .unwrap_or(true)
            })
        };

        // Obtain the JWK set. Updating any previously stored config.
        Effect::new(move |_| {
            if jwk_set_too_old.get() {
                match jwk_set_endpoint.read().as_ref() {
                    Ok(jwk_set_endpoint) => {
                        retrieve_jwk_set_action.dispatch(jwk_set_endpoint.clone());
                    }
                    Err(err) => {
                        tracing::trace!(reason = ?err, "JWK set should be updated, as it is too old, but no jwks_endpoint_url is known jet. Skipping update...")
                    }
                }
            }
        });

        Self { jwk_set }
    }
}

#[derive(Clone, Copy)]
struct CodeVerifierManager {
    code_verifier: Signal<Option<CodeVerifier<128>>>,
    set_code_verifier: WriteSignal<Option<CodeVerifier<128>>>,
    code_challenge: Memo<Option<CodeChallenge>>,
}

impl CodeVerifierManager {
    pub(crate) fn new() -> Self {
        // We keep the code_verifier, used for the code-to-token-exchange in session storage.
        // We cannot keep the code_verifier completely in-memory, as our authorization flow includes
        // navigating away from our Leptos application to the auth-providers login page and then
        // being redirected back to our application, meaning that we do a full reload!
        // But: We have to provide the code_verifier derived code_challenge on navigation away from
        // our app and need the same code_verifier later to do the token exchange, giving us no other
        // way than storing it.
        // TODO: Can we provide an "iframe" mode in which the login page is shown in an iframe while our Leptos application stays running in the background?
        let (code_verifier, set_code_verifier, _remove_code_verifier_from_storage) =
            use_storage_with_options::<Option<CodeVerifier<128>>, JsonSerdeCodec>(
                // Forcing session storage, because this data point must be as secure as possible,
                // and we do not care that we may lose the code from a page-refresh or tab-close.
                StorageType::Session,
                "leptos_keycloak_auth__code_verifier",
                UseStorageOptions::default()
                    .initial_value(None)
                    .on_error(|err| tracing::error!(?err, "code_verifier storage error")),
            );
        if code_verifier.get().is_none() {
            tracing::trace!("No code_verifier found in session storage, generating new one...");
            set_code_verifier.set(Some(CodeVerifier::<128>::generate()));
        }
        let code_challenge = Memo::new(move |_| {
            code_verifier
                .read()
                .as_ref()
                .map(|it| it.to_code_challenge())
        });

        Self {
            code_verifier,
            set_code_verifier,
            code_challenge,
        }
    }
}

#[derive(Clone, Copy)]
struct TokenManager {
    token: Signal<Option<TokenData>>,
    set_token: WriteSignal<Option<TokenData>>,

    access_token_nearly_expired: Memo<bool>,
    refresh_token_nearly_expired: Memo<bool>,
    access_token_expired: Memo<bool>,
    refresh_token_expired: Memo<bool>,

    exchange_code_for_token_action: Action<
        (
            TokenEndpoint,
            AuthorizationCode,
            CodeVerifier<128>,
            Option<SessionState>,
        ),
        (),
    >,
    token_endpoint: Signal<Result<TokenEndpoint, DerivedUrlError>>,
    remove_token_from_storage: StoredValue<Box<dyn Fn() + Send + Sync>>,
}

impl TokenManager {
    pub(crate) fn new(
        storage_type_provider: Callback<(), StorageType>,
        options: StoredValue<UseKeycloakAuthOptions>,
        handle_req_error: Callback<Option<RequestError>>,
        token_endpoint: Signal<Result<TokenEndpoint, DerivedUrlError>>,
    ) -> Self {
        let (token, set_token, remove_token_from_storage) =
            use_storage_with_options::<Option<TokenData>, JsonSerdeCodec>(
                storage_type_provider.run(()),
                "leptos_keycloak_auth__token",
                UseStorageOptions::default()
                    .initial_value(None)
                    .on_error(|err| tracing::error!(?err, "token storage error")),
            );
        let handle_token = Callback::new(move |val| set_token.set(val));

        // Note: Only call this after OIDC config was loaded. Otherwise, nothing happens and an error is logged!
        // TODO: Use a queuing system, so that no request is lost?
        let refresh_token_action =
            action::create_refresh_token_action(options, handle_token, handle_req_error);

        let trigger_refresh = Callback::new(move |()| {
            let token_endpoint = match token_endpoint.read_untracked().as_ref() {
                Ok(it) => it.clone(),
                Err(err) => {
                    tracing::info!(
                        ?err,
                        "Requested token refresh has no effect, as no token_endpoint is known yet."
                    );
                    return;
                }
            };

            let refresh_token = match token.read_untracked().as_ref() {
                Some(token) => token.refresh_token.clone(),
                None => {
                    tracing::info!(
                        "Requested token refresh has no effect, as no token is known yet."
                    );
                    return;
                }
            };

            refresh_token_action.dispatch((token_endpoint, refresh_token));
        });

        let access_token_nearly_expired = {
            let UseIntervalReturn { counter, .. } = use_interval(
                options
                    .read_value()
                    .advanced
                    .access_token_nearly_expired_check_interval_milliseconds,
            );
            Memo::new(move |_| {
                // Depend on counter to let this be checked every interval.
                let _count = counter.get();
                token
                    .get()
                    .map(|token| {
                        token.access_token_to_be_expired(
                            options.with_value(|o| o.advanced.access_token_nearly_expired_having),
                        )
                    })
                    .unwrap_or(false)
            })
        };

        let refresh_token_nearly_expired = {
            let UseIntervalReturn { counter, .. } = use_interval(
                options
                    .read_value()
                    .advanced
                    .refresh_token_nearly_expired_check_interval_milliseconds,
            );
            Memo::new(move |_| {
                // Depend on counter to let this be checked every interval.
                let _count = counter.get();
                token
                    .get()
                    .map(|token| {
                        token.refresh_token_to_be_expired(
                            options.with_value(|o| o.advanced.refresh_token_nearly_expired_having),
                        )
                    })
                    .unwrap_or(false)
            })
        };

        // True when a token is present and the access token is expired.
        // Defaults to `false` if no token data is present.
        let access_token_expired = {
            let UseIntervalReturn { counter, .. } = use_interval(
                options
                    .read_value()
                    .advanced
                    .access_token_expiration_check_interval_milliseconds,
            );
            Memo::new(move |_| {
                //tracing::trace!("Checking if access token is expired...");
                let _count = counter.get();
                token.with(move |token| {
                    if let Some(token) = token {
                        token.access_token_expired()
                    } else {
                        false
                    }
                })
            })
        };

        // True when a token is present and the refresh token is expired.
        // Defaults to `false` if no token data is present.
        // Defaults to `false` if token data is present, but no refresh expiration time is set.
        let refresh_token_expired = {
            let UseIntervalReturn { counter, .. } = use_interval(
                options
                    .read_value()
                    .advanced
                    .refresh_token_expiration_check_interval_milliseconds,
            );
            Memo::new(move |_| {
                //tracing::trace!("Checking if refresh token is expired...");
                let _count = counter.get();
                token.with(move |token| {
                    if let Some(token) = token {
                        token.refresh_token_expired()
                    } else {
                        false
                    }
                })
            })
        };

        // If either the access or the refresh token is about to expire
        // (although the refresh token *should* always outlive the access token...),
        // or the access token already expired, try to refresh the access token using the refresh token.
        Effect::new(move |_| {
            // TODO: Should we also take into account whether whe were able to decode the id token?

            // Note: These boolean-signals default to false. Therefore, no refresh-attempt
            // is made without a refresh token being present.
            let access_token_nearly_expired = access_token_nearly_expired.get();
            let refresh_token_nearly_expired = refresh_token_nearly_expired.get();
            let access_token_expired = access_token_expired.get();
            if access_token_nearly_expired || refresh_token_nearly_expired || access_token_expired {
                tracing::trace!(
                    access_token_nearly_expired,
                    refresh_token_nearly_expired,
                    access_token_expired,
                    "Refreshing token..."
                );
                trigger_refresh.run(());
            }
        });

        let token_remove = remove_token_from_storage.clone();
        Effect::new(move |_| {
            let access_token_expired = access_token_expired.get();
            let refresh_token_expired = refresh_token_expired.get();

            if access_token_expired && refresh_token_expired {
                // The token became unusable and can safely be forgotten.
                set_token.set(None);
                token_remove();
            }
        });

        Self {
            token,
            set_token,
            access_token_nearly_expired,
            refresh_token_nearly_expired,
            access_token_expired,
            refresh_token_expired,
            exchange_code_for_token_action: action::create_exchange_code_for_token_action(
                options,
                handle_token,
                handle_req_error,
            ),
            token_endpoint,
            remove_token_from_storage: StoredValue::new(Box::new(remove_token_from_storage)),
        }
    }

    /// Note: This silently errors if no token_endpoint is known yet.
    pub(crate) fn exchange_code_for_token(
        &self,
        code: AuthorizationCode,
        code_verifier: CodeVerifier<128>,
        session_state: Option<SessionState>,
    ) {
        let token_endpoint = match self.token_endpoint.read_untracked().as_ref() {
            Ok(token_endpoint) => token_endpoint.clone(),
            Err(err) => {
                tracing::warn!(?err, "Unexpected error: Could not exchange auth code for token, as no token_endpoint is known jet. Should not have been reached. If a successful login was possible, we should have received a token endpoint from the OIDC config.");
                return;
            }
        };

        self.exchange_code_for_token_action.dispatch((
            token_endpoint,
            code,
            code_verifier,
            session_state,
        ));
    }
}

/// Initializes a new `Auth` instance with the provided authentication
/// parameters. This function creates and returns an `Auth` struct
/// configured for authentication.
pub fn use_keycloak_auth(options: UseKeycloakAuthOptions) -> KeycloakAuth {
    tracing::trace!("Initializing Keycloak auth...");

    let discovery_endpoint: DiscoveryEndpoint = {
        let mut url = options.keycloak_server_url.clone();
        url.path_segments_mut()
            .expect("to allow path segments on Keycloak server url")
            .extend(&[
                "realms",
                &options.realm,
                ".well-known",
                "openid-configuration",
            ]);
        url
    };

    let storage_type_provider = options.advanced.storage_type_provider;
    let options = StoredValue::new(options);

    let (auth_error, set_auth_error) = signal::<Option<KeycloakAuthError>>(None);
    let handle_req_error = Callback::new(move |request_error: Option<RequestError>| {
        set_auth_error.set(request_error.map(|err| KeycloakAuthError::Request { source: err }))
    });

    let oidc_mgr = OidcManager::new(
        discovery_endpoint.clone(),
        storage_type_provider,
        options,
        handle_req_error,
    );

    let DerivedUrls {
        jwks_endpoint,
        authorization_endpoint,
        token_endpoint,
        end_session_endpoint,
    } = DerivedUrls::new(oidc_mgr.oidc_config);

    let jwk_set_mgr = JwkSetManager::new(
        jwks_endpoint,
        storage_type_provider,
        options,
        handle_req_error,
    );

    let token_mgr = TokenManager::new(
        storage_type_provider,
        options,
        handle_req_error,
        token_endpoint,
    );

    let code_mgr = CodeVerifierManager::new();

    // Current state of our url parameters.
    let url_state = use_query::<CallbackResponse>();

    // Handle changes in our url parameters.
    // THIS EFFECT MAINLY DRIVES THIS SYSTEM!
    Effect::new(move |_| {
        match url_state.get() {
            Ok(state) => match state {
                CallbackResponse::SuccessfulLogin(login_state) => {
                    tracing::trace!(?login_state, "Login successful");

                    // We assume that last_code only changes when we receive a "new" / not-seen-before code.
                    // This means we can safely call the token exchange here, as we will do this only once per code we see.
                    token_mgr.exchange_code_for_token(
                        login_state.code.clone(),
                        code_mgr.code_verifier.get_untracked().expect("present"),
                        login_state.session_state.clone(),
                    );

                    // We provide Keycloak with a `post_login_redirect_url`. When the Keycloak
                    // performs this redirect, it extends this url with query parameters,
                    // which we parsed into a `CallbackResponse::SuccessfulLogin`.
                    // We "consumed" this state now and no longer need it as part of our url state.
                    // Consider these query parameters more as function parameters and the
                    // redirect back to us as the function call.
                    // Leaving the parameters might lead to this branch being entered again.
                    // But we already "consumed" the code (by exchanging it to a toke) and can no
                    // longer do something with this data anyway.
                    // It is also cleaner from the users perspective to not leave remaining traces
                    // from the authorization process.
                    // We currently "remove" the query parameters by doing an extra, programmatic
                    // routing to the `post_login_redirect_url`. That will just be handled by the
                    // leptos router and performed on the client itself.
                    let navigate = use_navigate();
                    navigate(
                        options.read_value().post_login_redirect_url.as_ref(),
                        NavigateOptions::default(),
                    );
                }
                CallbackResponse::SuccessfulLogout(logout_state) => {
                    tracing::trace!(?logout_state, "Logout successful");

                    if logout_state.destroy_session {
                        // We have to use `request_animation_frame` here, as setting the token to `None` would
                        // otherwise lead to an immediate execution of all reactive primitives depending on this.
                        // This includes our `Authenticated` state (and all component trees rendered under
                        // a `ShowWhenAuthenticated`). But `Authenticated` expects a token to be present!
                        // We have to make sure that the state is switched to `NotAuthenticated` (by observing that
                        // no token is present) first!
                        let set_token = token_mgr.set_token;
                        let remove_token_from_storage = token_mgr.remove_token_from_storage;
                        let set_code_verifier = code_mgr.set_code_verifier;
                        request_animation_frame(move || {
                            tracing::trace!("Dropping all token data");
                            set_token.set(None);

                            // Even though setting the None value will lead to `None` being written to storage
                            // eventually, we will not completely rely on that side effect and explicitly remove
                            // the data from storage.
                            // We cannot only remove the data from storage, as we DEFINITELY WANT to trigger
                            // reactive effects depending on the current token state.
                            remove_token_from_storage.read_value()();

                            // We should recreate the code_verifier to have a new one for the next login phase.
                            set_code_verifier.set(Some(CodeVerifier::<128>::generate()));
                        });
                    }

                    // We currently "remove" the query parameters by doing an extra, programmatic
                    // routing to the `post_logout_redirect_url`. That will just be handled by the
                    // leptos router and performed on the client itself.
                    let navigate = use_navigate();
                    navigate(
                        options.read_value().post_logout_redirect_url.as_ref(),
                        NavigateOptions::default(),
                    );
                }
                CallbackResponse::Error(err_state) => {
                    set_auth_error.set(Some(KeycloakAuthError::Request {
                        source: RequestError::ErrResponse {
                            error_response: err_state,
                        },
                    }));
                }
            },
            Err(err) => {
                // Save to be ignored. This just means that we currently do not have the required parameters to do meaningful work.
                // You might want to debug this error if things don't work.
                set_auth_error.set(Some(ParamsSnafu { err }.build()));
            }
        }
    });

    let verified_and_decoded_id_token: Memo<
        Result<KeycloakIdTokenClaims, KeycloakIdTokenClaimsError>,
    > = Memo::new(move |_| {
        // TODO: User should be able to overwrite this.
        let client_id = options.read_value().client_id.clone();
        let expected_audiences: &[String] = &[client_id];
        token_validation::validate(
            token_mgr.token.get(),
            jwk_set_mgr.jwk_set.get().as_ref().map(|it| &it.jwk_set),
            expected_audiences,
        )
    });

    // Auth state derived from token data or potential errors.
    let state = Memo::new(move |_| {
        let token = token_mgr.token;
        let access_token_nearly_expired = token_mgr.access_token_nearly_expired;
        let refresh_token_nearly_expired = token_mgr.refresh_token_nearly_expired;

        // Note: The token might have already been set to None but access_token_expired was not yet updated...
        let has_token = token.read().is_some();
        let has_verified_and_decoded_id_token = verified_and_decoded_id_token.read().is_ok();

        if has_token && has_verified_and_decoded_id_token && !token_mgr.access_token_expired.get() {
            KeycloakAuthState::Authenticated(Authenticated {
                token: Signal::derive(move || token.get().expect("present")),
                access_token_nearly_expired: access_token_nearly_expired.into(),
                refresh_token_nearly_expired: refresh_token_nearly_expired.into(),
                id_token_claims: Signal::derive(move || {
                    verified_and_decoded_id_token.get().expect("present")
                }),
            })
        } else {
            KeycloakAuthState::NotAuthenticated {
                last_token_data: token_mgr.token,
                last_token_id_error: Signal::derive(move || {
                    verified_and_decoded_id_token.get().err()
                }),
                last_error: auth_error.into(),
            }
        }
    });

    let auth = KeycloakAuth {
        options,
        login_url: login::create_login_url_signal(
            authorization_endpoint,
            options,
            code_mgr.code_challenge,
        )
        .into(),
        logout_url: logout::create_logout_url_signal(
            end_session_endpoint,
            token_mgr.token,
            options,
        )
        .into(),
        state: state.into(),
        is_authenticated: Signal::derive(move || match state.read().deref() {
            KeycloakAuthState::Authenticated(_) => true,
            KeycloakAuthState::NotAuthenticated { .. } => false,
        }),
    };

    // We guarantee that the KeycloakAuth state is provided as context.
    provide_context(auth);

    auth
}
