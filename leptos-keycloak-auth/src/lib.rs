use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos_router::hooks::use_query;
use leptos_use::{
    storage::{use_storage_with_options, UseStorageOptions},
    use_interval, UseIntervalReturn,
};
use oidc::OidcConfig;
use request::RequestError;
use response::CallbackResponse;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use time::OffsetDateTime;
use token::{KeycloakIdTokenClaims, TokenData};

mod action;
pub mod components;
pub mod config;
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

/// Authentication handler responsible for handling user authentication and
/// token management.
#[derive(Debug, Clone, Copy)]
pub struct KeycloakAuth {
    /// Configuration used to initialize this Keycloak auth provider.
    options: StoredValue<UseKeycloakAuthOptions>,

    /// Last known token data. Single source of truth of token information.
    /// May contain an expired access and / or refresh token.
    pub token: Signal<Option<TokenData>>,

    /// The current state of authentication.
    /// Prefer using this to determine if a user is already authenticated.
    /// Will be of AuthState::Undetermined variant if neither a token nor any error were received.
    /// Will be of AuthState::NotAuthenticated variant if the token data contains an expired access token or an error was received.
    ///
    pub auth_state: Signal<AuthState>,

    /// Derived signal stating `true` when the `auth_state` is of the `Authenticated` variant.
    pub is_authenticated: Signal<bool>,

    /// Derived signal, updating in regular time intervals or when the token data changes, stating if the access token is about to expire.
    pub access_token_nearly_expired: Signal<bool>,

    /// Derived signal, updating in regular time intervals or when the token data changes, stating if the access token is about to expire.
    pub refresh_token_nearly_expired: Signal<bool>,

    /// URL for initiating the authentication process, directing the user to the authentication provider's login page.
    /// It may be None until OIDC discovery happened and the URL was parsed.
    pub login_url: Signal<Option<Url>>,

    /// Generates and returns the URL for initiating the logout process. This
    /// URL is used to redirect the user to the authentication provider's logout
    /// page.
    pub logout_url: Signal<Option<Url>>,

    /// Claims from the verified ID token. Contains user information like name, email and roles.
    /// Will contain an error if the ID token was not yet verified or could not be verified.
    /// Note: Roles will only be contained if activated in the Keycloak admin UI!
    pub id_token_claims: Signal<Result<KeycloakIdTokenClaims, KeycloakIdTokenClaimsError>>,
}

impl KeycloakAuth {
    /// This can be used to set the `post_login_redirect_url` dynamically. It's helpful if
    /// you would like to be redirected to the current page.
    // TODO: Decide whether this should be a signal and if this should be in our options... Or should this overwrite a signal internally?!!
    pub fn set_post_login_redirect_url(&mut self, url: Url) {
        self.options
            .update_value(|parameters| parameters.post_login_redirect_url = url);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthState {
    /// The Authenticated state is only used when there is a valid token which did not jet expire.
    /// If you encounter this state, be ensured that the token can be used to access your api.
    Authenticated(TokenData),
    NotAuthenticated {
        token_data: Option<TokenData>,
        last_error: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct LastUsedCode {
    session_state: Option<SessionState>,
    code: AuthorizationCode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct OidcConfigWithTimestamp {
    oidc_config: OidcConfig,
    retrieved: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct JwkSetWithTimestamp {
    jwk_set: jsonwebtoken::jwk::JwkSet,
    retrieved: OffsetDateTime,
}

/// Initializes a new `Auth` instance with the provided authentication
/// parameters. This function creates and returns an `Auth` struct
/// configured for authentication.
pub fn use_keycloak_auth(options: UseKeycloakAuthOptions) -> KeycloakAuth {
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

    let (last_used_code, set_last_used_code, _remove_last_used_code_from_storage) =
        use_storage_with_options::<Option<LastUsedCode>, JsonSerdeCodec>(
            storage_type_provider.run(()),
            "leptos_keycloak_auth__last_used_code",
            UseStorageOptions::default().initial_value(None),
        );

    let (token, set_token, remove_token_from_storage) =
        use_storage_with_options::<Option<TokenData>, JsonSerdeCodec>(
            storage_type_provider.run(()),
            "leptos_keycloak_auth__raw_token",
            UseStorageOptions::default().initial_value(None),
        );
    let handle_token = Callback::new(move |val| set_token.set(val));

    let (oidc_config_wt, set_oidc_config_wt, _remove_oidc_config_from_storage) =
        use_storage_with_options::<Option<OidcConfigWithTimestamp>, JsonSerdeCodec>(
            storage_type_provider.run(()),
            "leptos_keycloak_auth__oidc_config",
            UseStorageOptions::default().initial_value(None),
        );
    let handle_oidc_config = Callback::new(move |val| set_oidc_config_wt.set(val));

    let (jwk_set_wt, set_jwk_set_wt, _remove_jwk_set_from_storage) =
        use_storage_with_options::<Option<JwkSetWithTimestamp>, JsonSerdeCodec>(
            storage_type_provider.run(()),
            "leptos_keycloak_auth__jwk_set",
            UseStorageOptions::default().initial_value(None),
        );
    // This callback is called whenever an updated JWK set is available.
    let handle_jwk_set_wt = Callback::new(move |val: Option<JwkSetWithTimestamp>| {
        // If we no longer have JWKs, we should probably also forget our current token.
        if val.is_none() {
            tracing::debug!("No JWK set available, forgetting current token...");
            handle_token.run(None);
        }
        // If the JWK set changed, the Keycloak changed, and we should probably forget our token
        // and require re-authentication.
        // If jwk_set_wt is None, we cannot have a token yet and are safe to set it to None again.
        if jwk_set_wt.read_untracked() != val {
            tracing::debug!("JWK set changed, forgetting current token...");
            handle_token.run(None);
        }
        set_jwk_set_wt.set(val)
    });

    let DerivedUrls {
        jwks_endpoint,
        authorization_endpoint,
        token_endpoint,
        end_session_endpoint,
    } = DerivedUrls::new(oidc_config_wt);

    let verified_and_decoded_id_token: Memo<
        Result<KeycloakIdTokenClaims, KeycloakIdTokenClaimsError>,
    > = Memo::new(move |_| {
        // TODO: User should be able to overwrite this.
        let client_id = options.with_value(|o| o.client_id.clone());
        let expected_audiences: &[String] = &[client_id];
        token_validation::validate(
            token.get(),
            jwk_set_wt.get().as_ref().map(|it| &it.jwk_set),
            expected_audiences,
        )
    });

    // True when a token is present and the access token is not expired. // TODO: add: When Id token is valid.
    let is_authenticated = {
        let UseIntervalReturn { counter, .. } = use_interval(options.with_value(|o| {
            o.advanced
                .access_token_expiration_check_interval_milliseconds
        }));
        Memo::new(move |_| {
            let _count = counter.get();
            token.with(move |token| {
                if let Some(token) = token {
                    !token.access_token_expired()
                } else {
                    false
                }
            })
        })
    };

    // Auth state derived from token data or potential errors.
    let auth_state = Memo::new(move |_| {
        let token = token.get();
        let is_authenticated = is_authenticated.get();

        if is_authenticated {
            AuthState::Authenticated(token.expect("present"))
        } else {
            AuthState::NotAuthenticated {
                token_data: token,
                last_error: auth_error
                    .with(|opt_err| opt_err.as_ref().map(|err| format!("{err:?}"))),
            }
        }
    });

    // Fetch a token from the OIDC provider using an authorization code and an optional session state.
    let retrieve_oidc_config_action = action::create_retrieve_oidc_config_action(
        discovery_endpoint.clone(),
        handle_oidc_config,
        handle_req_error,
    );

    // Fetch a token from the OIDC provider using an authorization code and an optional session state.
    let retrieve_jwk_set_action =
        action::create_retrieve_jwk_set_action(handle_jwk_set_wt, handle_req_error);

    let oidc_config_too_old = {
        let UseIntervalReturn { counter, .. } = use_interval(
            options.with_value(|o| o.advanced.oidc_config_age_check_interval_milliseconds),
        );
        Memo::new(move |_| {
            let _count = counter.get();
            oidc_config_wt
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

    let jwk_set_too_old = {
        let UseIntervalReturn { counter, .. } = use_interval(
            options.with_value(|o| o.advanced.jwk_set_age_check_interval_milliseconds),
        );
        Memo::new(move |_| {
            let _count = counter.get();
            jwk_set_wt
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

    // Obtain the OIDC configuration. Updating any previously stored config.
    Effect::new(move |_| {
        if oidc_config_too_old.get() {
            retrieve_oidc_config_action.dispatch(());
        }
    });

    // Obtain the JWK set. Updating any previously stored config.
    Effect::new(move |_| {
        if jwk_set_too_old.get() {
            jwks_endpoint.with_untracked(|jwks_endpoint| match jwks_endpoint {
                Ok(jwks_endpoint_url) => {
                    retrieve_jwk_set_action.dispatch(jwks_endpoint_url.clone());
                }
                Err(err) => {
                    tracing::debug!(reason = ?err, "JWK set should be updated, as it is too old, but no jwks_endpoint_url is known jet. Skipping update...")
                }
            })
        }
    });

    // Fetch a token from the OIDC provider using an authorization code and an optional session state.
    let exchange_code_for_token_action: Action<
        (TokenEndpoint, AuthorizationCode, Option<SessionState>),
        (),
    > = action::create_exchange_code_for_token_action(options, handle_token, handle_req_error);

    // Note: Only call this after OIDC config was loaded. Otherwise, nothing happens and an error is logged!
    // TODO: Use a queuing system, so that no request is lost?
    let refresh_token_action =
        action::create_refresh_token_action(options, handle_token, handle_req_error);

    let trigger_refresh = Callback::new(move |()| {
        token_endpoint.with_untracked(|token_endpoint| {
            token.with_untracked(|token| {
                if let (Ok(token_endpoint), Some(token)) = (token_endpoint, token) {
                    refresh_token_action.dispatch((token_endpoint.clone(), token.refresh_token.clone()));
                } else {
                    tracing::info!("Requested token refresh has no effect, as no token_endpoint or refresh_token is currently known.")
                }
            })
        })
    });

    // Use the refresh token to create a new access token any time we are not authenticated but have token data available.
    // This may be necessary after the token data got deserialized form storage some time after te access token expired.
    Effect::new(move |_| {
        let auth_state = auth_state.get();
        match auth_state {
            AuthState::NotAuthenticated {
                token_data,
                last_error: _,
            } => {
                // If we have token data containing a non-expired refresh token,
                // we may be able to use it to generate a new access token.
                if let Some(token) = token_data {
                    if !token.refresh_token_expired() {
                        trigger_refresh.run(());
                    }
                }
            }
            AuthState::Authenticated(_) => {
                // Intentionally do nothing as we have a token which already has a non expired access token.
            }
        }
    });

    let access_token_nearly_expired = {
        let UseIntervalReturn { counter, .. } = use_interval(options.with_value(|o| {
            o.advanced
                .access_token_nearly_expired_check_interval_milliseconds
        }));
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
        let UseIntervalReturn { counter, .. } = use_interval(options.with_value(|o| {
            o.advanced
                .refresh_token_nearly_expired_check_interval_milliseconds
        }));
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

    // If either the access or the refresh token is about to expire (although the refresh token *should* always outlive the access token...),
    // try to refresh the access token using the refresh token.
    Effect::new(move |_| {
        let access_token_nearly_expired = access_token_nearly_expired.get();
        let refresh_token_nearly_expired = refresh_token_nearly_expired.get();
        if let Some(token) = token.get() {
            if !token.refresh_token_expired()
                && (access_token_nearly_expired || refresh_token_nearly_expired)
            {
                trigger_refresh.run(());
            }
        }
    });

    // Current state of our url parameters.
    let url_state = use_query::<CallbackResponse>();

    // Handle changes in our url parameters.
    // THIS EFFECT MAINLY DRIVES THIS SYSTEM!
    Effect::new(move |_| {
        match url_state.get() {
            Ok(state) => match state {
                CallbackResponse::SuccessfulLogin(login_state) => {
                    let perform_update = match last_used_code.get() {
                        Some(last_used_code) => last_used_code.code != login_state.code,
                        None => true,
                    };
                    if perform_update {
                        token_endpoint.with(|token_endpoint| match token_endpoint {
                            Ok(token_endpoint) => {
                                // We assume that last_code only changes when we receive a "new" / not-seen-before code.
                                // This means we can safely call the token exchange here, as we will do this only once per code we see.
                                exchange_code_for_token_action.dispatch((
                                    token_endpoint.clone(),
                                    login_state.code.clone(),
                                    login_state.session_state.clone(),
                                ));

                                set_last_used_code.set(Some(LastUsedCode {
                                    session_state: login_state.session_state,
                                    code: login_state.code,
                                }));
                            }
                            Err(err) => {
                                tracing::debug!(reason = ?err, "Could not execute exchange_code_for_token_action, as not token_endpoint is known jet...")
                            }
                        })
                    }
                }
                CallbackResponse::SuccessfulLogout(logout_state) => {
                    if logout_state.destroy_session {
                        handle_token.run(None);
                        // Even though setting the None value will lead to `None` being written to storage,
                        // we will not completely rely on that side effect and explicitly remove the data from storage.
                        // We cannot only remove the data from storage, as we DEFINITELY WANT to trigger reactive effects
                        // depending on the current token state, e.g. the auth_state and rendering of the `Authenticated` component!
                        remove_token_from_storage();
                    }
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

    let auth = KeycloakAuth {
        options,
        token,
        is_authenticated: is_authenticated.into(),
        access_token_nearly_expired: access_token_nearly_expired.into(),
        refresh_token_nearly_expired: refresh_token_nearly_expired.into(),
        auth_state: auth_state.into(),
        login_url: create_login_url_signal(authorization_endpoint, options),
        logout_url: create_logout_url_signal(end_session_endpoint, token, options),
        id_token_claims: verified_and_decoded_id_token.into(),
    };

    // We guarantee that the KeycloakAuth state is provided as context.
    provide_context(auth);

    auth
}

fn create_login_url_signal(
    authorization_endpoint_url: Signal<Result<AuthorizationEndpoint, DerivedUrlError>>,
    options: StoredValue<UseKeycloakAuthOptions>,
) -> Signal<Option<Url>> {
    Memo::new(move |_| {
        authorization_endpoint_url.with(|authorization_endpoint_url| {
            if let Ok(url) = authorization_endpoint_url {
                let mut url = url.clone();
                url.query_pairs_mut()
                    .append_pair("response_type", "code")
                    .append_pair(
                        "client_id",
                        &options.with_value(|params| params.client_id.clone()),
                    )
                    .append_pair(
                        "redirect_uri",
                        options
                            .with_value(|params| params.post_login_redirect_url.clone())
                            .as_str(),
                    )
                    .append_pair(
                        "scope",
                        &options.with_value(|params| {
                            params.scope.clone().unwrap_or("openid".to_owned())
                        }),
                    );
                Some(url)
            } else {
                Option::<Url>::None
            }
        })
    })
    .into()
}

fn create_logout_url_signal(
    end_session_endpoint_url: Signal<Result<EndSessionEndpoint, DerivedUrlError>>,
    token: Signal<Option<TokenData>>,
    options: StoredValue<UseKeycloakAuthOptions>,
) -> Signal<Option<Url>> {
    Memo::new(move |_| {
        end_session_endpoint_url.with(|end_session_endpoint| {
            if let Ok(end_session_endpoint) = end_session_endpoint {
                let mut end_session_endpoint = end_session_endpoint.clone();
                let mut post_logout_redirect_uri =
                    options.with_value(|o| o.post_logout_redirect_url.clone());
                post_logout_redirect_uri
                    .query_pairs_mut()
                    .append_pair("destroy_session", "true");

                end_session_endpoint.query_pairs_mut().append_pair(
                    "post_logout_redirect_uri",
                    post_logout_redirect_uri.as_str(),
                );
                if let Some(token_data) = token.get() {
                    // TODO: Only access verified ID tokens?
                    end_session_endpoint
                        .query_pairs_mut()
                        .append_pair("id_token_hint", &token_data.id_token);
                }
                Some(end_session_endpoint)
            } else {
                Option::<Url>::None
            }
        })
    })
    .into()
}
