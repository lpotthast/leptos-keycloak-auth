use error::{NoIdToken, UrlError};
use leptos::*;
use leptos_router::use_query;
use leptos_use::{
    storage::{use_storage_with_options, UseStorageOptions},
    use_interval, UseIntervalReturn,
};
use oidc_discovery::OidcConfig;
use response::CallbackResponse;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use token::{KeycloakIdTokenClaims, LifeLeft, TokenData};

pub mod components;
pub mod error;
mod oidc_discovery;
mod request;
mod response;
pub mod token;

pub use components::*;
pub use error::KeycloakAuthError;
pub use leptos_use::storage::StorageType;
pub use url::Url;

type DiscoveryEndpoint = Url;
type JwkSetEndpoint = Url;
type AuthorizationEndpoint = Url;
type TokenEndpoint = Url;
type EndSessionEndpoint = Url;

type AuthorizationCode = String;
type SessionState = String;
type AccessToken = String;
type RefreshToken = String;

/// Represents authentication parameters required for initializing the `Auth`
/// structure. These parameters include authentication and token endpoints,
/// client ID, and other related data.
pub struct UseKeycloakAuthOptions {
    /// Url of your keycloak instance, E.g. "https://localhost:8443/"
    pub keycloak_server_url: Url,

    /// The keycloak realm you want to use.
    pub realm: String,

    /// The name of this client as configured inside your Keycloak admin area.
    pub client_id: String,

    /// Url to which you want to be redirected after a successful login.
    pub post_login_redirect_url: Url,

    /// Url to which you want to be redirected after a successful logout.
    pub post_logout_redirect_url: Url,

    pub scope: Option<String>,

    pub advanced: AdvancedOptions,
}
pub struct AdvancedOptions {
    /// This library persists information in order to regain knowledge after cold app startup.
    /// The storage pin the storage provided here.
    ///
    pub storage_type_provider: Callback<(), leptos_use::storage::StorageType>,

    pub access_token_expiration_check_interval_milliseconds: u64,

    pub access_token_nearly_expired_check_interval_milliseconds: u64,
    pub access_token_nearly_expired_having: LifeLeft,

    pub refresh_token_nearly_expired_check_interval_milliseconds: u64,
    pub refresh_token_nearly_expired_having: LifeLeft,

    /// Intervall in milliseconds after which the oidc configuration should be checked for its age.
    /// A
    pub oidc_config_age_check_interval_milliseconds: u64,

    pub jwk_set_age_check_interval_milliseconds: u64,

    /// Time in seconds after which a discovered OIDC config is considered too old.
    pub max_oidc_config_age_seconds: u32,

    /// Time in seconds after which the loaded JWK set is considered too old.
    pub max_jwk_set_age_seconds: u32,
}

impl Default for AdvancedOptions {
    fn default() -> Self {
        Self {
            storage_type_provider: Callback::new(|()| StorageType::Local),
            access_token_expiration_check_interval_milliseconds: 2000,
            access_token_nearly_expired_check_interval_milliseconds: 2000,
            access_token_nearly_expired_having: LifeLeft::Percentage(0.25),
            refresh_token_nearly_expired_check_interval_milliseconds: 2000,
            refresh_token_nearly_expired_having: LifeLeft::Percentage(0.25),
            oidc_config_age_check_interval_milliseconds: 2000,
            jwk_set_age_check_interval_milliseconds: 2000,
            max_oidc_config_age_seconds: 60 * 3,
            max_jwk_set_age_seconds: 60 * 3,
        }
    }
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
    /// May be None until OIDC discovery happened and the URL was parsed.
    pub login_url: Signal<Option<Url>>,

    /// Generates and returns the URL for initiating the logout process. This
    /// URL is used to redirect the user to the authentication provider's logout
    /// page.
    pub logout_url: Signal<Option<Url>>,

    /// Claims from the verified ID token. Contains user information like name, email and roles.
    /// Will contain an error if the ID token was not jet verified or could not be verified.
    /// Note: Roles will only be contained if activated in the Keycloak admin UI!
    pub id_token_claims: Signal<Result<KeycloakIdTokenClaims, NoIdToken>>,
}

impl KeycloakAuth {
    /// This can be used to set the `post_login_redirect_url` dynamically. It's helpful if
    /// you would like to be redirected to the current page.
    // TODO: Decide wether this should be a signal and if this should be in our options... Or should this overwrite a signal internally?!!
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LastUsedCode {
    session_state: Option<SessionState>,
    code: AuthorizationCode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OidcConfigWithTimestamp {
    oidc_config: OidcConfig,
    retrieved: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    let options = store_value(options);

    let (auth_error, set_auth_error) = create_signal::<Option<KeycloakAuthError>>(None);

    let (last_used_code, set_last_used_code, _remove_last_used_code_from_storage) =
        use_storage_with_options(
            "leptos_keycloak_auth__last_used_code",
            Option::<LastUsedCode>::None,
            UseStorageOptions::default().storage_type(storage_type_provider.call(())),
        );

    let (token, set_token, remove_token_from_storage) = use_storage_with_options(
        "leptos_keycloak_auth__raw_token",
        Option::<TokenData>::None,
        UseStorageOptions::default().storage_type(storage_type_provider.call(())),
    );

    let (oidc_config_wt, set_oidc_config_wt, _remove_oidc_config_from_storage) =
        use_storage_with_options(
            "leptos_keycloak_auth__oidc_config",
            Option::<OidcConfigWithTimestamp>::None,
            UseStorageOptions::default().storage_type(storage_type_provider.call(())),
        );

    let (jwk_set_wt, set_jwk_set_wt, _remove_jwk_set_from_storage) = use_storage_with_options(
        "leptos_keycloak_auth__jwk_set",
        Option::<JwkSetWithTimestamp>::None,
        UseStorageOptions::default().storage_type(storage_type_provider.call(())),
    );

    let DerivedUrls {
        jwks_endpoint,
        authorization_endpoint,
        token_endpoint,
        end_session_endpoint,
    } = DerivedUrls::new(oidc_config_wt);

    let verified_and_decoded_id_token: Memo<Result<KeycloakIdTokenClaims, NoIdToken>> =
        create_memo(move |_| {
            // TODO: User should be able to overwrite this.
            let client_id = options.with_value(|o| o.client_id.clone());

            if let (Some(token), Some(jwk_set_wt)) = (token.get(), jwk_set_wt.get()) {
                let expected_audiences: &[String] = &[client_id];

                token::validate_and_decode_base64_encoded_token(
                    &token.id_token,
                    expected_audiences,
                    &jwk_set_wt.jwk_set,
                )
                .map(|standard_claims| standard_claims.into())
                .map_err(NoIdToken::JwtValidationError)
            } else {
                Err(NoIdToken::DependenciesMissing(
                    "No token or not JWK set.".to_owned(),
                ))
            }
        });

    // True when a token is present and the access token is not expired. // TODO: add: When Id token is valid.
    let is_authenticated = {
        let UseIntervalReturn { counter, .. } = use_interval(options.with_value(|o| {
            o.advanced
                .access_token_expiration_check_interval_milliseconds
        }));
        create_memo(move |_| {
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
    let auth_state = create_memo(move |_| {
        let token = token.get();
        let is_authenticated = is_authenticated.get();
        let auth_error = auth_error.get();

        if is_authenticated {
            AuthState::Authenticated(token.expect("present"))
        } else {
            AuthState::NotAuthenticated {
                token_data: token,
                last_error: auth_error.map(|err| format!("{err:?}")),
            }
        }
    });

    // Fetch a token from the OIDC provider using an authorization code and an optional session state.
    let retrieve_oidc_config_action = create_retrieve_oidc_config_action(
        discovery_endpoint.clone(),
        set_oidc_config_wt,
        set_auth_error,
    );

    // Fetch a token from the OIDC provider using an authorization code and an optional session state.
    let retrieve_jwk_set_action = create_retrieve_jwk_set_action(set_jwk_set_wt, set_auth_error);

    let oidc_config_too_old = {
        let UseIntervalReturn { counter, .. } = use_interval(
            options.with_value(|o| o.advanced.oidc_config_age_check_interval_milliseconds),
        );
        create_memo(move |_| {
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
        create_memo(move |_| {
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
    create_effect(move |_| {
        if oidc_config_too_old.get() {
            retrieve_oidc_config_action.dispatch(());
        }
    });

    // Obtain the JWK set. Updating any previously stored config.
    create_effect(move |_| {
        if jwk_set_too_old.get() {
            match jwks_endpoint.get_untracked() {
                Ok(jwks_endpoint_url) => {
                    retrieve_jwk_set_action.dispatch(jwks_endpoint_url);
                }
                Err(err) => {
                    tracing::debug!(reason = ?err, "JWK set should be updated, as it is too old, but no jwks_endpoint_url is known jet. Skipping update...")
                }
            }
        }
    });

    // Fetch a token from the OIDC provider using an authorization code and an optional session state.
    let exchange_code_for_token_action: Action<
        (TokenEndpoint, AuthorizationCode, Option<SessionState>),
        (),
    > = create_exchange_code_for_token_action(options, set_token, set_auth_error);

    // Note: Only call this after OIDC config was loaded. Otherwise, nothing happens and an error is logged!
    // TODO: Use a queuing system, so that no request is lost?
    let refresh_token_action = create_refresh_token_action(options, set_token, set_auth_error);

    let trigger_refresh = Callback::new(move |()| {
        if let (Ok(token_endpoint), Some(token)) =
            (token_endpoint.get_untracked(), token.get_untracked())
        {
            refresh_token_action.dispatch((token_endpoint, token.refresh_token));
        } else {
            tracing::info!("Requested token refresh has no effect, as no token_endpoint or refresh_token is currently known.")
        }
    });

    // Use the refresh token to create a new access token any time we are not authenticated but have token data available.
    // This may be necessary after the token data got deserialized form storage some time after te access token expired.
    create_effect(move |_| {
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
                        trigger_refresh.call(());
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
        create_memo(move |_| {
            // Depend on counter to let this be checked every now and than.
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
        create_memo(move |_| {
            // Depend on counter to let this be checked every now and than.
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

    // If either the access or the refresh token is about to expire (although the refresh token *should* always outlive the access token..),
    // try to refresh the access token using the refresh token.
    create_effect(move |_| {
        let access_token_nearly_expired = access_token_nearly_expired.get();
        let refresh_token_nearly_expired = refresh_token_nearly_expired.get();
        if let Some(token) = token.get() {
            if !token.refresh_token_expired()
                && (access_token_nearly_expired || refresh_token_nearly_expired)
            {
                trigger_refresh.call(());
            }
        }
    });

    // Current state of our url parameters.
    let url_state = use_query::<CallbackResponse>();

    // Handle changes in our url parameters.
    // THIS EFFECT MAINLY DRIVES THIS SYSTEM!
    create_effect(move |_| {
        match url_state.get() {
            Ok(state) => match state {
                CallbackResponse::SuccessLogin(login_state) => {
                    let perform_update = match last_used_code.get() {
                        Some(last_used_code) => last_used_code.code != login_state.code,
                        None => true,
                    };
                    if perform_update {
                        match token_endpoint.get() {
                            Ok(token_endpoint) => {
                                // We assume that last_code only changes when we receive a "new" / not-seen-before code.
                                // This means we can safely call the token exchange here, as we will do this only once per code we see.
                                exchange_code_for_token_action.dispatch((
                                    token_endpoint,
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
                        }
                    }
                }
                CallbackResponse::SuccessLogout(logout_state) => {
                    if logout_state.destroy_session {
                        set_token.set(None);
                        // Even though setting the None value will lead to `None` being written to storage,
                        // we will not completely rely on that side effect and explicitly remove the data from storage.
                        // We cannot only remove the data from storage, as we DEFINITELY WANT to trigger reactive effects
                        // depending on the current token state, e.g. the auth_state and rendering of the `Authenticated` component!
                        remove_token_from_storage();
                    }
                }
                CallbackResponse::Error(err_state) => {
                    set_auth_error.set(Some(KeycloakAuthError::Provider(err_state)));
                }
            },
            Err(err) => {
                // Save to be ignored. This just means that we currently do not have the required parameters to do meaningful work.
                // You might want to debug this error if things don't work.
                set_auth_error.set(Some(KeycloakAuthError::Params(err)));
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

struct DerivedUrls {
    jwks_endpoint: Signal<Result<JwkSetEndpoint, UrlError>>,
    authorization_endpoint: Signal<Result<AuthorizationEndpoint, UrlError>>,
    token_endpoint: Signal<Result<TokenEndpoint, UrlError>>,
    end_session_endpoint: Signal<Result<EndSessionEndpoint, UrlError>>,
}

impl DerivedUrls {
    fn new(oidc_config_wt: Signal<Option<OidcConfigWithTimestamp>>) -> Self {
        let jwks_endpoint_url: Signal<Result<Url, UrlError>> = Signal::derive(move || {
            oidc_config_wt.with(move |oidc_config| match oidc_config {
                Some(oidc_config) => Url::parse(&oidc_config.oidc_config.standard_claims.jwks_uri)
                    .map_err(UrlError::Parsing),
                None => Err(UrlError::DependenciesMissing("oidc_config is None")),
            })
        });

        let authorization_endpoint_url: Signal<Result<Url, UrlError>> = Signal::derive(move || {
            oidc_config_wt.with(move |oidc_config| match oidc_config {
                Some(oidc_config) => Url::parse(
                    &oidc_config
                        .oidc_config
                        .standard_claims
                        .authorization_endpoint,
                )
                .map_err(UrlError::Parsing),
                None => Err(UrlError::DependenciesMissing("oidc_config is None")),
            })
        });

        let token_endpoint_url: Signal<Result<Url, UrlError>> = Signal::derive(move || {
            oidc_config_wt.with(move |oidc_config| match oidc_config {
                Some(oidc_config) => {
                    match oidc_config
                        .oidc_config
                        .standard_claims
                        .token_endpoint
                        .as_deref()
                    {
                        Some(token_endpoint) => {
                            Url::parse(token_endpoint).map_err(UrlError::Parsing)
                        }
                        None => Err(UrlError::DependenciesMissing(
                            "oidc_config.standard_claims.token_endpoint is None",
                        )),
                    }
                }
                None => Err(UrlError::DependenciesMissing("oidc_config is None")),
            })
        });

        let end_session_endpoint_url: Signal<Result<Url, UrlError>> = Signal::derive(move || {
            oidc_config_wt.with(move |oidc_config| match oidc_config {
                Some(oidc_config) => {
                    match oidc_config
                        .oidc_config
                        .rp_initialized_claims
                        .end_session_endpoint
                        .as_deref()
                    {
                        Some(end_session_endpoint) => {
                            Url::parse(end_session_endpoint).map_err(UrlError::Parsing)
                        }
                        None => Err(UrlError::DependenciesMissing(
                            "oidc_config.rp_initialized_claims.end_session_endpoint is None",
                        )),
                    }
                }
                None => Err(UrlError::DependenciesMissing("oidc_config is None")),
            })
        });

        Self {
            jwks_endpoint: jwks_endpoint_url,
            authorization_endpoint: authorization_endpoint_url,
            token_endpoint: token_endpoint_url,
            end_session_endpoint: end_session_endpoint_url,
        }
    }
}

fn create_login_url_signal(
    authorization_endpoint_url: Signal<Result<AuthorizationEndpoint, UrlError>>,
    options: StoredValue<UseKeycloakAuthOptions>,
) -> Signal<Option<Url>> {
    create_memo(move |_| {
        if let Ok(mut url) = authorization_endpoint_url.get() {
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
                    &options
                        .with_value(|params| params.scope.clone().unwrap_or("openid".to_owned())),
                );
            Some(url)
        } else {
            Option::<Url>::None
        }
    })
    .into()
}

fn create_logout_url_signal(
    end_session_endpoint_url: Signal<Result<EndSessionEndpoint, UrlError>>,
    token: Signal<Option<TokenData>>,
    options: StoredValue<UseKeycloakAuthOptions>,
) -> Signal<Option<Url>> {
    create_memo(move |_| {
        if let Ok(mut end_session_endpoint) = end_session_endpoint_url.get() {
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
    .into()
}

fn create_retrieve_oidc_config_action(
    discovery_endpoint_url: DiscoveryEndpoint,
    set_oidc_config_wt: WriteSignal<Option<OidcConfigWithTimestamp>>,
    set_auth_error: WriteSignal<Option<KeycloakAuthError>>,
) -> Action<(), ()> {
    create_action(move |(): &()| {
        let discovery_endpoint_url = discovery_endpoint_url.clone();
        async move {
            let result = request::retrieve_oidc_config(discovery_endpoint_url).await;
            match result {
                Ok(oidc_config) => {
                    set_oidc_config_wt.set(Some(OidcConfigWithTimestamp {
                        oidc_config,
                        retrieved: OffsetDateTime::now_utc(),
                    }));
                    // set_auth_error.set(None);
                }
                Err(err) => {
                    // set_token.set(None);
                    tracing::error!(?err, "Could not retrieve OIDC config through discovery.");
                    set_auth_error.set(Some(err));
                }
            }
        }
    })
}

fn create_retrieve_jwk_set_action(
    set_jwk_set_wt: WriteSignal<Option<JwkSetWithTimestamp>>,
    set_auth_error: WriteSignal<Option<KeycloakAuthError>>,
) -> Action<Url, ()> {
    create_action(move |jwk_set_endpoint: &JwkSetEndpoint| {
        let jwk_set_endpoint = jwk_set_endpoint.clone();
        async move {
            let result = request::retrieve_jwk_set(jwk_set_endpoint).await;
            match result {
                Ok(jwk_set) => {
                    set_jwk_set_wt.set(Some(JwkSetWithTimestamp {
                        jwk_set,
                        retrieved: OffsetDateTime::now_utc(),
                    }));
                    // set_auth_error.set(None);
                }
                Err(err) => {
                    // set_token.set(None);
                    tracing::error!(?err, "Could not retrieve JWK set.");
                    set_auth_error.set(Some(err));
                }
            }
        }
    })
}

fn create_exchange_code_for_token_action(
    options: StoredValue<UseKeycloakAuthOptions>,
    set_token: WriteSignal<Option<TokenData>>,
    set_auth_error: WriteSignal<Option<KeycloakAuthError>>,
) -> Action<(TokenEndpoint, AuthorizationCode, Option<SessionState>), ()> {
    create_action(
        move |(token_endpoint, code, session_state): &(
            TokenEndpoint,
            AuthorizationCode,
            Option<SessionState>,
        )| {
            let client_id = options.with_value(|params| params.client_id.clone());
            let redirect_uri = options.with_value(|params| params.post_login_redirect_url.clone());
            let token_endpoint = token_endpoint.clone();
            let code = code.clone();
            let session_state = session_state.clone();
            async move {
                let result = request::exchange_code_for_token(
                    client_id,
                    redirect_uri,
                    token_endpoint,
                    code,
                    session_state,
                )
                .await;
                match result {
                    Ok(token) => {
                        set_token.set(Some(token));
                        // set_auth_error.set(None);
                    }
                    Err(err) => {
                        // set_token.set(None);
                        set_auth_error.set(Some(err));
                    }
                }
            }
        },
    )
}

fn create_refresh_token_action(
    options: StoredValue<UseKeycloakAuthOptions>,
    set_token: WriteSignal<Option<TokenData>>,
    set_auth_error: WriteSignal<Option<KeycloakAuthError>>,
) -> Action<(TokenEndpoint, RefreshToken), ()> {
    create_action(
        move |(token_endpoint, refresh_token): &(TokenEndpoint, RefreshToken)| {
            let client_id = options.with_value(|params| params.client_id.clone());
            let token_endpoint = token_endpoint.clone();
            let refresh_token = refresh_token.clone();
            async move {
                match request::refresh_token(client_id, token_endpoint, refresh_token).await {
                    Ok(refreshed_token) => set_token.set(Some(refreshed_token)),
                    Err(err) => set_auth_error.set(Some(err)),
                }
            }
        },
    )
}
