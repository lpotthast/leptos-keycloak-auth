use crate::{Authenticated, KeycloakAuth, UseKeycloakAuthOptions};
use leptos::prelude::*;

/// Get access to the current authentication state.
///
/// Panics when `init_keycloak_auth` was not yet called.
pub fn expect_keycloak_auth() -> KeycloakAuth {
    expect_context::<KeycloakAuth>()
}

/// Get access to the current user data.
///
/// Panics when the user is not currently authenticated.
///
/// Safe to call anywhere under `ShowWhenAuthenticated`.
pub fn expect_authenticated() -> Authenticated {
    expect_context::<Authenticated>()
}

/// Initializes a new `KeycloakAuth` instance, the authentication handler responsible for handling
/// user authentication and token management, with the provided authentication parameters.
///
/// This HAS TO BE called from inside a `<Router>` component, as `use_keycloak_auth` requires
/// reactive access to the current url of the page.
pub fn init_keycloak_auth(options: UseKeycloakAuthOptions) -> KeycloakAuth {
    tracing::trace!("Initializing Keycloak auth...");

    #[cfg(feature = "ssr")]
    {
        let auth = ssr_stub(options);
        provide_context(auth);
        auth
    }

    #[cfg(not(feature = "ssr"))]
    {
        let auth = real(options);
        provide_context(auth);
        auth
    }
}

#[cfg(feature = "ssr")]
fn ssr_stub(options: UseKeycloakAuthOptions) -> KeycloakAuth {
    use crate::config::Options;
    use crate::internal::derived_urls::DerivedUrls;
    use crate::{KeycloakAuth, KeycloakAuthState};
    use leptos::prelude::*;

    let options = Options::new(options);
    let options = StoredValue::new(options);

    KeycloakAuth {
        options,
        derived_urls: DerivedUrls::new(Signal::from(None)),
        login_url: Signal::from(None),
        logout_url: Signal::from(None),
        state: Signal::from(KeycloakAuthState::Indeterminate),
        is_authenticated: Signal::from(false),
        oidc_config_manager: crate::internal::oidc_config_manager::OidcConfigManager {
            oidc_config: Default::default(),
            set_oidc_config: {
                let (_, w) = signal(None);
                w
            },
            oidc_config_age: Default::default(),
            oidc_config_expires_in: Default::default(),
            oidc_config_too_old: Default::default(),
        },
        jwk_set_manager: crate::internal::jwk_set_manager::JwkSetManager {
            jwk_set: Default::default(),
            set_jwk_set: {
                let (_, w) = signal(None);
                w
            },
            jwk_set_old: Default::default(),
            set_jwk_set_old: {
                let (_, w) = signal(None);
                w
            },
            jwk_set_age: Default::default(),
            jwk_set_expires_in: Default::default(),
            jwk_set_too_old: Default::default(),
        },
        code_verifier_manager: crate::internal::code_verifier_manager::CodeVerifierManager {
            code_verifier: Default::default(),
            set_code_verifier: {
                let (_, w) = signal(None);
                w
            },
            code_challenge: Memo::new(|_| None),
        },
        token_manager: crate::internal::token_manager::TokenManager {
            token: Default::default(),
            set_token: {
                let (_, w) = signal(None);
                w
            },
            access_token_lifetime: Default::default(),
            access_token_expires_in: Default::default(),
            access_token_nearly_expired: Default::default(),
            access_token_expired: Default::default(),
            refresh_token_lifetime: Default::default(),
            refresh_token_expires_in: Default::default(),
            refresh_token_nearly_expired: Default::default(),
            refresh_token_expired: Default::default(),
            exchange_code_for_token_action: Action::new(|_| async move {}),
            token_endpoint: Signal::from(Err(
                crate::internal::derived_urls::DerivedUrlError::NoConfig,
            )),
            trigger_refresh: Callback::new(|_| ()),
        },
    }
}

#[cfg(not(feature = "ssr"))]
fn real(options: UseKeycloakAuthOptions) -> KeycloakAuth {
    use crate::config::Options;
    use crate::error::KeycloakAuthError;
    use crate::internal::derived_urls::DerivedUrls;
    use crate::internal::token_manager::OnRefreshError;
    use crate::request::RequestError;
    use crate::response::CallbackResponse;
    use crate::token_claims::KeycloakIdTokenClaims;
    use crate::token_validation::KeycloakIdTokenClaimsError;
    use crate::{
        Authenticated, KeycloakAuth, KeycloakAuthState, NotAuthenticated, RequestAction, internal,
        login, logout, token_validation,
    };
    use leptos::callback::Callback;
    use leptos::prelude::*;
    use leptos_router::NavigateOptions;
    use leptos_router::hooks::{use_navigate, use_query};
    use std::ops::Deref;
    use time::OffsetDateTime;

    let options = Options::new(options);
    let options = StoredValue::new(options);

    let (auth_error, set_auth_error) = signal::<Option<KeycloakAuthError>>(None);
    let handle_req_error = Callback::new(move |request_error: Option<RequestError>| {
        set_auth_error.set(request_error.map(|err| KeycloakAuthError::Request { source: err }))
    });

    let oidc_mgr = internal::oidc_config_manager::OidcConfigManager::new(options, handle_req_error);

    let derived_urls = oidc_mgr.derive_urls();
    let DerivedUrls {
        jwks_endpoint,
        authorization_endpoint,
        token_endpoint,
        end_session_endpoint,
    } = derived_urls;

    let jwk_set_mgr =
        internal::jwk_set_manager::JwkSetManager::new(options, jwks_endpoint, handle_req_error);

    let token_mgr =
        internal::token_manager::TokenManager::new(options, handle_req_error, token_endpoint);

    let code_mgr = internal::code_verifier_manager::CodeVerifierManager::new();

    // Current state of our url parameters.
    let url_state = use_query::<CallbackResponse>();

    let (pending_login, set_pending_login) = signal(false);
    let unset_pending_login = Callback::<(), ()>::from(move || {
        set_pending_login.set(false);
    });

    // Handle changes in our url parameters.
    // THIS EFFECT MAINLY DRIVES THIS SYSTEM!
    Effect::new(move |_| {
        match url_state.get() {
            Ok(state) => match state {
                CallbackResponse::SuccessfulLogin(login_state) => {
                    tracing::trace!(?login_state, "Login successful");
                    set_pending_login.set(true);

                    // We assume that last_code only changes when we receive a "new" / not-seen-before code.
                    // This means we can safely call the token exchange here, as we will do this only once per code we see.
                    token_mgr.exchange_code_for_token(
                        login_state.code.clone(),
                        code_mgr.code_verifier.get_untracked().expect("present"),
                        login_state.session_state.clone(),
                        unset_pending_login,
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
                        options
                            .read_value()
                            .post_login_redirect_url
                            .read_untracked()
                            .as_ref(),
                        NavigateOptions::default(),
                    );
                }
                CallbackResponse::SuccessfulLogout(logout_state) => {
                    tracing::trace!(?logout_state, "Logout successful");

                    // Note: This currently ignores the responses `destroy_session`.

                    // We have to use `request_animation_frame` here, as setting the token to `None` would
                    // otherwise lead to an immediate execution of all reactive primitives depending on this.
                    // This includes our `Authenticated` state (and all component trees rendered under
                    // a `ShowWhenAuthenticated`). But `Authenticated` expects a token to be present!
                    // We have to make sure that the state is switched to `NotAuthenticated` (by observing that
                    // no token is present) first!
                    request_animation_frame(move || {
                        token_mgr.forget();

                        // We should recreate the code_verifier to have a new one for the next login phase.
                        code_mgr.regenerate();
                    });

                    // We currently "remove" the query parameters by doing an extra, programmatic
                    // routing to the `post_logout_redirect_url`. That will just be handled by the
                    // leptos router and performed on the client itself.
                    let navigate = use_navigate();
                    navigate(
                        options
                            .read_value()
                            .post_logout_redirect_url
                            .read_untracked()
                            .as_ref(),
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
                set_auth_error.set(Some(KeycloakAuthError::Params { err }));
            }
        }
    });

    let verified_and_decoded_id_token: Memo<
        Result<KeycloakIdTokenClaims, KeycloakIdTokenClaimsError>,
    > = Memo::new(move |_| {
        let expected_audiences = options
            .read_value()
            .id_token_validation
            .expected_audiences
            .get();
        let expected_issuers = options
            .read_value()
            .id_token_validation
            .expected_issuers
            .get();

        let result;

        let first_try = token_validation::validate(
            token_mgr.token.get(),
            jwk_set_mgr.jwk_set.get().as_ref().map(|it| &it.jwk_set),
            expected_audiences.as_deref(),
            expected_issuers.as_deref(),
        );

        if first_try.is_ok() {
            result = first_try
        } else {
            // If validation with the current JWK set fails, we should not try to validate with a
            // missing old set. This would just lest to a `NoJwkSet` error being ultimately stored,
            // hiding the real reason why validation failed in the first place.
            if jwk_set_mgr.jwk_set_old.read().is_some() {
                let second_try = token_validation::validate(
                    token_mgr.token.get(),
                    jwk_set_mgr.jwk_set_old.get().as_ref().map(|it| &it.jwk_set),
                    expected_audiences.as_deref(),
                    expected_issuers.as_deref(),
                );
                result = second_try;
            } else {
                result = first_try;
            }
        }

        tracing::trace!(?result, "ID token validation result");
        result
    });

    let (last_refresh_from_error, set_last_refresh_from_error) =
        signal::<Option<OffsetDateTime>>(None);
    let auth_error_reporter = Callback::new(move |status_code: http::StatusCode| {
        // Should the user report that a request using the current access token failed,
        // this may mean that the token was revoked.
        // We can try to refresh the token.
        match status_code {
            // NOTE: This MUST NOT lead to an infinite loop of refreshed and failed requests.
            // Which may happen if
            // - the refresh succeeds but
            // - the 401 error cannot be resolved with the refresh.
            http::StatusCode::UNAUTHORIZED => {
                if last_refresh_from_error
                    .get_untracked()
                    .filter(|it| (OffsetDateTime::now_utc() - *it).whole_seconds() > 1)
                    .is_some()
                {
                    token_mgr.refresh_token(OnRefreshError::DropToken);
                    set_last_refresh_from_error.set(Some(OffsetDateTime::now_utc()));
                }
                RequestAction::Fail
            }
            _ => RequestAction::Fail,
        }
    });

    let (pending_hydration, set_pending_hydration) =
        signal(options.read_value().delay_during_hydration);
    if options.read_value().delay_during_hydration {
        request_animation_frame(move || {
            set_pending_hydration.set(false);
        });
    }

    // Auth state derived from token data or potential errors.
    let state = Memo::new(move |_| {
        let token = token_mgr.token;

        // Note: The token might have already been set to None but access_token_expired was not yet updated...
        let has_token = token.read().is_some();
        let has_verified_and_decoded_id_token = verified_and_decoded_id_token.read().is_ok();

        if pending_hydration.get() || pending_login.get() {
            tracing::trace!("Switching to: KeycloakAuthState::Indeterminate");
            KeycloakAuthState::Indeterminate
        } else if has_token
            && has_verified_and_decoded_id_token
            && !token_mgr.access_token_expired.get()
        {
            tracing::trace!("Switching to: KeycloakAuthState::Authenticated");
            KeycloakAuthState::Authenticated(Authenticated {
                access_token: Signal::derive(move || {
                    token
                        .read()
                        .as_ref()
                        .map(|it| it.access_token.clone())
                        .expect("present")
                }),
                id_token_claims: Signal::derive(move || {
                    verified_and_decoded_id_token.get().expect("present")
                }),
                auth_error_reporter,
            })
        } else {
            tracing::trace!("Switching to: KeycloakAuthState::NotAuthenticated");
            KeycloakAuthState::NotAuthenticated(NotAuthenticated {
                has_token_data: Signal::derive(move || token.get().is_some()),
                last_id_token_error: Signal::derive(move || {
                    verified_and_decoded_id_token.get().err()
                }),
                last_error: auth_error.into(),
            })
        }
    });

    let auth = KeycloakAuth {
        options,
        derived_urls,
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
            pending_hydration.into(),
        )
        .into(),
        state: state.into(),
        is_authenticated: Signal::derive(move || match state.read().deref() {
            KeycloakAuthState::Authenticated(_) => true,
            KeycloakAuthState::NotAuthenticated { .. } | KeycloakAuthState::Indeterminate => false,
        }),
        oidc_config_manager: oidc_mgr,
        jwk_set_manager: jwk_set_mgr,
        code_verifier_manager: code_mgr,
        token_manager: token_mgr,
    };

    auth
}
