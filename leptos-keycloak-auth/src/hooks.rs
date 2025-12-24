use crate::request::GrantType;
use crate::token_validation::NonceValidation;
use crate::{AccessToken, Authenticated, KeycloakAuth, UseKeycloakAuthOptions, internal};
use leptos::prelude::*;

/// Get access to the current authentication state.
///
/// Panics when `init_keycloak_auth` was not yet called.
#[must_use]
pub fn use_keycloak_auth() -> KeycloakAuth {
    expect_context::<KeycloakAuth>()
}

/// Get access to the current user data.
///
/// Panics when the user is not currently authenticated.
///
/// Safe to call anywhere under [`Authenticated`](crate::components::Authenticated).
#[must_use]
pub fn use_authenticated() -> Authenticated {
    expect_context::<Authenticated>()
}

/// Get access to the current authentication state without panicking.
///
/// This is only useful in apps where `init_keycloak_auth`/`<AuthProvider>` is not called/used
/// globally on every route.
///
/// # Example
/// ```no_run
/// use leptos_keycloak_auth::try_use_keycloak_auth;
///
/// # use leptos::prelude::*;
/// # #[component]
/// # fn Example() -> impl IntoView {
/// if let Some(auth) = try_use_keycloak_auth() {
///     if auth.is_authenticated.get() {
///         view! { <a href="/account">"My Account"</a> }.into_any()
///     } else {
///         view! { <span>"Not logged in"</span> }.into_any()
///     }
/// } else {
///     view! { <span>"Loading..."</span> }.into_any()
/// }
/// # }
/// ```
#[must_use]
pub fn try_use_keycloak_auth() -> Option<KeycloakAuth> {
    use_context::<KeycloakAuth>()
}

/// Get access to the current user data without panicking.
///
/// Returns `None` when the user is not currently authenticated or when auth is not initialized.
/// This is useful for components that want to adapt their behavior based on authentication status.
///
/// # Example
/// ```no_run
/// use leptos_keycloak_auth::try_use_authenticated;
///
/// # use leptos::prelude::*;
/// # #[component]
/// # fn Example() -> impl IntoView {
/// match try_use_authenticated() {
///     Some(auth) => view! { <p>"Welcome, " { auth.id_token_claims.read().name.clone() }</p> }.into_any(),
///     None => view! { <p>"Welcome, guest!"</p> }.into_any()
/// }
/// # }
/// ```
#[must_use]
pub fn try_use_authenticated() -> Option<Authenticated> {
    use_context::<Authenticated>()
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

    let code_verifier = Signal::from(crate::code_verifier::CodeVerifier::generate());

    let hydration_manager = internal::hydration_manager::HydrationManager::new();

    KeycloakAuth {
        options,
        derived_urls: DerivedUrls::new(Signal::from(None)),
        login_url: Signal::from(None),
        logout_url: Signal::from(None),
        state: Signal::from(KeycloakAuthState::Indeterminate),
        is_authenticated: Signal::from(false),
        oidc_config_manager: internal::oidc_config_manager::OidcConfigManager {
            oidc_config: Default::default(),
            set_oidc_config: { Callback::new(|_| {}) },
            oidc_config_age: Default::default(),
            oidc_config_expires_in: Default::default(),
            oidc_config_too_old: Default::default(),
        },
        jwk_set_manager: internal::jwk_set_manager::JwkSetManager {
            jwk_set: Default::default(),
            set_jwk_set: { Callback::new(|_| {}) },
            jwk_set_old: Default::default(),
            set_jwk_set_old: { Callback::new(|_| {}) },
            jwk_set_age: Default::default(),
            jwk_set_expires_in: Default::default(),
            jwk_set_too_old: Default::default(),
        },
        code_verifier_manager: internal::code_verifier_manager::CodeVerifierManager {
            code_verifier,
            set_code_verifier: { Callback::new(|_| {}) },
            code_challenge: Memo::new(move |_| code_verifier.read().to_code_challenge()),
        },
        token_manager: internal::token_manager::TokenManager {
            token: Default::default(),
            set_token: { Callback::new(|_| {}) },
            access_token_lifetime: Default::default(),
            access_token_expires_in: Default::default(),
            access_token_nearly_expired: Default::default(),
            access_token_expired: Default::default(),
            refresh_token_lifetime: Default::default(),
            refresh_token_expires_in: Default::default(),
            refresh_token_nearly_expired: Default::default(),
            refresh_token_expired: Default::default(),
            exchange_code_for_token_action: Action::new(|_| async move {}),
            token_endpoint: Signal::from(Err(internal::derived_urls::DerivedUrlError::NoConfig)),
            trigger_refresh: Callback::new(|_| ()),
        },
        csrf_token_manager: internal::csrf_token_manager::CsrfTokenManager::new(),
        nonce_manager: internal::nonce_manager::NonceManager::new(),
        suspicious_logout: Signal::from(false),
        dismiss_suspicious_logout_warning: Callback::new(|_| ()),
        hydration_manager,
    }
}

#[cfg(not(feature = "ssr"))]
#[allow(clippy::too_many_lines)]
fn real(options: UseKeycloakAuthOptions) -> KeycloakAuth {
    use crate::config::Options;
    use crate::error::KeycloakAuthError;
    use crate::internal::derived_urls::DerivedUrls;
    use crate::internal::token_manager::OnRefreshError;
    use crate::request::RequestError;
    use crate::response::CallbackResponse;
    use crate::token_claims::KeycloakIdTokenClaims;
    use crate::token_validation::IdTokenClaimsError;
    use crate::{
        Authenticated, KeycloakAuth, KeycloakAuthState, NotAuthenticated, RequestAction, login,
        logout, token_validation,
    };
    use leptos::callback::Callback;
    use leptos::prelude::*;
    use leptos_router::NavigateOptions;
    use leptos_router::hooks::{use_navigate, use_query};
    use std::ops::Deref;
    use time::OffsetDateTime;

    let options = Options::new(options);
    let options = StoredValue::new(options);

    let hydration_manager = internal::hydration_manager::HydrationManager::new();

    let (auth_error, set_auth_error) = signal::<Option<KeycloakAuthError>>(None);
    let handle_req_error = Callback::new(move |request_error: Option<RequestError>| {
        set_auth_error.set(request_error.map(|err| KeycloakAuthError::Request { source: err }));
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

    let nonce_mgr = internal::nonce_manager::NonceManager::new();

    let csrf_mgr = internal::csrf_token_manager::CsrfTokenManager::new();

    // Allow tracing of suspicious logout attempts (potential CSRF attacks).
    let (suspicious_logout, set_suspicious_logout) = signal(false);
    let dismiss_suspicious_logout_warning = Callback::new(move |()| {
        set_suspicious_logout.set(false);
    });

    // Current state of our url parameters.
    let url_state = use_query::<CallbackResponse>();

    let (pending_login, set_pending_login) = signal(false);
    let unset_pending_login = Callback::<(), ()>::from(move || {
        set_pending_login.set(false);
        // Reset suspicious logout flag on successful login.
        dismiss_suspicious_logout_warning.run(());
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
                        code_mgr.code_verifier.get_untracked(),
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
                CallbackResponse::SuccessfulLogout(logout_response) => {
                    tracing::trace!(?logout_response, "Logout callback received");

                    // Validate CSRF token to detection potentially malicious logout not controlled
                    // by us.
                    let is_suspicious_logout =
                        if options.read_value().advanced.logout_csrf_detection {
                            !csrf_mgr.validate_logout_token(
                                logout_response.state.as_deref().unwrap_or_default(),
                            )
                        } else {
                            tracing::debug!("Logout CSRF detection is disabled");
                            false
                        };

                    // Note: This currently ignores the response's `destroy_session`.

                    // Store suspicious logout flag for user notification.
                    set_suspicious_logout.set(is_suspicious_logout);

                    // Regardless of state validation, we must clean up local state
                    // because Keycloak has already destroyed the session.
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

                        // We should regenerate the nonce to have a new one for the next login phase.
                        nonce_mgr.regenerate();

                        // We should use a new CSRF token in the next logout.
                        csrf_mgr.regenerate();
                    });

                    // We "remove" the auth related query parameters set in the logout process
                    // by doing an extra, programmatic routing to the user supplied
                    // `post_logout_redirect_url`.
                    // That will just be handled by the leptos router and performed on the client
                    // itself.
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
                // Save to be ignored. This just means that we currently do not have the required
                // parameters to do meaningful work.
                // You might want to debug this error if things don't work.
                set_auth_error.set(Some(KeycloakAuthError::Params { err }));
            }
        }
    });

    let verified_and_decoded_id_token: Memo<Result<KeycloakIdTokenClaims, IdTokenClaimsError>> =
        Memo::new(move |_| {
            let options = options.read_value();
            let expected_audiences = options.id_token_validation.expected_audiences.get();
            let expected_issuers = options.id_token_validation.expected_issuers.get();
            let nonce_validation_requested = options.advanced.nonce_validation;

            let token_data = token_validation::validate_token_data_presence(token_mgr.token.get())?;
            let jwk_set = token_validation::validate_jwk_set_presence(jwk_set_mgr.jwk_set.get())?;

            // Do not require a nonce in the ID token when the token data source was a refresh.
            // As stated in <https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse>,
            // refresh tokens SHOULD NOT have a `nonce` claim, and Keycloak generally respects that.
            // A backwards compatibility claim mapper can be enabled to still include nonce claims in
            // refresh tokens, but this is not required from a security perspective. If the mapper is
            // enabled, also enabling nonce claims in ID tokens returned from a refresh, we again
            // validate against the initial nonce value, as this value is only regenerated on logout.
            let expected_nonce = nonce_mgr.nonce().read_untracked();
            let nonce_validation_required =
                nonce_validation_requested && token_data.grant_type != GrantType::RefreshToken;
            let nonce_validation = match (nonce_validation_requested, nonce_validation_required) {
                (true, true) => NonceValidation::Required {
                    expected_nonce: expected_nonce.as_str(),
                },
                (true, false) => NonceValidation::IfPresent {
                    expected_nonce: expected_nonce.as_str(),
                },
                (false, _) => NonceValidation::Disabled,
            };

            let result: Result<KeycloakIdTokenClaims, IdTokenClaimsError>;

            let first_try = token_validation::validate(
                &token_data,
                &jwk_set.jwk_set,
                expected_audiences.as_deref(),
                expected_issuers.as_deref(),
                nonce_validation,
            );

            if first_try.is_ok() {
                result = first_try;
            } else {
                // If validation with the current JWK set fails, we should not try to validate with a
                // missing old set. This would just lead to a `NoJwkSet` error being ultimately stored,
                // hiding the real reason why validation failed in the first place.
                if let Some(jwk_set_old) = jwk_set_mgr.jwk_set_old.read().as_ref() {
                    let second_try = token_validation::validate(
                        &token_data,
                        &jwk_set_old.jwk_set,
                        expected_audiences.as_deref(),
                        expected_issuers.as_deref(),
                        nonce_validation,
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
                // If we never attempted a refresh before (is_none).
                if last_refresh_from_error.get_untracked().is_none_or(
                    // If the last error is old.
                    |it| (OffsetDateTime::now_utc() - it).whole_seconds() > 1,
                ) {
                    token_mgr.refresh_token(OnRefreshError::DropToken);
                    set_last_refresh_from_error.set(Some(OffsetDateTime::now_utc()));
                }
                RequestAction::Fail
            }
            _ => RequestAction::Fail,
        }
    });

    // Create a persistent `Authenticated` state that doesn't get recreated on every evaluation of
    // our `state` memo.
    // We ensure the assumptions made here (`expect`s) are upheld by only providing this
    // `Authenticated` state as context (through `provide_context`) when the user really is
    // authenticated.
    let authenticated = StoredValue::new(Authenticated {
        access_token: Memo::new(move |prev: Option<&AccessToken>| {
            match token_mgr.token.read().as_ref().map(|it| &it.access_token) {
                None => match prev {
                    None => {
                        panic!("access_token signal should only be read when authenticated");
                    }
                    Some(prev) => prev.clone(),
                },
                Some(access_token) => access_token.clone(),
            }
        }),
        id_token_claims: Memo::new(move |prev: Option<&KeycloakIdTokenClaims>| {
            match verified_and_decoded_id_token.read().as_ref() {
                Err(err) => match prev {
                    None => {
                        panic!(
                            "id_token_claims signal should only be read when authenticated: {err:?}"
                        );
                    }
                    Some(prev) => prev.clone(),
                },
                Ok(token) => token.clone(),
            }
        }),
        auth_error_reporter,
    });

    // Create a persistent `NotAuthenticated` state. Same reasoning as above.
    let not_authenticated = StoredValue::new(NotAuthenticated {
        has_token_data: Signal::derive(move || token_mgr.token.get().is_some()),
        last_id_token_error: Signal::derive(move || verified_and_decoded_id_token.get().err()),
        last_error: auth_error.into(),
    });

    // Auth state derived from token data or potential errors.
    // Using persistent `authenticated` and `not_authenticated` values with inner signals prevents
    // unnecessary rerenders of the children passed to `Authenticated` when tokens refresh.
    let state = Memo::new(move |_| {
        let token = token_mgr.token;

        // Note: The token might have already been set to None but access_token_expired was not yet updated...
        let has_token = token.read().is_some();
        let has_verified_and_decoded_id_token = verified_and_decoded_id_token.read().is_ok();

        // Hydration-safety. Force server and client to render the same initial view.
        if hydration_manager.in_hydration_window.get() || pending_login.get() {
            tracing::trace!("Switching to: KeycloakAuthState::Indeterminate");
            KeycloakAuthState::Indeterminate
        } else if has_token
            && has_verified_and_decoded_id_token
            && !token_mgr.access_token_expired.get()
        {
            tracing::trace!("Switching to: KeycloakAuthState::Authenticated");
            KeycloakAuthState::Authenticated(authenticated.get_value())
        } else {
            tracing::trace!("Switching to: KeycloakAuthState::NotAuthenticated");
            KeycloakAuthState::NotAuthenticated(not_authenticated.get_value())
        }
    });

    let is_authenticated = Signal::derive(move || match state.read().deref() {
        KeycloakAuthState::Authenticated(_) => true,
        KeycloakAuthState::NotAuthenticated { .. } | KeycloakAuthState::Indeterminate => false,
    });

    let auth = KeycloakAuth {
        options,
        derived_urls,
        login_url: login::create_login_url_signal(
            authorization_endpoint,
            options,
            code_mgr.code_challenge,
            nonce_mgr.nonce(),
        )
        .into(),
        logout_url: logout::create_logout_url_signal(
            end_session_endpoint,
            token_mgr.token,
            options,
            csrf_mgr.logout_token(),
        )
        .into(),
        state: state.into(),
        is_authenticated,
        suspicious_logout: suspicious_logout.into(),
        dismiss_suspicious_logout_warning,
        oidc_config_manager: oidc_mgr,
        jwk_set_manager: jwk_set_mgr,
        code_verifier_manager: code_mgr,
        token_manager: token_mgr,
        csrf_token_manager: csrf_mgr,
        nonce_manager: nonce_mgr,
        hydration_manager,
    };

    // TODO: Make this configurable.
    Effect::new(move |_| {
        if let Err(err) = verified_and_decoded_id_token.read().as_ref() {
            match err {
                IdTokenClaimsError::NoToken | IdTokenClaimsError::NoJwkSet => {
                    /* Ignored. We are just missing some data. */
                }
                IdTokenClaimsError::Validation { .. }
                | IdTokenClaimsError::NonceMismatch
                | IdTokenClaimsError::MissingNonce => {
                    // Note: This will end our session when the ID token expires. The specification
                    // states in <https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse>
                    // that re-issued ID tokens must always use the original ID token expiration
                    // time, meaning that refreshes won't help us.

                    // Note: It does not seem to be enough to just drop token data at this point,
                    // as the Keycloak session might still be present. This could lead to the user
                    // repeatedly starting the login flow without ever getting logged in (trusted)
                    // on our end as we repeatedly just throw away the received token.
                    tracing::warn!(
                        ?err,
                        "ID token could not be verified. Ending session to force reauthentication."
                    );
                    auth.end_session();
                }
            }
        }
    });

    auth
}
