use crate::config::Options;
use crate::error::KeycloakAuthError;
use crate::internal::derived_urls::DerivedUrls;
use crate::internal::token_manager::OnRefreshError;
use crate::request::RequestError;
use crate::response::CallbackResponse;
use crate::token::KeycloakIdTokenClaims;
use crate::token_validation::KeycloakIdTokenClaimsError;
use crate::{
    code_verifier, internal, login, logout, token_validation, Authenticated, KeycloakAuth,
    KeycloakAuthState, RequestAction, UseKeycloakAuthOptions,
};
use leptos::callback::Callback;
use leptos::context::provide_context;
use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_query};
use leptos_router::NavigateOptions;
use std::ops::Deref;
use time::OffsetDateTime;

/// Initializes a new `KeycloakAuth` instance, the authentication handler responsible for handling
/// user authentication and token management, with the provided authentication parameters.
pub fn use_keycloak_auth(options: UseKeycloakAuthOptions) -> KeycloakAuth {
    tracing::trace!("Initializing Keycloak auth...");

    let options = Options::new(options);
    let options = StoredValue::new(options);

    let (auth_error, set_auth_error) = signal::<Option<KeycloakAuthError>>(None);
    let handle_req_error = Callback::new(move |request_error: Option<RequestError>| {
        set_auth_error.set(request_error.map(|err| KeycloakAuthError::Request { source: err }))
    });

    let oidc_mgr = internal::oidc_config_manager::OidcConfigManager::new(options, handle_req_error);

    let DerivedUrls {
        jwks_endpoint,
        authorization_endpoint,
        token_endpoint,
        end_session_endpoint,
    } = oidc_mgr.derive_urls();

    let jwk_set_mgr =
        internal::jwk_set_manager::JwkSetManager::new(options, jwks_endpoint, handle_req_error);

    let token_mgr =
        internal::token_manager::TokenManager::new(options, handle_req_error, token_endpoint);

    let code_mgr = internal::code_verifier_manager::CodeVerifierManager::new();

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
                            #[allow(unused_qualifications)]
                            set_code_verifier
                                .set(Some(code_verifier::CodeVerifier::<128>::generate()));
                        });
                    }

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
        // TODO: User should be able to overwrite this.
        let client_id = options.read_value().client_id.clone();
        let expected_audiences: &[String] = &[client_id];

        let first_try = token_validation::validate(
            token_mgr.token.get(),
            jwk_set_mgr.jwk_set.get().as_ref().map(|it| &it.jwk_set),
            expected_audiences,
        );

        if first_try.is_ok() {
            return first_try;
        }

        let second_try = token_validation::validate(
            token_mgr.token.get(),
            jwk_set_mgr.jwk_set_old.get().as_ref().map(|it| &it.jwk_set),
            expected_audiences,
        );

        second_try
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

    // Auth state derived from token data or potential errors.
    let state = Memo::new(move |_| {
        let token = token_mgr.token;

        // Note: The token might have already been set to None but access_token_expired was not yet updated...
        let has_token = token.read().is_some();
        let has_verified_and_decoded_id_token = verified_and_decoded_id_token.read().is_ok();

        if has_token && has_verified_and_decoded_id_token && !token_mgr.access_token_expired.get() {
            KeycloakAuthState::Authenticated(Authenticated {
                access_token: Signal::derive(move || token.get().expect("present").access_token),
                id_token_claims: Signal::derive(move || {
                    verified_and_decoded_id_token.get().expect("present")
                }),
                auth_error_reporter,
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
        #[cfg(feature = "internals")]
        oidc_config_manager: oidc_mgr,
        #[cfg(feature = "internals")]
        jwk_set_manager: jwk_set_mgr,
        #[cfg(feature = "internals")]
        code_verifier_manager: code_mgr,
        #[cfg(feature = "internals")]
        token_manager: token_mgr,
    };

    // We guarantee that the KeycloakAuth state is provided as context.
    provide_context(auth);

    auth
}
