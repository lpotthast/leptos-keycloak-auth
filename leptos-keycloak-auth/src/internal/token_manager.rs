use crate::action::ExchangeCodeForTokenInput;
use crate::code_verifier::CodeVerifier;
use crate::config::Options;
use crate::internal::derived_urls::DerivedUrlError;
use crate::request::RequestError;
use crate::response::{KnownOidcErrorCode, OidcErrorCode};
use crate::storage::{use_storage_with_options_and_error_handler, UseStorageReturn};
use crate::time_ext::TimeDurationExt;
use crate::token::TokenData;
use crate::{action, AuthorizationCode, SessionState, TokenEndpoint};
use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos_use::storage::StorageType;
use leptos_use::{use_interval, UseIntervalReturn};
use std::fmt::{Debug, Formatter};
use std::time::Duration as StdDuration;

/// Strategy for handling token refresh failures.
#[derive(Debug, Clone, Copy)]
pub(crate) enum OnRefreshError {
    /// Don't take any action. Keep the current (possibly expired) token.
    DoNothing,

    /// Drop the token, effectively logging the user out.
    DropToken,
}

/// Manages the lifecycle of OAuth tokens including storage, expiry tracking, and automatic refresh.
/// The manager automatically monitors token expiration and triggers refresh operations when tokens
/// are "nearly expired" (configured via `AdvancedOptions`). This ensures a seamless user experience
/// without interruption due to expired tokens.
///
/// The `TokenManager` is responsible for:
/// - Exchanging authorization codes for tokens
/// - Storing access and refresh tokens in local storage
/// - Refreshing access tokens using refresh tokens
/// - Tracking access and refresh token expiration and triggering proactive refreshes
/// - Providing reactive signals for token state
///
/// # Internal Use
/// This is an internal component exposed via the `internals` feature flag for advanced
/// use cases like testing or debugging.
#[derive(Clone, Copy)]
pub struct TokenManager {
    /// Last known token data. Single source of truth of token information.
    /// May contain an expired access and / or refresh token.
    pub token: Signal<Option<TokenData>>,

    /// Setter for the currently known token data.
    pub(crate) set_token: Callback<Option<TokenData>>,

    /// Duration for which the access token is valid, as configured in Keycloak's realm settings.
    pub access_token_lifetime: Signal<StdDuration>,

    /// The duration for which the access token is still valid.
    /// Periodically recomputed. Slowly approaching zero.
    pub access_token_expires_in: Signal<StdDuration>,

    /// Whether the access token is about to expire. How much token lifetime
    /// must be "left over" for this to switch from `false` to `true` depends on configuration.
    /// Used to control automatic token refreshes.
    pub access_token_nearly_expired: Signal<bool>,

    /// Whether the access token is expired / no longer usable. When this is `true`:
    /// - `access_token_expires_in` will always report `Duration::ZERO`
    /// - `access_token_nearly_expired` will always report `true`
    pub access_token_expired: Signal<bool>,

    /// Duration for which the refresh token is valid, as configured in Keycloak's realm settings.
    pub refresh_token_lifetime: Signal<StdDuration>,

    /// The duration for which the refresh token is still valid.
    /// Periodically recomputed. Slowly approaching zero.
    pub refresh_token_expires_in: Signal<StdDuration>,

    /// Whether the refresh token is about to expire. How much token lifetime
    /// must be "left over" for this to switch from `false` to `true` depends on configuration.
    /// Used to control automatic token refreshes.
    pub refresh_token_nearly_expired: Signal<bool>,

    /// Whether the refresh token is expired / no longer usable. When this is `true`:
    /// - `refresh_token_expires_in` will always report `Duration::ZERO`
    /// - `refresh_token_nearly_expired` will always report `true`
    pub refresh_token_expired: Signal<bool>,

    pub(crate) exchange_code_for_token_action: Action<ExchangeCodeForTokenInput, ()>,

    pub token_endpoint: Signal<Result<TokenEndpoint, DerivedUrlError>>,

    pub(crate) trigger_refresh: Callback<(OnRefreshError,)>,
}

impl Debug for TokenManager {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenManager")
            .field("token", &self.token)
            .field("set_token", &self.set_token)
            .field("access_token_lifetime", &self.access_token_lifetime)
            .field("access_token_expires_in", &self.access_token_expires_in)
            .field(
                "access_token_nearly_expired",
                &self.access_token_nearly_expired,
            )
            .field("access_token_expired", &self.access_token_expired)
            .field("refresh_token_lifetime", &self.refresh_token_lifetime)
            .field("refresh_token_expires_in", &self.refresh_token_expires_in)
            .field(
                "refresh_token_nearly_expired",
                &self.refresh_token_nearly_expired,
            )
            .field("refresh_token_expired", &self.refresh_token_expired)
            .field("exchange_code_for_token_action", &"...")
            .field("token_endpoint", &self.token_endpoint)
            .finish_non_exhaustive()
    }
}

impl TokenManager {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn new(
        options: StoredValue<Options>,
        handle_req_error: Callback<Option<RequestError>>,
        token_endpoint: Signal<Result<TokenEndpoint, DerivedUrlError>>,
    ) -> Self {
        let UseStorageReturn {
            read: token,
            write: set_token,
            remove: _remove_token_from_storage,
            ..
        } = use_storage_with_options_and_error_handler::<Option<TokenData>, JsonSerdeCodec>(
            StorageType::Local,
            "leptos_keycloak_auth__token",
            move || None,
        );

        // Immediately forget the previously cached value when the discovery endpoint changed!
        if let Some(source) = token.get_untracked().map(|it| it.source)
            && source != options.read_value().discovery_endpoint()
        {
            tracing::trace!("Current token came from old discovery endpoint. Dropping it.");
            set_token.run(None);
        }

        let handle_token = Callback::new(move |val| set_token.run(val));

        // Note: Only call this after the OIDC config was loaded. Otherwise, no refresh can happen!
        let refresh_token_action =
            action::create_refresh_token_action(options, handle_token, handle_req_error);

        let trigger_refresh = Callback::new(move |(on_refresh_error,)| {
            let token_endpoint = match token_endpoint.read_untracked().as_ref() {
                Ok(it) => it.clone(),
                Err(err) => {
                    tracing::debug!(
                        ?err,
                        "Requested token refresh has no effect, as no token_endpoint is known yet."
                    );
                    return;
                }
            };

            let refresh_token = match token.read_untracked().as_ref() {
                Some(token) => token.refresh_token.clone(),
                None => {
                    tracing::debug!(
                        "Requested token refresh has no effect, as no token is known yet."
                    );
                    return;
                }
            };

            let on_refresh_error = Callback::new(move |err: RequestError| {
                match on_refresh_error {
                    OnRefreshError::DoNothing => {
                        // Even if we haven't gotten an external request to always drop the token
                        // when an error was received, we may still want to drop the taken,
                        // based on the error that we got.
                        match &err {
                            RequestError::Send { .. } | RequestError::Decode { .. } => {}
                            RequestError::ErrResponse { error_response } => {
                                if error_response.is_invalid_refresh_token() {
                                    tracing::trace!(
                                        "The known refresh_token is not valid. Dropping the refresh token. No additional refreshes will be performed."
                                    );
                                    // Drop all token data, including our access_token.
                                    set_token.run(None);
                                } else if error_response.is_session_not_active() {
                                    tracing::trace!(
                                        "The known refresh_token might be valid but the user has no Keycloak session anymore. User was logged out. Dropping the refresh_token. No additional refreshes will be performed."
                                    );
                                    // Drop all token data, including our access_token.
                                    set_token.run(None);
                                } else if error_response.error
                                    == OidcErrorCode::Known(KnownOidcErrorCode::InvalidGrant)
                                {
                                    tracing::warn!(
                                        "Received an unexpected `invalid_grant` error. Did Keycloak's error messages change? If you see this, report at `https://github.com/lpotthast/leptos-keycloak-auth/issues`."
                                    );
                                    // Drop all token data, including our access_token.
                                    set_token.run(None);
                                } else {
                                    tracing::warn!(
                                        "Token refresh failed due to unexpected Keycloak error response: {error_response:?}"
                                    );
                                }
                            }
                        }
                    }
                    OnRefreshError::DropToken => {
                        set_token.run(None);
                    }
                }
                err
            });

            refresh_token_action.dispatch((token_endpoint, refresh_token, on_refresh_error));
        });

        let access_token_lifetime = Memo::new(move |_| {
            token.read().as_ref().map_or(StdDuration::ZERO, |it| {
                it.estimated_access_token_lifetime().to_std_duration()
            })
        });

        let access_token_expires_in = {
            let UseIntervalReturn { counter, .. } = use_interval::<u64>(
                options
                    .read_value()
                    .advanced
                    .access_token_age_check_interval
                    .as_millis()
                    .try_into()
                    .expect("Millis to not overflow a u64"),
            );
            Memo::new(move |_| {
                let _count = counter.get();
                token.read().as_ref().map_or(StdDuration::ZERO, |it| {
                    it.access_token_time_left().to_std_duration()
                })
            })
        };

        let access_token_nearly_expired = Memo::new(move |_| {
            let life_left = options.with_value(|o| o.advanced.access_token_nearly_expired_having);
            life_left.nearly_expired(access_token_lifetime.get(), access_token_expires_in.get())
        });

        // True when a token is present and the access token is expired.
        // Defaults to `false` if no token data is present.
        let access_token_expired = Memo::new(move |_| access_token_expires_in.get().is_zero());

        let refresh_token_lifetime = Memo::new(move |_| {
            token
                .read()
                .as_ref()
                .and_then(|it| {
                    it.estimated_refresh_token_lifetime()
                        .map(TimeDurationExt::to_std_duration)
                })
                .unwrap_or(StdDuration::ZERO)
        });

        let refresh_token_expires_in = {
            let UseIntervalReturn { counter, .. } = use_interval::<u64>(
                options
                    .read_value()
                    .advanced
                    .refresh_token_age_check_interval
                    .as_millis()
                    .try_into()
                    .expect("Millis to not overflow a u64"),
            );
            Memo::new(move |_| {
                let _count = counter.get();
                token
                    .read()
                    .as_ref()
                    .and_then(|it| {
                        it.refresh_token_time_left()
                            .map(TimeDurationExt::to_std_duration)
                    })
                    .unwrap_or(StdDuration::ZERO)
            })
        };

        let refresh_token_nearly_expired = Memo::new(move |_| {
            let life_left = options.with_value(|o| o.advanced.refresh_token_nearly_expired_having);
            life_left.nearly_expired(refresh_token_lifetime.get(), refresh_token_expires_in.get())
        });

        // True when a token is present and the refresh token is expired.
        // Defaults to `false` if no token data is present.
        let refresh_token_expired = Memo::new(move |_| refresh_token_expires_in.get().is_zero());

        // If either the access or the refresh token is about to expire
        // (although the refresh token *should* always outlive the access token...),
        // or the access token already expired, try to refresh the access token using the refresh token.
        Effect::new(move |_| {
            let has_token = token.read().is_some();
            let access_token_expired = access_token_expired.get();
            let access_token_nearly_expired = access_token_nearly_expired.get();
            let refresh_token_nearly_expired = refresh_token_nearly_expired.get();

            if has_token
                && (access_token_expired
                    || access_token_nearly_expired
                    || refresh_token_nearly_expired)
            {
                tracing::trace!(
                    access_token_expired,
                    access_token_nearly_expired,
                    refresh_token_nearly_expired,
                    "Refreshing token..."
                );
                trigger_refresh.run((OnRefreshError::DoNothing,));
            }
        });

        Effect::new(move |_| {
            let access_token_expired = access_token_expired.get();
            let refresh_token_expired = refresh_token_expired.get();

            if access_token_expired && refresh_token_expired {
                // The token became unusable and can safely be forgotten.
                set_token.run(None);
            }
        });

        Self {
            token,
            set_token,
            access_token_lifetime: access_token_lifetime.into(),
            access_token_expires_in: access_token_expires_in.into(),
            access_token_nearly_expired: access_token_nearly_expired.into(),
            access_token_expired: access_token_expired.into(),
            refresh_token_lifetime: refresh_token_lifetime.into(),
            refresh_token_expires_in: refresh_token_expires_in.into(),
            refresh_token_nearly_expired: refresh_token_nearly_expired.into(),
            refresh_token_expired: refresh_token_expired.into(),
            exchange_code_for_token_action: action::create_exchange_code_for_token_action(
                options,
                handle_token,
                handle_req_error,
            ),
            token_endpoint,
            trigger_refresh,
        }
    }

    /// Note: This silently errors if no `token` OIDC endpoint is known yet.
    pub(crate) fn exchange_code_for_token(
        &self,
        auth_code: AuthorizationCode,
        code_verifier: CodeVerifier<128>,
        session_state: Option<SessionState>,
        finally: Callback<()>,
    ) {
        let token_endpoint = match self.token_endpoint.read_untracked().as_ref() {
            Ok(token_endpoint) => token_endpoint.clone(),
            Err(err) => {
                tracing::error!(
                    ?err,
                    "Unexpected error: Could not exchange auth code for token, as no token_endpoint is known yet. Should not have been reached. If a successful login was possible, we should have received a token endpoint from the OIDC config."
                );
                finally.run(());
                return;
            }
        };

        self.exchange_code_for_token_action
            .dispatch(ExchangeCodeForTokenInput {
                token_endpoint,
                auth_code,
                code_verifier,
                session_state,
                finally,
            });
    }

    pub(crate) fn refresh_token(&self, on_refresh_error: OnRefreshError) {
        self.trigger_refresh.run((on_refresh_error,));
    }

    /// Forget any known token. This is a local operation, not hitting Keycloak in any way.
    /// It immediately locks the user out of protected areas, but does not perform a logout on the
    /// OIDC server. If the user tried to log in again, his session would most likely be restored.
    pub(crate) fn forget(&self) {
        tracing::trace!("Dropping all token data");
        self.set_token.run(None);
    }
}
