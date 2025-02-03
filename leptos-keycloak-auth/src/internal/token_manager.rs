use crate::action::ExchangeCodeForTokenInput;
use crate::code_verifier::CodeVerifier;
use crate::config::Options;
use crate::internal::derived_urls::DerivedUrlError;
use crate::request::RequestError;
use crate::time_ext::TimeDurationExt;
use crate::token::TokenData;
use crate::{action, AuthorizationCode, SessionState, TokenEndpoint};
use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos_use::storage::{use_storage_with_options, StorageType, UseStorageOptions};
use leptos_use::{use_interval, UseIntervalReturn};
use std::fmt::{Debug, Formatter};
use std::time::Duration as StdDuration;

#[derive(Debug, Clone, Copy)]
pub(crate) enum OnRefreshError {
    DoNothing,
    DropToken,
}

#[derive(Clone, Copy)]
pub struct TokenManager {
    /// Last known token data. Single source of truth of token information.
    /// May contain an expired access and / or refresh token.
    pub token: Signal<Option<TokenData>>,
    pub set_token: WriteSignal<Option<TokenData>>,
    pub access_token_lifetime: Signal<StdDuration>,
    pub access_token_expires_in: Signal<StdDuration>,
    pub access_token_nearly_expired: Signal<bool>,
    pub access_token_expired: Signal<bool>,
    pub refresh_token_lifetime: Signal<StdDuration>,
    pub refresh_token_expires_in: Signal<StdDuration>,
    pub refresh_token_nearly_expired: Signal<bool>,
    pub refresh_token_expired: Signal<bool>,
    pub exchange_code_for_token_action: Action<ExchangeCodeForTokenInput, ()>,
    pub token_endpoint: Signal<Result<TokenEndpoint, DerivedUrlError>>,
    pub remove_token_from_storage: StoredValue<Box<dyn Fn() + Send + Sync>>,
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
            .field("remove_token_from_storage", &self.remove_token_from_storage)
            .finish()
    }
}

impl TokenManager {
    pub(crate) fn new(
        options: StoredValue<Options>,
        handle_req_error: Callback<Option<RequestError>>,
        token_endpoint: Signal<Result<TokenEndpoint, DerivedUrlError>>,
    ) -> Self {
        let (token, set_token, remove_token_from_storage) =
            use_storage_with_options::<Option<TokenData>, JsonSerdeCodec>(
                StorageType::Local,
                "leptos_keycloak_auth__token",
                UseStorageOptions::default()
                    .initial_value(None)
                    .on_error(|err| tracing::error!(?err, "token storage error")),
            );
        let handle_token = Callback::new(move |val| set_token.set(val));

        // Note: Only call this after the OIDC config was loaded. Otherwise, no refresh can happen!
        let refresh_token_action =
            action::create_refresh_token_action(options, handle_token, handle_req_error);

        let remover = remove_token_from_storage.clone();
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

            let remover_clone = remover.clone();
            let on_refresh_error = Callback::new(move |(err,)| {
                match on_refresh_error {
                    OnRefreshError::DoNothing => {
                        // Even if we haven't gotten an external request to always drop the token
                        // when an error was received, we may still want to drop the taken,
                        // based on the error that we got.
                        // If Keycloak answers with a `BAD_REQUEST` response of
                        // `{"error":"invalid_grant","error_description":"Invalid refresh token"}`,
                        // we should still drop the token.
                        // AND: We do so immediately, without checking if the token is fully expired.
                        // This means that even if the token is only about to expire, we will drop it now,
                        // as the refresh could have been triggered from us not being able to use
                        // the access token. Not dropping it because it is not fully expired would
                        // let us get stuck in a loop. We therefore deem the access token to also
                        // be unusable.
                        match &err {
                            RequestError::Send { .. } => {}
                            RequestError::Decode { .. } => {}
                            RequestError::ErrResponse { error_response } => {
                                if error_response.error == "invalid_grant"
                                    && error_response.error_description == "Invalid refresh token"
                                {
                                    set_token.set(None);
                                    remover_clone();
                                }
                            }
                        }
                    }
                    OnRefreshError::DropToken => {
                        set_token.set(None);
                        remover_clone();
                    }
                }
                err
            });

            refresh_token_action.dispatch((token_endpoint, refresh_token, on_refresh_error));
        });

        let access_token_lifetime = Memo::new(move |_| {
            token
                .read()
                .as_ref()
                .map(|it| it.estimated_access_token_lifetime().to_std_duration())
                .unwrap_or(StdDuration::ZERO)
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
                token
                    .read()
                    .as_ref()
                    .map(|it| it.access_token_time_left().to_std_duration())
                    .unwrap_or(StdDuration::ZERO)
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
                        .map(|it| it.to_std_duration())
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
                    .and_then(|it| it.refresh_token_time_left().map(|it| it.to_std_duration()))
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
            remove_token_from_storage: StoredValue::new(Box::new(remove_token_from_storage)),
            trigger_refresh,
        }
    }

    /// Note: This silently errors if no token_endpoint is known yet.
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
                tracing::warn!(?err, "Unexpected error: Could not exchange auth code for token, as no token_endpoint is known yet. Should not have been reached. If a successful login was possible, we should have received a token endpoint from the OIDC config.");
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

    pub(crate) fn forget(&self) {
        self.set_token.set(None);
    }
}
