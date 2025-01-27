use crate::code_verifier::CodeVerifier;
use crate::internal::derived_urls::DerivedUrlError;
use crate::request::RequestError;
use crate::time_ext::TimeDurationExt;
use crate::token::TokenData;
use crate::{action, AuthorizationCode, SessionState, TokenEndpoint, UseKeycloakAuthOptions};
use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos_use::storage::{use_storage_with_options, StorageType, UseStorageOptions};
use leptos_use::{use_interval, UseIntervalReturn};
use std::fmt::{Debug, Formatter};
use std::time::Duration;

#[derive(Clone, Copy)]
pub struct TokenManager {
    /// Last known token data. Single source of truth of token information.
    /// May contain an expired access and / or refresh token.
    pub token: Signal<Option<TokenData>>,
    pub set_token: WriteSignal<Option<TokenData>>,
    pub access_token_lifetime: Signal<Duration>,
    pub access_token_expires_in: Signal<Duration>,
    pub access_token_nearly_expired: Signal<bool>,
    pub access_token_expired: Signal<bool>,
    pub refresh_token_lifetime: Signal<Duration>,
    pub refresh_token_expires_in: Signal<Duration>,
    pub refresh_token_nearly_expired: Signal<bool>,
    pub refresh_token_expired: Signal<bool>,
    pub exchange_code_for_token_action: Action<
        (
            TokenEndpoint,
            AuthorizationCode,
            CodeVerifier<128>,
            Option<SessionState>,
        ),
        (),
    >,
    pub token_endpoint: Signal<Result<TokenEndpoint, DerivedUrlError>>,
    pub remove_token_from_storage: StoredValue<Box<dyn Fn() + Send + Sync>>,
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
        options: StoredValue<UseKeycloakAuthOptions>,
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

        // Note: Only call this after OIDC config was loaded. Otherwise, nothing happens and an error is logged!
        // TODO: Use a queuing system, so that no request is lost?
        let refresh_token_action =
            action::create_refresh_token_action(options, handle_token, handle_req_error);

        let trigger_refresh = Callback::new(move |()| {
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

            refresh_token_action.dispatch((token_endpoint, refresh_token));
        });

        let access_token_lifetime = Memo::new(move |_| {
            token
                .read()
                .as_ref()
                .map(|it| it.estimated_access_token_lifetime().to_std_duration())
                .unwrap_or(Duration::ZERO)
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
                    .unwrap_or(Duration::ZERO)
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
                .unwrap_or(Duration::ZERO)
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
                    .unwrap_or(Duration::ZERO)
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
            // TODO: Should we also take into account whether whe were able to decode the id token?

            // Note: These boolean-signals default to false. Therefore, no refresh-attempt
            // is made without a refresh token being present.
            let access_token_nearly_expired = access_token_nearly_expired.get();
            let refresh_token_nearly_expired = refresh_token_nearly_expired.get();
            let access_token_expired = access_token_expired.get();
            if (access_token_nearly_expired || refresh_token_nearly_expired || access_token_expired)
                && token.read().is_some()
            {
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
