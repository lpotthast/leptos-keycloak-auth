use std::{
    fmt::{Debug, Formatter},
    time::Duration as StdDuration,
};

use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos_use::{UseIntervalReturn, storage::StorageType, use_interval};
use rootcause::Report;
use serde::{Deserialize, Serialize};

use crate::{
    AuthorizationCode, SessionState, TokenEndpoint, action,
    action::ExchangeCodeForTokenInput,
    code_verifier::CodeVerifier,
    config::{LifeLeft, Options},
    error::KeycloakAuthError,
    internal::derived_urls::DerivedUrl,
    request::RequestError,
    storage::{UseStorageReturn, use_storage_with_options_and_error_handler},
    time_ext::TimeDurationExt,
    token::TokenData,
};

/// Session version identifier. Internally represented using a numeric value.
///
/// This type is not orderable by design to prevent any potential issues due to numeric overflows.
/// We only ever need to compare two potentially different version for equality, which will still
/// work when overflown.
#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub struct SessionVersion(u64);

impl SessionVersion {
    const ZERO: SessionVersion = SessionVersion(0);

    pub fn increment(self) -> Self {
        SessionVersion(self.0.wrapping_add(1))
    }
}

impl Default for SessionVersion {
    fn default() -> Self {
        Self::ZERO
    }
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

    /// Which authentication session we are currently in.
    ///
    /// Incrementing the version creates a boundary that allows us to invalidate operations which
    /// originated from the previous version.
    ///
    /// ## When to INCREMENT:
    /// - On login response (NEW session, or error)
    /// - On refresh response (RENEWED session, or error)
    /// - On logout (NO session)
    /// - Weh auth state gets forgotten (NO session)
    ///
    /// ## When NOT to increment:
    /// - On automatic expiration (through time passing):
    ///   We might already have a refresh request in-flight!
    pub session_version: Signal<SessionVersion>,

    /// Update the token data, automatically incrementing the session version.
    /// This is the only way to update tokens, ensuring session version increments to invalidate
    /// any stale async operations from a previous authentication session.
    pub(crate) update_token: Callback<Option<TokenData>>,

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
    ///
    /// `Duration::ZERO` if the expiry of the refresh token is unknown, e.g. for offline tokens,
    /// for which Keycloak reports `refresh_expires_in: 0`.
    pub refresh_token_lifetime: Signal<StdDuration>,

    /// The duration for which the refresh token is still valid.
    /// Periodically recomputed. Slowly approaching zero.
    /// `Duration::ZERO` if the expiry of the refresh token is unknown.
    pub refresh_token_expires_in: Signal<StdDuration>,

    /// Whether the refresh token is about to expire. How much token lifetime
    /// must be "left over" for this to switch from `false` to `true` depends on configuration.
    /// Used to control automatic token refreshes.
    /// Always `false` if the expiry of the refresh token is unknown.
    pub refresh_token_nearly_expired: Signal<bool>,

    /// Whether the refresh token is expired / no longer usable.
    /// Always `false` if the expiry of the refresh token is unknown. When this is `true`:
    /// - `refresh_token_expires_in` will always report `Duration::ZERO`
    /// - `refresh_token_nearly_expired` will always report `true`
    pub refresh_token_expired: Signal<bool>,

    trigger_exchange_code_for_token: Callback<(
        AuthorizationCode,
        CodeVerifier<128>,
        Option<SessionState>,
        Callback<()>,
    )>,

    trigger_refresh: Callback<()>,
}

impl Debug for TokenManager {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenManager")
            .field("token", &self.token)
            .field("session_version", &self.session_version)
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
            .finish_non_exhaustive()
    }
}

impl TokenManager {
    #[cfg(feature = "ssr")]
    pub(crate) fn new() -> Self {
        Self {
            token: Signal::default(),
            session_version: Signal::default(),
            update_token: Callback::new(|_| {}),
            access_token_lifetime: Signal::default(),
            access_token_expires_in: Signal::default(),
            access_token_nearly_expired: Signal::default(),
            access_token_expired: Signal::default(),
            refresh_token_lifetime: Signal::default(),
            refresh_token_expires_in: Signal::default(),
            refresh_token_nearly_expired: Signal::default(),
            refresh_token_expired: Signal::default(),
            trigger_refresh: Callback::new(|()| ()),
            trigger_exchange_code_for_token: Callback::new(|_| ()),
        }
    }

    #[cfg(not(feature = "ssr"))]
    #[allow(clippy::too_many_lines)]
    pub(crate) fn new(
        options: StoredValue<Options>,
        handle_error: Callback<Report<KeycloakAuthError>>,
        token_endpoint: Signal<DerivedUrl<TokenEndpoint>>,
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

        let UseStorageReturn {
            read: session_version,
            write: set_session_version,
            remove: _remove_session_version_storage,
            ..
        } = use_storage_with_options_and_error_handler::<SessionVersion, JsonSerdeCodec>(
            StorageType::Local,
            "leptos_keycloak_auth__session_version",
            move || SessionVersion::ZERO,
        );

        let update_token = Callback::new(move |val: Option<TokenData>| {
            set_session_version.run(session_version.get_untracked().increment());
            set_token.run(val);
        });

        // Immediately forget the previously cached value when the discovery endpoint changed!
        if let Some(source) = token.get_untracked().map(|it| it.source)
            && source != options.read_value().discovery_endpoint()
        {
            tracing::trace!("Current token came from old discovery endpoint. Dropping it.");
            update_token.run(None);
        }

        // Note: Only call this after the OIDC config was loaded. Otherwise, no refresh can happen!
        let refresh_token_action = action::create_refresh_token_action(
            options,
            update_token,
            handle_error,
            session_version,
        );

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

            let on_refresh_error = Callback::new(move |err: Report<RequestError>| {
                drop_token_if_session_ended(&err, update_token);
                err
            });

            refresh_token_action.dispatch((token_endpoint, refresh_token, on_refresh_error));
        });

        let exchange_code_for_token_action =
            action::create_exchange_code_for_token_action(options, update_token, handle_error);

        let trigger_exchange_code_for_token = Callback::new(
            move |(auth_code, code_verifier, session_state, finally): (
                AuthorizationCode,
                CodeVerifier<128>,
                Option<SessionState>,
                Callback<()>,
            )| {
                let token_endpoint = match token_endpoint.read_untracked().as_ref() {
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

                exchange_code_for_token_action.dispatch(ExchangeCodeForTokenInput {
                    token_endpoint,
                    auth_code,
                    code_verifier,
                    session_state,
                    finally,
                });
            },
        );

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

        // True when the access token is expired.
        // Also `true` if no token data is present, as `access_token_expires_in` is then zero.
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
            is_refresh_token_nearly_expired(
                life_left,
                refresh_token_lifetime.get(),
                refresh_token_expires_in.get(),
            )
        });

        // True when the refresh token has a known expiry and is expired.
        // Defaults to `false` if no token data is present.
        let refresh_token_expired = Memo::new(move |_| {
            is_refresh_token_expired(refresh_token_lifetime.get(), refresh_token_expires_in.get())
        });

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
                trigger_refresh.run(());
            }
        });

        Effect::new(move |_| {
            let access_token_expired = access_token_expired.get();
            let refresh_token_expired = refresh_token_expired.get();

            if access_token_expired && refresh_token_expired {
                // The token became unusable and can safely be forgotten.
                // Don't increment `session_version` here. If a refresh is in-flight and succeeds
                // (server accepted the just-expired token), we WANT that fresh response to be
                // processed to keep the user logged in!
                set_token.run(None);
            }
        });

        Self {
            token,
            session_version,
            update_token,
            access_token_lifetime: access_token_lifetime.into(),
            access_token_expires_in: access_token_expires_in.into(),
            access_token_nearly_expired: access_token_nearly_expired.into(),
            access_token_expired: access_token_expired.into(),
            refresh_token_lifetime: refresh_token_lifetime.into(),
            refresh_token_expires_in: refresh_token_expires_in.into(),
            refresh_token_nearly_expired: refresh_token_nearly_expired.into(),
            refresh_token_expired: refresh_token_expired.into(),
            trigger_exchange_code_for_token,
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
        self.trigger_exchange_code_for_token.run((
            auth_code,
            code_verifier,
            session_state,
            finally,
        ));
    }

    pub(crate) fn refresh_token(&self) {
        self.trigger_refresh.run(());
    }

    /// Forget any known token. This is a local operation, not hitting Keycloak in any way.
    /// It immediately locks the user out of protected areas, but does not perform a logout on the
    /// OIDC server. If the user tried to log in again, his session would most likely be restored.
    pub(crate) fn forget(&self) {
        tracing::trace!("Dropping all token data");
        self.update_token.run(None);
    }
}

/// Drop all token data if a failed refresh shows that the session ended.
///
/// Any other failure, e.g. a network error, keeps the current (possibly expired) token, so that
/// a later refresh can still succeed.
pub(crate) fn drop_token_if_session_ended(
    err: &Report<RequestError>,
    update_token: Callback<Option<TokenData>>,
) {
    match err.current_context() {
        RequestError::ErrResponse { error_response }
            if error_response.is_likely_session_ended() =>
        {
            if error_response.is_invalid_refresh_token() || error_response.is_session_not_active() {
                tracing::trace!(
                    %error_response,
                    "The refresh token is invalid or the user has no Keycloak session anymore. Dropping all token data. No additional refreshes will be performed."
                );
            } else {
                tracing::warn!(
                    %error_response,
                    "Received an unexpected `invalid_grant` error. Did Keycloak's error messages change? If you see this, report at `https://github.com/lpotthast/leptos-keycloak-auth/issues`. Dropping all token data."
                );
            }
            update_token.run(None);
        }
        RequestError::ErrResponse { error_response } => {
            tracing::warn!(
                %error_response,
                "Token refresh failed due to an unexpected Keycloak error response. Keeping the current token."
            );
        }
        RequestError::Send | RequestError::Decode => {
            tracing::debug!(?err, "Token refresh failed. Keeping the current token.");
        }
    }
}

/// Whether a refresh token is about to expire.
///
/// A zero `lifetime` means that the expiry is unknown, either because the token response did not
/// state one or because Keycloak reported `refresh_expires_in: 0`, which it does for offline
/// tokens not limited by a maximum offline session lifespan. Such a refresh token is never
/// considered nearly expired. Treating it as such would trigger a refresh after every refresh.
fn is_refresh_token_nearly_expired(
    life_left: LifeLeft,
    lifetime: StdDuration,
    left: StdDuration,
) -> bool {
    !lifetime.is_zero() && life_left.nearly_expired(lifetime, left)
}

/// Whether a refresh token is expired. Refresh tokens with an unknown expiry (zero `lifetime`)
/// never are. See [`is_refresh_token_nearly_expired`].
fn is_refresh_token_expired(lifetime: StdDuration, left: StdDuration) -> bool {
    !lifetime.is_zero() && left.is_zero()
}

#[cfg(test)]
mod tests {
    use assertr::prelude::*;

    use super::*;

    #[test]
    fn session_version_default_is_zero() {
        assert_that!(SessionVersion::default()).is_equal_to(SessionVersion::ZERO);
        assert_that!(SessionVersion::ZERO).is_equal_to(SessionVersion(0));
    }

    #[test]
    fn session_version_increment() {
        let v = SessionVersion(0);
        assert_that!(v.increment()).is_equal_to(SessionVersion(1));
    }

    #[test]
    fn session_version_increment_wraps_around() {
        let v = SessionVersion(u64::MAX);
        assert_that!(v.increment()).is_equal_to(SessionVersion(0));
    }

    #[test]
    fn refresh_token_with_unknown_expiry_is_never_nearly_expired() {
        let life_left = LifeLeft::Percentage(0.25);
        assert_that!(is_refresh_token_nearly_expired(
            life_left,
            StdDuration::ZERO,
            StdDuration::ZERO
        ))
        .is_false();
    }

    #[test]
    fn refresh_token_with_unknown_expiry_is_never_expired() {
        assert_that!(is_refresh_token_expired(
            StdDuration::ZERO,
            StdDuration::ZERO
        ))
        .is_false();
    }

    #[test]
    fn refresh_token_with_known_expiry_can_be_nearly_expired() {
        let life_left = LifeLeft::Percentage(0.25);
        let lifetime = StdDuration::from_secs(1800);
        assert_that!(is_refresh_token_nearly_expired(
            life_left,
            lifetime,
            StdDuration::from_secs(1200)
        ))
        .is_false();
        assert_that!(is_refresh_token_nearly_expired(
            life_left,
            lifetime,
            StdDuration::from_secs(300)
        ))
        .is_true();
    }

    #[test]
    fn refresh_token_with_known_expiry_can_be_expired() {
        let lifetime = StdDuration::from_secs(1800);
        assert_that!(is_refresh_token_expired(
            lifetime,
            StdDuration::from_secs(1)
        ))
        .is_false();
        assert_that!(is_refresh_token_expired(lifetime, StdDuration::ZERO)).is_true();
    }
}
