use crate::config::Options;
use crate::internal::JwkSetWithTimestamp;
use crate::internal::derived_urls::DerivedUrlError;
use crate::request::RequestError;
use crate::storage::{UseStorageReturn, use_storage_with_options_and_error_handler};
use crate::time_ext::TimeDurationExt;
use crate::{JwkSetEndpoint, action};
use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos_use::storage::StorageType;
use leptos_use::{UseIntervalReturn, use_interval};
use std::time::Duration as StdDuration;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy)]
pub struct JwkSetManager {
    pub jwk_set: Signal<Option<JwkSetWithTimestamp>>,
    pub(crate) set_jwk_set: WriteSignal<Option<JwkSetWithTimestamp>>,
    pub jwk_set_old: Signal<Option<JwkSetWithTimestamp>>,
    pub(crate) set_jwk_set_old: WriteSignal<Option<JwkSetWithTimestamp>>,
    #[allow(unused)]
    pub jwk_set_age: Signal<StdDuration>,
    #[allow(unused)]
    pub jwk_set_expires_in: Signal<StdDuration>,
    #[allow(unused)]
    pub jwk_set_too_old: Signal<bool>,
}

impl JwkSetManager {
    pub(crate) fn new(
        options: StoredValue<Options>,
        jwk_set_endpoint: Signal<Result<JwkSetEndpoint, DerivedUrlError>>,
        handle_req_error: Callback<Option<RequestError>>,
    ) -> Self {
        let UseStorageReturn {
            read: jwk_set_old,
            write: set_jwk_set_old,
            remove: _remove_jwk_set_old_from_storage,
            ..
        } = use_storage_with_options_and_error_handler::<Option<JwkSetWithTimestamp>, JsonSerdeCodec>(
            StorageType::Local,
            "leptos_keycloak_auth__jwk_set_old",
            None,
        );

        // Immediately forget the previously cached value when the discovery endpoint changed!
        if let Some(source) = jwk_set_old.get_untracked().map(|it| it.source) {
            if source != options.read_value().discovery_endpoint() {
                tracing::trace!(
                    "Current JWK set (old) came from old discovery endpoint. Dropping it."
                );
                set_jwk_set_old.set(None);
            }
        }

        let UseStorageReturn {
            read: jwk_set,
            write: set_jwk_set,
            remove: _remove_jwk_set_from_storage,
            ..
        } = use_storage_with_options_and_error_handler::<Option<JwkSetWithTimestamp>, JsonSerdeCodec>(
            StorageType::Local,
            "leptos_keycloak_auth__jwk_set",
            None,
        );

        // Immediately forget the previously cached value when the discovery endpoint changed!
        if let Some(source) = jwk_set.get_untracked().map(|it| it.source) {
            if source != options.read_value().discovery_endpoint() {
                tracing::trace!("Current JWK set came from old discovery endpoint. Dropping it.");
                set_jwk_set.set(None);
            }
        }

        // Defaults to `Duration::MAX` if no config is known yet.
        // This leads to a refresh if no config is known yet!
        let jwk_set_age = {
            let UseIntervalReturn { counter, .. } = use_interval::<u64>(
                options
                    .read_value()
                    .advanced
                    .jwk_set_age_check_interval
                    .as_millis()
                    .try_into()
                    .expect("Millis to not overflow a u64"),
            );
            Memo::new(move |_| {
                let _count = counter.get();
                jwk_set
                    .read()
                    .as_ref()
                    .map(|it| (OffsetDateTime::now_utc() - it.retrieved).to_std_duration())
                    .unwrap_or(StdDuration::MAX)
            })
        };

        let jwk_set_expires_in = Memo::new(move |_| {
            options
                .read_value()
                .advanced
                .max_jwk_set_age
                .saturating_sub(jwk_set_age.get())
        });

        let jwk_set_too_old =
            Memo::new(move |_| jwk_set_age.get() > options.read_value().advanced.max_jwk_set_age);

        // This callback is called whenever an updated JWK set is available.
        let handle_jwk_set = Callback::new(move |val: Option<JwkSetWithTimestamp>| {
            // If the JWK set changed, the Keycloak realm rolled its keys.
            // Note that this is done automatically in a certain interval.
            // New tokens must be validated against the new JWK set.
            // But old tokens, which may still be relevant because they didn't expire yet,
            // should still be validatable. We therefore need to also track any `previous`
            // JWK set.

            if val.as_ref().map(|it| &it.jwk_set)
                != jwk_set.read_untracked().as_ref().map(|it| &it.jwk_set)
            {
                tracing::trace!("JWK set changed");

                // Rotate currently known JWK set to `jwk_set_old`.
                // Because we only do this if the new JWK set is different, old and current
                // should always be different sets.
                set_jwk_set_old.set(
                    set_jwk_set
                        .try_update(|it| {
                            let old = it.take();
                            *it = val;
                            old
                        })
                        .flatten(),
                );
            } else {
                // If the JWK set itself is still the same, we still have to store the new
                // timestamp stored in our newly received `val`!
                // We would otherwise always have an "outdated" JWK set once it became too old.
                set_jwk_set.set(val);
            }
        });

        // Fetch a token from the OIDC provider using an authorization code and an optional session state.
        let retrieve_jwk_set_action =
            action::create_retrieve_jwk_set_action(handle_jwk_set, handle_req_error);

        // Obtain the JWK set. Updating any previously stored config.
        Effect::new(move |_| {
            if jwk_set_too_old.get() {
                match jwk_set_endpoint.read().as_ref() {
                    Ok(jwk_set_endpoint) => {
                        retrieve_jwk_set_action.dispatch((
                            jwk_set_endpoint.clone(),
                            options.read_value().discovery_endpoint(),
                        ));
                    }
                    Err(err) => {
                        tracing::trace!(reason = ?err, "JWK set should be updated, as it is too old, but no jwks_endpoint_url is known jet. Skipping update...")
                    }
                }
            }
        });

        Self {
            jwk_set,
            set_jwk_set,
            jwk_set_old,
            set_jwk_set_old,
            jwk_set_age: jwk_set_age.into(),
            jwk_set_expires_in: jwk_set_expires_in.into(),
            jwk_set_too_old: jwk_set_too_old.into(),
        }
    }

    #[expect(unused)]
    pub(crate) fn forget(&self) {
        self.set_jwk_set_old.set(None);
        self.set_jwk_set.set(None);
    }
}
