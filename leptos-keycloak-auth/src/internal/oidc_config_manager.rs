use std::{fmt::Debug, time::Duration as StdDuration};

use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos_use::storage::StorageType;

use crate::{
    config::Options,
    internal::{OidcConfigWithTimestamp, derived_urls::DerivedUrls, track_age_of},
    request::RequestError,
    storage::{UseStorageReturn, use_storage_with_options_and_error_handler},
};

/// Manages OIDC discovery configuration with automatic fetching and caching.
///
/// The `OidcConfigManager` is responsible for:
/// - Fetching OIDC discovery metadata
/// - Caching the configuration in local storage
/// - Tracking configuration age and triggering refreshes when too old
/// - Providing reactive signals for configuration state
///
/// # Internal Use
/// This is an internal component exposed via the `internals` feature flag for advanced
/// use cases like testing or debugging.
#[derive(Debug, Clone, Copy)]
pub struct OidcConfigManager {
    pub oidc_config: Signal<Option<OidcConfigWithTimestamp>>,
    pub(crate) set_oidc_config: Callback<Option<OidcConfigWithTimestamp>>,

    #[allow(unused)]
    pub oidc_config_age: Signal<StdDuration>,
    #[allow(unused)]
    pub oidc_config_expires_in: Signal<StdDuration>,
    #[allow(unused)]
    pub oidc_config_too_old: Signal<bool>,
}

impl OidcConfigManager {
    #[cfg(feature = "ssr")]
    pub(crate) fn new() -> Self {
        Self {
            oidc_config: Signal::default(),
            set_oidc_config: { Callback::new(|_| {}) },
            oidc_config_age: Signal::default(),
            oidc_config_expires_in: Signal::default(),
            oidc_config_too_old: Signal::default(),
        }
    }

    #[cfg(not(feature = "ssr"))]
    pub(crate) fn new(
        options: StoredValue<Options>,
        handle_req_error: Callback<Option<RequestError>>,
    ) -> Self {
        let UseStorageReturn {
            read: oidc_config,
            write: set_oidc_config,
            remove: _remove_oidc_config_from_storage,
            ..
        } = use_storage_with_options_and_error_handler::<
            Option<OidcConfigWithTimestamp>,
            JsonSerdeCodec,
        >(
            StorageType::Local,
            "leptos_keycloak_auth__oidc_config",
            move || None,
        );

        // Immediately forget the previously cached value when the discovery endpoint changed!
        if let Some(source) = oidc_config.get_untracked().map(|it| it.source)
            && source != options.read_value().discovery_endpoint()
        {
            tracing::trace!("Current OIDC config came from old discovery endpoint. Dropping it.");
            set_oidc_config.run(None);
        }

        // Defaults to `Duration::MAX` if no config is known yet.
        // This leads to a refresh if no config is known yet!
        let oidc_config_age = track_age_of(
            oidc_config,
            options.read_value().advanced.oidc_config_age_check_interval,
        );

        let oidc_config_expires_in = Memo::new(move |_| {
            options
                .read_value()
                .advanced
                .max_oidc_config_age
                .saturating_sub(oidc_config_age.get())
        });

        let oidc_config_too_old = Memo::new(move |_| {
            oidc_config_age.get() > options.read_value().advanced.max_oidc_config_age
        });

        let retrieve_oidc_config_action = crate::action::create_retrieve_oidc_config_action(
            Callback::new(move |val| set_oidc_config.run(val)),
            handle_req_error,
            options.read_value().advanced.request_timeout,
        );

        Effect::new(move |_| {
            if oidc_config_too_old.get() {
                let discovery_endpoint = options.read_value().discovery_endpoint();
                retrieve_oidc_config_action.dispatch((discovery_endpoint,));
            }
        });

        Self {
            oidc_config,
            set_oidc_config,
            oidc_config_age: oidc_config_age.into(),
            oidc_config_expires_in: oidc_config_expires_in.into(),
            oidc_config_too_old: oidc_config_too_old.into(),
        }
    }

    pub(crate) fn derive_urls(&self) -> DerivedUrls {
        DerivedUrls::new(self.oidc_config)
    }

    #[expect(unused)]
    pub(crate) fn forget(&self) {
        self.set_oidc_config.run(None);
    }
}
