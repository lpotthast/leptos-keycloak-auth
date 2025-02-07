use crate::config::Options;
use crate::internal::derived_urls::DerivedUrls;
use crate::internal::OidcConfigWithTimestamp;
use crate::request::RequestError;
use crate::time_ext::TimeDurationExt;
use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos_use::storage::{use_storage_with_options, StorageType, UseStorageOptions};
use leptos_use::{use_interval, UseIntervalReturn};
use std::time::Duration as StdDuration;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy)]
pub struct OidcConfigManager {
    pub oidc_config: Signal<Option<OidcConfigWithTimestamp>>,
    pub(crate) set_oidc_config: WriteSignal<Option<OidcConfigWithTimestamp>>,
    #[allow(unused)]
    pub oidc_config_age: Signal<StdDuration>,
    #[allow(unused)]
    pub oidc_config_expires_in: Signal<StdDuration>,
    #[allow(unused)]
    pub oidc_config_too_old: Signal<bool>,
}

impl OidcConfigManager {
    pub(crate) fn new(
        options: StoredValue<Options>,
        handle_req_error: Callback<Option<RequestError>>,
    ) -> Self {
        let (oidc_config, set_oidc_config, _remove_oidc_config_from_storage) =
            use_storage_with_options::<Option<OidcConfigWithTimestamp>, JsonSerdeCodec>(
                StorageType::Local,
                "leptos_keycloak_auth__oidc_config",
                UseStorageOptions::default()
                    .initial_value(None)
                    .delay_during_hydration(false),
            );

        // Immediately forget the previously cached value when the discovery endpoint changed!
        if let Some(source) = oidc_config.get_untracked().map(|it| it.source) {
            if source != options.read_value().discovery_endpoint() {
                tracing::trace!(
                    "Current OIDC config came from old discovery endpoint. Dropping it."
                );
                set_oidc_config.set(None);
            }
        }

        // Defaults to `Duration::MAX` if no config is known yet.
        // This leads to a refresh if no config is known yet!
        let oidc_config_age = {
            let UseIntervalReturn { counter, .. } = use_interval::<u64>(
                options
                    .read_value()
                    .advanced
                    .oidc_config_age_check_interval
                    .as_millis()
                    .try_into()
                    .expect("Millis to not overflow a u64"),
            );
            Memo::new(move |_| {
                let _count = counter.get();
                oidc_config
                    .read()
                    .as_ref()
                    .map(|it| (OffsetDateTime::now_utc() - it.retrieved).to_std_duration())
                    .unwrap_or(StdDuration::MAX)
            })
        };

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
            Callback::new(move |val| set_oidc_config.set(val)),
            handle_req_error,
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
        self.set_oidc_config.set(None);
    }
}
