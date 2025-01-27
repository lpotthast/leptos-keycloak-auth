use crate::internal::OidcConfigWithTimestamp;
use crate::request::RequestError;
use crate::time_ext::TimeDurationExt;
use crate::{DiscoveryEndpoint, UseKeycloakAuthOptions};
use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos_use::storage::{use_storage_with_options, StorageType, UseStorageOptions};
use leptos_use::{use_interval, UseIntervalReturn};
use std::time::Duration;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy)]
pub struct OidcConfigManager {
    pub oidc_config: Signal<Option<OidcConfigWithTimestamp>>,
    #[allow(unused)]
    pub oidc_config_age: Signal<Duration>,
    #[allow(unused)]
    pub oidc_config_expires_in: Signal<Duration>,
    #[allow(unused)]
    pub oidc_config_too_old: Signal<bool>,
}
impl OidcConfigManager {
    pub(crate) fn new(
        options: StoredValue<UseKeycloakAuthOptions>,
        discovery_endpoint: DiscoveryEndpoint,
        handle_req_error: Callback<Option<RequestError>>,
    ) -> Self {
        let (oidc_config, set_oidc_config, _remove_oidc_config_from_storage) =
            use_storage_with_options::<Option<OidcConfigWithTimestamp>, JsonSerdeCodec>(
                StorageType::Local,
                "leptos_keycloak_auth__oidc_config",
                UseStorageOptions::default().initial_value(None),
            );

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
                    .unwrap_or(Duration::MAX)
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
            discovery_endpoint.clone(),
            Callback::new(move |val| set_oidc_config.set(val)),
            handle_req_error,
        );

        Effect::new(move |_| {
            if oidc_config_too_old.get() {
                retrieve_oidc_config_action.dispatch(());
            }
        });

        Self {
            oidc_config,
            oidc_config_age: oidc_config_age.into(),
            oidc_config_expires_in: oidc_config_expires_in.into(),
            oidc_config_too_old: oidc_config_too_old.into(),
        }
    }
}
