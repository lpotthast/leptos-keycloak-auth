use std::time::Duration as StdDuration;

use leptos::prelude::*;
use leptos_use::{UseIntervalReturn, use_interval};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;

use crate::{oidc::OidcConfig, time_ext::TimeDurationExt};

pub(crate) mod code_verifier_manager;
pub(crate) mod csrf_token_manager;
pub(crate) mod derived_urls;
pub(crate) mod hydration_manager;
pub(crate) mod jwk_set_manager;
pub(crate) mod nonce_manager;
pub(crate) mod oidc_config_manager;
pub(crate) mod token_manager;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OidcConfigWithTimestamp {
    pub oidc_config: OidcConfig,

    #[serde(with = "time::serde::rfc3339")]
    pub retrieved: OffsetDateTime,

    /// The discovery endpoint used to query this information.
    /// This OIDC config data immediately becomes invalid if we no longer work with that source,
    /// e.g. the app was reconfigured to use a different authentication provider!
    /// We see any change in the url, be it host, port, realm, ... as a potentially completely
    /// different provider for which the already known / cached information is no longer applicable.
    pub source: Url,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwkSetWithTimestamp {
    pub jwk_set: jsonwebtoken::jwk::JwkSet,

    #[serde(with = "time::serde::rfc3339")]
    pub retrieved: OffsetDateTime,

    /// The discovery endpoint used to query this information.
    /// This JWK set data immediately becomes invalid if we no longer work with that source,
    /// e.g. the app was reconfigured to use a different authentication provider!
    /// We see any change in the url, be it host, port, realm, ... as a potentially completely
    /// different provider for which the already known / cached information is no longer applicable.
    pub source: Url,
}

trait BornAt {
    fn born_at(&self) -> OffsetDateTime;
}
impl BornAt for OidcConfigWithTimestamp {
    fn born_at(&self) -> OffsetDateTime {
        self.retrieved
    }
}
impl BornAt for JwkSetWithTimestamp {
    fn born_at(&self) -> OffsetDateTime {
        self.retrieved
    }
}

/// Creates a periodically updating signal, tracking the time the given object is alive for.
fn track_age_of<T: BornAt + Send + Sync + 'static>(
    data: Signal<Option<T>>,
    check_interval: StdDuration,
) -> Memo<StdDuration> {
    let UseIntervalReturn { counter, .. } = use_interval::<u64>(
        check_interval
            .as_millis()
            .try_into()
            .expect("Millis to not overflow a u64"),
    );
    Memo::new(move |_| {
        let _count = counter.get();
        data.read().as_ref().map_or(StdDuration::MAX, |it| {
            (OffsetDateTime::now_utc() - it.born_at()).to_std_duration()
        })
    })
}
