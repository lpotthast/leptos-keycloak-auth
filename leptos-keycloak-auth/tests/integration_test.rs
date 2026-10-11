use std::time::Duration;

use assertr::assertions::Patience;
use browser_test::{
    BrowserTestRunner, BrowserTests, Cancellation, DriverOutput, ElementQueryWait, Pause, Timeouts,
    Visibility, failure_report,
};
use leptos_browser_test::{BuildProfile, LeptosTestAppConfig};
use rootcause::{Report, hooks::Hooks, prelude::ResultExt};
use rootcause_backtrace::BacktraceCollector;
use rootcause_tracing::{RootcauseLayer, SpanCollector};
use tracing_subscriber::layer::SubscriberExt;

use crate::{
    harness::with_page, keycloak_container::KeycloakContainer,
    ui_tests::test_01_auth_flow::AuthFlow,
};

mod backend;
mod common;
mod frontend;
mod harness;
mod keycloak_container;
mod pages;
mod ui_tests;

const USERNAME: &str = "bob@foo.bar";
const PASSWORD: &str = "245who875hg45";
const KEYCLOAK_UUID: &str = "a7060488-c80b-40c5-83e2-d7000bf9738e";
const REALM: &str = "test-realm";
const CLIENT_ID: &str = "test-client";

#[tokio::test(flavor = "multi_thread")]
async fn test_integration() -> Result<(), Report> {
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            .with(RootcauseLayer)
            .with(common::tracing::fmt_layer()),
    )
    .context("Setting global tracing subscriber")?;

    // browser-test installs its failure report hooks with its first run, unless hooks are already
    // installed. Add them to ours, as rootcause only takes one set of hooks per process.
    failure_report::hooks(Hooks::new())
        .report_creation_hook(SpanCollector {
            capture_span_for_reports_with_children: false,
        })
        .report_creation_hook(BacktraceCollector {
            capture_backtrace_for_reports_with_children: false,
            ..BacktraceCollector::new_from_env()
        })
        .install()
        .context("Installing rootcause hooks")?;

    // Eventual assertions observe as long and as often as element lookups wait (see the runner's
    // element-query wait below).
    Patience::DEFAULT
        .with_timeout(Duration::from_secs(10))
        .with_interval(Duration::from_millis(100))
        .with_consistency_duration(Duration::from_millis(300))
        .with_observation_timeout(Duration::from_secs(2))
        .set_global();

    let keycloak = KeycloakContainer::start().await;
    keycloak.configure_test_realm().await;

    backend::start(keycloak.url.clone()).await;

    let fe_dir = frontend::dir();
    frontend::write_dotenv(&fe_dir, keycloak.port);

    // The fixed site_addr keeps Keycloak's redirect URIs in sync with where cargo-leptos serves.
    let app = LeptosTestAppConfig::new(&fe_dir)
        .with_app_name("leptos-keycloak-auth test-frontend")
        .with_site_addr(frontend::ADDR)
        // The test-frontend only defines release profiles (see its Cargo.toml).
        .with_build_profile(BuildProfile::Release)
        .start()
        .await
        .map_err(Report::into_dynamic)
        .context("Starting test-frontend")?;

    let tests = BrowserTests::sequential().with(with_page(AuthFlow));

    BrowserTestRunner::new(Cancellation::on_shutdown_signals())
        .with_visibility(Visibility::from_env()?.unwrap_or_default())
        .with_pause(Pause::from_env()?.unwrap_or_default().with_hint(format!(
            "test-frontend running at {}, Keycloak running at {}",
            app.base_url(),
            keycloak.url,
        )))
        .with_timeouts(
            Timeouts::new()
                .with_script(Duration::from_secs(5))
                .with_page_load(Duration::from_secs(10))
                // Page objects wait for elements through `query`, polling with the element-query
                // wait below, and for values through eventual assertions. Polling survives
                // navigations, unlike an implicit wait.
                .with_implicit_wait(Duration::ZERO),
        )
        .with_element_query_wait(ElementQueryWait::new(
            Duration::from_secs(10),
            Duration::from_millis(100),
        ))
        .with_driver_output(DriverOutput::from_env()?.unwrap_or(DriverOutput::tail_lines(100)))
        .run(app.base_url(), tests)
        .await
        .map_err(Report::into_dynamic)
        .context("Running browser tests")?;

    Ok(())
}
