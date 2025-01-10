use std::env;
use std::process::Stdio;
use std::time::Duration;

use assertr::prelude::*;
use chrome_for_testing_manager::{ChromeForTestingManager, PortRequest, VersionRequest};
use http::StatusCode;
use keycloak::{
    types::{
        ClientRepresentation, CredentialRepresentation, RealmRepresentation, RoleRepresentation,
        RolesRepresentation, UserRepresentation,
    },
    KeycloakAdmin,
};
use reqwest::Client;

use keycloak_container::KeycloakContainer;
use serde::Deserialize;
use thirtyfour::error::{WebDriverErrorInfo, WebDriverErrorValue};
use thirtyfour::prelude::*;
use tokio::process::Command;
use tokio::time::error::Elapsed;
use tokio_process_tools::{TerminateOnDrop, WaitFor};

mod backend;
mod common;
mod keycloak_container;

async fn start_frontend() -> TerminateOnDrop {
    let fe_dir = env::current_dir().unwrap().join("tests").join("frontend");
    tracing::info!("Starting frontend in {:?}", fe_dir);
    let fe = Command::new("cargo")
        .arg("leptos")
        .arg("serve")
        .current_dir(fe_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let fe_process =
        tokio_process_tools::ProcessHandle::new_from_child_with_piped_io("cargo leptos serve", fe);

    let _out_inspector = fe_process.stdout().inspect(|stdout_line| tracing::info!(stdout_line, "cargo leptos log"));
    let _err_inspector = fe_process.stderr().inspect(|stderr_line| tracing::info!(stderr_line, "cargo leptos log"));

    let fe_start_timeout = Duration::from_secs(60 * 10);
    tracing::info!("Waiting {fe_start_timeout:?} for frontend to start...");
    match fe_process
        .stdout()
        .wait_for_with_timeout(
            |line| line.contains("listening on http://127.0.0.1:3000"),
            fe_start_timeout,
        )
        .await
    {
        Ok(_wait_for) => {}
        Err(_elapsed) => {
            tracing::error!("Frontend failed to start in {fe_start_timeout:?}. Expected to see 'listening on http://127.0.0.1:3000' on stdout. Compilation might not be ready yet. A restart might work as it will pick up the previously done compilation work.");
        }
    };
    let fe =
        fe_process.terminate_on_drop(Some(Duration::from_secs(10)), Some(Duration::from_secs(10)));

    tracing::info!("Frontend started!");
    fe
}

#[tokio::test(flavor = "multi_thread")]
async fn test_integration() {
    common::tracing::init_subscriber();

    // Start and configure keycloak.
    let keycloak_container = KeycloakContainer::start().await;
    let admin_client = keycloak_container.admin_client().await;
    configure_keycloak(&admin_client).await;

    // Start axum backend.
    let be_jh =
        backend::start_axum_backend(keycloak_container.url.clone(), "test-realm".to_owned()).await;

    // Start leptos frontend.
    let _fe = start_frontend().await;

    // Optional long wait-time. Use this if you want to play around with a fully running stack.
    // tokio::time::sleep(Duration::from_secs(600)).await;

    async fn ui_test() -> anyhow::Result<()> {
        let mgr = ChromeForTestingManager::new();
        let selected = mgr.resolve_version(VersionRequest::Latest).await?;
        let loaded = mgr.download(selected).await?;
        let (_chromedriver, port) = mgr.launch_chromedriver(&loaded, PortRequest::Any).await?;

        tracing::info!("Starting webdriver...");
        let caps = mgr.prepare_caps(&loaded).await?;
        let driver = WebDriver::new(format!("http://localhost:{port}"), caps).await?;

        tracing::info!("Navigating to frontend...");
        driver.goto("http://127.0.0.1:3000").await?;

        let count_span = driver.find(By::Id("count")).await?;
        let count_text = count_span.text().await?;
        assert_that(count_text).is_equal_to("Count: 0");

        // Click login button.
        // Wait for navigation to keycloak site.
        // Enter user and password and click login.
        // Wait for redirect to leptos app.
        // Check page being updated to reflect authentication state.
        // Click logout.
        // Wait for redirect to logout page.

        Ok(())
    }

    match ui_test().await {
        Ok(()) => {
            tracing::info!("Frontend test passed!");
        }
        Err(err) => {
            tracing::error!("Frontend test failed: {:?}", err);
        }
    }

    let access_token = keycloak_container
        .perform_password_login(
            "test-user-mail@foo.bar",
            "password",
            "test-realm",
            "test-client",
        )
        .await;

    let response = Client::new()
        .get("http://127.0.0.1:9999/who-am-i")
        .bearer_auth(access_token)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .unwrap();

    #[derive(Debug, Deserialize)]
    struct WhoAmIResponse {
        name: String,
        keycloak_uuid: String,
        token_valid_for_whole_seconds: i32,
    }

    tracing::info!(?response);
    let status = response.status();
    let data = response.json::<WhoAmIResponse>().await.unwrap();
    tracing::info!(?status, ?data);

    assert_that(status).is_equal_to(StatusCode::OK);
    assert_that(data.name.as_str()).is_equal_to("test-user-mail@foo.bar");
    assert_that(data.keycloak_uuid.as_str()).is_equal_to("a7060488-c80b-40c5-83e2-d7000bf9738e");
    assert_that(data.token_valid_for_whole_seconds).is_greater_than(0);

    be_jh.abort();
}

async fn configure_keycloak(admin_client: &KeycloakAdmin) {
    tracing::info!("Configuring Keycloak...");

    admin_client
        .post(RealmRepresentation {
            enabled: Some(true),
            realm: Some("test-realm".to_owned()),
            display_name: Some("test-realm".to_owned()),
            registration_email_as_username: Some(true),
            clients: Some(vec![
                // Being public and accepting direct-access-grants allows us to log in with grant type "password".
                ClientRepresentation {
                    enabled: Some(true),
                    public_client: Some(true),
                    direct_access_grants_enabled: Some(true),
                    id: Some("test-client".to_owned()),
                    ..Default::default()
                },
            ]),
            roles: Some(RolesRepresentation {
                realm: Some(vec![RoleRepresentation {
                    name: Some("developer".to_owned()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            users: Some(vec![
                // The user should be "fully set up" to allow logins!
                // No unverified mail, all required fields set (including names), no temporary password, no required pw reset action!
                UserRepresentation {
                    id: Some("a7060488-c80b-40c5-83e2-d7000bf9738e".to_owned()),
                    enabled: Some(true),
                    username: Some("test-user-mail@foo.bar".to_owned()),
                    email: Some("test-user-mail@foo.bar".to_owned()),
                    email_verified: Some(true),
                    first_name: Some("firstName".to_owned()),
                    last_name: Some("lastName".to_owned()),
                    realm_roles: Some(vec!["developer".to_owned()]),
                    credentials: Some(vec![CredentialRepresentation {
                        type_: Some("password".to_owned()),
                        value: Some("password".to_owned()),
                        temporary: Some(false),
                        ..Default::default()
                    }]),
                    required_actions: Some(vec![]),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        })
        .await
        .unwrap();
}
