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
use keycloak_container::KeycloakContainer;
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use thirtyfour::prelude::*;

mod backend;
mod common;
mod frontend;
mod keycloak_container;

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
    let _fe = frontend::start_frontend(keycloak_container.port).await;

    // Optional long wait-time. Use this if you want to play around with a fully running stack.
    tokio::time::sleep(Duration::from_secs(1)).await;

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
            ssl_required: Some("none".to_owned()),
            realm: Some("test-realm".to_owned()),
            display_name: Some("test-realm".to_owned()),
            registration_email_as_username: Some(true),
            clients: Some(vec![
                // Being public and accepting direct-access-grants allows us to log in with grant type "password".
                ClientRepresentation {
                    enabled: Some(true),
                    public_client: Some(true),
                    direct_access_grants_enabled: Some(true),
                    redirect_uris: Some(vec!["http://127.0.0.1:3000/*".to_owned()]),
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
