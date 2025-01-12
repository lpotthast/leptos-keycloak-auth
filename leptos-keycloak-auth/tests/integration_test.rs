use assertr::prelude::*;
use chrome_for_testing_manager::{ChromeForTestingManager, PortRequest, VersionRequest};
use keycloak::{
    types::{
        ClientRepresentation, CredentialRepresentation, RealmRepresentation, RoleRepresentation,
        RolesRepresentation, UserRepresentation,
    },
    KeycloakAdmin,
};
use keycloak_container::KeycloakContainer;
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
    tokio::time::sleep(Duration::from_secs(900)).await;

    async fn ui_test() -> anyhow::Result<()> {
        let mgr = ChromeForTestingManager::new();
        let selected = mgr.resolve_version(VersionRequest::Latest).await?;
        let loaded = mgr.download(selected).await?;
        let (_chromedriver, port) = mgr.launch_chromedriver(&loaded, PortRequest::Any).await?;

        tracing::info!("Starting webdriver...");
        let mut caps = mgr.prepare_caps(&loaded).await?;
        caps.unset_headless()?;
        let driver = WebDriver::new(format!("http://localhost:{port}"), caps).await?;

        tracing::info!("Navigating to frontend...");
        driver.goto("http://127.0.0.1:3000").await?;

        let mut timeouts = TimeoutConfiguration::default();
        timeouts.set_implicit(Some(Duration::from_secs(3)));
        driver.update_timeouts(timeouts).await?;

        let count_span = driver.find(By::Id("count")).await?;
        let count_text = count_span.text().await?;
        assert_that(count_text).is_equal_to("Count: 0");

        tracing::info!("Navigating to 'My Account' page.");
        let my_account_button = driver.find(By::LinkText("My Account")).await?;
        my_account_button.click().await?;

        tracing::info!("Expect that we are not logged in yet.");
        let heading = driver.find(By::Id("unauthenticated")).await?;
        assert_that(heading.text().await?).is_equal_to("Unauthenticated");

        let keycloak_port_div = driver.find(By::Id("keycloak-port")).await?;
        let keycloak_port = keycloak_port_div.text().await?;
        let keycloak_port = keycloak_port.trim().parse::<u16>()?;

        tracing::info!("Click 'Log in' button.");
        let login_button = driver.find(By::LinkText("Log in")).await?;
        login_button.click().await?;
        login_button.wait_until().stale().await?;

        tracing::info!("Wait for navigation to keycloak site.");
        assert_that(driver.current_url().await?.as_str()).is_equal_to(format!("http://localhost:{keycloak_port}/realms/test-realm/protocol/openid-connect/auth?response_type=code&client_id=test-client&redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fmy-account&scope=openid"));

        tracing::info!("Enter username.");
        let username_input = driver.find(By::Id("username")).await?;
        username_input.send_keys("test-user-mail@foo.bar").await?;

        tracing::info!("Enter password.");
        let password_input = driver.find(By::Id("password")).await?;
        password_input.send_keys("password").await?;

        tracing::info!("Click 'Sign In'.");
        let sign_in_button = driver.find(By::Id("kc-login")).await?;
        sign_in_button.click().await?;
        sign_in_button.wait_until().stale().await?;

        tracing::info!("Wait for redirect to 'My Account' page.");
        assert_that(driver.current_url().await?.as_str()).starts_with("http://127.0.0.1:3000/my-account?session_state=");

        let greeting = driver.find(By::Id("greeting")).await?;
        assert_that(greeting.text().await?).is_equal_to("Hello, firstName lastName!");

        let back_to_root_button = driver.find(By::LinkText("Back to root")).await?;
        back_to_root_button.click().await?;

        tracing::info!("Wait for redirect to 'Root' page.");
        assert_that(driver.current_url().await?.as_str()).starts_with("http://127.0.0.1:3000/");

        tracing::info!("Navigate to 'My Account' page.");
        let my_account_button = driver.find(By::LinkText("My Account")).await?;
        my_account_button.click().await?;

        tracing::info!("Wait for redirect to 'My Account' page.");
        assert_that(driver.current_url().await?.as_str()).is_equal_to("http://127.0.0.1:3000/my-account");

        let greeting = driver.find(By::Id("greeting")).await?;
        assert_that(greeting.text().await?).is_equal_to("Hello, firstName lastName!");

        tracing::info!("Click 'Logout' button.");
        let logout_button = driver.find(By::LinkText("Logout")).await?;
        logout_button.click().await?;

        tracing::info!("Expect that we are not logged in again.");
        let heading = driver.find(By::Id("unauthenticated")).await?;
        assert_that(heading.text().await?).is_equal_to("Unauthenticated");

        driver.quit().await?;

        Ok(())
    }

    match ui_test().await {
        Ok(()) => {
            tracing::info!("Frontend test passed!");
            be_jh.abort();
        }
        Err(err) => {
            panic!("Frontend test failed: {:?}", err);
        }
    }
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
