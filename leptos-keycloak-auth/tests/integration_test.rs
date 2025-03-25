use assertr::prelude::*;
use chrome_for_testing_manager::prelude::*;
use keycloak::{
    KeycloakAdmin,
    types::{
        ClientRepresentation, CredentialRepresentation, RealmRepresentation, RoleRepresentation,
        RolesRepresentation, UserRepresentation,
    },
};
use keycloak_container::KeycloakContainer;
use std::time::Duration;
use thirtyfour::prelude::*;

mod backend;
mod common;
mod frontend;
mod keycloak_container;

const DELAY_TEST_EXECUTION: bool = false;

const USERNAME: &str = "bob@foo.bar";
const PASSWORD: &str = "245who875hg45";

#[tokio::test(flavor = "multi_thread")]
async fn test_integration() -> anyhow::Result<()> {
    common::tracing::init_subscriber();

    // Start and configure keycloak.
    let keycloak_container = KeycloakContainer::start().await;
    let admin_client = keycloak_container.admin_client().await;
    configure_keycloak(&admin_client).await;

    // Start axum backend.
    let be_jh =
        backend::start_axum_backend(keycloak_container.url.clone(), "test-realm".to_owned()).await;

    // Start leptos frontend.
    let fe = frontend::start_frontend(keycloak_container.port).await;

    // Optional long wait-time. Use this if you want to play around with a fully running stack.
    if DELAY_TEST_EXECUTION {
        tracing::info!("Continue with test? y/n");
        let mut buf = String::new();
        loop {
            buf.clear();
            let input = std::io::stdin().read_line(&mut buf);
            if let Ok(_) = input {
                match buf.trim() {
                    "y" => break,
                    "n" => return Ok(()),
                    _ => {}
                }
            }
            if let Err(err) = input {
                tracing::error!("Error reading input: {err:?}");
                return Err(err.into());
            }
        }
    }

    tracing::info!("Starting webdriver...");
    let chromedriver = Chromedriver::run_latest_stable().await?;
    chromedriver
        .with_custom_session(
            |caps| caps.unset_headless(),
            async |driver| match ui_test(&driver).await {
                Ok(()) => {
                    tracing::info!("Frontend test passed!");
                    Ok(())
                }
                Err(err) => {
                    tracing::error!("Frontend test failed: {:?}", err);
                    Ok(())
                }
            },
        )
        .await?;

    chromedriver.terminate().await?;
    drop(fe);
    be_jh.abort();
    Ok(())
}

async fn ui_test(driver: &WebDriver) -> anyhow::Result<()> {
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

    tracing::info!("Read keycloak port from frontend.");
    let keycloak_port_div = driver.find(By::Id("keycloak-port")).await?;
    let keycloak_port = keycloak_port_div.text().await?;
    let keycloak_port = keycloak_port.trim().parse::<u16>()?;

    tracing::info!("Click 'Log in' button.");
    let login_button = driver.find(By::LinkText("Log in")).await?;
    login_button.click().await?;
    login_button.wait_until().stale().await?;

    tracing::info!("Wait for navigation to keycloak site.");
    let current_url = driver.current_url().await?.as_str().to_owned();
    assert_that(current_url)
        .starts_with(format!(
            "http://localhost:{keycloak_port}/realms/test-realm/protocol/openid-connect/auth"
        ))
        .contains("?response_type=code")
        .contains("&code_challenge=")
        .contains("&code_challenge_method=S256")
        .contains("&client_id=test-client")
        .contains("&redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fmy-account")
        .contains("&scope=openid");

    tracing::info!("Enter username.");
    let username_input = driver.find(By::Id("username")).await?;
    username_input.send_keys(USERNAME).await?;

    tracing::info!("Enter password.");
    let password_input = driver.find(By::Id("password")).await?;
    password_input.send_keys(PASSWORD).await?;

    tracing::info!("Click 'Sign In'.");
    let sign_in_button = driver.find(By::Id("kc-login")).await?;
    sign_in_button.click().await?;
    sign_in_button.wait_until().stale().await?;

    tracing::info!("Wait for redirect to 'My Account' page.");
    assert_that(driver.current_url().await?.as_str())
        .starts_with("http://127.0.0.1:3000/my-account");

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
    assert_that(driver.current_url().await?.as_str())
        .is_equal_to("http://127.0.0.1:3000/my-account");

    let greeting = driver.find(By::Id("greeting")).await?;
    assert_that(greeting.text().await?).is_equal_to("Hello, firstName lastName!");

    let username = driver.find(By::Id("username")).await?;
    assert_that(username.text().await?).is_equal_to(USERNAME);
    let keycloak_uuid = driver.find(By::Id("keycloak_uuid")).await?;
    assert_that(keycloak_uuid.text().await?).is_equal_to("a7060488-c80b-40c5-83e2-d7000bf9738e");
    let token_valid_for_whole_seconds =
        driver.find(By::Id("token_valid_for_whole_seconds")).await?;
    assert_that(token_valid_for_whole_seconds.text().await?.parse::<u32>()?).is_in_range(200..=300);

    tracing::info!("Click 'Logout' button.");
    let logout_button = driver.find(By::LinkText("Logout")).await?;
    logout_button.click().await?;

    tracing::info!("Expect that we are not logged in again.");
    let heading = driver.find(By::Id("unauthenticated")).await?;
    assert_that(heading.text().await?).is_equal_to("Unauthenticated");

    Ok(())
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
                    standard_flow_enabled: Some(true),
                    direct_access_grants_enabled: Some(false),
                    web_origins: Some(vec!["http://127.0.0.1:3000".to_owned()]),
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
                    username: Some(USERNAME.to_owned()),
                    email: Some(USERNAME.to_owned()),
                    email_verified: Some(true),
                    first_name: Some("firstName".to_owned()),
                    last_name: Some("lastName".to_owned()),
                    realm_roles: Some(vec!["developer".to_owned()]),
                    credentials: Some(vec![CredentialRepresentation {
                        type_: Some("password".to_owned()),
                        value: Some(PASSWORD.to_owned()),
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
