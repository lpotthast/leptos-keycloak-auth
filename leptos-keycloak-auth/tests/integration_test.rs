use crate::ui_tests::test_01_auth_flow::AuthFlow;
use crate::ui_tests::UiTest;
use chrome_for_testing_manager::prelude::*;
use keycloak::{
    types::{
        ClientRepresentation, CredentialRepresentation, RealmRepresentation, RoleRepresentation,
        RolesRepresentation, UserRepresentation,
    },
    KeycloakAdmin,
};
use keycloak_container::KeycloakContainer;
use thirtyfour::prelude::*;

mod backend;
mod common;
mod frontend;
mod keycloak_container;
mod pages;
mod ui_tests;

const DELAY_TEST_EXECUTION: bool = false;

const USERNAME: &str = "bob@foo.bar";
const PASSWORD: &str = "245who875hg45";
const KEYCLOAK_UUID: &str = "a7060488-c80b-40c5-83e2-d7000bf9738e";

#[tokio::test(flavor = "multi_thread")]
async fn test_integration() -> anyhow::Result<()> {
    common::tracing::init_subscriber();

    // Start and configure Keycloak.
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
            if input.is_ok() {
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

    let tests: Vec<Box<dyn UiTest>> = vec![Box::new(AuthFlow {})];

    tracing::info!("Starting webdriver...");
    let chromedriver =
        Chromedriver::run(VersionRequest::LatestIn(Channel::Stable), PortRequest::Any).await?;

    for test in tests {
        #[allow(clippy::redundant_closure_for_method_calls)]
        chromedriver
            .with_custom_session(
                |caps| caps.unset_headless(),
                async |driver| {
                    tracing::info!("Executing test: {}", test.name());
                    match test.run(driver).await {
                        Ok(()) => {
                            tracing::info!("Test '{}' passed!", test.name());
                        }
                        Err(err) => {
                            tracing::error!("Test '{}' failed: {:?}", test.name(), err);
                        }
                    }
                    Ok(())
                },
            )
            .await?;
    }

    chromedriver.terminate().await?;

    drop(fe);
    be_jh.abort();
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
            // We use an aggressively short access_token lifetime of 5 seconds here, in order to
            // force many token refreshes quickly. We want to make sure that those do not interfere
            // with the user application, e.g. leading to no accidental rerendering.
            access_token_lifespan: Some(5),
            clients: Some(vec![ClientRepresentation {
                enabled: Some(true),
                public_client: Some(true),
                standard_flow_enabled: Some(true),
                direct_access_grants_enabled: Some(false),
                web_origins: Some(vec!["http://127.0.0.1:3000".to_owned()]),
                redirect_uris: Some(vec!["http://127.0.0.1:3000/*".to_owned()]),
                id: Some("test-client".to_owned()),
                ..Default::default()
            }]),
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
                    id: Some(KEYCLOAK_UUID.to_owned()),
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
