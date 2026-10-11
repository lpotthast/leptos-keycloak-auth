use keycloak::{
    KeycloakAdmin, KeycloakAdminToken,
    types::{
        ClientRepresentation, CredentialRepresentation, RealmRepresentation, RoleRepresentation,
        RolesRepresentation, UserRepresentation,
    },
};
use testcontainers::{
    GenericImage, ImageExt,
    core::{ContainerPort, WaitFor, logs::LogFrame},
    runners::AsyncRunner,
};
use url::Url;

use crate::{CLIENT_ID, KEYCLOAK_UUID, PASSWORD, REALM, USERNAME, frontend};

const ADMIN_USER: &str = "admin";
const ADMIN_PASSWORD: &str = "admin";

/// A running Keycloak container. Dropping it (even in a panic) shuts the container down.
pub struct KeycloakContainer {
    _container: testcontainers::ContainerAsync<GenericImage>,
    pub port: u16,
    pub url: Url,
}

impl KeycloakContainer {
    pub async fn start() -> Self {
        tracing::info!("Starting Keycloak...");

        // This setup is roughly equivalent to the following cli command:
        // `podman run -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:26.4.0 start-dev`
        let container = GenericImage::new("quay.io/keycloak/keycloak", "26.4.0")
            .with_exposed_port(ContainerPort::Tcp(8080))
            // Keycloak logs this as part of its "started" line.
            .with_wait_for(WaitFor::message_on_stdout(
                "Listening on: http://0.0.0.0:8080",
            ))
            .with_log_consumer(|frame: &LogFrame| {
                let (LogFrame::StdOut(bytes) | LogFrame::StdErr(bytes)) = frame;
                println!("{}", String::from_utf8_lossy(bytes));
            })
            .with_env_var("KC_BOOTSTRAP_ADMIN_USERNAME", ADMIN_USER)
            .with_env_var("KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
            .with_env_var("KC_HTTP_ENABLED", "true")
            .with_env_var("KC_HOSTNAME_STRICT_HTTPS", "false")
            .with_cmd(["start-dev"])
            .start()
            .await
            .expect("Starting Keycloak");

        let port = container
            .get_host_port_ipv4(8080)
            .await
            .expect("Reading Keycloak's host port");
        let url = Url::parse(&format!("http://127.0.0.1:{port}")).expect("Parsing Keycloak's URL");
        tracing::info!(available_at = %url, "Keycloak started.");

        Self {
            _container: container,
            port,
            url,
        }
    }

    /// Create the test realm with the test-frontend's client and the test user.
    pub async fn configure_test_realm(&self) {
        tracing::info!("Configuring Keycloak...");

        let client = reqwest::Client::new();
        let admin_token =
            KeycloakAdminToken::acquire(self.url.as_str(), ADMIN_USER, ADMIN_PASSWORD, &client)
                .await
                .expect("Acquiring a Keycloak admin token");
        let admin = KeycloakAdmin::new(self.url.as_str(), admin_token, client);

        admin
            .post(RealmRepresentation {
                enabled: Some(true),
                ssl_required: Some("none".to_owned()),
                realm: Some(REALM.to_owned()),
                display_name: Some(REALM.to_owned()),
                registration_email_as_username: Some(true),
                // We use an aggressively short access_token lifetime of 5 seconds here, in order to
                // force many token refreshes quickly. We want to make sure that those do not
                // interfere with the user application, e.g. leading to no accidental rerendering.
                access_token_lifespan: Some(5),
                sso_session_idle_timeout: Some(10),
                sso_session_max_lifespan: Some(20),
                clients: Some(vec![ClientRepresentation {
                    enabled: Some(true),
                    public_client: Some(true),
                    standard_flow_enabled: Some(true),
                    direct_access_grants_enabled: Some(false),
                    web_origins: Some(vec![frontend::origin()]),
                    redirect_uris: Some(vec![format!("{}/*", frontend::origin())]),
                    id: Some(CLIENT_ID.to_owned()),
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
                    // The user must be "fully set up" to allow logins: no unverified mail, all
                    // required fields set (including names), no temporary password and no required
                    // actions (like a password reset).
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
            .expect("Creating the test realm");
    }
}
