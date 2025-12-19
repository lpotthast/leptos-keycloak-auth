use crate::pages::BaseActions;
use assertr::prelude::*;
use thirtyfour::{By, WebDriver};

pub(crate) struct KeycloakLogin<'d> {
    pub driver: &'d WebDriver,

    pub keycloak_port: u16,
}

impl BaseActions for KeycloakLogin<'_> {
    fn driver(&self) -> &WebDriver {
        self.driver
    }
}

impl KeycloakLogin<'_> {
    pub async fn wait_for_navigation(&self) -> anyhow::Result<()> {
        let expected_url = format!(
            "http://localhost:{}/realms/test-realm/protocol/openid-connect/auth",
            self.keycloak_port
        );
        tracing::info!("Wait for navigation to: {expected_url}");
        let current_url = self.driver.current_url().await?.as_str().to_owned();
        assert_that(current_url)
            .starts_with(expected_url)
            .contains("?response_type=code")
            .contains("&code_challenge=")
            .contains("&code_challenge_method=S256")
            .contains("&client_id=test-client")
            .contains("&redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fmy-account")
            .contains("&scope=openid");
        Ok(())
    }

    pub async fn enter_username(&self, username: &str) -> anyhow::Result<()> {
        tracing::info!("Enter username.");
        let username_input = self.driver.find(By::Id("username")).await?;
        username_input.send_keys(username).await?;
        Ok(())
    }

    pub async fn enter_password(&self, password: &str) -> anyhow::Result<()> {
        tracing::info!("Enter username.");
        let username_input = self.driver.find(By::Id("password")).await?;
        username_input.send_keys(password).await?;
        Ok(())
    }

    pub async fn click_sign_in(&self) -> anyhow::Result<()> {
        self.click_element_with_id("kc-login").await?;
        Ok(())
    }
}
