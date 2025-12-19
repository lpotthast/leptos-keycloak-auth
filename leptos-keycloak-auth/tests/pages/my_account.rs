use crate::pages::BaseActions;
use crate::{KEYCLOAK_UUID, USERNAME};
use assertr::prelude::*;
use thirtyfour::{By, WebDriver};

pub struct MyAccount<'d> {
    pub driver: &'d WebDriver,
}

impl BaseActions for MyAccount<'_> {
    fn driver(&self) -> &WebDriver {
        self.driver
    }
}

impl MyAccount<'_> {
    pub async fn wait_for_navigation(&self) -> anyhow::Result<()> {
        tracing::info!("Wait for redirect to 'My Account' page.");
        assert_that(self.driver.current_url().await?.as_str())
            .starts_with("http://127.0.0.1:3000/my-account");
        Ok(())
    }

    pub async fn expect_not_authenticated(&self) -> anyhow::Result<()> {
        tracing::info!("Expect that we are not logged in.");
        let heading = self.driver.find(By::Id("unauthenticated")).await?;
        assert_that(heading.text().await?).is_equal_to("Unauthenticated");
        Ok(())
    }

    pub async fn expect_authenticated(&self) -> anyhow::Result<()> {
        self.expect_greeting("Hello, firstName lastName!").await?;
        self.expect_username(USERNAME).await?;
        self.expect_keycloak_uuid(KEYCLOAK_UUID).await?;
        Ok(())
    }

    pub async fn expect_suspicious_logout_modal_is_shown(&self) -> anyhow::Result<()> {
        let _modal_header = self
            .driver
            .find(By::Id("suspicious-logout-detected"))
            .await?;
        self.click_element_with_id("dismiss").await?;
        Ok(())
    }

    pub async fn read_keycloak_port(&self) -> anyhow::Result<u16> {
        tracing::info!("Read keycloak port from frontend.");
        let keycloak_port_div = self.driver.find(By::Id("keycloak-port")).await?;
        let keycloak_port = keycloak_port_div.text().await?;
        let keycloak_port = keycloak_port.trim().parse::<u16>()?;
        Ok(keycloak_port)
    }

    pub async fn click_login(&self) -> anyhow::Result<()> {
        self.click_link_btn_with_title("Log in").await
    }

    pub async fn expect_greeting(&self, expected: &str) -> anyhow::Result<()> {
        let greeting = self.driver.find(By::Id("greeting")).await?;
        assert_that(greeting.text().await?).is_equal_to(expected);
        Ok(())
    }

    pub async fn expect_username(&self, expected: &str) -> anyhow::Result<()> {
        let username = self.driver.find(By::Id("username")).await?;
        assert_that(username.text().await?).is_equal_to(expected);
        Ok(())
    }

    pub async fn expect_keycloak_uuid(&self, expected: &str) -> anyhow::Result<()> {
        let username = self.driver.find(By::Id("keycloak_uuid")).await?;
        assert_that(username.text().await?).is_equal_to(expected);
        Ok(())
    }

    pub async fn get_token_valid_for_whole_seconds(&self) -> anyhow::Result<u64> {
        let token_valid_for_whole_seconds_el = self
            .driver
            .find(By::Id("token_valid_for_whole_seconds"))
            .await?;
        let valid_for = token_valid_for_whole_seconds_el
            .text()
            .await?
            .parse::<u64>()?;
        Ok(valid_for)
    }
    pub async fn expect_render_count(&self, expected: u32) -> anyhow::Result<()> {
        let render_count = self.driver.find(By::Id("render-count")).await?;
        assert_that(render_count.text().await?).is_equal_to(format!("render count: {expected}"));
        Ok(())
    }

    pub async fn click_logout(&self) -> anyhow::Result<()> {
        self.click_link_btn_with_title("Logout").await
    }

    pub async fn click_programmatic_logout(&self) -> anyhow::Result<()> {
        self.click_element_with_id("programmatic-logout").await
    }

    pub async fn click_forget_auth_state(&self) -> anyhow::Result<()> {
        self.click_element_with_id("forget-auth-state").await
    }

    pub async fn click_force_malicious_logout(&self) -> anyhow::Result<()> {
        self.click_element_with_id("force-malicious-logout").await
    }

    pub async fn click_back_to_root(&self) -> anyhow::Result<()> {
        self.click_link_btn_with_title("Back to root").await
    }
}
