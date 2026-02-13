use assertr::{assert_that, prelude::*};
use thirtyfour::{By, WebDriver};

use crate::pages::BaseActions;

pub struct Root<'d> {
    pub driver: &'d WebDriver,
}

impl BaseActions for Root<'_> {
    fn driver(&self) -> &WebDriver {
        self.driver
    }
}

impl Root<'_> {
    pub async fn goto(&self) -> anyhow::Result<()> {
        tracing::info!("Navigating to frontend...");
        self.driver.goto("http://127.0.0.1:3000").await?;
        Ok(())
    }

    pub async fn wait_for_navigation(&self) -> anyhow::Result<()> {
        tracing::info!("Wait for redirect to 'Root' page.");
        assert_that(self.driver.current_url().await?.as_str())
            .starts_with("http://127.0.0.1:3000/");
        Ok(())
    }

    pub async fn read_keycloak_port(&self) -> anyhow::Result<u16> {
        tracing::info!("Read keycloak port from frontend.");
        let keycloak_port_div = self.driver.find(By::Id("keycloak-port")).await?;
        let keycloak_port = keycloak_port_div.text().await?;
        let keycloak_port = keycloak_port.trim().parse::<u16>()?;
        Ok(keycloak_port)
    }

    pub(crate) async fn check_not_logged_in(&self) -> anyhow::Result<()> {
        let el = self.driver.find(By::Id("auth-state")).await?;
        let text = el.text().await?;
        assert_that(text).contains("You are not logged in.");
        Ok(())
    }

    pub(crate) async fn click_on_my_account(&self) -> anyhow::Result<()> {
        self.click_link_btn_with_title("My Account").await?;
        Ok(())
    }
}
