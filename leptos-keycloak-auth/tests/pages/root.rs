use crate::pages::BaseActions;
use assertr::assert_that;
use assertr::prelude::*;
use thirtyfour::{By, WebDriver};

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

    pub(crate) async fn check_that_count_is(&self, expected: u64) -> anyhow::Result<()> {
        tracing::info!("Check that count is: {expected}");
        let count_span = self.driver.find(By::Id("count")).await?;
        let count_text = count_span.text().await?;
        assert_that(count_text).is_equal_to(format!("Count: {expected}"));
        Ok(())
    }

    pub(crate) async fn click_on_my_account(&self) -> anyhow::Result<()> {
        self.click_link_btn_with_title("My Account").await?;
        Ok(())
    }
}
