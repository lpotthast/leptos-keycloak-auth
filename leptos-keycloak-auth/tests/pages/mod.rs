use thirtyfour::{By, WebDriver, prelude::ElementWaitable};

pub mod keycloak_login;
pub mod my_account;
pub mod root;

trait BaseActions {
    fn driver(&self) -> &WebDriver;

    async fn click_element_with_id(&self, id: &str) -> anyhow::Result<()> {
        tracing::info!("Click element with id '{id}'.");
        let element = self.driver().find(By::Id(id)).await?;
        element.click().await?;
        element.wait_until().stale().await?;
        Ok(())
    }

    async fn click_link_btn_with_title(&self, title: &str) -> anyhow::Result<()> {
        tracing::info!("Click '{title}' button.");
        let link_btn = self.driver().find(By::LinkText(title)).await?;
        link_btn.click().await?;
        link_btn.wait_until().stale().await?;
        Ok(())
    }
}
