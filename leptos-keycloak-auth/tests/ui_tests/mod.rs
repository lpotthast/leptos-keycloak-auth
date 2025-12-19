use thirtyfour::WebDriver;

pub mod test_01_auth_flow;

#[async_trait::async_trait]
pub trait UiTest {
    fn name(&self) -> String;

    async fn run(&self, driver: &WebDriver) -> anyhow::Result<()>;
}
