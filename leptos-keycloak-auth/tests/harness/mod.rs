//! Page context and health checks around browser tests.
use std::{borrow::Cow, panic::AssertUnwindSafe};

use browser_test::{BrowserTest, SessionSettings, async_trait, thirtyfour::WebDriver};
use futures::FutureExt;
use rootcause::Report;

use crate::pages::Page;

/// Run `test` with a [`Page`] on the test-frontend at the runner's base URL, then expect the
/// page it ends on to be healthy (see [`Page::expect_healthy`]).
pub fn with_page(test: impl for<'a> BrowserTest<Page<'a>> + 'static) -> impl BrowserTest<str> {
    WithPage(test)
}

struct WithPage<T>(T);

#[async_trait]
impl<T: for<'a> BrowserTest<Page<'a>>> BrowserTest<str> for WithPage<T> {
    fn name(&self) -> Cow<'_, str> {
        self.0.name()
    }

    fn description(&self) -> Option<Cow<'_, str>> {
        self.0.description()
    }

    fn session_settings(&self) -> SessionSettings {
        self.0.session_settings()
    }

    async fn run(&self, driver: &WebDriver, base_url: &str) -> Result<(), Report> {
        let page = Page::new(driver, base_url);
        match AssertUnwindSafe(self.0.run(driver, &page))
            .catch_unwind()
            .await
        {
            Ok(result) => {
                result?;
                page.expect_healthy().await;
                Ok(())
            }
            // What the page reported is often the cause of a failed assertion.
            Err(panic) => {
                if let Some(diagnostics) = page.diagnostics().await {
                    tracing::error!("The page reported: {diagnostics:#?}");
                }
                std::panic::resume_unwind(panic)
            }
        }
    }
}
