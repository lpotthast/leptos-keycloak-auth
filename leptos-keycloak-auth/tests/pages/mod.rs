//! [`Page`] holds what every page object needs: lookups, clicks, navigation and waits, each timed
//! as a browser-test step, and the health checks of the test-frontend's pages. Page objects for
//! single pages wrap a [`Page`].

use assertr::{expectation::Expectation, prelude::*};
use browser_test::{
    StepExt,
    thirtyfour::{By, WebDriver, WebElement, prelude::ElementQueryable},
};
use serde::Deserialize;
use url::Url;

pub mod keycloak_login;
pub mod my_account;
pub mod root;

#[derive(Clone, Copy)]
pub struct Page<'d> {
    driver: &'d WebDriver,
    base_url: &'d str,
}

impl<'d> Page<'d> {
    pub fn new(driver: &'d WebDriver, base_url: &'d str) -> Self {
        Self { driver, base_url }
    }

    pub fn driver(&self) -> &'d WebDriver {
        self.driver
    }

    /// The test-frontend's URL of `path`.
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// Navigate to `path` of the test-frontend and wait until it hydrated.
    pub async fn goto_path(&self, path: &str) {
        // The page we leave must not have reported problems.
        self.expect_healthy().await;
        self.driver
            .goto(self.url(path))
            .step("navigate")
            .detail(path)
            .await
            .unwrap_or_else(|err| panic!("Navigating to '{path}': {err:?}"));
        self.wait_for_hydration().await;
    }

    /// Wait until the test-frontend's page hydrated, so that its event handlers are attached.
    pub async fn wait_for_hydration(&self) {
        self.driver
            .query(By::Css("body[data-hydrated]"))
            .first()
            .step("wait_for_hydration")
            .await
            .unwrap_or_else(|err| panic!("Waiting for the page to hydrate: {err:?}"));
    }

    /// Wait until the current URL meets `expected`, then return it.
    pub async fn wait_for_url(&self, expected: impl Expectation<Url>) -> Url {
        assert_that!(|| self.driver.current_url())
            .with_subject_name("current URL")
            .eventually_ok()
            .matches(expected)
            .step("wait_for_url")
            .await
            .actual()
            .clone()
    }

    pub async fn element_with_id(&self, id: &str) -> WebElement {
        self.driver
            .query(By::Id(id))
            .first()
            .step("find")
            .detail(format!("#{id}"))
            .await
            .unwrap_or_else(|err| panic!("Finding element with id '{id}': {err:?}"))
    }

    pub async fn click_element_with_id(&self, id: &str) {
        let element = self.element_with_id(id).await;
        // The click may navigate away from the page, taking what it reported with it.
        self.expect_healthy().await;
        element
            .click()
            .step("click")
            .detail(format!("#{id}"))
            .await
            .unwrap_or_else(|err| panic!("Clicking element with id '{id}': {err:?}"));
    }

    pub async fn type_into_element_with_id(&self, id: &str, text: &str) {
        self.element_with_id(id)
            .await
            .send_keys(text)
            .step("type")
            .detail(format!("#{id}"))
            .await
            .unwrap_or_else(|err| panic!("Typing into element with id '{id}': {err:?}"));
    }

    pub async fn click_link_btn_with_title(&self, title: &str) {
        let link_btn = self
            .driver
            .query(By::LinkText(title))
            .first()
            .step("find")
            .detail(format!("'{title}' button"))
            .await
            .unwrap_or_else(|err| panic!("Finding '{title}' button: {err:?}"));
        // The click may navigate away from the page, taking what it reported with it.
        self.expect_healthy().await;
        link_btn
            .click()
            .step("click")
            .detail(format!("'{title}' button"))
            .await
            .unwrap_or_else(|err| panic!("Clicking '{title}' button: {err:?}"));
    }

    /// Expect that the current page reported no problems since it loaded. Only the
    /// test-frontend's pages are checked: other pages, like Keycloak's, report nothing.
    pub async fn expect_healthy(&self) {
        if let Some(diagnostics) = self.diagnostics().await {
            assert_that!(diagnostics)
                .with_subject_name("what the page reported")
                .is_equal_to(Diagnostics::default());
        }
    }

    /// What the current page reported since it loaded, if it is one of the test-frontend's.
    pub async fn diagnostics(&self) -> Option<Diagnostics> {
        async {
            let url = self
                .driver
                .current_url()
                .await
                .expect("Reading the current URL");
            if !url.as_str().starts_with(self.base_url) {
                return None;
            }
            let diagnostics = self
                .driver
                .execute(DIAGNOSTICS, vec![])
                .await
                .expect("Reading what the page reported")
                .convert::<Option<Diagnostics>>()
                .expect("Parsing what the page reported")
                .unwrap_or_else(|| panic!("The page at {url} has no diagnostics installed"));
            Some(diagnostics)
        }
        .step("check_health")
        .await
    }
}

/// What a test-frontend page reported since it loaded, collected by the script in its `shell`.
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
pub struct Diagnostics {
    /// Rust panics.
    pub panics: Vec<String>,
    /// Uncaught errors and unhandled promise rejections.
    pub uncaught_errors: Vec<String>,
    /// Every other `console.error` message.
    pub console_errors: Vec<String>,
    /// `console.warn` messages.
    pub console_warnings: Vec<String>,
}

/// Reads the page's [`Diagnostics`], or `null` when the page has none installed.
const DIAGNOSTICS: &str = "if (!Array.isArray(window.__panics)) return null;
    return {
        panics: window.__panics,
        uncaught_errors: window.__uncaughtErrors,
        console_errors: window.__consoleErrors,
        console_warnings: window.__consoleWarnings,
    };";
