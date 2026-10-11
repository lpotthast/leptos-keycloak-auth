use assertr::{matchers::string::StartsWith, prelude::*};

use crate::{KEYCLOAK_UUID, USERNAME, pages::Page};

pub const PATH: &str = "/my-account";

pub struct MyAccount<'d> {
    pub page: Page<'d>,
}

impl MyAccount<'_> {
    pub async fn goto(&self) {
        self.page.goto_path(PATH).await;
    }

    /// Wait for the navigation to the 'My Account' page, which may still carry the query
    /// parameters of a login or logout callback.
    pub async fn wait_for_navigation(&self) {
        self.page
            .wait_for_url(StartsWith::new(self.page.url(PATH)))
            .await;
        self.page.wait_for_hydration().await;
    }

    pub async fn expect_not_authenticated(&self) {
        assert_that!(self.page.element_with_id("unauthenticated").await)
            .text()
            .await
            .is_equal_to("Unauthenticated");
    }

    pub async fn expect_authenticated(&self) {
        assert_that!(self.page.element_with_id("greeting").await)
            .text()
            .await
            .is_equal_to("Hello, firstName lastName!");
        assert_that!(self.page.element_with_id("username").await)
            .text()
            .await
            .is_equal_to(USERNAME);
        assert_that!(self.page.element_with_id("keycloak_uuid").await)
            .text()
            .await
            .is_equal_to(KEYCLOAK_UUID);
    }

    pub async fn expect_render_count(&self, expected: u32) {
        assert_that!(self.page.element_with_id("render-count").await)
            .text()
            .await
            .is_equal_to(format!("render count: {expected}"));
    }

    pub async fn read_token_valid_for_whole_seconds(&self) -> u64 {
        self.page
            .element_with_id("token_valid_for_whole_seconds")
            .await
            .text()
            .await
            .expect("Reading the token's remaining validity")
            .parse()
            .expect("Parsing the token's remaining validity")
    }

    pub async fn dismiss_suspicious_logout_modal(&self) {
        self.page
            .element_with_id("suspicious-logout-detected")
            .await;
        self.page.click_element_with_id("dismiss").await;
    }

    pub async fn click_login(&self) {
        self.page.click_link_btn_with_title("Log in").await;
    }

    pub async fn click_logout(&self) {
        self.page.click_link_btn_with_title("Logout").await;
    }

    pub async fn click_programmatic_logout(&self) {
        self.page.click_element_with_id("programmatic-logout").await;
    }

    pub async fn click_forget_auth_state(&self) {
        self.page.click_element_with_id("forget-auth-state").await;
    }

    pub async fn click_force_malicious_logout(&self) {
        self.page
            .click_element_with_id("force-malicious-logout")
            .await;
    }

    pub async fn click_back_to_root(&self) {
        self.page.click_link_btn_with_title("Back to root").await;
    }
}
