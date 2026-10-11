use assertr::{matchers::eq, prelude::*};
use url::Url;

use crate::pages::Page;

pub struct Root<'d> {
    pub page: Page<'d>,
}

impl Root<'_> {
    pub async fn goto(&self) {
        self.page.goto_path("/").await;
    }

    pub async fn wait_for_navigation(&self) {
        let expected = Url::parse(&self.page.url("/")).expect("Parsing the root URL");
        self.page.wait_for_url(eq(expected)).await;
        self.page.wait_for_hydration().await;
    }

    pub async fn read_keycloak_server_url(&self) -> Url {
        let keycloak_server_url = self
            .page
            .element_with_id("keycloak-server-url")
            .await
            .text()
            .await
            .expect("Reading the Keycloak server URL");
        Url::parse(keycloak_server_url.trim()).expect("Parsing the Keycloak server URL")
    }

    pub async fn expect_not_authenticated(&self) {
        // The text settles once the app determined the auth state.
        let auth_state = self.page.element_with_id("auth-state").await;
        assert_that!(|| auth_state.text())
            .with_subject_name("text of #auth-state")
            .eventually_ok()
            .giving_up_on_any_error()
            .matches(eq("You are not logged in.".to_owned()))
            .await;
    }

    pub async fn click_my_account(&self) {
        self.page.click_link_btn_with_title("My Account").await;
    }
}
