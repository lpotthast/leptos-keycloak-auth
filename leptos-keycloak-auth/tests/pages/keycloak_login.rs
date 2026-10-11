use std::collections::HashMap;

use assertr::{matchers::string::StartsWith, prelude::*};
use url::Url;

use crate::{
    CLIENT_ID, REALM,
    pages::{Page, my_account},
};

pub struct KeycloakLogin<'d> {
    pub page: Page<'d>,
    pub keycloak_server_url: Url,
}

impl KeycloakLogin<'_> {
    /// Wait for the navigation to Keycloak's login page, expecting the parameters of an
    /// authorization code flow with PKCE, redirecting back to the 'My Account' page.
    pub async fn wait_for_navigation(&self) {
        let auth_endpoint = self
            .keycloak_server_url
            .join(&format!("realms/{REALM}/protocol/openid-connect/auth"))
            .expect("Joining the Keycloak auth endpoint URL");
        let url = self
            .page
            .wait_for_url(StartsWith::new(auth_endpoint.as_str()))
            .await;

        let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_that!(query)
            .contains_entry("response_type", "code")
            .contains_key("code_challenge")
            .contains_entry("code_challenge_method", "S256")
            .contains_entry("client_id", CLIENT_ID)
            .contains_entry("redirect_uri", self.page.url(my_account::PATH))
            .contains_entry("scope", "openid");
    }

    pub async fn sign_in(&self, username: &str, password: &str) {
        self.page
            .type_into_element_with_id("username", username)
            .await;
        self.page
            .type_into_element_with_id("password", password)
            .await;
        self.page.click_element_with_id("kc-login").await;
    }
}
