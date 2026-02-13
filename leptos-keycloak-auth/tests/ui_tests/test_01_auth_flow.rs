use std::time::Duration;

use assertr::prelude::*;
use thirtyfour::{TimeoutConfiguration, WebDriver};

use crate::{
    PASSWORD, USERNAME, pages,
    pages::{keycloak_login::KeycloakLogin, my_account::MyAccount},
    ui_tests::UiTest,
};

pub struct AuthFlow {}

#[async_trait::async_trait]
impl UiTest for AuthFlow {
    fn name(&self) -> String {
        "auth_flow".to_string()
    }

    async fn run(&self, driver: &WebDriver) -> anyhow::Result<()> {
        let mut timeouts = TimeoutConfiguration::default();
        timeouts.set_implicit(Some(Duration::from_secs(3)));
        driver.update_timeouts(timeouts).await?;

        let root = pages::root::Root { driver };
        root.goto().await?;
        root.wait_for_navigation().await?;

        let keycloak_port = root.read_keycloak_port().await?;

        root.check_not_logged_in().await?;
        root.click_on_my_account().await?;

        let my_account = MyAccount { driver };
        my_account.expect_not_authenticated().await?;

        let keycloak = KeycloakLogin {
            driver,
            keycloak_port,
        };

        self.log_in(&my_account, &keycloak).await?;

        my_account.expect_authenticated().await?;
        my_account.click_back_to_root().await?;

        root.wait_for_navigation().await?;
        root.click_on_my_account().await?;

        my_account.wait_for_navigation().await?;
        my_account.expect_authenticated().await?;

        let token_valid_for_whole_seconds = my_account.get_token_valid_for_whole_seconds().await?;
        assert_that(token_valid_for_whole_seconds).is_in_range(1..=5);
        my_account.expect_render_count(1).await?;
        // Sleep long enough to witness at least one token refresh.
        tokio::time::sleep(Duration::from_secs(token_valid_for_whole_seconds + 1)).await;
        // The user component must not have been rerendered!
        my_account.expect_render_count(1).await?;

        /* Logging out through the link button displaying in the logout url works. */
        my_account.click_logout().await?;
        my_account.expect_not_authenticated().await?;
        self.log_in(&my_account, &keycloak).await?;
        my_account.expect_authenticated().await?;

        /* Logging out through the programmatic logout button works. */
        my_account.click_programmatic_logout().await?;
        my_account.expect_not_authenticated().await?;
        self.log_in(&my_account, &keycloak).await?;
        my_account.expect_authenticated().await?;

        /* Forgetting the auth state keeps our Keycloak session on the Keycloak server and allows
        us to log back in without entering our credentials again. */
        my_account.click_forget_auth_state().await?;
        my_account.expect_not_authenticated().await?;
        my_account.click_login().await?;
        my_account.expect_authenticated().await?;

        /* Logging out through invalid url trigger suspicious logout signal. */
        my_account.click_force_malicious_logout().await?;
        my_account.expect_suspicious_logout_modal_is_shown().await?;
        my_account.expect_not_authenticated().await?;

        Ok(())
    }
}

impl AuthFlow {
    async fn log_in<'d>(
        &self,
        my_account: &MyAccount<'d>,
        keycloak_login: &KeycloakLogin<'d>,
    ) -> anyhow::Result<()> {
        my_account.click_login().await?;
        keycloak_login.wait_for_navigation().await?;
        keycloak_login.enter_username(USERNAME).await?;
        keycloak_login.enter_password(PASSWORD).await?;
        keycloak_login.click_sign_in().await?;
        my_account.wait_for_navigation().await?;
        Ok(())
    }
}
