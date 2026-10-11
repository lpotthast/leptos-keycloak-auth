use std::time::Duration;

use assertr::prelude::*;
use browser_test::browser_test;
use rootcause::Report;

use crate::{
    PASSWORD, USERNAME,
    pages::{Page, keycloak_login::KeycloakLogin, my_account::MyAccount, root::Root},
};

/// Logging in and out, token refreshes and session handling work end to end.
#[browser_test]
pub async fn auth_flow(page: &Page<'_>) -> Result<(), Report> {
    let root = Root { page: *page };
    let my_account = MyAccount { page: *page };

    root.goto().await;
    root.wait_for_navigation().await;
    root.expect_not_authenticated().await;

    let keycloak = KeycloakLogin {
        page: *page,
        keycloak_server_url: root.read_keycloak_server_url().await,
    };

    root.click_my_account().await;
    my_account.expect_not_authenticated().await;
    log_in(&my_account, &keycloak).await;
    my_account.expect_authenticated().await;

    /* The session is shared with other tabs: the app opened in a second tab is authenticated right
    away, without logging in again. */
    expect_authenticated_in_new_tab(&my_account).await;

    /* The session survives navigating within the app. */
    my_account.click_back_to_root().await;
    root.wait_for_navigation().await;
    root.click_my_account().await;
    my_account.wait_for_navigation().await;
    my_account.expect_authenticated().await;

    /* Token refreshes don't rerender the user component. */
    let token_valid_for_whole_seconds = my_account.read_token_valid_for_whole_seconds().await;
    assert_that!(token_valid_for_whole_seconds).is_in_range(1..=5);
    my_account.expect_render_count(1).await;
    // Sleep long enough to witness at least one token refresh.
    tokio::time::sleep(Duration::from_secs(token_valid_for_whole_seconds + 1)).await;
    my_account.expect_render_count(1).await;

    /* Logging out through the link button displaying in the logout url works. */
    my_account.click_logout().await;
    my_account.expect_not_authenticated().await;
    log_in(&my_account, &keycloak).await;
    my_account.expect_authenticated().await;

    /* Logging out through the programmatic logout button works. */
    my_account.click_programmatic_logout().await;
    my_account.expect_not_authenticated().await;
    log_in(&my_account, &keycloak).await;
    my_account.expect_authenticated().await;

    /* Forgetting the auth state keeps our Keycloak session on the Keycloak server and allows
    us to log back in without entering our credentials again. */
    my_account.click_forget_auth_state().await;
    my_account.expect_not_authenticated().await;
    my_account.click_login().await;
    my_account.expect_authenticated().await;

    /* Logging out through invalid url trigger suspicious logout signal. */
    my_account.click_force_malicious_logout().await;
    my_account.dismiss_suspicious_logout_modal().await;
    my_account.expect_not_authenticated().await;

    Ok(())
}

async fn log_in(my_account: &MyAccount<'_>, keycloak_login: &KeycloakLogin<'_>) {
    my_account.click_login().await;
    keycloak_login.wait_for_navigation().await;
    keycloak_login.sign_in(USERNAME, PASSWORD).await;
    my_account.wait_for_navigation().await;
}

/// Open the "My Account" page in a new tab, expect it to be authenticated there, and close the tab
/// again.
async fn expect_authenticated_in_new_tab(my_account: &MyAccount<'_>) {
    let driver = my_account.page.driver();
    let original_window = driver.window().await.expect("Reading the current window");
    let new_tab = driver.new_tab().await.expect("Opening a new tab");
    driver
        .switch_to_window(new_tab)
        .await
        .expect("Switching to the new tab");

    my_account.goto().await;
    my_account.expect_authenticated().await;
    my_account.page.expect_healthy().await;

    driver.close_window().await.expect("Closing the new tab");
    driver
        .switch_to_window(original_window)
        .await
        .expect("Switching back to the original window");
}
