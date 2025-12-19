use crate::{expect_keycloak_auth, KeycloakAuth, KeycloakAuthState};
use leptos::either::EitherOf3;
use leptos::prelude::*;
use leptos_router::NavigateOptions;
use url::Url;

/// Show `children` when the user is [`Authenticated`](crate::state::Authenticated).
///
/// If the user is authenticated, it renders the children; otherwise, it falls back to the provided
/// `fallback` view.
///
/// The children function is only evaluated once when the authentication status switches to being
/// [`Authenticated`](crate::state::Authenticated). No internal state change, like an automated
/// token refresh should lead to children being re-rendered.
///
/// Once the authentication status is no longer `Authenticated`, the children view is dropped and
/// not hold onto for further display. Once authenticated again, children are rendered new.
///
/// # Example
/// ```no_run
/// use leptos::prelude::*;
/// use leptos_keycloak_auth::components::ShowWhenAuthenticated;
/// use leptos_keycloak_auth::expect_keycloak_auth;
///
/// # #[component]
/// # fn Component() -> impl IntoView {
/// // Requires an `init_keycloak_auth` to have taken place before.
/// let auth = expect_keycloak_auth();
///
/// let login_url = auth.login_url;
/// let logout_url = auth.logout_url;
///
/// view! {
///     <ShowWhenAuthenticated fallback=move || view! { <a href=login_url.get().map(|url| url.to_string()).unwrap_or_default()>"Login"</a> }>
///         <p>"You are authenticated!"</p>
///         <a href=logout_url.get().map(|url| url.to_string()).unwrap_or_default()>"Logout"</a>
///     </ShowWhenAuthenticated>
/// }
/// # }
/// ```
#[component(transparent)]
#[allow(clippy::must_use_candidate)]
pub fn ShowWhenAuthenticated<C>(
    #[prop(into, optional)] fallback: ViewFn,

    children: TypedChildrenFn<C>,
) -> impl IntoView
where
    C: IntoView + 'static,
{
    let auth = expect_keycloak_auth();

    let children = children.into_inner();

    move || match auth.state.get() {
        KeycloakAuthState::Authenticated(authenticated) => {
            provide_context(authenticated);
            EitherOf3::A(children())
        }
        KeycloakAuthState::NotAuthenticated(_not_authenticated) => {
            let _ = take_context::<crate::Authenticated>();
            EitherOf3::B(fallback.run())
        }
        KeycloakAuthState::Indeterminate => EitherOf3::C(()),
    }
}

/// Immediately programmatically logs out the user when rendered.
///
/// You may use this in your router and render it as the only component when the user hits
/// the "/logout" path locally.
///
/// # Params
/// - `and_route_to` Path to which the Leptos router should navigate to after logout happened. The
///   redirect to this path is performed by Keycloak as a response to our programmatic logout
///   request. Should the user not currently be authenticated, we do not interact with Keycloak at
///   all but instead perform the redirect immediately locally using the Leptos router.
#[component]
pub fn EndSession(#[prop(into, optional)] and_route_to: Option<Url>) -> impl IntoView {
    match use_context::<KeycloakAuth>() {
        Some(auth) => {
            tracing::trace!("Logging out...");
            match and_route_to {
                None => auth.end_session(),
                Some(path) => auth.end_session_and_go_to(path),
            }
        }
        None => {
            tracing::trace!("No session. Only redirecting...");
            let navigate = leptos_router::hooks::use_navigate();
            match and_route_to {
                None => {}
                Some(path) => {
                    // We do not give the user the ability to provide these navigation options,
                    // as we cannot guarantee the same behavior in both code paths.
                    navigate(path.as_str(), NavigateOptions::default());
                }
            }
        }
    }
}

#[cfg(feature = "internals")]
#[component]
pub fn DebugState() -> impl IntoView {
    let auth = expect_keycloak_auth();

    view! {
        <div style="width: 100%;">
            <h3>"Internal data: derived_urls"</h3>
            <div>
                "jwks_endpoint: " {move || format!("{:?}", auth.derived_urls().jwks_endpoint.get().map(|url| url.to_string()).map_err(|err| err.to_string()))}
            </div>
            <div>
                "authorization_endpoint: " {move || format!("{:?}", auth.derived_urls().authorization_endpoint.get().map(|url| url.to_string()).map_err(|err| err.to_string()))}
            </div>
            <div>
                "token_endpoint: " {move || format!("{:?}", auth.derived_urls().token_endpoint.get().map(|url| url.to_string()).map_err(|err| err.to_string()))}
            </div>
            <div>
                "end_session_endpoint: " {move || format!("{:?}", auth.derived_urls().end_session_endpoint.get().map(|url| url.to_string()).map_err(|err| err.to_string()))}
            </div>
        </div>

        <div style="width: 100%;">
            <h3>"Internal data: oidc_config_manager"</h3>
            <div>
                "oidc_config_age: " {move || format!("{:?}", auth.oidc_config_manager().oidc_config_age.get())}
            </div>
            <div>
                "oidc_config_expires_in: " {move || format!("{:?}", auth.oidc_config_manager().oidc_config_expires_in.get())}
            </div>
            <div>
                "oidc_config_too_old: " {move || format!("{:?}", auth.oidc_config_manager().oidc_config_too_old.get())}
            </div>
        </div>

        <div style="width: 100%;">
            <h3>"Internal data: jwk_set_manager"</h3>
            <div>
                "jwk_set_age: " {move || format!("{:?}", auth.jwk_set_manager().jwk_set_age.get())}
            </div>
            <div>
                "jwk_set_expires_in: " {move || format!("{:?}", auth.jwk_set_manager().jwk_set_expires_in.get())}
            </div>
            <div>
                "jwk_set_too_old: " {move || format!("{:?}", auth.jwk_set_manager().jwk_set_too_old.get())}
            </div>
        </div>

        <div style="width: 100%;">
            <h3>"Internal data: code_verifier_manager"</h3>
            <div>
                "code_verifier: " {move || format!("{:?}", auth.code_verifier_manager().code_verifier.get())}
            </div>
            <div>
                "code_challenge: " {move || format!("{:?}", auth.code_verifier_manager().code_challenge.get())}
            </div>
        </div>

        <div style="width: 100%;">
            <h3>"Internal data: csrf_token_manager"</h3>
            <div>
                "logout_token: " {move || format!("{:?}", auth.csrf_token_manager().logout_token().get())}
            </div>
        </div>

        <div style="width: 100%;">
            <h3>"Internal data: token_manager"</h3>
            <div>
                "access_token_lifetime: " {move || format!("{:?}", auth.token_manager().access_token_lifetime.get())}
            </div>
            <div>
                "access_token_expires_in: " {move || format!("{:?}", auth.token_manager().access_token_expires_in.get())}
            </div>
            <div>
                "access_token_nearly_expired: " {move || format!("{:?}", auth.token_manager().access_token_nearly_expired.get())}
            </div>
            <div>
                "access_token_expired: " {move || format!("{:?}", auth.token_manager().access_token_expired.get())}
            </div>
            <div>
                "refresh_token_lifetime: " {move || format!("{:?}", auth.token_manager().refresh_token_lifetime.get())}
            </div>
            <div>
                "refresh_token_expires_in: " {move || format!("{:?}", auth.token_manager().refresh_token_expires_in.get())}
            </div>
            <div>
                "refresh_token_nearly_expired: " {move || format!("{:?}", auth.token_manager().refresh_token_nearly_expired.get())}
            </div>
            <div>
                "refresh_token_expired: " {move || format!("{:?}", auth.token_manager().refresh_token_expired.get())}
            </div>
            <div>
                "token_endpoint: " {move || format!("{:?}", auth.token_manager().token_endpoint.get())}
            </div>
        </div>
    }
}
