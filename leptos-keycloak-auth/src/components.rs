use crate::config::{AdvancedOptions, IdTokenValidationOptions, UseKeycloakAuthOptions};
use crate::{
    current_url, init_keycloak_auth, try_use_keycloak_auth, use_keycloak_auth, KeycloakAuth,
    KeycloakAuthState,
};
use leptos::either::EitherOf3;
use leptos::prelude::*;
use leptos_router::NavigateOptions;
use url::Url;

/// Initialize Keycloak authentication and provide it to child components.
///
/// This component wraps `init_keycloak_auth` with a cleaner, more declarative API.
/// It provides smart defaults to minimize boilerplate for common configurations.
///
/// By default, users are redirected to the current page after login/logout.
///
/// # Example
/// ```no_run
/// use leptos::prelude::*;
/// use leptos_keycloak_auth::components::AuthProvider;
/// use leptos_router::components::Router;
/// use leptos_keycloak_auth::url::Url;
///
/// # #[component]
/// # fn Example() -> impl IntoView {
/// view! {
///     <Router>
///         <AuthProvider
///             keycloak_server_url=Url::parse("http://localhost:8443").expect("valid keycloak url")
///             realm="my-realm"
///             client="my-client"
///         >
///             <p>"<Routes> and further app content..."</p>
///         </AuthProvider>
///     </Router>
/// }
/// # }
/// ```
#[allow(clippy::must_use_candidate)]
#[component]
pub fn AuthProvider(
    /// URL of your Keycloak instance (e.g., "http://localhost:8443").
    #[prop(into)]
    keycloak_server_url: Url,

    /// The Keycloak realm to use.
    #[prop(into)]
    realm: String,

    /// The client ID configured in Keycloak.
    #[prop(into)]
    client: String,

    /// Default post-login redirect behavior.
    /// Defaults to reactive tracking of the current page.
    #[prop(into, optional)]
    post_login_redirect_url: Option<Signal<Url>>,

    /// Default post-logout redirect behavior.
    /// Defaults to reactive tracking of the current page.
    #[prop(into, optional)]
    post_logout_redirect_url: Option<Signal<Url>>,

    /// Additional OAuth scopes (openid is always included).
    #[prop(default = vec![])]
    scope: Vec<String>,

    /// Expected audiences for ID token validation (defaults to `["<client_id>"]`).
    #[prop(optional)]
    expected_audiences: Option<Vec<String>>,

    /// Expected issuers for ID token validation (defaults to `["<server>/realms/<realm>"]`).
    #[prop(optional)]
    expected_issuers: Option<Vec<String>>,

    /// Advanced configuration options.
    #[prop(optional)]
    advanced: Option<AdvancedOptions>,

    children: Children,
) -> impl IntoView {
    // Resolve initial redirect URLs based on default behavior
    let post_login_redirect_url =
        post_login_redirect_url.unwrap_or_else(|| Signal::derive(current_url));
    let post_logout_redirect_url =
        post_logout_redirect_url.unwrap_or_else(|| Signal::derive(current_url));

    // Default expected_audiences to [client_id]
    let expected_audiences = expected_audiences.unwrap_or_else(|| vec![client.clone()]);

    // Auto-generate expected_issuers from server + realm
    let expected_issuers = expected_issuers.unwrap_or_else(|| {
        vec![format!(
            "{}/realms/{}",
            keycloak_server_url.as_str().trim_end_matches('/'),
            realm
        )]
    });

    // Initialize auth.
    let _auth = init_keycloak_auth(UseKeycloakAuthOptions {
        keycloak_server_url,
        realm,
        client_id: client,
        post_login_redirect_url,
        post_logout_redirect_url,
        scope,
        id_token_validation: IdTokenValidationOptions {
            expected_audiences: Some(expected_audiences),
            expected_issuers: Some(expected_issuers),
        },
        advanced: advanced.unwrap_or_default(),
    });

    view! {
        { children() }
    }
}

/// Small convenience component that calls [`use_keycloak_auth`](use_keycloak_auth) for you
/// and provides the state to the callback.
///
/// # Example
/// ```no_run
/// use leptos::prelude::*;
/// use leptos_keycloak_auth::components::AuthProvider;
/// use leptos_keycloak_auth::components::WithAuth;
/// use leptos_keycloak_auth::url::Url;
///
/// #[component]
/// fn Init(children: Children) -> impl IntoView {
///     view! {
///         <AuthProvider
///             keycloak_server_url=Url::parse("...").unwrap()
///             realm="my-realm"
///             client="my-client"
///         >
///             { children() }
///     
///             <WithAuth render=|auth| view! {
///                 // <Modal show_when=auth.suspicious_logout>
///                 //     <ModalHeader attr:id="suspicious-logout-detected"><ModalTitle>"Suspicious Logout Detected"</ModalTitle></ModalHeader>
///                 //     <ModalBody>"We could not verify that you were logged out by us."</ModalBody>
///                 //     <ModalFooter>
///                 //         <ButtonWrapper>
///                 //             <Button
///                 //                 attr:id="dismiss"
///                 //                 on_press=move |_| { auth.dismiss_suspicious_logout_warning.run(()); }
///                 //                 color=ButtonColor::Primary
///                 //             >
///                 //                 "Dismiss"
///                 //             </Button>
///                 //         </ButtonWrapper>
///                 //     </ModalFooter>
///                 // </Modal>
///             }/>
///         </AuthProvider>
///     }
/// }
/// ```
#[component]
pub fn WithAuth<R, IV>(render: R) -> impl IntoView
where
    R: FnOnce(KeycloakAuth) -> IV + 'static,
    IV: IntoView,
{
    let auth = use_keycloak_auth();
    render(auth)
}

/// Show `children` only when the user is authenticated, providing direct access to the
/// `Authenticated` state, eliminating the need to call `use_authenticated()` explicitly.
///
/// If you also want to render an alternative in case the user is not authenticated, consider using
/// [`MaybeAuthenticated`] instead.
///
/// The children function is only evaluated once when the authentication status switches to being
/// [`Authenticated`](crate::state::Authenticated). No internal state change, like an automated
/// token refresh will lead to children re-rendering. Once the authentication status is no longer
/// `Authenticated`, the children view is dropped and not hold onto for further display. Once
/// authenticated again, children are rendered new.
///
/// # Example
/// ```no_run
/// use leptos::prelude::*;
/// use leptos_keycloak_auth::components::Authenticated;
///
/// # #[component]
/// # fn Component() -> impl IntoView {
/// view! {
///     <Authenticated children=move |auth| view! {
///         <p>"Welcome, " { auth.id_token_claims.read().name.clone() }</p>
///         <p>"Your secure content here"</p>
///     }/>
/// }
/// # }
/// ```
#[component(transparent)]
#[allow(clippy::must_use_candidate)]
pub fn Authenticated<C, V>(children: C) -> impl IntoView
where
    C: Fn(crate::Authenticated) -> V + 'static + Send,
    V: IntoView + 'static,
{
    let auth = use_keycloak_auth();
    let state = auth.state();

    move || match state.get() {
        KeycloakAuthState::Authenticated(authenticated_ctx) => {
            provide_context(authenticated_ctx);
            Some(children(authenticated_ctx))
        }
        KeycloakAuthState::NotAuthenticated(_) | KeycloakAuthState::Indeterminate => {
            let _ = take_context::<crate::Authenticated>();
            None
        }
    }
}

/// Show children only when user is NOT authenticated.
///
/// Useful for login pages, signup forms, or content that should only be visible to
/// unauthenticated users.
///
/// The [`MaybeAuthenticated`](MaybeAuthenticated) component might be generally more useful.
///
/// # Example
/// ```no_run
/// use leptos::prelude::*;
/// use leptos_keycloak_auth::components::Unauthenticated;
///
/// # #[component]
/// # fn Component() -> impl IntoView {
/// view! {
///     <Unauthenticated children=|_| view! {
///         <h1>"Please log in"</h1>
///         <p>"You must be logged in to access this application."</p>
///     }/>
/// }
/// # }
/// ```
#[component(transparent)]
#[allow(clippy::must_use_candidate)]
pub fn Unauthenticated<C, V>(children: C) -> impl IntoView
where
    C: Fn(crate::NotAuthenticated) -> V + 'static + Send,
    V: IntoView + 'static,
{
    let auth = use_keycloak_auth();
    let state = auth.state();

    move || match state.get() {
        KeycloakAuthState::NotAuthenticated(not_authenticated_ctx) => {
            provide_context(not_authenticated_ctx);
            Some(children(not_authenticated_ctx))
        }
        KeycloakAuthState::Authenticated(_) | KeycloakAuthState::Indeterminate => None,
    }
}

/// Render different content based on authentication status.
///
/// Perfect for public pages that want to show different content to authenticated vs.
/// unauthenticated users (e.g., navigation bars, landing pages).
///
/// # Example
/// ```no_run
/// use leptos::prelude::*;
/// use leptos_keycloak_auth::components::MaybeAuthenticated;
///
/// # #[component]
/// # fn Component() -> impl IntoView {
/// view! {
///     <MaybeAuthenticated
///         authenticated=|auth| view! {
///             <p>"Welcome back, " { auth.id_token_claims.read().name.clone() }</p>
///             <a href="/account">"My Account"</a>
///         }
///         unauthenticated=|_| view! {
///             <p>"Welcome, guest!"</p>
///             <a href="/login">"Log In"</a>
///         }
///     />
/// }
/// # }
/// ```
#[component(transparent)]
#[allow(clippy::must_use_candidate)]
pub fn MaybeAuthenticated<FA, FU, VA, VU>(
    /// View provider for when the user is authenticated.
    authenticated: FA,

    /// View provider for when the user is not authenticated.
    unauthenticated: FU,

    /// Optional view to show during indeterminate state (defaults to empty).
    #[prop(into, optional)]
    fallback: Option<ViewFn>,
) -> impl IntoView
where
    FA: Fn(crate::Authenticated) -> VA + 'static + Send,
    FU: Fn(crate::NotAuthenticated) -> VU + 'static + Send,
    VA: IntoView + 'static,
    VU: IntoView + 'static,
{
    let auth = use_keycloak_auth();
    let state = auth.state();

    move || match state.get() {
        KeycloakAuthState::Authenticated(authenticated_ctx) => {
            let _ = take_context::<crate::NotAuthenticated>();
            provide_context(authenticated_ctx);
            EitherOf3::<AnyView, AnyView, AnyView>::A(authenticated(authenticated_ctx).into_any())
        }
        KeycloakAuthState::NotAuthenticated(not_authenticated_ctx) => {
            let _ = take_context::<crate::Authenticated>();
            provide_context(not_authenticated_ctx);
            EitherOf3::<AnyView, AnyView, AnyView>::B(
                unauthenticated(not_authenticated_ctx).into_any(),
            )
        }
        KeycloakAuthState::Indeterminate => {
            let _ = take_context::<crate::Authenticated>();
            EitherOf3::<AnyView, AnyView, AnyView>::C(match &fallback {
                Some(f) => f.run(),
                None => ().into_any(),
            })
        }
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
#[allow(clippy::must_use_candidate)]
pub fn EndSession(#[prop(into, optional)] and_route_to: Option<Url>) -> impl IntoView {
    let auth = try_use_keycloak_auth();
    // The session MUST only be ended on the client, not on the server.
    Effect::new(move |_| {
        match auth {
            Some(auth) => {
                tracing::trace!("Logging out...");
                match and_route_to.clone() {
                    None => auth.end_session(),
                    Some(path) => auth.end_session_and_go_to(path),
                }
            }
            None => {
                tracing::trace!("No session. Only redirecting...");
                let navigate = leptos_router::hooks::use_navigate();
                match and_route_to.clone() {
                    None => {}
                    Some(path) => {
                        // We do not give the user the ability to provide these navigation options,
                        // as we cannot guarantee the same behavior in both code paths.
                        navigate(path.as_str(), NavigateOptions::default());
                    }
                }
            }
        }
    });
}

/// Debug component showing internal authentication state.
///
/// This component is only available with the `internals` feature and only renders on the client
/// to avoid hydration mismatches.
#[cfg(feature = "internals")]
#[component]
pub fn DebugState() -> impl IntoView {
    view! {
        <div style="width: 100%; overflow: auto;">
            <MaybeAuthenticated
                authenticated=move |_| view! { <DebugStateInner/> }
                unauthenticated=move |_| view! { <DebugStateInner/> }
            />
        </div>
    }
}

#[cfg(feature = "internals")]
#[component]
fn DebugStateInner() -> impl IntoView {
    let auth = use_keycloak_auth();
    let auth_state = Signal::derive(move || auth.state_pretty_printer());
    view! {
        <div style="width: 100%;">
            <h3>"Internal data: state"</h3>
            <pre id="auth-state">
                { move || auth_state.read()() }
            </pre>
        </div>

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
            <h3>"Internal data: nonce_manager"</h3>
            <div>
                "nonce: " {move || format!("{:?}", auth.nonce_manager().nonce().get())}
            </div>
        </div>

        <div style="width: 100%;">
            <h3>"Internal data: token_manager"</h3>
            <div>
                "token_data: " {move || format!("{:#?}", auth.token_manager().token.get())}
            </div>
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
