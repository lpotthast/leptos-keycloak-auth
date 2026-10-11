#![allow(clippy::must_use_candidate)]

use std::sync::atomic::{AtomicU32, Ordering};

use leptonic::{
    CapturedElement, IntoAttrs,
    atoms::{
        button::Button,
        dialog::{Dialog, DialogDescription, DialogTitle},
        link::Link,
        modal::{ModalBackdrop, ModalContent},
        separator::Separator,
    },
    hooks::landmark::{LandmarkRole, UseLandmarkInput, UseLandmarkReturn, use_landmark},
};
use leptos::prelude::*;
use leptos_keycloak_auth::{
    components::{AuthProvider, DebugState, MaybeAuthenticated, WithAuth},
    url::Url,
    use_authenticated, use_keycloak_auth,
};
use leptos_meta::{Meta, MetaTags, Stylesheet, Title, provide_meta_context};
use leptos_router::{
    components::{Outlet, Router},
    hooks::use_location,
};

use crate::{routes::routes, services::user_service::UserService};

#[must_use]
pub fn shell(options: LeptosOptions, keycloak_port: u16) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <meta name="keycloak-port" content=keycloak_port />
                // What the page reports, read by the browser tests' health checks (each list
                // separately): Rust panics (the panic hook logs them with `console.error` before
                // the wasm traps), uncaught errors and unhandled rejections, every other
                // `console.error`, and `console.warn`.
                <script>
                    "window.__panics = [];
                    window.__uncaughtErrors = [];
                    window.__consoleErrors = [];
                    window.__consoleWarnings = [];
                    window.addEventListener('error', e => window.__uncaughtErrors.push(String(e.message)));
                    window.addEventListener('unhandledrejection', e => window.__uncaughtErrors.push(String(e.reason)));
                    const consoleError = console.error.bind(console);
                    console.error = (...args) => {
                        const message = args.map(String).join(' ');
                        if (message.includes('panicked at')) {
                            window.__panics.push(message);
                        } else {
                            window.__consoleErrors.push(message);
                        }
                        consoleError(...args);
                    };
                    const consoleWarn = console.warn.bind(console);
                    console.warn = (...args) => {
                        window.__consoleWarnings.push(args.map(String).join(' '));
                        consoleWarn(...args);
                    };"
                </script>
                <AutoReload options=options.clone() />
                <HydrationScripts options />
                <MetaTags />
            </head>
            <body>
                <App />
            </body>
        </html>
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KeycloakServerUrl(Url);

impl KeycloakServerUrl {
    fn provide() {
        #[cfg(feature = "ssr")]
        let keycloak_port = {
            dotenvy::dotenv().unwrap();
            let keycloak_port = std::env::var("KC_PORT")
                .expect("KC_PORT must be set")
                .parse::<u16>()
                .expect("KC_PORT to be a u16");
            tracing::info!(keycloak_port, "parsed KC_PORT");
            keycloak_port
        };
        #[cfg(not(feature = "ssr"))]
        let keycloak_port = {
            leptos_use::use_document()
                .as_ref()
                .unwrap()
                .query_selector("meta[name='keycloak-port']")
                .ok()
                .flatten()
                .and_then(|element| {
                    use wasm_bindgen::JsCast;
                    element.dyn_into::<leptos::web_sys::HtmlMetaElement>().ok()
                })
                .map(|meta| meta.content())
                .unwrap_or_default()
                .parse::<u16>()
                .expect("keycloak-port should be a valid number")
        };
        let keycloak_server_url = Url::parse(&format!("http://localhost:{keycloak_port}"))
            .expect("valid keycloak server url");
        provide_context(KeycloakServerUrl(keycloak_server_url));
    }

    fn get() -> Self {
        expect_context::<KeycloakServerUrl>()
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    KeycloakServerUrl::provide();

    view! {
        <Meta name="description" content="leptos-keycloak-auth test-frontend" />

        <Stylesheet id="leptos" href="/pkg/frontend.css" />

        <Title text="leptos-keycloak-auth test-frontend" />

        <Router>
            <Init>{routes::route_tree()}</Init>
        </Router>
    }
}

/// These initializations always take place when the app starts.
#[component]
pub fn Init(children: Children) -> impl IntoView {
    // Services
    UserService::provide();

    view! {
        <AuthProvider
            keycloak_server_url=KeycloakServerUrl::get().0
            realm="test-realm"
            client="test-client"
        >
            {children()}

            <WithAuth render=move |auth| {
                view! {
                    <ModalBackdrop
                        is_open=auth.suspicious_logout
                        set_open=move |open: bool| {
                            if !open {
                                auth.dismiss_suspicious_logout_warning.run(());
                            }
                        }
                    >
                        <ModalContent>
                            <Dialog>
                                <DialogTitle attr:id="suspicious-logout-detected">
                                    "Suspicious Logout Detected"
                                </DialogTitle>
                                <DialogDescription>
                                    "We could not verify that you were logged out by us."
                                </DialogDescription>
                                <div class="actions">
                                    <Button
                                        id="dismiss"
                                        on_press=move |_| {
                                            auth.dismiss_suspicious_logout_warning.run(());
                                        }
                                        attr:data-variant="primary"
                                    >
                                        "Dismiss"
                                    </Button>
                                </div>
                            </Dialog>
                        </ModalContent>
                    </ModalBackdrop>
                }
            } />
        </AuthProvider>
    }
}

/// A landmark of `role`, named `label`, around `children`. F6 and Shift+F6 move the focus
/// between landmarks.
#[component]
fn Landmark(
    role: LandmarkRole,
    #[prop(into)] label: String,
    #[prop(into, optional)] class: String,
    children: Children,
) -> impl IntoView {
    let element = CapturedElement::new();
    let UseLandmarkReturn { props } = use_landmark(UseLandmarkInput {
        element,
        role,
        aria_label: Some(label).into(),
        aria_labelledby: None,
        focus: None,
    });
    view! {
        <div {..props.into_attrs()} {..element.attr()} class=class>
            {children()}
        </div>
    }
}

#[component]
pub fn MainLayout() -> impl IntoView {
    let keycloak_server_url = KeycloakServerUrl::get().0;

    view! {
        <div class="page">
            <Landmark role=LandmarkRole::Banner label="Header">
                <h2>"leptos-keycloak-auth - test-frontend"</h2>
                <div class="muted">
                    "Keycloak: "
                    <span id="keycloak-server-url">{keycloak_server_url.to_string()}</span>
                </div>
            </Landmark>

            <Separator />

            <Landmark role=LandmarkRole::Main label="Content" class="content">
                <Outlet />
            </Landmark>

            <Separator />

            <Landmark role=LandmarkRole::Region label="Debug state" class="debug-state">
                <DebugState />
            </Landmark>
        </div>
    }
}

#[component]
pub fn Home() -> impl IntoView {
    view! {
        <h2>"Home"</h2>

        <p id="auth-state">
            <MaybeAuthenticated
                authenticated=move |_| view! { "You are logged in!" }
                unauthenticated=move |_| view! { "You are not logged in." }
                fallback=move || view! { "Auth state is undetermined." }
            />
        </p>

        <div class="actions">
            <Link href=routes::MyAccount.materialize() attr:id="to-my-account" classes="button">
                "My Account"
            </Link>
        </div>
    }
}

/// A component that expects to be rendered only when the user is authenticated.
#[component]
pub fn MyAccountPage() -> impl IntoView {
    static RENDER_COUNT: AtomicU32 = AtomicU32::new(0);

    RENDER_COUNT.fetch_add(1, Ordering::Release);

    let location = use_location();
    Effect::new(move || {
        if location.pathname.get() != routes::MyAccount.materialize() {
            let msg = indoc::formatdoc! {"
                Navigating away from '{path}'. Resetting RENDER_COUNT to 0.
                We dont want to track the number of navigations to the path that renders this component.
                We are only interested in spotting accidental rerenders while staying at the current location.
                ",
                path = routes::MyAccount.materialize()
            };
            tracing::info!("{msg}");
        }
        RENDER_COUNT.store(0, Ordering::Release);
    });

    let auth = use_keycloak_auth();
    let authenticated = use_authenticated();

    let user_name = Signal::derive(move || authenticated.id_token_claims.read().name.clone());
    let logout_url = Signal::derive(move || auth.logout_url.get().map(|url| url.to_string()));
    let logout_url_unavailable = Signal::derive(move || logout_url.get().is_none());
    // The logout URL without its `state` parameter, the CSRF token proving that we started the
    // logout.
    let malicious_logout_url = Signal::derive(move || {
        auth.logout_url.get().map(|mut url| {
            let query_without_csrf_token = url
                .query_pairs()
                .filter(|(key, _value)| key != "state")
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<Vec<_>>();
            url.query_pairs_mut()
                .clear()
                .extend_pairs(query_without_csrf_token);
            url.to_string()
        })
    });

    let user_service = UserService::get();
    let who_am_i = LocalResource::new(move || async move { user_service.who_am_i().await.ok() });
    let who_am_i = Signal::derive(move || who_am_i.get().flatten());

    view! {
        <h1 id="greeting">"Hello, " {move || user_name.get()} "!"</h1>

        <div id="render-count">"render count: " {RENDER_COUNT.load(Ordering::Acquire)}</div>

        <Suspense fallback=|| {
            view! { "" }
        }>
            {move || {
                who_am_i
                    .get()
                    .map(|who_am_i| {
                        view! {
                            <div>
                                "username: " <span id="username">{who_am_i.username.clone()}</span>
                            </div>
                            <div>
                                "keycloak_uuid: "
                                <span id="keycloak_uuid">{who_am_i.keycloak_uuid.clone()}</span>
                            </div>
                            <div>
                                "token_valid_for_whole_seconds: "
                                <span id="token_valid_for_whole_seconds">
                                    {who_am_i.token_valid_for_whole_seconds}
                                </span>
                            </div>
                        }
                    })
            }}
        </Suspense>

        <div class="actions">
            <Link
                href=move || logout_url.get().unwrap_or_default()
                is_disabled=logout_url_unavailable
                attr:id="logout"
                classes="button"
            >
                "Logout"
            </Link>

            <Button id="programmatic-logout" on_press=move |_| auth.end_session()>
                "Programmatic Logout"
            </Button>

            <Button id="forget-auth-state" on_press=move |_| auth.forget_session()>
                "Forget auth state"
            </Button>

            <Link
                href=move || malicious_logout_url.get().unwrap_or_default()
                is_disabled=logout_url_unavailable
                attr:id="force-malicious-logout"
                classes="button"
                attr:data-variant="danger"
            >
                "Force malicious logout"
            </Link>
        </div>

        <BackToRoot />
    }
}

/// A link back to the root page.
#[component]
fn BackToRoot() -> impl IntoView {
    view! {
        <div class="actions back-to-root">
            <Link href=routes::Root.materialize() attr:id="back-to-root" classes="button">
                "Back to root"
            </Link>
        </div>
    }
}

#[component]
pub fn Login() -> impl IntoView {
    view! {
        <h1 id="unauthenticated">"Unauthenticated"</h1>

        <div class="actions">
            <LoginButton />
        </div>

        <BackToRoot />
    }
}

/// A button to start the login flow, bringing the user to Keycloak login page.
/// Once credentials were entered, a redirect to the current url will be performed.
#[component]
pub fn LoginButton() -> impl IntoView {
    let auth = use_keycloak_auth();
    let login_url_unavailable = Signal::derive(move || auth.login_url.read().is_none());
    let login_url = Signal::derive(move || {
        auth.login_url
            .get()
            .map(|url| url.to_string())
            .unwrap_or_default()
    });

    view! {
        <Link
            href=move || login_url.get()
            is_disabled=login_url_unavailable
            classes="button"
            attr:data-variant="primary"
        >
            "Log in"
        </Link>
    }
}
