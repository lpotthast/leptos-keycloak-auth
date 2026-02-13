#![allow(clippy::must_use_candidate)]

use std::sync::atomic::{AtomicU32, Ordering};

use leptonic::{atoms::button::LinkTarget, components::prelude::*};
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
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <meta name="keycloak-port" content={keycloak_port}/>
                <link rel="preconnect" href="https://fonts.gstatic.com"/>
                <AutoReload options=options.clone() />
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeycloakPort(u16);

impl KeycloakPort {
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
        provide_context(KeycloakPort(keycloak_port));
    }

    fn get() -> Self {
        expect_context::<KeycloakPort>()
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    KeycloakPort::provide();

    view! {
        <Meta name="charset" content="UTF-8"/>
        <Meta name="description" content="Leptonic SSR template"/>
        <Meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <Meta name="theme-color" content="#8856e6"/>

        <Stylesheet id="leptos" href="/pkg/frontend.css"/>
        <Stylesheet href="https://fonts.googleapis.com/css?family=Roboto&display=swap"/>

        <Title text="Leptonic SSR template"/>

        <Root default_theme=LeptonicTheme::default()>
            <main style=r"
                height: 100%;
                width: 100%;
                display: flex;
                flex-direction: column;
                align-items: center;
                padding: 1em;
                background-color: antiquewhite;
                overflow: auto;
            ">
                <Router>
                    <Init>
                        { routes::generated_routes() }
                    </Init>
                </Router>
            </main>
        </Root>
    }
}

/// These initializations always take place when the app starts.
#[component]
pub fn Init(children: Children) -> impl IntoView {
    // Services
    UserService::provide();

    view! {
        <AuthProvider
            keycloak_server_url=Url::parse(&format!("http://localhost:{}", KeycloakPort::get().0)).expect("valid keycloak server url")
            realm="test-realm"
            client="test-client"
        >
            { children() }

            <WithAuth render=move |auth| view! {
                <Modal show_when=auth.suspicious_logout>
                    <ModalHeader attr:id="suspicious-logout-detected"><ModalTitle>"Suspicious Logout Detected"</ModalTitle></ModalHeader>
                    <ModalBody>"We could not verify that you were logged out by us."</ModalBody>
                    <ModalFooter>
                        <ButtonWrapper>
                            <Button
                                attr:id="dismiss"
                                on_press=move |_| { auth.dismiss_suspicious_logout_warning.run(()); }
                                color=ButtonColor::Primary
                            >
                                "Dismiss"
                            </Button>
                        </ButtonWrapper>
                    </ModalFooter>
                </Modal>
            }/>
        </AuthProvider>
    }
}

#[component]
pub fn MainLayout() -> impl IntoView {
    let keycloak_port = expect_context::<KeycloakPort>();

    view! {
        <h2>"leptos-keycloak-auth - test-frontend"</h2>

        <div>
            "Keycloak port: " <span id="keycloak-port">{ keycloak_port.0 }</span>
        </div>

        <div style="width: 100%; min-height: 1px; background-color:black; margin-top: 1em;"/>

        <Outlet />

        <div style="width: 100%; min-height: 1px; background-color:black; margin-top: 1em;"/>

        <DebugState attr:style="font-size: 0.6em;"/>
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

        <LinkButton attr:id="to-my-account" href=routes::root::MyAccount.materialize()>
            "My Account"
        </LinkButton>
    }
}

/// A component that expects to be rendered only when the user is authenticated.
#[component]
pub fn MyAccount() -> impl IntoView {
    static RENDER_COUNT: AtomicU32 = AtomicU32::new(0);

    RENDER_COUNT.fetch_add(1, Ordering::Release);

    let location = use_location();
    Effect::new(move || {
        if location.pathname.get() != routes::root::MyAccount.materialize() {
            let msg = indoc::formatdoc! {"
                Navigating away from '{path}'. Resetting RENDER_COUNT to 0.
                We dont want to track the number of navigations to the path that renders this component.
                We are only interested in spotting accidental rerenders while staying at the current location.
                ",
                path = routes::root::MyAccount.materialize()
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
    let malicious_logout_url = Signal::derive(move || {
        logout_url.get().map(|real| {
            let mut parsed = real.parse::<Url>().expect("valid url");
            let query_without_csrf_token = parsed
                .query_pairs()
                .filter(|(k, _v)| k != "state")
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<Vec<_>>();
            {
                let mut query_mut = parsed.query_pairs_mut();
                query_mut.clear();
                for (k, v) in query_without_csrf_token {
                    query_mut.append_pair(&k, &v);
                }
            }
            parsed.to_string()
        })
    });

    let user_service = UserService::get();
    let who_am_i = LocalResource::new(move || async move { user_service.who_am_i().await.ok() });
    let who_am_i = Signal::derive(move || who_am_i.get().flatten());

    view! {
        <h1 id="greeting">
            "Hello, " { move || user_name.get() } "!"
        </h1>

        <div id="render-count">
            "render count: " { RENDER_COUNT.load(Ordering::Acquire) }
        </div>

        <Suspense fallback=|| view! { "" }>
            { move || who_am_i.get().map(|who_am_i| view! {
                <div>"username: " <span id="username">{ who_am_i.username.clone() }</span></div>
                <div>"keycloak_uuid: " <span id="keycloak_uuid">{ who_am_i.keycloak_uuid.clone() }</span></div>
                <div>"token_valid_for_whole_seconds: " <span id="token_valid_for_whole_seconds">{ who_am_i.token_valid_for_whole_seconds }</span></div>
            }) }
        </Suspense>

        <LinkButton attr:id="logout" href=move || logout_url.get().unwrap_or_default() disabled=logout_url_unavailable>
            "Logout"
        </LinkButton>

        <Button attr:id="programmatic-logout" on_press=move |_| auth.end_session()>
            "Programmatic Logout"
        </Button>

        <Button attr:id="forget-auth-state" on_press=move |_| auth.forget_session()>
            "Forget auth state"
        </Button>

        <LinkButton attr:id="force-malicious-logout" href=move || malicious_logout_url.get().unwrap_or_default() disabled=logout_url_unavailable>
            "Force malicious logout"
        </LinkButton>

        <LinkButton attr:id="back-to-root" href=routes::Root.materialize() attr:style="margin-top: 3em;">
            "Back to root"
        </LinkButton>
    }
}

#[component]
pub fn Login() -> impl IntoView {
    view! {
        <h1 id="unauthenticated">"Unauthenticated"</h1>

        <LoginButton />

        <LinkButton attr:id="back-to-root" href=routes::Root.materialize() attr:style="margin-top: 3em;">
            "Back to root"
        </LinkButton>
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
        <LinkButton
            href=move || login_url.get()
            target=LinkTarget::_Self
            disabled=login_url_unavailable
        >
            "Log in"
        </LinkButton>
    }
}
