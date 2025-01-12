use leptonic::atoms::button::LinkTarget;
use leptonic::components::prelude::*;
use leptos::prelude::*;
use leptos_keycloak_auth::{
    use_keycloak_auth, Authenticated, KeycloakAuth, Url, UseKeycloakAuthOptions,
};
use leptos_meta::{provide_meta_context, Meta, MetaTags, Stylesheet, Title};
use leptos_router::components::*;
use leptos_routes::routes;

#[routes]
pub mod routes {
    #[route("/")]
    pub mod root {}

    #[route("/my-account")]
    pub mod my_account {}
}

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
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

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Meta name="charset" content="UTF-8"/>
        <Meta name="description" content="Leptonic SSR template"/>
        <Meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <Meta name="theme-color" content="#8856e6"/>

        <Stylesheet id="leptos" href="/pkg/frontend.css"/>
        <Stylesheet href="https://fonts.googleapis.com/css?family=Roboto&display=swap"/>

        <Title text="Leptonic SSR template"/>

        <Root default_theme=LeptonicTheme::default()>
            <main style=r#"
                height: 100%;
                width: 100%;
                display: flex;
                flex-direction: column;
                align-items: center;
                padding: 1em;
                background-color: antiquewhite;
            "#>
                <Router>
                    <Routes fallback=|| view! { "Page not found." }>
                        <Route path=routes::Root.path() view=Welcome/>
                        <Route path=routes::MyAccount.path() view=|| view! { <Protected> <MyAccount/> </Protected> }/>
                    </Routes>
                </Router>
            </main>
        </Root>
    }
}

#[server]
async fn get_keycloak_port() -> Result<u16, ServerFnError> {
    let _ = dotenvy::dotenv().ok();
    let port = std::env::var("KEYCLOAK_PORT").expect("KEYCLOAK_PORT must be set");
    let keycloak_port = port.parse::<u16>().expect("KEYCLOAK_PORT to be a u16");
    tracing::info!(keycloak_port, "parsed KEYCLOAK_PORT");
    Ok(keycloak_port)
}

#[component]
pub fn Protected(children: ChildrenFn) -> impl IntoView {
    // Our test-setup starts Keycloak with randomized ports, so we cannot hardcode "8443" here!
    let keycloak_port =
        LocalResource::new(|| async move { get_keycloak_port().await.unwrap_or(8443) });

    view! {
        <Suspense fallback=|| view! { "loading..." }>
            {Suspend::new(async move {
                let p = keycloak_port.await;
                let _ = use_keycloak_auth(UseKeycloakAuthOptions {
                    keycloak_server_url: Url::parse(&format!("http://localhost:{}/", p)).unwrap(),
                    realm: "test-realm".to_owned(),
                    client_id: "test-client".to_owned(),
                    post_login_redirect_url: Url::parse("http://127.0.0.1:3000/my-account").unwrap(),
                    post_logout_redirect_url: Url::parse("http://127.0.0.1:3000/my-account").unwrap(),
                    scope: Some("openid".to_string()),
                    advanced: Default::default(),
                });
                view! {
                    <Authenticated unauthenticated=|| view! { <Login/> }>
                        { children() }
                    </Authenticated>
                }
            })}
        </Suspense>
    }
}

#[component]
pub fn Login() -> impl IntoView {
    let auth = expect_context::<KeycloakAuth>();
    let login_url_unavailable = Signal::derive(move || auth.login_url.get().is_none());
    let login_url = Signal::derive(move || {
        auth.login_url
            .get()
            .map(|url| url.to_string())
            .unwrap_or_default()
    });
    let auth_state = Signal::derive(move || format!("{:#?}", auth.auth_state.get()));

    view! {
       <h1>"Unauthenticated 1"</h1>

        <div>
            "Auth State:"
            { move || auth_state.get() }
        </div>

        <LinkButton
            href=move || login_url.get()
            target=LinkTarget::_Self
            disabled=login_url_unavailable
        >
            "Log in"
        </LinkButton>
    }
}

#[component]
pub fn MyAccount() -> impl IntoView {
    let auth = expect_context::<KeycloakAuth>();

    let user_name = Signal::derive(move || {
        auth.id_token_claims
            .get()
            .map(|claims| claims.name.clone())
            .unwrap_or_default()
    });
    let logout_url = Signal::derive(move || auth.logout_url.get().map(|url| url.to_string()));
    let logout_url_unavailable = Signal::derive(move || logout_url.get().is_none());

    view! {
        <h1>
            "Hello, " {move || user_name.get()}
        </h1>

        <LinkButton attr:id="logout" href=move || logout_url.get().unwrap_or_default() disabled=logout_url_unavailable>
            "Logout"
        </LinkButton>

        <LinkButton attr:id="back-to-root" href=routes::Root.materialize() attr:style="margin-top: 3em;">
            "Back to root"
        </LinkButton>
    }
}

#[component]
pub fn Welcome() -> impl IntoView {
    let (count, set_count) = signal(0);

    view! {
        <h2>"Welcome to Leptonic"</h2>

        <LinkButton attr:id="to-my-account" href=routes::MyAccount.materialize()>
            "My Account"
        </LinkButton>

        <span id="count" style="margin-top: 3em;">
            "Count: " { move || count.get() }
        </span>

        <Button attr:id="increase" on_press=move|_| set_count.update(|c| *c += 1)>
            "Increase"
        </Button>
    }
}
