use leptonic::atoms::button::LinkTarget;
use leptonic::components::prelude::*;
use leptos::prelude::*;
use leptos_keycloak_auth::components::ShowWhenAuthenticated;
use leptos_keycloak_auth::url::Url;
use leptos_keycloak_auth::{to_current_url, use_keycloak_auth, Authenticated, KeycloakAuth, UseKeycloakAuthOptions, ValidationOptions};
use leptos_meta::{provide_meta_context, Meta, MetaTags, Stylesheet, Title};
use leptos_router::components::*;
use leptos_routes::routes;

#[routes]
pub mod routes {
    #[route("/")]
    pub mod root {}

    #[route("/public")]
    pub mod public {}

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
                        <Route path=routes::Public.path() view=Public/>
                        <Route path=routes::MyAccount.path() view=|| view! { <Protected> <MyAccount/> </Protected> }/>
                    </Routes>
                </Router>
            </main>
        </Root>
    }
}

#[component]
pub fn Welcome() -> impl IntoView {
    let (count, set_count) = signal(0);

    view! {
        <h2>"Welcome to Leptonic"</h2>

        <LinkButton attr:id="to-public" href=routes::Public.materialize().strip_prefix("/").unwrap().to_string()>
            "Public2"
        </LinkButton>

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

#[component]
pub fn Public() -> impl IntoView {
    view! {
        <h2>"Welcome to Leptonic"</h2>

        <LinkButton attr:id="to-my-account" href=routes::Root.materialize()>
            "Back"
        </LinkButton>
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct WhoAmIResponse {
    username: String,
    keycloak_uuid: String,
    token_valid_for_whole_seconds: i32,
}

#[component]
pub fn MyAccount() -> impl IntoView {
    let auth = expect_context::<KeycloakAuth>();

    let auth_state = auth.state_pretty_printer();

    let authenticated = expect_context::<Authenticated>();

    let user_name = Signal::derive(move || authenticated.id_token_claims.read().name.clone());
    let logout_url = Signal::derive(move || auth.logout_url.get().map(|url| url.to_string()));
    let logout_url_unavailable = Signal::derive(move || logout_url.get().is_none());

    let who_am_i = LocalResource::new(move || {
        let client = authenticated.client();
        async move {
            client
                .get("http://127.0.0.1:9999/who-am-i")
                .await
                .unwrap()
                .json::<WhoAmIResponse>()
                .await
                .unwrap()
        }
    });

    view! {
        <h1 id="greeting">
            "Hello, " { move || user_name.get() } "!"
        </h1>

        <Suspense fallback=|| view! { "" }>
            { move || who_am_i.get().map(|who_am_i| view! {
                <div>"username: " <span id="username">{ who_am_i.username.clone() }</span></div>
                <div>"keycloak_uuid: " <span id="keycloak_uuid">{ who_am_i.keycloak_uuid.clone() }</span></div>
                <div>"token_valid_for_whole_seconds: " <span id="token_valid_for_whole_seconds">{ who_am_i.token_valid_for_whole_seconds }</span></div>
            }) }
        </Suspense>

        <pre id="auth-state" style="width: 100%; overflow: auto;">
            { move || auth_state() }
        </pre>

        <LinkButton attr:id="logout" href=move || logout_url.get().unwrap_or_default() disabled=logout_url_unavailable>
            "Logout"
        </LinkButton>

        <LinkButton attr:id="back-to-root" href=routes::Root.materialize() attr:style="margin-top: 3em;">
            "Back to root"
        </LinkButton>
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
        <Suspense fallback=|| view! { "" }>
            {Suspend::new(async move {
                let port = keycloak_port.await;
                let keycloak_server_url = format!("http://localhost:{port}");
                let auth = use_keycloak_auth(UseKeycloakAuthOptions {
                    keycloak_server_url: Url::parse(&keycloak_server_url).unwrap(),
                    realm: "test-realm".to_owned(),
                    client_id: "test-client".to_owned(),
                    post_login_redirect_url: to_current_url(),
                    post_logout_redirect_url: to_current_url(),
                    scope: vec![],
                    id_token_validation: ValidationOptions {
                        expected_audiences: Some(vec!["test-client".to_owned()]),
                        expected_issuers: Some(vec![format!("{keycloak_server_url}/realms/test-realm")]),
                    },
                    advanced: Default::default(),
                });
                view! {
                    <ShowWhenAuthenticated fallback=|| view! { <Login/> }>
                        { children() }
                    </ShowWhenAuthenticated>

                    <div style="width: 100%;">
                        <h3>"Internal data: oidc_config_manager"</h3>
                        <div>
                            "oidc_config_age: " {move || format!("{:?}", auth.oidc_config_manager.oidc_config_age.get())}
                        </div>
                        <div>
                            "oidc_config_expires_in: " {move || format!("{:?}", auth.oidc_config_manager.oidc_config_expires_in.get())}
                        </div>
                        <div>
                            "oidc_config_too_old: " {move || format!("{:?}", auth.oidc_config_manager.oidc_config_too_old.get())}
                        </div>
                    </div>

                    <div style="width: 100%;">
                        <h3>"Internal data: jwk_set_manager"</h3>
                        <div>
                            "jwk_set_age: " {move || format!("{:?}", auth.jwk_set_manager.jwk_set_age.get())}
                        </div>
                        <div>
                            "jwk_set_expires_in: " {move || format!("{:?}", auth.jwk_set_manager.jwk_set_expires_in.get())}
                        </div>
                        <div>
                            "jwk_set_too_old: " {move || format!("{:?}", auth.jwk_set_manager.jwk_set_too_old.get())}
                        </div>
                    </div>

                    <div style="width: 100%;">
                        <h3>"Internal data: code_verifier_manager"</h3>
                        <div>
                            "code_verifier: " {move || format!("{:?}", auth.code_verifier_manager.code_verifier.get())}
                        </div>
                        <div>
                            "code_challenge: " {move || format!("{:?}", auth.code_verifier_manager.code_challenge.get())}
                        </div>
                    </div>

                    <div style="width: 100%;">
                        <h3>"Internal data: token_manager"</h3>
                        <div>
                            "access_token_lifetime: " {move || format!("{:?}", auth.token_manager.access_token_lifetime.get())}
                        </div>
                        <div>
                            "access_token_expires_in: " {move || format!("{:?}", auth.token_manager.access_token_expires_in.get())}
                        </div>
                        <div>
                            "access_token_nearly_expired: " {move || format!("{:?}", auth.token_manager.access_token_nearly_expired.get())}
                        </div>
                        <div>
                            "access_token_expired: " {move || format!("{:?}", auth.token_manager.access_token_expired.get())}
                        </div>
                        <div>
                            "refresh_token_lifetime: " {move || format!("{:?}", auth.token_manager.refresh_token_lifetime.get())}
                        </div>
                        <div>
                            "refresh_token_expires_in: " {move || format!("{:?}", auth.token_manager.refresh_token_expires_in.get())}
                        </div>
                        <div>
                            "refresh_token_nearly_expired: " {move || format!("{:?}", auth.token_manager.refresh_token_nearly_expired.get())}
                        </div>
                        <div>
                            "refresh_token_expired: " {move || format!("{:?}", auth.token_manager.refresh_token_expired.get())}
                        </div>
                        <div>
                            "token_endpoint: " {move || format!("{:?}", auth.token_manager.token_endpoint.get())}
                        </div>
                    </div>
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
    let keycloak_port =
        Signal::derive(
            move || match auth.login_url.get().and_then(|it| it.port()) {
                None => "".to_owned(),
                Some(port) => format!("{port}"),
            },
        );
    let auth_state = auth.state_pretty_printer();

    view! {
       <h1 id="unauthenticated">"Unauthenticated"</h1>

        <div id="keycloak-port">
            { move || keycloak_port.get() }
        </div>

        <pre id="auth-state" style="width: 100%; overflow: auto;">
            { move || auth_state() }
        </pre>

        <LinkButton
            href=move || login_url.get()
            target=LinkTarget::_Self
            disabled=login_url_unavailable
        >
            "Log in"
        </LinkButton>

        <LinkButton attr:id="back-to-root" href=routes::Root.materialize() attr:style="margin-top: 3em;">
            "Back to root"
        </LinkButton>
    }
}
