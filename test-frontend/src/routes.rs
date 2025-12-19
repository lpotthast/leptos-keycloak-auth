use leptos_routes::routes;

#[allow(clippy::module_inception)]
#[routes(with_views, fallback = "|| view! { \"Page not found.\" }")]
pub mod routes {
    use crate::app::MainLayout;
    use crate::app::MyAccount;
    use crate::app::Protected;
    use crate::app::Public;
    use crate::app::Welcome;
    use leptos_keycloak_auth::components::EndSession;
    use leptos_keycloak_auth::url::Url;

    #[route("/", layout = "MainLayout", fallback = "Welcome")]
    pub mod root {

        #[route("/public", view = "Public")]
        pub mod public {}

        #[route(
            "/my-account",
            view = "|| view! { <Protected> <MyAccount/> </Protected> }"
        )]
        pub mod my_account {}

        /// A route that, when reached, programmatically logs out the current user (if authenticated)
        /// and redirects to `"/"`.
        #[route(
            "/logout",
            view = "|| view! { <Protected> <EndSession and_route_to=Url::parse(\"http://127.0.0.1:3000\").unwrap()/> </Protected> }"
        )]
        pub mod logout {}
    }
}
