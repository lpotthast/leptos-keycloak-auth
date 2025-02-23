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
            view = "|| view! { <Protected> <EndSession and_route_to=\"http://127.0.0.1:3000\"/> </Protected> }"
        )]
        pub mod logout {}
    }
}
