use leptos_routes::routes;

#[allow(clippy::module_inception)]
#[routes(with_views, fallback = "|| view! { \"Page not found.\" }")]
pub mod routes {
    use leptos_keycloak_auth::{
        components::{EndSession, MaybeAuthenticated},
        url::Url,
    };

    use crate::app::{Home, Login, MainLayout, MyAccount};

    #[route("/", layout = "MainLayout", fallback = "Home")]
    pub mod root {

        #[route(
            "/my-account",
            view = "|| view! {
                <MaybeAuthenticated
                    authenticated=|_auth| view! {
                        <MyAccount/>
                    }
                    unauthenticated=|_| view! {
                        <Login/>
                    }
                />
            }"
        )]
        pub mod my_account {}

        /// A route that, when reached, programmatically logs out the current user (if authenticated)
        /// and redirects to `"/"`.
        #[route(
            "/logout",
            view = "|| view! { <EndSession and_route_to=Url::parse(\"http://127.0.0.1:3000\").unwrap()/> }"
        )]
        pub mod logout {}
    }
}
