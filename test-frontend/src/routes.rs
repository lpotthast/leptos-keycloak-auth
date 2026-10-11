use std::sync::LazyLock;

use leptos::prelude::*;
use leptos_keycloak_auth::{
    components::{EndSession, MaybeAuthenticated},
    url::Url,
};
use leptos_routes::routes;

use crate::app::{Home, Login, MainLayout, MyAccountPage};

static BASE_URL: LazyLock<Url> = LazyLock::new(|| Url::parse("http://127.0.0.1:3000").unwrap());

#[routes]
pub mod routes {
    fallback!(|| view! { "Page not found." });

    layout!(MainLayout);
    index!(Home);

    #[route("/my-account")]
    mod my_account {
        page!(|| view! {
            <MaybeAuthenticated
                authenticated=|_| MyAccountPage
                unauthenticated=|_| Login
            />
        });
    }

    /// A route that, when reached, programmatically logs out the current user (if authenticated)
    /// and redirects to `"/"`.
    #[route("/logout")]
    mod logout {
        page!(|| view! { <EndSession and_route_to=BASE_URL.clone()/> });
    }
}
