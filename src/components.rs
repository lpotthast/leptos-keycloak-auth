use leptos::prelude::*;

use crate::KeycloakAuth;

/// A transparent component representing authenticated user status.
/// It provides a way to conditionally render its children based on the user's authentication status.
/// If the user is authenticated, it renders the children; otherwise, it falls back to the provided loading or unauthenticated view.
#[component(transparent)]
pub fn Authenticated<C>(
    #[prop(into, optional)]
    unauthenticated: ViewFn,

    children: TypedChildrenFn<C>,
) -> impl IntoView
where
    C: IntoView + 'static,
{
    let auth = expect_context::<KeycloakAuth>();

    view! {
        <Show
            when= move || auth.is_authenticated.get()
            fallback=move || unauthenticated.run()
            children=children
        />
    }
}
