use crate::{KeycloakAuth, KeycloakAuthState};
use leptos::either::Either;
use leptos::prelude::*;

/// A transparent component representing authenticated user status.
/// It provides a way to conditionally render its children based on the user's authentication status.
/// If the user is authenticated, it renders the children; otherwise, it falls back to the provided loading or unauthenticated view.
#[component(transparent)]
pub fn Authenticated<C>(
    #[prop(into, optional)] unauthenticated: ViewFn,

    children: TypedChildrenFn<C>,
) -> impl IntoView
where
    C: IntoView + 'static,
{
    let auth = expect_context::<KeycloakAuth>();

    let children = children.into_inner();

    move || match auth.state.get() {
        KeycloakAuthState::Authenticated(authenticated) => {
            provide_context(authenticated);
            Either::Left(children())
        }
        KeycloakAuthState::NotAuthenticated(_not_authenticated) => {
            let _ = take_context::<crate::Authenticated>();
            Either::Right(unauthenticated.run())
        }
    }
}
