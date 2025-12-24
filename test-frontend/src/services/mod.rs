use leptos_keycloak_auth::{use_authenticated, AuthenticatedClient};

pub mod user_service;

pub trait BaseService {
    fn get_authenticated_client(&self) -> AuthenticatedClient {
        use_authenticated().client()
    }
}
