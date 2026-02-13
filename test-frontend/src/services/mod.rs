use leptos_keycloak_auth::{AuthenticatedClient, use_authenticated};

pub mod user_service;

pub trait BaseService {
    fn get_authenticated_client(&self) -> AuthenticatedClient {
        use_authenticated().client()
    }
}
