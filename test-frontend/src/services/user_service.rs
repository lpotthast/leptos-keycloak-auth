use leptos::prelude::*;

use crate::{environment::ENVIRONMENT, services::BaseService};

#[derive(Debug, Clone, serde::Deserialize)]
pub struct WhoAmIResponse {
    pub username: String,
    pub keycloak_uuid: String,
    pub token_valid_for_whole_seconds: i32,
}

#[derive(Debug, Clone, Copy)]
pub struct UserService {
    pub api_url: StoredValue<String>,
}

impl BaseService for UserService {}

impl UserService {
    pub fn provide() {
        provide_context(UserService {
            api_url: StoredValue::new(ENVIRONMENT.api_url()),
        });
    }

    #[must_use]
    pub fn get() -> UserService {
        expect_context::<UserService>()
    }

    /// # Errors
    /// Returns an error when the HTTP call fails or when the response cannot be JSON deserialized
    /// as a `WhoAmIResponse`.
    pub async fn who_am_i(&self) -> Result<WhoAmIResponse, String> {
        self.get_authenticated_client()
            .get(format!("{}/who-am-i", self.api_url.read_value()))
            .await
            .map_err(|err| err.to_string())?
            .json::<WhoAmIResponse>()
            .await
            .map_err(|err| err.to_string())
    }
}
