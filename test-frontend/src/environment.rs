use std::sync::LazyLock;

use dotenv_codegen::dotenv;

pub static ENVIRONMENT: LazyLock<Environment> = LazyLock::new(|| Environment {
    api_protocol: dotenv!("API_PROTOCOL"),
    api_host: dotenv!("API_HOST"),
    api_port: dotenv!("API_PORT"),
    kc_protocol: dotenv!("KC_PROTOCOL"),
    kc_host: dotenv!("KC_HOST"),
    kc_port: dotenv!("KC_PORT"),
    kc_realm: dotenv!("KC_REALM"),
    kc_client: dotenv!("KC_CLIENT"),
});

pub struct Environment {
    pub api_protocol: &'static str,
    pub api_host: &'static str,
    pub api_port: &'static str,
    pub kc_protocol: &'static str,
    pub kc_host: &'static str,
    pub kc_port: &'static str,
    pub kc_realm: &'static str,
    pub kc_client: &'static str,
}

impl Environment {
    #[must_use]
    pub fn api_url(&self) -> String {
        format!(
            "{}://{}:{}",
            self.api_protocol, self.api_host, self.api_port
        )
    }
}
