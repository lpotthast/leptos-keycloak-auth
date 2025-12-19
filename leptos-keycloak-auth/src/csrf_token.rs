/// Cryptographically secure token used to avoid CSRF attack.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CsrfToken {
    csrf_token: String,
}

impl CsrfToken {
    /// Generate a new cryptographically secure CSRF token, using 32 bytes of cryptographically
    /// secure random data, base64 url encoded as a 43 character string.
    pub fn new() -> Self {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use rand::Rng;

        let mut rng = rand::rng();
        let bytes: [u8; 32] = rng.random();
        let csrf_token = URL_SAFE_NO_PAD.encode(bytes);

        Self { csrf_token }
    }

    pub fn as_str(&self) -> &str {
        &self.csrf_token
    }
}

impl Default for CsrfToken {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assertr::assert_that;
    use assertr::prelude::*;
    use std::collections::HashSet;

    #[test]
    fn generate_logout_token_on_creation() {
        let token = CsrfToken::new();
        assert_that(token.as_str()).is_not_empty().has_length(43);
    }

    #[test]
    fn tokens_are_unique() {
        let mut tokens = HashSet::new();

        for _ in 0..100 {
            assert_that(tokens.insert(CsrfToken::new()))
                .with_detail_message("Generated duplicate token.")
                .with_detail_message(format!("{tokens:?}"))
                .is_true();
        }
    }
}
