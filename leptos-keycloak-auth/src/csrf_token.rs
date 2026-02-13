/// Cryptographically secure token used to avoid or detect CSRF attacks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CsrfToken {
    csrf_token: String,
}

impl CsrfToken {
    /// Generate a new cryptographically secure CSRF token using 32 bytes of random data,
    /// base64 url encoded as a 43 character string.
    pub fn new() -> Self {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use rand::RngExt;

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
    use std::collections::HashSet;

    use assertr::{assert_that, prelude::*};

    use super::*;

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
