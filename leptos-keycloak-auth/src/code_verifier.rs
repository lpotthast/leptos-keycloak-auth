#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CodeVerifier<const LENGTH: usize> {
    code_verifier: String,
}

impl<const LENGTH: usize> CodeVerifier<LENGTH> {
    /// see: https://datatracker.ietf.org/doc/html/rfc7636
    pub(crate) fn generate() -> Self {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use rand::Rng;

        if LENGTH < 43 || LENGTH > 128 {
            panic!("Invalid code verifier length");
        }

        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        let mut rng = rand::rng();

        // Leveraging the base64 encoding ratio of encoding 3 bytes into 4 characters
        // with the fact that we use the NO_PAD config.
        let bytes_needed = (LENGTH * 3) / 4;

        let result = (0..bytes_needed)
            .map(|_i| CHARSET[rng.random_range(0..CHARSET.len())] as char)
            .collect::<String>();

        let code_verifier = URL_SAFE_NO_PAD.encode(&result);

        assert_eq!(code_verifier.len(), LENGTH);

        Self { code_verifier }
    }

    pub(crate) fn to_code_challenge(&self) -> CodeChallenge {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use sha2::Digest;

        let mut hasher = sha2::Sha256::new();
        hasher.update(self.code_verifier.as_bytes());
        let digest = hasher.finalize();

        let code_challenge = URL_SAFE_NO_PAD.encode(digest);

        CodeChallenge {
            code_challenge,
            code_challenge_method: CodeChallengeMethod::S256,
        }
    }

    pub fn code_verifier(&self) -> &str {
        self.code_verifier.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeChallengeMethod {
    S256,
}

impl CodeChallengeMethod {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            CodeChallengeMethod::S256 => "S256",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeChallenge {
    code_challenge: String,
    code_challenge_method: CodeChallengeMethod,
}

impl CodeChallenge {
    pub fn code_challenge(&self) -> &str {
        self.code_challenge.as_str()
    }

    pub fn code_challenge_method(&self) -> CodeChallengeMethod {
        self.code_challenge_method
    }
}

#[cfg(test)]
mod test {
    use super::{CodeChallengeMethod, CodeVerifier};
    use assertr::prelude::*;

    #[test]
    fn test_43() {
        let verifier = CodeVerifier::<43>::generate();
        assert_that(verifier.code_verifier()).has_length(43);

        let challenge = verifier.to_code_challenge();
        assert_that(challenge.code_challenge_method()).is_equal_to(CodeChallengeMethod::S256);
        assert_that(challenge.code_challenge()).has_length(43);
    }
    #[test]
    fn test_128() {
        let verifier = CodeVerifier::<128>::generate();
        assert_that(verifier.code_verifier()).has_length(128);

        let challenge = verifier.to_code_challenge();
        assert_that(challenge.code_challenge_method()).is_equal_to(CodeChallengeMethod::S256);
        assert_that(challenge.code_challenge()).has_length(43);
    }
}
