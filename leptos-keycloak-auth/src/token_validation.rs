use rootcause::{Report, bail, prelude::*};
use thiserror::Error;

use crate::{
    internal::JwkSetWithTimestamp,
    token::TokenData,
    token_claims::{KeycloakIdTokenClaims, StandardIdTokenClaims},
};

/// Error contexts of verifying and decoding a JWT.
///
/// The underlying `jsonwebtoken` error, if any, is a child report.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum JwtValidationError {
    /// The JWT header could not be decoded. The input may have the wrong format.
    #[error("Failed to decode the JWT header.")]
    DecodeHeader,

    /// No JWK of the JWK set matches the key ID (`kid`) of the token.
    #[error("Found no JWK matching the token's key ID {token_kid:?}.")]
    NoMatchingJwk {
        /// The key ID the token header references.
        token_kid: Option<String>,
    },

    /// The token uses a symmetric (HMAC) algorithm. ID tokens must be verified against the public
    /// JWK set.
    #[error("The token uses the symmetric algorithm {token_alg:?}, which is not accepted.")]
    SymmetricAlgorithm {
        /// The algorithm the token header specifies.
        token_alg: jsonwebtoken::Algorithm,
    },

    /// The token's algorithm does not match the algorithm its JWK is declared for.
    #[error(
        "The token algorithm {token_alg:?} does not match the algorithm of its JWK {jwk_alg:?}."
    )]
    AlgorithmMismatch {
        /// The algorithm the token header specifies.
        token_alg: jsonwebtoken::Algorithm,
        /// The algorithm the JWK is declared for.
        jwk_alg: jsonwebtoken::jwk::KeyAlgorithm,
    },

    /// No decoding key could be constructed from the JWK.
    #[error("Failed to construct a decoding key from the JWK.")]
    JwkToDecodingKey,

    /// The token could not be verified or decoded, e.g. due to an invalid signature, an expired
    /// token, or an unexpected audience or issuer.
    #[error("Failed to verify and decode the JWT.")]
    Decode,
}

/// Error contexts of validating the ID token.
///
/// Reported through
/// [`NotAuthenticated::last_id_token_error`](crate::NotAuthenticated::last_id_token_error).
/// A [`JwtValidationError`] is a child report of [`IdTokenClaimsError::Validation`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum IdTokenClaimsError {
    /// No token is known.
    #[error("No token is known.")]
    NoToken,

    /// No JWK set is known yet to verify the ID token with.
    #[error("No JWK set is known.")]
    NoJwkSet,

    /// The ID token could not be verified and decoded.
    #[error("The ID token failed validation.")]
    Validation,

    /// The `nonce` claim of the ID token does not match the nonce sent in the authorization
    /// request.
    #[error("The nonce of the ID token does not match the expected nonce.")]
    NonceMismatch,

    /// The ID token lacks the required `nonce` claim.
    #[error("The ID token is missing the nonce claim.")]
    MissingNonce,
}

pub(crate) fn validate_token_data_presence(
    token: Option<TokenData>,
) -> Result<TokenData, Report<IdTokenClaimsError>> {
    token.ok_or_else(|| Report::new(IdTokenClaimsError::NoToken))
}

pub(crate) fn validate_jwk_set_presence(
    jwk_set: Option<JwkSetWithTimestamp>,
) -> Result<JwkSetWithTimestamp, Report<IdTokenClaimsError>> {
    jwk_set.ok_or_else(|| Report::new(IdTokenClaimsError::NoJwkSet))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NonceValidation<'n> {
    Required { expected_nonce: &'n str },
    IfPresent { expected_nonce: &'n str },
    Disabled,
}

pub(crate) fn validate(
    token: &TokenData,
    jwk_set: &jsonwebtoken::jwk::JwkSet,
    expected_audiences: Option<&[String]>,
    expected_issuers: Option<&[String]>,
    nonce_validation: NonceValidation<'_>,
) -> Result<KeycloakIdTokenClaims, Report<IdTokenClaimsError>> {
    let standard_id_token_claims = validate_and_decode_base64_encoded_token(
        &token.id_token,
        expected_audiences,
        expected_issuers,
        jwk_set,
    )
    .context(IdTokenClaimsError::Validation)?;

    let (expected_nonce, nonce_required) = match nonce_validation {
        NonceValidation::Required { expected_nonce } => (expected_nonce, true),
        NonceValidation::IfPresent { expected_nonce } => (expected_nonce, false),
        NonceValidation::Disabled => {
            return Ok(KeycloakIdTokenClaims::from(standard_id_token_claims));
        }
    };
    match &standard_id_token_claims.nonce {
        Some(actual_nonce) if actual_nonce == expected_nonce => {
            tracing::trace!("Nonce validation succeeded.");
        }
        Some(actual_nonce) => {
            tracing::error!(expected_nonce, actual_nonce, "Nonce mismatch.");
            bail!(IdTokenClaimsError::NonceMismatch);
        }
        None if nonce_required => {
            tracing::error!("ID token is missing the `nonce` claim.");
            bail!(IdTokenClaimsError::MissingNonce);
        }
        None => {}
    }

    Ok(KeycloakIdTokenClaims::from(standard_id_token_claims))
}

fn validate_and_decode_base64_encoded_token(
    base64_encoded_token: &str,
    expected_audiences: Option<&[String]>,
    expected_issuers: Option<&[String]>,
    jwk_set: &jsonwebtoken::jwk::JwkSet,
) -> Result<StandardIdTokenClaims, Report<JwtValidationError>> {
    let jwt_header = jsonwebtoken::decode_header(base64_encoded_token)
        .context(JwtValidationError::DecodeHeader)?;

    tracing::trace!(?jwt_header, "Decoded JWT header");

    let jwk = jwk_set
        .keys
        .iter()
        .find(|it| it.common.key_id == jwt_header.kid)
        .ok_or_else(|| {
            Report::new(JwtValidationError::NoMatchingJwk {
                token_kid: jwt_header.kid.clone(),
            })
        })?;

    let algorithm = determine_algorithm(jwt_header.alg, jwk)?;
    let validation = create_validation(algorithm, expected_audiences, expected_issuers);

    let jwt_decoding_key =
        jsonwebtoken::DecodingKey::from_jwk(jwk).context(JwtValidationError::JwkToDecodingKey)?;

    let token_data = jsonwebtoken::decode::<StandardIdTokenClaims>(
        base64_encoded_token,
        &jwt_decoding_key,
        &validation,
    )
    .context(JwtValidationError::Decode)?;

    let raw_claims: StandardIdTokenClaims = token_data.claims;
    tracing::trace!(?raw_claims, "Decoded JWT");

    Ok(raw_claims)
}

/// Determine the algorithm to verify the token with.
///
/// The token header is attacker-controlled, so its `alg` is only accepted when it is an asymmetric
/// algorithm and, should the JWK declare an algorithm, matches the algorithm the JWK was published
/// for.
fn determine_algorithm(
    header_alg: jsonwebtoken::Algorithm,
    jwk: &jsonwebtoken::jwk::Jwk,
) -> Result<jsonwebtoken::Algorithm, Report<JwtValidationError>> {
    use jsonwebtoken::{AlgorithmFamily, jwk::KeyAlgorithm};

    if header_alg.family() == AlgorithmFamily::Hmac {
        bail!(JwtValidationError::SymmetricAlgorithm {
            token_alg: header_alg,
        });
    }

    if let Some(jwk_alg) = jwk.common.key_algorithm
        && jwk_alg != KeyAlgorithm::from(header_alg)
    {
        bail!(JwtValidationError::AlgorithmMismatch {
            token_alg: header_alg,
            jwk_alg,
        });
    }

    Ok(header_alg)
}

fn create_validation(
    algorithm: jsonwebtoken::Algorithm,
    expected_audiences: Option<&[String]>,
    expected_issuers: Option<&[String]>,
) -> jsonwebtoken::Validation {
    let mut validation = jsonwebtoken::Validation::new(algorithm);
    match expected_audiences {
        Some(expected_audiences) => validation.set_audience(expected_audiences),
        // `jsonwebtoken` rejects any token carrying an `aud` claim when no audience is configured.
        // Keycloak ID tokens always carry one, so skipping must be explicit.
        None => validation.validate_aud = false,
    }
    if let Some(expected_issuers) = expected_issuers {
        validation.set_issuer(expected_issuers);
    }
    validation
}

#[cfg(test)]
mod tests {
    use assertr::prelude::*;
    use jsonwebtoken::{
        Algorithm,
        jwk::{
            AlgorithmParameters, CommonParameters, Jwk, KeyAlgorithm, RSAKeyParameters, RSAKeyType,
        },
    };

    use super::*;

    #[test]
    fn validate_token_data_presence_none_returns_no_token_error() {
        let result = validate_token_data_presence(None);
        assert_that!(result.unwrap_err().current_context())
            .is_equal_to(IdTokenClaimsError::NoToken);
    }

    #[test]
    fn validate_jwk_set_presence_none_returns_no_jwk_set_error() {
        let result = validate_jwk_set_presence(None);
        assert_that!(result.unwrap_err().current_context())
            .is_equal_to(IdTokenClaimsError::NoJwkSet);
    }

    fn jwk_with_alg(alg: Option<KeyAlgorithm>) -> Jwk {
        Jwk {
            common: CommonParameters {
                key_algorithm: alg,
                ..CommonParameters::default()
            },
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA,
                n: String::new(),
                e: String::new(),
            }),
        }
    }

    #[test]
    fn determine_algorithm_accepts_header_alg_when_jwk_declares_none() {
        let result = determine_algorithm(Algorithm::RS256, &jwk_with_alg(None));
        assert_that!(result).ok().is_equal_to(Algorithm::RS256);
    }

    #[test]
    fn determine_algorithm_accepts_header_alg_matching_jwk_alg() {
        let result =
            determine_algorithm(Algorithm::PS512, &jwk_with_alg(Some(KeyAlgorithm::PS512)));
        assert_that!(result).ok().is_equal_to(Algorithm::PS512);
    }

    #[test]
    fn determine_algorithm_rejects_header_alg_not_matching_jwk_alg() {
        let result =
            determine_algorithm(Algorithm::RS384, &jwk_with_alg(Some(KeyAlgorithm::RS256)));
        assert_that!(result.unwrap_err().current_context()).is_equal_to(
            JwtValidationError::AlgorithmMismatch {
                token_alg: Algorithm::RS384,
                jwk_alg: KeyAlgorithm::RS256,
            },
        );
    }

    #[test]
    fn determine_algorithm_rejects_non_signature_jwk_alg() {
        let result = determine_algorithm(
            Algorithm::RS256,
            &jwk_with_alg(Some(KeyAlgorithm::RSA_OAEP)),
        );
        assert_that!(result.unwrap_err().current_context()).is_equal_to(
            JwtValidationError::AlgorithmMismatch {
                token_alg: Algorithm::RS256,
                jwk_alg: KeyAlgorithm::RSA_OAEP,
            },
        );
    }

    #[test]
    fn determine_algorithm_rejects_symmetric_header_alg() {
        let result = determine_algorithm(Algorithm::HS256, &jwk_with_alg(None));
        assert_that!(result.unwrap_err().current_context()).is_equal_to(
            JwtValidationError::SymmetricAlgorithm {
                token_alg: Algorithm::HS256,
            },
        );
    }

    #[test]
    fn create_validation_skips_audience_check_when_no_audience_is_expected() {
        let validation = create_validation(Algorithm::RS256, None, None);
        assert_that!(validation.validate_aud).is_false();
    }

    #[test]
    fn create_validation_checks_audience_when_audience_is_expected() {
        let validation = create_validation(Algorithm::RS256, Some(&["my-client".to_owned()]), None);
        assert_that!(validation.validate_aud).is_true();
        assert_that!(validation.aud).is_some();
    }
}
