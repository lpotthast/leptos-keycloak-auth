use crate::internal::JwkSetWithTimestamp;
use crate::token::TokenData;
use crate::token_claims::{KeycloakIdTokenClaims, StandardIdTokenClaims};
use snafu::{OptionExt, ResultExt, Snafu};

#[derive(Debug, Clone, PartialEq, Snafu)]
pub enum JwtValidationError {
    #[snafu(display(
        "JwtValidationError: Could not decode JWT header. Input may have the wrong format"
    ))]
    DecodeHeader { source: jsonwebtoken::errors::Error },

    #[snafu(display(
        "JwtValidationError: Could not find a JWK which would match the tokens 'kid': {token_kid:?}"
    ))]
    NoMatchingJwk { token_kid: Option<String> },

    #[snafu(display("JwtValidationError: Could not construct DecodingKey from JWK"))]
    JwkToDecodingKey { source: jsonwebtoken::errors::Error },

    #[snafu(display("JwtValidationError: Could not decode JWT"))]
    Decode { source: jsonwebtoken::errors::Error },
}

#[derive(Debug, Clone, PartialEq, Snafu)]
#[allow(clippy::enum_variant_names)]
pub enum IdTokenClaimsError {
    #[snafu(display("IdTokenClaimsError: No token."))]
    NoToken,

    #[snafu(display("IdTokenClaimsError: No JWK set."))]
    NoJwkSet,

    #[snafu(display("IdTokenClaimsError: Validation failed."))]
    Validation { source: JwtValidationError },

    #[snafu(display("IdTokenClaimsError: Nonce mismatch."))]
    NonceMismatch,

    #[snafu(display("IdTokenClaimsError: Missing nonce in ID token."))]
    MissingNonce,
}

pub(crate) fn validate_token_data_presence(
    token: Option<TokenData>,
) -> Result<TokenData, IdTokenClaimsError> {
    let token_data = token.context(NoTokenSnafu {})?;
    Ok(token_data)
}

pub(crate) fn validate_jwk_set_presence(
    jwk_set: Option<JwkSetWithTimestamp>,
) -> Result<JwkSetWithTimestamp, IdTokenClaimsError> {
    let jwk_set = jwk_set.context(NoJwkSetSnafu {})?;
    Ok(jwk_set)
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
) -> Result<KeycloakIdTokenClaims, IdTokenClaimsError> {
    let standard_id_token_claims = validate_and_decode_base64_encoded_token(
        &token.id_token,
        expected_audiences,
        expected_issuers,
        jwk_set,
    )
    .context(ValidationSnafu {})?;

    match nonce_validation {
        NonceValidation::Required { expected_nonce } => match &standard_id_token_claims.nonce {
            Some(actual_nonce) if actual_nonce == expected_nonce => {
                tracing::trace!("Nonce validation succeeded.");
            }
            Some(actual_nonce) => {
                tracing::error!(expected_nonce, actual_nonce, "Nonce mismatch.");
                return Err(IdTokenClaimsError::NonceMismatch);
            }
            None => {
                tracing::error!("ID token is missing the `nonce` claim.");
                return Err(IdTokenClaimsError::MissingNonce);
            }
        },
        NonceValidation::IfPresent { expected_nonce } => match &standard_id_token_claims.nonce {
            Some(actual_nonce) if actual_nonce == expected_nonce => {
                tracing::trace!("Nonce validation succeeded.");
            }
            Some(actual_nonce) => {
                tracing::error!(expected_nonce, actual_nonce, "Nonce mismatch.");
                return Err(IdTokenClaimsError::NonceMismatch);
            }
            None => {}
        },
        NonceValidation::Disabled => {}
    }

    Ok(KeycloakIdTokenClaims::from(standard_id_token_claims))
}

fn validate_and_decode_base64_encoded_token(
    base64_encoded_token: &str,
    expected_audiences: Option<&[String]>,
    expected_issuers: Option<&[String]>,
    jwk_set: &jsonwebtoken::jwk::JwkSet,
) -> Result<StandardIdTokenClaims, JwtValidationError> {
    let jwt_header =
        jsonwebtoken::decode_header(base64_encoded_token).context(DecodeHeaderSnafu {})?;

    tracing::trace!(?jwt_header, "Decoded JWT header");

    let mut validation = jsonwebtoken::Validation::new(jwt_header.alg);
    if let Some(expected_audiences) = expected_audiences {
        validation.set_audience(expected_audiences);
    }
    if let Some(expected_issuers) = expected_issuers {
        validation.set_issuer(expected_issuers);
    }

    let jwk = jwk_set
        .keys
        .iter()
        .find(|it| it.common.key_id == jwt_header.kid)
        .ok_or_else(|| {
            NoMatchingJwkSnafu {
                token_kid: jwt_header.kid,
            }
            .build()
        })?;

    let jwt_decoding_key =
        jsonwebtoken::DecodingKey::from_jwk(jwk).context(JwkToDecodingKeySnafu {})?;

    let token_data = jsonwebtoken::decode::<StandardIdTokenClaims>(
        base64_encoded_token,
        &jwt_decoding_key,
        &validation,
    )
    .context(DecodeSnafu {})?;

    let raw_claims: StandardIdTokenClaims = token_data.claims;
    tracing::trace!(?raw_claims, "Decoded JWT");

    Ok(raw_claims)
}
