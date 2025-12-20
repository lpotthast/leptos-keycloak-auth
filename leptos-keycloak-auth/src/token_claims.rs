use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::OffsetDateTime;

/// See: <https://openid.net/specs/openid-connect-core-1_0.html#IDToken>
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct StandardIdTokenClaims {
    pub(crate) iss: String,
    pub(crate) sub: String,
    pub(crate) aud: RawAudiences,
    pub(crate) exp: i64,
    pub(crate) iat: i64,
    pub(crate) auth_time: Option<i64>,
    pub(crate) nonce: Option<String>,
    pub(crate) acr: Option<String>,
    pub(crate) amr: Option<Vec<String>>,
    pub(crate) azp: Option<String>,
    #[serde(flatten)]
    pub(crate) remaining: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum RawAudiences {
    Single(String),
    Multiple(Vec<String>),
}

/// See: <https://openid.net/specs/openid-connect-core-1_0.html#IDToken>
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct KeycloakIdTokenClaims {
    /// (iss) REQUIRED. Issuer Identifier for the Issuer of the response.
    /// The iss value is a case sensitive URL using the https scheme that contains scheme, host,
    /// and optionally, port number and path components and no query or fragment components.
    pub issuer: String,

    /// (sub) REQUIRED. Subject Identifier.
    /// A locally unique and never reassigned identifier within the Issuer for the End-User, which
    /// is intended to be consumed by the Client,
    /// e.g., `24400320` or `AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4`.
    /// It MUST NOT exceed 255 ASCII characters in length. The sub value is a case sensitive string.
    pub subject_identifier: String,

    /// (aud) REQUIRED. Audience(s) that this ID Token is intended for.
    /// It MUST contain the OAuth 2.0 `client_id` of the Relying Party as an audience value.
    /// It MAY also contain identifiers for other audiences. In the general case, the aud value is
    /// an array of case sensitive strings.
    /// In the common special case when there is one audience, the aud value MAY be a single case
    /// sensitive string.
    pub audiences: Audiences,

    /// (`exp`) REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for
    /// processing.
    /// The processing of this parameter requires that the current date/time MUST be before the
    /// expiration date/time listed in the value.
    /// Implementers MAY provide for some small leeway, usually no more than a few minutes, to
    /// account for clock skew.
    /// Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as
    /// measured in UTC until the date/time.
    /// See RFC 3339 [RFC3339] for details regarding date/times in general and UTC in particular.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,

    /// (`iat`) REQUIRED. Time at which the JWT was issued.
    /// Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as
    /// measured in UTC until the date/time.
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,

    /// (`auth_time`) REQUIRED or OPTIONAL. Time when the End-User authentication occurred.
    /// Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as
    /// measured in UTC until the date/time.
    /// When a `max_age` request is made or when `auth_time` is requested as an Essential Claim,
    /// then this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL.
    /// (The `auth_time` Claim semantically corresponds to the `OpenID 2.0 PAPE` [OpenID.PAPE]
    /// `auth_time` response parameter.)
    #[serde(with = "time::serde::rfc3339::option")]
    pub auth_time: Option<OffsetDateTime>,

    /// (`nonce`) OPTIONAL. String value used to associate a Client session with an ID Token, and to
    /// mitigate replay attacks.
    /// The value is passed through unmodified from the Authentication Request to the ID Token.
    /// If present in the ID Token, Clients MUST verify that the nonce Claim Value is equal to the
    /// value of the nonce parameter sent in the Authentication Request.
    /// If present in the Authentication Request, Authorization Servers MUST include a nonce Claim
    /// in the ID Token with the Claim Value being the nonce value sent in the Authentication
    /// Request.
    /// Authorization Servers SHOULD perform no other processing on nonce values used. The nonce
    /// value is a case sensitive string.
    pub nonce: Option<String>,

    /// (`acr`) OPTIONAL. Authentication Context Class Reference.
    /// String specifying an Authentication Context Class Reference value that identifies the
    /// Authentication Context Class that the authentication performed satisfied.
    /// The value "0" indicates the End-User authentication did not meet the requirements of
    /// ISO/IEC 29115 [ISO29115] level 1.
    /// Authentication using a long-lived browser cookie, for instance, is one example where the
    /// use of "level 0" is appropriate.
    /// Authentications with level 0 SHOULD NOT be used to authorize access to any resource of any
    /// monetary value.
    /// (This corresponds to the `OpenID 2.0 PAPE` [OpenID.PAPE] `nist_auth_level` 0.)
    /// An absolute URI or an RFC 6711 [RFC6711] registered name SHOULD be used as the acr value;
    /// registered names MUST NOT be used with a different meaning than that which is registered.
    /// Parties using this claim will need to agree upon the meanings of the values used, which may
    /// be context-specific.
    /// The acr value is a case-sensitive string.
    pub auth_context_class_reference: Option<String>,

    /// (`amr`) OPTIONAL. Authentication Methods References.
    /// JSON array of strings that are identifiers for authentication methods used in the
    /// authentication.
    /// For instance, values might indicate that both password and OTP authentication methods were
    /// used.
    /// The definition of particular values to be used in the amr Claim is beyond the scope of this
    /// specification.
    /// Parties using this claim will need to agree upon the meanings of the values used, which may
    /// be context-specific.
    /// The amr value is an array of case-sensitive strings.
    pub authentication_methods_references: Option<Vec<String>>,

    /// (`azp`) OPTIONAL. Authorized party - the party to which the ID Token was issued.
    /// If present, it MUST contain the OAuth 2.0 Client ID of this party.
    /// This Claim is only needed when the ID Token has a single audience value and that audience
    /// is different than the authorized party.
    /// It MAY be included even when the authorized party is the same as the sole audience.
    /// The azp value is a case-sensitive string containing a `StringOrURI` value.
    pub authorized_party: Option<String>,

    /// KEYCLOAK SPECIFIC. Whether the user verified his email address.
    pub email_verified: bool,

    /// KEYCLOAK SPECIFIC. Full name of the user. Expect this to roughly be
    /// `format!("{given_name} {family_name}")`.
    pub name: String,

    /// KEYCLOAK SPECIFIC. Preferred username. It may be the users email, name or something else
    /// entirely.
    pub preferred_username: String,

    /// KEYCLOAK SPECIFIC. First name.
    pub given_name: String,

    /// KEYCLOAK SPECIFIC. Last name.
    pub family_name: String,

    /// KEYCLOAK SPECIFIC. Email address of the user.
    pub email: String,

    /// KEYCLOAK SPECIFIC. Realm roles. This will be `None` unless roles are explicitly added to ID
    /// tokens using the Keycloak Admin UI.
    pub realm_access: Option<RealmAccess>,

    /// KEYCLOAK SPECIFIC. Realm roles. This will be `None` unless roles are explicitly added to ID
    /// tokens using the Keycloak Admin UI.
    pub resource_access: Option<ResourceAccess>,

    pub additional_claims: HashMap<String, serde_json::Value>,
}

impl From<StandardIdTokenClaims> for KeycloakIdTokenClaims {
    fn from(mut raw: StandardIdTokenClaims) -> Self {
        Self {
            issuer: raw.iss,
            subject_identifier: raw.sub,
            audiences: match raw.aud {
                RawAudiences::Single(s) => Audiences::Single(s),
                RawAudiences::Multiple(m) => Audiences::Multiple(m),
            },
            expires_at: OffsetDateTime::from_unix_timestamp(raw.exp).unwrap_or_else(|err| {
                tracing::warn!(?err, "Token contained a non-parsable 'exp' (expires_at) value. Continuing with `now_utc()` being the expiry time.");
                OffsetDateTime::now_utc()
            }),
            issued_at: OffsetDateTime::from_unix_timestamp(raw.iat).unwrap_or_else(|err| {
                tracing::warn!(?err, "Token contained a non-parsable 'iat' (issued_at) value. Continuing with `now_utc()` being the issuing time.");
                OffsetDateTime::now_utc()
            }),
            auth_time: raw.auth_time.map(|auth_time| OffsetDateTime::from_unix_timestamp(auth_time).unwrap_or_else(|err| {
                tracing::warn!(?err, "Token contained a non-parsable 'auth_time' value. Continuing with `now_utc()` being the authorization time.");
                OffsetDateTime::now_utc()
            })),
            nonce: raw.nonce,
            auth_context_class_reference: raw.acr,
            authentication_methods_references: raw.amr,
            authorized_party: raw.azp,
            email_verified: raw.remaining
                .remove("email_verified")
                .and_then(|it| serde_json::from_value(it).ok())
                .unwrap_or_default(),
            name: raw.remaining
                .remove("name")
                .and_then(|it| serde_json::from_value(it).ok())
                .unwrap_or_default(),
            preferred_username: raw.remaining
                .remove("preferred_username")
                .and_then(|it| serde_json::from_value(it).ok())
                .unwrap_or_default(),
            given_name: raw.remaining
                .remove("given_name")
                .and_then(|it| serde_json::from_value(it).ok())
                .unwrap_or_default(),
            family_name: raw.remaining
                .remove("family_name")
                .and_then(|it| serde_json::from_value(it).ok())
                .unwrap_or_default(),
            email: raw.remaining
                .remove("email")
                .and_then(|it| serde_json::from_value(it).ok())
                .unwrap_or_default(),
            realm_access: raw.remaining
                .remove("realm_access")
                .and_then(|it| serde_json::from_value(it).ok())
                .unwrap_or_default(),
            resource_access: raw.remaining
                .remove("resource_access")
                .and_then(|it| serde_json::from_value(it).ok())
                .unwrap_or_default(),
            additional_claims: raw.remaining
                .remove("additional_claims")
                .and_then(|it| serde_json::from_value(it).ok())
                .unwrap_or_default(),
        }
    }
}

/// Represents the audience(s) (`aud` claim) from an ID token.
///
/// The `OpenID Connect` specification allows the `audience` to be either a single string
/// or an array of strings. This enum handles both cases.
///
/// This type is accessed through [`KeycloakIdTokenClaims::audiences`] field.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum Audiences {
    /// A single audience value (common case).
    Single(String),

    /// Multiple audience values.
    Multiple(Vec<String>),
}

/// Contains a list of role names assigned to a user.
///
/// # Note
/// Roles must be explicitly configured to be included in ID tokens via the Keycloak Admin UI.
/// By default, Keycloak may not include roles in ID tokens!
///
/// This type is accessed through [`RealmAccess`] and [`ResourceAccess`] fields in
/// [`KeycloakIdTokenClaims`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Access {
    /// A list of role names assigned to the user.
    pub roles: Vec<String>,
}

/// Realm-level role assignments from the ID token.
///
/// # Note
/// This will be `None` in the ID token unless roles are explicitly configured to be included via
/// the Keycloak Admin UI.
///
/// # Example
/// ```no_run
/// use leptos::prelude::*;
/// use leptos_keycloak_auth::expect_authenticated;
///
/// let authenticated = expect_authenticated();
/// let id_claims = authenticated.id_token_claims.get();
///
/// if let Some(realm_access) = &id_claims.realm_access {
///     if realm_access.0.roles.contains(&"admin".to_string()) {
///         // User has admin role at realm level.
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RealmAccess(pub Access);

/// Resource-specific role assignments from the ID token.
///
/// Contains roles assigned to the user for specific resources (clients) in Keycloak.
/// This is a map where keys are client/resource IDs and values are the roles for that resource.
///
/// # Note
/// This will be `None` in the ID token unless roles are explicitly configured to be
/// included via the Keycloak Admin UI.
///
/// # Example
/// ```no_run
/// use leptos::prelude::*;
/// use leptos_keycloak_auth::expect_authenticated;
///
/// let authenticated = expect_authenticated();
/// let id_claims = authenticated.id_token_claims.get();
///
/// if let Some(resource_access) = &id_claims.resource_access {
///     if let Some(my_app_access) = resource_access.0.get("client-id") {
///         if my_app_access.roles.contains(&"editor".to_string()) {
///             // User has `editor` role for `client-id`.
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceAccess(pub HashMap<String, Access>);
