use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use url::Url;

use crate::{AccessToken, DiscoveryEndpoint, request::GrantType, response::SuccessTokenResponse};

/// A structure representing the storage of authentication tokens.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct TokenData {
    /// The ID Token is a security token that contains Claims about the Authentication of an End-User by an Authorization Server when using a Client, and potentially other requested Claims.
    pub(crate) id_token: String,

    // pub id_token_decoded: IdToken,
    /// Access token. Allows access to resources requiring authentication unless expired.
    pub(crate) access_token: AccessToken,

    /// Point in time when the `access_token` expires.
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) access_token_expires_at: OffsetDateTime,

    /// Refresh token. May be used to obtain a new access token without user intervention.
    pub(crate) refresh_token: String,

    /// Point in time when the `refresh_token` expires.
    #[serde(with = "time::serde::rfc3339::option")]
    pub(crate) refresh_expires_at: Option<OffsetDateTime>,

    /// Point in time this token data was read.
    /// This may be used to calculate an estimated lifetime of the refresh or access token.
    /// If `refresh_expires_at` is after `time_received`, it was valid when the token data was received.
    /// At all later points in time, this may be used to calculate a percentage of the refresh tokens expiration time.
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) time_received: OffsetDateTime,

    /// The grant type used to request this token data.
    ///
    /// Can inform whether this token data originated from a token refresh or an initial request.
    pub(crate) grant_type: GrantType,

    /// The discovery endpoint used to query this information.
    /// This OIDC config data immediately becomes invalid if we no longer work with that source,
    /// e.g. the app was reconfigured to use a different authentication provider!
    /// We see any change in the url, be it host, port, realm, ... as a potentially completely
    /// different provider for which the already known / cached information is no longer applicable.
    pub(crate) source: Url,
}

impl TokenData {
    pub(crate) fn from_token_response(
        success_token_response: SuccessTokenResponse,
        grant_type: GrantType,
        discovery_endpoint: DiscoveryEndpoint,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id_token: success_token_response.id_token,
            access_token: success_token_response.access_token,
            access_token_expires_at: now + Duration::seconds(success_token_response.expires_in),
            refresh_token: success_token_response.refresh_token,
            refresh_expires_at: success_token_response
                .refresh_expires_in
                .map(|refresh_expires_in| now + Duration::seconds(refresh_expires_in)),
            time_received: now,
            grant_type,
            source: discovery_endpoint,
        }
    }

    /// # Returns
    /// A negative duration should the expiration time lay in the past.
    pub(crate) fn access_token_time_left(&self) -> Duration {
        self.access_token_expires_at - OffsetDateTime::now_utc()
    }

    pub(crate) fn estimated_access_token_lifetime(&self) -> Duration {
        self.access_token_expires_at - self.time_received
    }

    pub(crate) fn refresh_token_time_left(&self) -> Option<Duration> {
        self.refresh_expires_at
            .as_ref()
            .map(|expires_in| *expires_in - OffsetDateTime::now_utc())
    }

    pub(crate) fn estimated_refresh_token_lifetime(&self) -> Option<Duration> {
        self.refresh_expires_at
            .as_ref()
            .map(|expires_in| *expires_in - self.time_received)
    }
}

#[cfg(test)]
mod tests {
    use assertr::prelude::*;
    use time::Duration;

    use super::*;

    fn make_token_data(
        access_expires_in_secs: i64,
        refresh_expires_in_secs: Option<i64>,
    ) -> TokenData {
        let now = OffsetDateTime::now_utc();
        TokenData {
            id_token: "test-id-token".to_string(),
            access_token: "test-access-token".to_string(),
            access_token_expires_at: now + Duration::seconds(access_expires_in_secs),
            refresh_token: "test-refresh-token".to_string(),
            refresh_expires_at: refresh_expires_in_secs.map(|s| now + Duration::seconds(s)),
            time_received: now,
            grant_type: GrantType::AuthorizationCode,
            source: Url::parse(
                "https://keycloak.example.com/realms/test/.well-known/openid-configuration",
            )
            .unwrap(),
        }
    }

    #[test]
    fn access_token_time_left_positive_when_not_expired() {
        let token = make_token_data(300, None);
        let left = token.access_token_time_left();
        // Should be close to 300 seconds (within a reasonable margin for test execution time).
        assert_that(left.whole_seconds()).is_greater_or_equal_to(299);
    }

    #[test]
    fn access_token_time_left_negative_when_expired() {
        let now = OffsetDateTime::now_utc();
        let token = TokenData {
            id_token: "test".to_string(),
            access_token: "test".to_string(),
            access_token_expires_at: now - Duration::seconds(10),
            refresh_token: "test".to_string(),
            refresh_expires_at: None,
            time_received: now - Duration::seconds(310),
            grant_type: GrantType::AuthorizationCode,
            source: Url::parse("https://example.com").unwrap(),
        };
        let left = token.access_token_time_left();
        assert_that(left.whole_seconds()).is_less_than(0);
    }

    #[test]
    fn estimated_access_token_lifetime() {
        let token = make_token_data(300, None);
        let lifetime = token.estimated_access_token_lifetime();
        assert_that(lifetime.whole_seconds()).is_equal_to(300);
    }

    #[test]
    fn refresh_token_time_left_some_when_present() {
        let token = make_token_data(300, Some(1800));
        let left = token.refresh_token_time_left();
        assert_that(left).is_some();
        assert_that(left.unwrap().whole_seconds()).is_greater_or_equal_to(1799);
    }

    #[test]
    fn refresh_token_time_left_none_when_absent() {
        let token = make_token_data(300, None);
        let left = token.refresh_token_time_left();
        assert_that(left).is_none();
    }

    #[test]
    fn estimated_refresh_token_lifetime_some_when_present() {
        let token = make_token_data(300, Some(1800));
        let lifetime = token.estimated_refresh_token_lifetime();
        assert_that(lifetime).is_some();
        assert_that(lifetime.unwrap().whole_seconds()).is_equal_to(1800);
    }

    #[test]
    fn estimated_refresh_token_lifetime_none_when_absent() {
        let token = make_token_data(300, None);
        let lifetime = token.estimated_refresh_token_lifetime();
        assert_that(lifetime).is_none();
    }

    #[test]
    fn from_token_response() {
        use crate::response::SuccessTokenResponse;
        let response = SuccessTokenResponse {
            access_token: "at".to_string(),
            expires_in: 300,
            refresh_expires_in: Some(1800),
            refresh_token: "rt".to_string(),
            token_type: Some("Bearer".to_string()),
            id_token: "idt".to_string(),
            not_before_policy: None,
            session_state: None,
            scope: Some("openid".to_string()),
        };
        let discovery = Url::parse("https://example.com/.well-known/openid-configuration").unwrap();
        let token = TokenData::from_token_response(
            response,
            GrantType::AuthorizationCode,
            discovery.clone(),
        );

        assert_that(token.access_token.as_str()).is_equal_to("at");
        assert_that(token.refresh_token.as_str()).is_equal_to("rt");
        assert_that(token.id_token.as_str()).is_equal_to("idt");
        assert_that(token.grant_type).is_equal_to(GrantType::AuthorizationCode);
        assert_that(token.source).is_equal_to(discovery);
        assert_that(token.refresh_expires_at).is_some();
    }
}
