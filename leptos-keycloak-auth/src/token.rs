use crate::response::SuccessTokenResponse;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

/// A structure representing the storage of authentication tokens.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct TokenData {
    /// The ID Token is a security token that contains Claims about the Authentication of an End-User by an Authorization Server when using a Client, and potentially other requested Claims.
    pub(crate) id_token: String,

    // pub id_token_decoded: IdToken,
    /// Access token. Allows access to resources requiring authentication unless expired.
    pub(crate) access_token: String,

    /// Point in time when the `access_token` expires.
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) access_token_expires_at: OffsetDateTime,

    /// Refresh token. May be used to obtain a new access token without user intervention.
    pub(crate) refresh_token: String,

    /// Point in time when the `refresh_toke` expires.
    #[serde(with = "time::serde::rfc3339::option")]
    pub(crate) refresh_expires_at: Option<OffsetDateTime>,

    /// Point in time this token data was read.
    /// This may be used to calculate an estimated lifetime of the refresh or access token.
    /// If `refresh_expires_at` is after `time_received`, it was valid when the token data was received.
    /// At all later points in time, this may be used to calculate a percentage of the refresh tokens expiration time.
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) time_received: OffsetDateTime,
}

impl TokenData {
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

impl From<SuccessTokenResponse> for TokenData {
    fn from(value: SuccessTokenResponse) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id_token: value.id_token,
            access_token: value.access_token,
            access_token_expires_at: now + Duration::seconds(value.expires_in),
            refresh_token: value.refresh_token,
            refresh_expires_at: value
                .refresh_expires_in
                .map(|refresh_expires_in| now + Duration::seconds(refresh_expires_in)),
            time_received: now,
        }
    }
}
