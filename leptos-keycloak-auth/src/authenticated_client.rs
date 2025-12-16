use crate::{Authenticated, RequestAction};
use http::StatusCode;
use leptos::prelude::ReadUntracked;

#[derive(Debug, Clone)]
pub struct AuthenticatedClient {
    client: reqwest::Client,
    auth: Authenticated,
}

impl AuthenticatedClient {
    pub(crate) fn new(client: reqwest::Client, auth: Authenticated) -> Self {
        Self { client, auth }
    }

    fn create_request(
        &self,
        method: reqwest::Method,
        url: impl reqwest::IntoUrl,
        with: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
        access_token: &str,
    ) -> Result<reqwest::Request, reqwest::Error> {
        let mut req_builder = self.client.request(method, url);

        // Let the user build the request.
        req_builder = with(req_builder);

        // Add the access token in an `AUTHORIZATION` header.
        req_builder = req_builder.bearer_auth(access_token);

        req_builder.build()
    }

    pub async fn get(
        &self,
        url: impl reqwest::IntoUrl + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.get_with(url, |builder| builder).await
    }

    pub async fn get_with(
        &self,
        url: impl reqwest::IntoUrl + Clone,
        with: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.request(reqwest::Method::GET, url, with).await
    }

    pub async fn post(
        &self,
        url: impl reqwest::IntoUrl + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.post_with(url, |builder| builder).await
    }

    pub async fn post_with(
        &self,
        url: impl reqwest::IntoUrl + Clone,
        with: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.request(reqwest::Method::POST, url, with).await
    }

    pub async fn put(
        &self,
        url: impl reqwest::IntoUrl + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.put_with(url, |builder| builder).await
    }

    pub async fn put_with(
        &self,
        url: impl reqwest::IntoUrl + Clone,
        with: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.request(reqwest::Method::PUT, url, with).await
    }

    pub async fn patch(
        &self,
        url: impl reqwest::IntoUrl + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.patch_with(url, |builder| builder).await
    }

    pub async fn patch_with(
        &self,
        url: impl reqwest::IntoUrl + Clone,
        with: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.request(reqwest::Method::PATCH, url, with).await
    }

    pub async fn delete(
        &self,
        url: impl reqwest::IntoUrl + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.delete_with(url, |builder| builder).await
    }

    pub async fn delete_with(
        &self,
        url: impl reqwest::IntoUrl + Clone,
        with: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.request(reqwest::Method::DELETE, url, with).await
    }

    /// Performs a request while automatically setting the `access_token` as an AUTHORIZATION header.
    ///
    /// Handles responses failing with a 401 status code (UNAUTHORIZED), by triggering
    /// a background token refresh and silently retrying the request afterwards.
    pub async fn request(
        &self,
        method: reqwest::Method,
        url: impl reqwest::IntoUrl + Clone,
        with: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let req = self.create_request(
            method.clone(),
            url.clone(),
            with.clone(),
            self.auth.access_token.read_untracked().as_str(),
        )?;
        let resp = self.client.execute(req).await?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            // When a 401 occurs despite having a valid (non-expired, decodable) token,
            // it could mean that:
            // - the token was revoked on Keycloak side (admin action, password change).
            // - the token rotation/invalidation happened due to a security event.
            // - the users session was terminated server-side.
            // - the token was blacklisted for suspicious activity.
            // We should try to refresh the token and retry the request.
            // If that try fails as well, we deem the user unauthenticated
            // and consider him logged out in the process.
            match self.auth.report_failed_http_request(resp.status()) {
                RequestAction::Retry => {
                    // New token is now available. Retry the request.
                    let req2 = self.create_request(
                        method,
                        url,
                        with,
                        self.auth.access_token.read_untracked().as_str(),
                    )?;
                    let resp2 = self.client.execute(req2).await?;
                    Ok(resp2)
                }
                RequestAction::Fail => {
                    // Nothing to do here. Request cannot be retried.
                    Ok(resp)
                }
            }
        } else {
            Ok(resp)
        }
    }
}
