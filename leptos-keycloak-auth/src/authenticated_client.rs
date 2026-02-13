use http::StatusCode;
use leptos::prelude::{Callable, ReadUntracked};

use crate::Authenticated;

/// HTTP client with automatic access token injection and token refresh on 401 responses.
///
/// This client wraps a `reqwest::Client` and provides the same HTTP methods to issue GET, POST,
/// PUT, PATCH and DELETE requests with two key enhancements:
///
/// 1. **Automatic Token Injection**: All requests automatically include the current access token in
///    the `Authorization` header as a Bearer token.
///
/// 2. **Automatic Retry on 401**: When a request receives a 401 Unauthorized response, the client
///    automatically attempts to refresh the access token and retry the request once. This handles
///    scenarios where tokens are revoked, rotated, or expired on the Keycloak side, which are
///    not covered by our periodic client-side token refreshes. This vastly improves the user
///    (developer) experience, as no retries must be implemented explicitly, making access token
///    handling fully transparent.
///
/// Create an instance using [`Authenticated::client()`] or [`Authenticated::client_from()`].
///
/// # Example
/// ```no_run
/// # use leptos_keycloak_auth::use_authenticated;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let client = use_authenticated().client();
/// let response = client.get("https://api.example.com/protected-resource").await?;
/// # Ok(())
/// # }
/// ```
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

    /// Perform a GET request with automatic token injection.
    ///
    /// The access token is automatically added to the `Authorization` header as a Bearer token.
    /// If the request receives a 401 response, the token will be refreshed and the request retried
    /// once.
    ///
    /// # Parameters
    /// - `url`: The URL to send the GET request to.
    ///
    /// # Returns
    /// The HTTP response from the server.
    ///
    /// # Errors
    /// Returns an error if the request fails due to network issues, invalid URL,
    /// or other `reqwest` errors.
    ///
    /// # Example
    /// ```no_run
    /// # use leptos_keycloak_auth::use_authenticated;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = use_authenticated().client();
    ///
    /// let response = client.get("https://api.example.com/protected-resource").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get(
        &self,
        url: impl reqwest::IntoUrl + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.get_with(url, |builder| builder).await
    }

    /// Perform a GET request with automatic token injection and custom request configuration.
    ///
    /// Similar to [`get`](Self::get), but allows you to customize the request using a builder
    /// function. Use this to add custom headers, query parameters, timeouts, or other request
    /// configuration.
    ///
    /// # Parameters
    /// - `url`: The URL to send the GET request to.
    /// - `with`: A function getting passed the `RequestBuilder` for modification.
    ///
    /// # Errors
    /// Returns an error if the request fails due to network issues, invalid URL, or other `reqwest`
    /// errors.
    ///
    /// # Example
    /// ```no_run
    /// # use leptos_keycloak_auth::use_authenticated;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = use_authenticated().client();
    ///
    /// let response = client
    ///     .get_with("https://api.example.com/protected-resource", |builder| {
    ///         builder
    ///             .query(&[("limit", "10"), ("offset", "0")])
    ///             .header(http::header::ACCEPT, "application/json")
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_with(
        &self,
        url: impl reqwest::IntoUrl + Clone,
        with: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.request(reqwest::Method::GET, url, with).await
    }

    /// Perform a POST request with automatic token injection.
    ///
    /// The access token is automatically added to the `Authorization` header as a Bearer token.
    /// If the request receives a 401 response, the token will be refreshed and the request retried
    /// once.
    ///
    /// # Parameters
    /// - `url`: The URL to send the POST request to.
    ///
    /// # Errors
    /// Returns an error if the request fails due to network issues, invalid URL, or other `reqwest`
    /// errors.
    ///
    /// # Example
    /// ```no_run
    /// # use leptos_keycloak_auth::use_authenticated;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = use_authenticated().client();
    ///
    /// // For POST with body, use post_with instead!
    /// let response = client.post("https://api.example.com/trigger-protected-action").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn post(
        &self,
        url: impl reqwest::IntoUrl + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.post_with(url, |builder| builder).await
    }

    /// Perform a POST request with custom request builder configuration.
    ///
    /// Similar to [`post`](Self::post), but allows you to customize the request using a builder
    /// function. Use this to set the request body (JSON, form data, etc.), headers, or other configuration.
    ///
    /// # Parameters
    /// - `url`: The URL to send the POST request to.
    /// - `with`: A function getting passed the `RequestBuilder` for modification.
    ///
    /// # Errors
    /// Returns an error if the request fails due to network issues, invalid URL, or other `reqwest`
    /// errors.
    ///
    /// # Example
    /// ```no_run
    /// # use leptos_keycloak_auth::use_authenticated;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = use_authenticated().client();
    ///
    /// #[derive(serde::Serialize)]
    /// struct CreateResource { name: String }
    /// let new = CreateResource { name: "Bob".to_string() };
    ///
    /// let response = client
    ///     .post_with("https://api.example.com/protected-resource", |builder| {
    ///         builder.json(&new)
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn post_with(
        &self,
        url: impl reqwest::IntoUrl + Clone,
        with: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.request(reqwest::Method::POST, url, with).await
    }

    /// Perform a PUT request with automatic token injection.
    ///
    /// The access token is automatically added to the `Authorization` header as a Bearer token.
    /// If the request receives a 401 response, the token will be refreshed and the request retried
    /// once.
    ///
    /// # Parameters
    /// - `url`: The URL to send the PUT request to.
    ///
    /// # Errors
    /// Returns an error if the request fails due to network issues, invalid URL, or other `reqwest`
    /// errors.
    ///
    /// # Example
    /// ```no_run
    /// # use leptos_keycloak_auth::use_authenticated;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = use_authenticated().client();
    ///
    /// // For PUT with body, use put_with instead!
    /// let response = client.put("https://api.example.com/resource/123").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn put(
        &self,
        url: impl reqwest::IntoUrl + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.put_with(url, |builder| builder).await
    }

    /// Perform a PUT request with custom request builder configuration.
    ///
    /// Similar to [`put`](Self::put), but allows you to customize the request using a builder
    /// function. Use this to set the request body, headers, or other configuration.
    ///
    /// # Parameters
    /// - `url`: The URL to send the PUT request to.
    /// - `with`: A function getting passed the `RequestBuilder` for modification.
    ///
    /// # Errors
    /// Returns an error if the request fails due to network issues, invalid URL, or other `reqwest`
    /// errors.
    ///
    /// # Example
    /// ```no_run
    /// # use leptos_keycloak_auth::use_authenticated;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = use_authenticated().client();
    ///
    /// #[derive(serde::Serialize)]
    /// struct Update { name: String }
    /// let update = Update { name: "Bob".to_string() };
    ///
    /// let response = client
    ///     .put_with("https://api.example.com/protected-resource/42", |builder: reqwest::RequestBuilder| {
    ///         builder.json(&update)
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn put_with(
        &self,
        url: impl reqwest::IntoUrl + Clone,
        with: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.request(reqwest::Method::PUT, url, with).await
    }

    /// Perform a PATCH request with automatic token injection.
    ///
    /// The access token is automatically added to the `Authorization` header as a Bearer token.
    /// If the request receives a 401 response, the token will be refreshed and the request retried
    /// once.
    ///
    /// # Parameters
    /// - `url`: The URL to send the PATCH request to.
    ///
    /// # Errors
    /// Returns an error if the request fails due to network issues, invalid URL, or other `reqwest`
    /// errors.
    ///
    /// # Example
    /// ```no_run
    /// # use leptos_keycloak_auth::use_authenticated;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = use_authenticated().client();
    ///
    /// // For PATCH with body, use patch_with instead!
    /// let response = client.patch("https://api.example.com/protected-resource/42").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn patch(
        &self,
        url: impl reqwest::IntoUrl + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.patch_with(url, |builder| builder).await
    }

    /// Perform a PATCH request with custom request builder configuration.
    ///
    /// Similar to [`patch`](Self::patch), but allows you to customize the request using a builder
    /// function. Use this to set the request body (typically a partial update), headers, or other
    /// configuration.
    ///
    /// # Parameters
    /// - `url`: The URL to send the PATCH request to.
    /// - `with`: A function getting passed the `RequestBuilder` for modification.
    ///
    /// # Errors
    /// Returns an error if the request fails due to network issues, invalid URL, or other `reqwest`
    /// errors.
    ///
    /// # Example
    /// ```no_run
    /// # use leptos::prelude::*;
    /// # use leptos_keycloak_auth::use_authenticated;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = use_authenticated().client();
    ///
    /// #[derive(serde::Serialize)]
    /// struct PartialUpdate { name: Option<String> }
    /// let partial = PartialUpdate { name: Some("Bob".to_string()) };
    ///
    /// let response = client
    ///     .patch_with("https://api.example.com/protected-resource/42", |builder| {
    ///         builder.json(&partial)
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn patch_with(
        &self,
        url: impl reqwest::IntoUrl + Clone,
        with: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.request(reqwest::Method::PATCH, url, with).await
    }

    /// Perform a DELETE request with automatic token injection.
    ///
    /// The access token is automatically added to the `Authorization` header as a Bearer token.
    /// If the request receives a 401 response, the token will be refreshed and the request retried
    /// once.
    ///
    /// # Parameters
    /// - `url`: The URL to send the DELETE request to.
    ///
    /// # Errors
    /// Returns an error if the request fails due to network issues, invalid URL, or other `reqwest`
    /// errors.
    ///
    /// # Example
    /// ```no_run
    /// # use leptos::prelude::*;
    /// # use leptos_keycloak_auth::use_authenticated;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = use_authenticated().client();
    ///
    /// let response = client.delete("https://api.example.com/protected-resource/42").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn delete(
        &self,
        url: impl reqwest::IntoUrl + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.delete_with(url, |builder| builder).await
    }

    /// Perform a DELETE request with custom request builder configuration.
    ///
    /// Similar to [`delete`](Self::delete), but allows you to customize the request using a builder
    /// function. Use this to add custom headers or other configuration.
    ///
    /// # Parameters
    /// - `url`: The URL to send the DELETE request to.
    /// - `with`: A function getting passed the `RequestBuilder` for modification.
    ///
    /// # Errors
    /// Returns an error if the request fails due to network issues, invalid URL, or other `reqwest`
    /// errors.
    ///
    /// # Example
    /// ```no_run
    /// # use leptos_keycloak_auth::use_authenticated;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = use_authenticated().client();
    ///
    /// let response = client
    ///     .delete_with("https://api.example.com/protected-resource/42", |builder| {
    ///         builder.header("X-Reason", "Deletion requested for reason: ...s")
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn delete_with(
        &self,
        url: impl reqwest::IntoUrl + Clone,
        with: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder + Clone,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.request(reqwest::Method::DELETE, url, with).await
    }

    /// Performs a request while automatically setting the `access_token` as an AUTHORIZATION header.
    ///
    /// Handles responses failing with a 401 status code (UNAUTHORIZED) by directly refreshing
    /// the access token and retrying the request once.
    ///
    /// # Errors
    /// Returns an error if the request fails due to network issues, invalid URL, or other `reqwest`
    /// errors.
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
            // We directly refresh the token and retry the request once.

            match self.auth.refresh_context.try_refresh().await {
                Some(Ok(())) => {
                    // Retry the request with the fresh token.
                    let req2 = self.create_request(
                        method,
                        url,
                        with,
                        self.auth.access_token.read_untracked().as_str(),
                    )?;
                    let resp2 = self.client.execute(req2).await?;
                    Ok(resp2)
                }
                Some(Err(err)) => {
                    tracing::warn!(?err, "Token refresh on 401 failed. Logging user out.");
                    // Drop token data — effectively logs the user out.
                    self.auth.refresh_context.update_token.run(None);
                    Ok(resp)
                }
                None => {
                    // Can't refresh — no refresh token, no endpoint, or stale session.
                    Ok(resp)
                }
            }
        } else {
            Ok(resp)
        }
    }
}
