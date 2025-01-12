use axum::{
    response::{IntoResponse, Response},
    routing::get,
    Extension, Json, Router,
};
use axum_keycloak_auth::{
    decode::KeycloakToken,
    instance::{KeycloakAuthInstance, KeycloakConfig},
    layer::KeycloakAuthLayer,
    PassthroughMode,
};
use http::StatusCode;
use serde::Serialize;
use std::time::Duration;
use tokio::{net::TcpListener, task::JoinHandle};
use tower::ServiceBuilder;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::sensitive_headers::{
    SetSensitiveRequestHeadersLayer, SetSensitiveResponseHeadersLayer,
};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::{Level, Span};
use url::Url;

pub struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn start_axum_backend(keycloak_url: Url, realm: String) -> JoinHandle<()> {
    let keycloak_auth_instance = KeycloakAuthInstance::new(
        KeycloakConfig::builder()
            .server(keycloak_url)
            .realm(realm)
            .build(),
    );

    let router = Router::new().route("/who-am-i", get(who_am_i));

    let router = router.layer(
        ServiceBuilder::new()
            // Mark the specific headers as sensitive so that they don't show up in logs.
            .layer(SetSensitiveRequestHeadersLayer::new([
                http::header::AUTHORIZATION,
                http::header::COOKIE,
            ]))
            .layer(SetSensitiveResponseHeadersLayer::new([]))
            // Add high level tracing to all requests.
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(
                        DefaultMakeSpan::new()
                            .level(Level::INFO)
                            .include_headers(false),
                    )
                    .on_response(|response: &Response, latency: Duration, _span: &Span| {
                        tracing::info!(
                            status = response.status().as_u16(),
                            latency = format_args!("{} ms", latency.as_millis()),
                            "response"
                        );
                    }),
            )
            // Set a timeout
            .layer(TimeoutLayer::new(Duration::from_secs(60)))
            // Allow origins using a CORS layers.
            .layer(
                CorsLayer::new()
                    .allow_origin(AllowOrigin::list(vec!["http://127.0.0.1:3000"
                        .parse()
                        .expect("valid url")]))
                    .allow_methods(Any)
                    .allow_headers(Any),
            ),
    );

    let router = router.layer(
        KeycloakAuthLayer::<String>::builder()
            .instance(keycloak_auth_instance)
            .passthrough_mode(PassthroughMode::Block)
            .expected_audiences(vec![String::from("account")])
            .persist_raw_claims(false)
            .build(),
    );

    let listener = TcpListener::bind("127.0.0.1:9999")
        .await
        .expect("TcpListener");

    let server_jh = tokio::spawn(async move {
        tracing::info!("Serving test backend...");
        axum::serve(listener, router.into_make_service())
            .await
            .expect("Server to start successfully");
        tracing::info!("Test backend stopped!");
    });

    server_jh
}

pub async fn who_am_i(Extension(token): Extension<KeycloakToken<String>>) -> Response {
    #[derive(Debug, Serialize)]
    struct Response {
        name: String,
        keycloak_uuid: uuid::Uuid,
        token_valid_for_whole_seconds: i64,
    }

    (
        StatusCode::OK,
        Json(Response {
            name: token.extra.profile.preferred_username,
            keycloak_uuid: uuid::Uuid::try_parse(&token.subject).expect("uuid"),
            token_valid_for_whole_seconds: (token.expires_at - time::OffsetDateTime::now_utc())
                .whole_seconds(),
        }),
    )
        .into_response()
}
