use axum::{
    Extension, Json, Router,
    response::{IntoResponse, Response},
    routing::get,
};
use axum_keycloak_auth::{
    PassthroughMode,
    decode::KeycloakToken,
    instance::{KeycloakAuthInstance, KeycloakConfig},
    layer::KeycloakAuthLayer,
};
use http::header::{ACCEPT, AUTHORIZATION};
use http::{Method, StatusCode};
use serde::Serialize;
use std::time::Duration;
use tokio::{net::TcpListener, task::JoinHandle};
use tower::ServiceBuilder;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::sensitive_headers::{
    SetSensitiveRequestHeadersLayer, SetSensitiveResponseHeadersLayer,
};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::{Level, Span};
use url::Url;

pub async fn start_axum_backend(keycloak_url: Url, realm: String) -> JoinHandle<()> {
    let keycloak_auth_instance = KeycloakAuthInstance::new(
        KeycloakConfig::builder()
            .server(keycloak_url)
            .realm(realm)
            .build(),
    );

    let router = Router::new().route("/who-am-i", get(who_am_i));

    let router = router.layer(
        // NOTE: The earlier layers of a ServiceBuilder are the OUTERMOST ones, and executed first.
        // The later layers are the INNERMOST ones, and executed last when receiving a request.
        // This differs to adding one layer at a time to a router, where the first ones ore INNERMOST.
        ServiceBuilder::new()
            // Add high level tracing to all requests.
            // Tracing as innermost layer so it can capture the request after / response before
            // (including) all other middleware.
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
            // Sensitive headers should be set before tracing to ensure
            // sensitive data doesn't leak into logs.
            .layer(SetSensitiveRequestHeadersLayer::new([
                http::header::AUTHORIZATION,
                http::header::COOKIE,
            ]))
            .layer(SetSensitiveResponseHeadersLayer::new([]))
            // Timeout should be near the bottom to ensure the entire
            // request pipeline respects the timeout.
            .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(10)))
            // CORS should usually be early to handle preflight requests
            // before other middleware.
            .layer(
                CorsLayer::new()
                    .allow_origin(AllowOrigin::list(vec![
                        "http://127.0.0.1:3000".parse().expect("valid url"),
                    ]))
                    .allow_methods([Method::GET, Method::POST])
                    .allow_headers([AUTHORIZATION, ACCEPT])
                    .allow_credentials(true),
            )
            .layer(
                KeycloakAuthLayer::<String>::builder()
                    .instance(keycloak_auth_instance)
                    .passthrough_mode(PassthroughMode::Block)
                    .expected_audiences(vec![])
                    .persist_raw_claims(false)
                    .build(),
            ),
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
        username: String,
        keycloak_uuid: uuid::Uuid,
        token_valid_for_whole_seconds: i64,
    }

    (
        StatusCode::OK,
        Json(Response {
            username: token.extra.profile.preferred_username,
            keycloak_uuid: uuid::Uuid::try_parse(&token.subject).expect("uuid"),
            token_valid_for_whole_seconds: (token.expires_at - time::OffsetDateTime::now_utc())
                .whole_seconds(),
        }),
    )
        .into_response()
}
