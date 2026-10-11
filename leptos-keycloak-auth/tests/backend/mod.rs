use std::time::Duration;

use axum::{Extension, Json, Router, response::Response, routing::get};
use axum_keycloak_auth::{
    PassthroughMode,
    decode::KeycloakToken,
    instance::{KeycloakAuthInstance, KeycloakConfig},
    layer::KeycloakAuthLayer,
};
use http::{Method, StatusCode, header};
use serde::Serialize;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    timeout::TimeoutLayer,
    trace::{DefaultMakeSpan, TraceLayer},
};
use tracing::{Level, Span};
use url::Url;

use crate::{REALM, frontend};

/// The backend's port. Must match `API_PORT` in the test-frontend's `.env.template`, which the
/// frontend compiles in.
const PORT: u16 = 9999;

/// Start the backend. It serves until the test ends.
pub async fn start(keycloak_url: Url) {
    let keycloak_auth_instance = KeycloakAuthInstance::new(
        KeycloakConfig::builder()
            .server(keycloak_url)
            .realm(REALM.to_owned())
            .build(),
    );

    // The earlier layers of a ServiceBuilder are the OUTERMOST ones, seeing a request first.
    let router = Router::new().route("/who-am-i", get(who_am_i)).layer(
        ServiceBuilder::new()
            // Outermost, to trace the whole request handling, including all other middleware.
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
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                Duration::from_secs(10),
            ))
            // Before authentication, to answer preflight requests, which carry no token.
            .layer(
                CorsLayer::new()
                    .allow_origin(AllowOrigin::exact(
                        frontend::origin()
                            .parse()
                            .expect("Parsing the frontend origin"),
                    ))
                    .allow_methods([Method::GET])
                    .allow_headers([header::AUTHORIZATION, header::ACCEPT]),
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

    let listener = TcpListener::bind(("127.0.0.1", PORT))
        .await
        .expect("Binding the backend's listener");

    tokio::spawn(async move {
        tracing::info!("Serving test backend on port {PORT}...");
        axum::serve(listener, router)
            .await
            .expect("Serving the test backend");
    });
}

#[derive(Debug, Serialize)]
struct WhoAmI {
    username: String,
    keycloak_uuid: uuid::Uuid,
    token_valid_for_whole_seconds: i64,
}

async fn who_am_i(Extension(token): Extension<KeycloakToken<String>>) -> Json<WhoAmI> {
    Json(WhoAmI {
        username: token.extra.profile.preferred_username,
        keycloak_uuid: uuid::Uuid::try_parse(&token.subject).expect("Parsing the subject as UUID"),
        token_valid_for_whole_seconds: (token.expires_at - time::OffsetDateTime::now_utc())
            .whole_seconds(),
    })
}
