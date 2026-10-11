use tracing_subscriber::{Layer, filter::Targets, registry::LookupSpan};

/// Build the formatted log layer with the test-specific target filters.
pub fn fmt_layer<S>() -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    let log_filter = Targets::new()
        .with_default(tracing::Level::INFO)
        .with_target("tokio", tracing::Level::WARN)
        .with_target("axum", tracing::Level::WARN)
        .with_target("leptos_keycloak_auth", tracing::Level::TRACE)
        .with_target("axum_keycloak_auth", tracing::Level::DEBUG)
        .with_target("runtime", tracing::Level::WARN);

    tracing_subscriber::fmt::layer()
        .pretty()
        .with_test_writer()
        .with_file(true)
        .with_line_number(true)
        .with_ansi(true)
        .with_thread_names(false)
        .with_thread_ids(false)
        .with_filter(log_filter)
}
