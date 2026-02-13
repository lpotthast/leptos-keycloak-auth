#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    use axum::Router;
    use frontend::app::*;
    use leptos::{logging::log, prelude::*};
    use leptos_axum::{LeptosRoutes, generate_route_list};
    use tracing_subscriber::{
        Layer, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
    };

    dotenvy::dotenv().unwrap();

    let log_filter = tracing_subscriber::filter::Targets::new()
        .with_default(tracing::Level::INFO)
        .with_target("tokio", tracing::Level::WARN)
        .with_target("runtime", tracing::Level::WARN);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .pretty()
        .with_file(true)
        .with_line_number(true)
        .with_ansi(true)
        .with_thread_names(false)
        .with_thread_ids(false);

    let fmt_layer_filtered = fmt_layer.with_filter(log_filter);

    tracing_subscriber::Registry::default()
        .with(fmt_layer_filtered)
        .init();

    let conf = get_configuration(None).unwrap();
    let addr = conf.leptos_options.site_addr;
    let leptos_options = conf.leptos_options;
    // Generate the list of routes in your Leptos App
    let routes = generate_route_list(App);

    let keycloak_port = std::env::var("KC_PORT")
        .expect("KC_PORT must be set")
        .parse::<u16>()
        .expect("KC_PORT to be a u16");
    tracing::info!(keycloak_port, "parsed KC_PORT");

    let app = Router::new()
        .leptos_routes(&leptos_options, routes, {
            let leptos_options = leptos_options.clone();
            move || shell(leptos_options.clone(), keycloak_port)
        })
        .fallback(leptos_axum::file_and_error_handler(move |options| {
            shell(options, keycloak_port)
        }))
        .with_state(leptos_options);

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    log!("listening on http://{}", &addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

#[cfg(not(feature = "ssr"))]
pub fn main() {
    // no client-side main function
    // unless we want this to work with e.g., Trunk for pure client-side testing
    // see lib.rs for hydration function instead
}
