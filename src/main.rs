#![recursion_limit = "512"]

#[cfg(feature = "ssr")]
mod server_main {
    use leptos::prelude::*;

    pub async fn run() {
        dotenvy::dotenv().ok();
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        tracing_subscriber::fmt().with_env_filter(filter).init();

        let conf = get_configuration(None).expect("failed to read Leptos configuration");
        let addr = conf.leptos_options.site_addr;

        let app = time_tracking_leptos::test_support::router().await;

        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .expect("failed to bind listen address");
        tracing::info!("listening on http://{addr}");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("server error");
    }
}

#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    server_main::run().await;
}

#[cfg(not(feature = "ssr"))]
fn main() {
    // The wasm bundle's entrypoint is `lib::hydrate`, not this.
}
