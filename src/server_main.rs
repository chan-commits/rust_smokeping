mod frontend;
mod server;
mod logging;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init_logging("/tmp/rust_smokeping_server.log");

    let database_url =
        std::env::var("SMOKEPING_DATABASE_URL").unwrap_or_else(|_| "smokeping.db".to_string());
    let bind =
        std::env::var("SMOKEPING_SERVER_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let auth_file =
        std::env::var("SMOKEPING_AUTH_FILE").unwrap_or_else(|_| ".smokeping_auth.json".to_string());
    let base_path =
        std::env::var("SMOKEPING_BASE_PATH").unwrap_or_else(|_| "/smokeping".to_string());

    server::run(database_url, bind, auth_file, base_path).await
}
