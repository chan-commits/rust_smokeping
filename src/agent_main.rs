mod agent;
mod logging;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init_logging("/tmp/rust_smokeping_agent.log");

    let server_url = std::env::var("SMOKEPING_SERVER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let agent_id = std::env::var("SMOKEPING_AGENT_ID").unwrap_or_else(|_| "agent-1".to_string());
    let agent_ip = std::env::var("SMOKEPING_AGENT_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
    let base_path =
        std::env::var("SMOKEPING_BASE_PATH").unwrap_or_else(|_| "/smokeping".to_string());
    let auth_username = std::env::var("SMOKEPING_AUTH_USERNAME").ok();
    let auth_password = std::env::var("SMOKEPING_AUTH_PASSWORD").ok();

    agent::run(
        server_url,
        agent_id,
        agent_ip,
        base_path,
        auth_username,
        auth_password,
    )
    .await
}
