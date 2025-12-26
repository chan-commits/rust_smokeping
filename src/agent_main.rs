mod agent;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let server_url = std::env::var("SMOKEPING_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let agent_id = std::env::var("SMOKEPING_AGENT_ID").unwrap_or_else(|_| "agent-1".to_string());
    let agent_ip = std::env::var("SMOKEPING_AGENT_IP").unwrap_or_else(|_| "127.0.0.1".to_string());

    agent::run(server_url, agent_id, agent_ip).await
}
