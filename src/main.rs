use clap::{Parser, Subcommand};

mod agent;
mod server;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Server {
        #[arg(long, default_value = "smokeping.db")]
        database_url: String,
        #[arg(long, default_value = "0.0.0.0:8080")]
        bind: String,
        #[arg(long, default_value = ".smokeping_auth.json")]
        auth_file: String,
        #[arg(long, default_value = "/smokeping")]
        base_path: String,
    },
    Agent {
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        server_url: String,
        #[arg(long, default_value = "agent-1")]
        agent_id: String,
        #[arg(long, default_value = "127.0.0.1")]
        agent_ip: String,
        #[arg(long, default_value = "/smokeping")]
        base_path: String,
        #[arg(long)]
        auth_username: Option<String>,
        #[arg(long)]
        auth_password: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Server {
            database_url,
            bind,
            auth_file,
            base_path,
        } => server::run(database_url, bind, auth_file, base_path).await,
        Commands::Agent {
            server_url,
            agent_id,
            agent_ip,
            base_path,
            auth_username,
            auth_password,
        } => agent::run(
            server_url,
            agent_id,
            agent_ip,
            base_path,
            auth_username,
            auth_password,
        )
        .await,
    }
}
