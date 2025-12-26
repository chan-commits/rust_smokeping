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
    },
    Agent {
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        server_url: String,
        #[arg(long, default_value = "agent-1")]
        agent_id: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Server { database_url, bind } => {
            server::run(database_url, bind).await
        }
        Commands::Agent {
            server_url,
            agent_id,
        } => agent::run(server_url, agent_id).await,
    }
}
