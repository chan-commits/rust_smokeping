use anyhow::Context;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;

#[derive(Deserialize)]
struct Target {
    id: i64,
    address: String,
}

#[derive(Deserialize)]
struct Config {
    interval_seconds: i64,
    timeout_seconds: i64,
}

#[derive(Serialize)]
struct MeasurementInput {
    target_id: i64,
    avg_ms: Option<f64>,
    packet_loss: Option<f64>,
    success: bool,
    mtr: String,
    traceroute: String,
    timestamp: DateTime<Utc>,
}

pub async fn run(server_url: String, agent_id: String) -> anyhow::Result<()> {
    tracing::info!("agent {} starting", agent_id);
    let client = Client::new();

    loop {
        let config = fetch_config(&client, &server_url).await?;
        let targets = fetch_targets(&client, &server_url).await?;

        for target in targets {
            let timestamp = Utc::now();
            let (success, avg_ms, packet_loss) = run_ping(&target.address, config.timeout_seconds).await;
            let mtr = run_mtr(&target.address).await.unwrap_or_else(|e| e.to_string());
            let traceroute = run_traceroute(&target.address).await.unwrap_or_else(|e| e.to_string());

            let payload = MeasurementInput {
                target_id: target.id,
                avg_ms,
                packet_loss,
                success,
                mtr,
                traceroute,
                timestamp,
            };

            post_measurement(&client, &server_url, payload).await?;
        }

        tokio::time::sleep(Duration::from_secs(config.interval_seconds as u64)).await;
    }
}

async fn fetch_config(client: &Client, server_url: &str) -> anyhow::Result<Config> {
    let url = format!("{}/api/config", server_url.trim_end_matches('/'));
    let config = client.get(url).send().await?.json().await?;
    Ok(config)
}

async fn fetch_targets(client: &Client, server_url: &str) -> anyhow::Result<Vec<Target>> {
    let url = format!("{}/api/targets", server_url.trim_end_matches('/'));
    let targets = client.get(url).send().await?.json().await?;
    Ok(targets)
}

async fn post_measurement(
    client: &Client,
    server_url: &str,
    payload: MeasurementInput,
) -> anyhow::Result<()> {
    let url = format!("{}/api/measurements", server_url.trim_end_matches('/'));
    client.post(url).json(&payload).send().await?.error_for_status()?;
    Ok(())
}

async fn run_ping(address: &str, timeout_seconds: i64) -> (bool, Option<f64>, Option<f64>) {
    let output = Command::new("ping")
        .arg("-c")
        .arg("4")
        .arg("-W")
        .arg(timeout_seconds.to_string())
        .arg(address)
        .output()
        .await;

    let output = match output {
        Ok(output) => output,
        Err(_) => return (false, None, None),
    };

    if !output.status.success() {
        return (false, None, None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut avg_ms = None;
    let mut packet_loss = None;
    for line in stdout.lines() {
        if line.contains("packet loss") {
            if let Some(loss) = line.split(',').nth(2) {
                let loss = loss.trim().split('%').next().unwrap_or("");
                packet_loss = loss.parse::<f64>().ok();
            }
        }
        if line.contains("min/avg") {
            if let Some(stats) = line.split('=').nth(1) {
                let avg = stats.split('/').nth(1).unwrap_or("");
                avg_ms = avg.trim().parse::<f64>().ok();
            }
        }
    }

    (true, avg_ms, packet_loss)
}

async fn run_mtr(address: &str) -> anyhow::Result<String> {
    let output = Command::new("mtr")
        .arg("-rwzbc")
        .arg("10")
        .arg(address)
        .output()
        .await
        .context("mtr failed to execute")?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

async fn run_traceroute(address: &str) -> anyhow::Result<String> {
    let output = Command::new("traceroute")
        .arg(address)
        .output()
        .await
        .context("traceroute failed to execute")?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

