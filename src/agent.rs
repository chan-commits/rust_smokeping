use anyhow::Context;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Child;
use tokio::process::Command;
use tokio::task::JoinSet;
use tokio::io::AsyncReadExt;

#[derive(Clone)]
struct AgentAuth {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct Target {
    id: i64,
    address: String,
}

#[derive(Deserialize, Clone)]
struct Config {
    interval_seconds: i64,
    timeout_seconds: i64,
    mtr_runs: i64,
    ping_runs: i64,
}

#[derive(Deserialize)]
struct AgentRegistration {
    id: i64,
}

#[derive(Serialize)]
struct MeasurementInput {
    target_id: i64,
    agent_id: i64,
    avg_ms: Option<f64>,
    packet_loss: Option<f64>,
    success: bool,
    mtr: String,
    traceroute: String,
    timestamp: DateTime<Utc>,
}

pub async fn run(
    server_url: String,
    agent_id: String,
    agent_ip: String,
    base_path: String,
    auth_username: Option<String>,
    auth_password: Option<String>,
) -> anyhow::Result<()> {
    tracing::info!("agent {} starting", agent_id);
    let client = Client::new();
    let mut auth = normalize_auth(auth_username, auth_password)?;
    let base_path = normalize_base_path(&base_path);
    let base_url = sanitize_server_url(server_url, &mut auth)?;
    let server_url = format!("{}{}", base_url, base_path);
    let agent_record = register_agent(&client, &server_url, &agent_id, &agent_ip, &auth).await?;

    loop {
        match run_cycle(&client, &server_url, &auth, agent_record.id).await {
            Ok(interval_seconds) => {
                tokio::time::sleep(Duration::from_secs(interval_seconds as u64)).await;
            }
            Err(err) => {
                tracing::warn!(error = %err, "agent cycle failed, retrying");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}

async fn run_cycle(
    client: &Client,
    server_url: &str,
    auth: &Option<AgentAuth>,
    agent_id: i64,
) -> anyhow::Result<i64> {
    let config = fetch_config(client, server_url, auth).await?;
    let targets = fetch_targets(client, server_url, auth).await?;
    let server_url = server_url.to_string();
    let auth = auth.clone();
    let mut join_set = JoinSet::new();

    for target in targets {
        let client = client.clone();
        let server_url = server_url.clone();
        let auth = auth.clone();
        let config = config.clone();
        join_set.spawn(async move {
            let timestamp = Utc::now();
            let (success, avg_ms, packet_loss) =
                run_ping(&target.address, config.timeout_seconds, config.ping_runs).await;
            let mtr = run_mtr(&target.address, config.mtr_runs, config.timeout_seconds)
                .await
                .unwrap_or_else(|e| e.to_string());
            let traceroute = run_traceroute(&target.address, config.timeout_seconds)
                .await
                .unwrap_or_else(|e| e.to_string());

            let payload = MeasurementInput {
                target_id: target.id,
                agent_id,
                avg_ms,
                packet_loss,
                success,
                mtr,
                traceroute,
                timestamp,
            };

            post_measurement(&client, &server_url, payload, &auth).await?;
            Ok::<_, anyhow::Error>(())
        });
    }

    while let Some(result) = join_set.join_next().await {
        result??;
    }

    Ok(config.interval_seconds)
}

fn normalize_base_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return String::new();
    }
    let mut path = trimmed.to_string();
    if !path.starts_with('/') {
        path = format!("/{}", path);
    }
    path.trim_end_matches('/').to_string()
}

fn normalize_auth(
    auth_username: Option<String>,
    auth_password: Option<String>,
) -> anyhow::Result<Option<AgentAuth>> {
    let username = auth_username.and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
    let password = auth_password.and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });

    match (username, password) {
        (Some(username), Some(password)) => Ok(Some(AgentAuth { username, password })),
        (None, None) => Ok(None),
        _ => anyhow::bail!(
            "both SMOKEPING_AUTH_USERNAME and SMOKEPING_AUTH_PASSWORD must be set together"
        ),
    }
}

fn sanitize_server_url(
    server_url: String,
    auth: &mut Option<AgentAuth>,
) -> anyhow::Result<String> {
    let mut parsed = reqwest::Url::parse(&server_url)
        .with_context(|| format!("invalid server url: {}", server_url))?;
    if auth.is_none() {
        let username = parsed.username();
        if !username.is_empty() {
            let Some(password) = parsed.password() else {
                anyhow::bail!(
                    "SMOKEPING_SERVER_URL includes a username but no password; \
provide both or use SMOKEPING_AUTH_USERNAME/SMOKEPING_AUTH_PASSWORD"
                );
            };
            *auth = Some(AgentAuth {
                username: username.to_string(),
                password: password.to_string(),
            });
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
        }
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

fn with_auth(
    builder: reqwest::RequestBuilder,
    auth: &Option<AgentAuth>,
) -> reqwest::RequestBuilder {
    if let Some(auth) = auth {
        builder.basic_auth(&auth.username, Some(&auth.password))
    } else {
        builder
    }
}

fn auth_hint(status: reqwest::StatusCode, auth: &Option<AgentAuth>) -> &'static str {
    if status != reqwest::StatusCode::UNAUTHORIZED {
        return "";
    }
    if auth.is_some() {
        " (unauthorized: check SMOKEPING_AUTH_USERNAME/SMOKEPING_AUTH_PASSWORD)"
    } else {
        " (unauthorized: set SMOKEPING_AUTH_USERNAME/SMOKEPING_AUTH_PASSWORD or embed credentials in SMOKEPING_SERVER_URL)"
    }
}

async fn send_json<T: for<'de> Deserialize<'de>>(
    request: reqwest::RequestBuilder,
    auth: &Option<AgentAuth>,
) -> anyhow::Result<T> {
    let response = with_auth(request, auth).send().await?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        anyhow::bail!(
            "request failed with status {}{}: {}",
            status,
            auth_hint(status, auth),
            body
        );
    }
    serde_json::from_str(&body).with_context(|| {
        format!(
            "failed to decode JSON response (status {}), body: {}",
            status, body
        )
    })
}

async fn register_agent(
    client: &Client,
    server_url: &str,
    agent_id: &str,
    agent_ip: &str,
    auth: &Option<AgentAuth>,
) -> anyhow::Result<AgentRegistration> {
    let url = format!("{}/api/agents", server_url.trim_end_matches('/'));
    let body = serde_json::json!({
        "name": agent_id,
        "address": agent_ip,
    });
    send_json(client.post(url).json(&body), auth).await
}

async fn fetch_config(
    client: &Client,
    server_url: &str,
    auth: &Option<AgentAuth>,
) -> anyhow::Result<Config> {
    let url = format!("{}/api/config", server_url.trim_end_matches('/'));
    send_json(client.get(url), auth).await
}

async fn fetch_targets(
    client: &Client,
    server_url: &str,
    auth: &Option<AgentAuth>,
) -> anyhow::Result<Vec<Target>> {
    let url = format!("{}/api/targets", server_url.trim_end_matches('/'));
    send_json(client.get(url), auth).await
}

async fn post_measurement(
    client: &Client,
    server_url: &str,
    payload: MeasurementInput,
    auth: &Option<AgentAuth>,
) -> anyhow::Result<()> {
    let url = format!("{}/api/measurements", server_url.trim_end_matches('/'));
    let response = with_auth(client.post(url).json(&payload), auth)
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await?;
        anyhow::bail!(
            "measurement upload failed with status {}{}: {}",
            status,
            auth_hint(status, auth),
            body
        );
    }
    Ok(())
}

async fn run_ping(
    address: &str,
    timeout_seconds: i64,
    ping_runs: i64,
) -> (bool, Option<f64>, Option<f64>) {
    let ping_runs = ping_runs.max(1);
    let output = Command::new("ping")
        .arg("-c")
        .arg(ping_runs.to_string())
        .arg("-W")
        .arg(timeout_seconds.to_string())
        .arg(address)
        .output()
        .await;

    let output = match output {
        Ok(output) => output,
        Err(_) => return (false, None, None),
    };

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

    let success = packet_loss.map(|loss| loss < 100.0).unwrap_or(false);
    (success, avg_ms, packet_loss)
}

async fn run_mtr(address: &str, runs: i64, timeout_seconds: i64) -> anyhow::Result<String> {
    let mut command = Command::new("mtr");
    command
        .arg("-rwzbc")
        .arg(runs.to_string())
        .arg(address);
    let mtr_timeout_seconds = timeout_seconds.max(50);
    run_command_with_timeout(command, mtr_timeout_seconds).await
}

async fn run_traceroute(address: &str, timeout_seconds: i64) -> anyhow::Result<String> {
    let mut command = Command::new("traceroute");
    command.arg(address);
    let traceroute_timeout_seconds = timeout_seconds.max(50);
    run_command_with_timeout(command, traceroute_timeout_seconds).await
}

async fn run_command_with_timeout(
    mut command: Command,
    timeout_seconds: i64,
) -> anyhow::Result<String> {
    let timeout_seconds = timeout_seconds.max(1);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let mut child = command.spawn().context("command failed to execute")?;
    let mut stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            tracing::warn!("command did not provide stdout pipe");
            let _ = terminate_child(&mut child).await;
            return Ok(String::new());
        }
    };

    match tokio::time::timeout(Duration::from_secs(timeout_seconds as u64), child.wait()).await {
        Ok(result) => {
            result.context("command failed while running")?;
            let mut buffer = Vec::new();
            stdout.read_to_end(&mut buffer).await?;
            Ok(String::from_utf8_lossy(&buffer).to_string())
        }
        Err(_) => {
            terminate_child(&mut child).await;
            anyhow::bail!("command timed out after {}s", timeout_seconds);
        }
    }
}

async fn terminate_child(child: &mut Child) {
    if let Err(error) = child.kill().await {
        tracing::warn!(error = %error, "failed to kill timed-out command");
    }
}
