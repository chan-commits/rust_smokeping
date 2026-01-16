use anyhow::Context;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;
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
    tracing::info!(
        server_url = %server_url,
        agent_id = %agent_record.id,
        agent_name = %agent_id,
        agent_ip = %agent_ip,
        "agent registered"
    );

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
    let cycle_start = Instant::now();
    let config = fetch_config(client, server_url, auth).await?;
    let targets = fetch_targets(client, server_url, auth).await?;
    tracing::info!(
        interval_seconds = config.interval_seconds,
        timeout_seconds = config.timeout_seconds,
        mtr_runs = config.mtr_runs,
        ping_runs = config.ping_runs,
        target_count = targets.len(),
        "starting agent cycle"
    );
    let server_url = server_url.to_string();
    let auth = auth.clone();
    let mut join_set = JoinSet::new();
    let mut success_count = 0usize;
    let mut failure_count = 0usize;

    for target in targets {
        let client = client.clone();
        let server_url = server_url.clone();
        let auth = auth.clone();
        let config = config.clone();
        join_set.spawn(async move {
            let timestamp = Utc::now();
            let (success, avg_ms, packet_loss) = run_ping(
                &target.address,
                config.timeout_seconds,
                config.ping_runs,
            )
            .await;
            tracing::debug!(
                target_id = target.id,
                target_address = %target.address,
                success,
                avg_ms,
                packet_loss,
                "ping result"
            );
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
            Ok::<_, anyhow::Error>(success)
        });
    }

    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(Ok(success)) => {
                if success {
                    success_count += 1;
                } else {
                    failure_count += 1;
                }
            }
            Ok(Err(err)) => {
                failure_count += 1;
                tracing::warn!(error = %err, "measurement task failed");
            }
            Err(err) => {
                failure_count += 1;
                tracing::warn!(error = %err, "measurement task panicked");
            }
        }
    }

    tracing::info!(
        duration_ms = cycle_start.elapsed().as_millis(),
        success_count,
        failure_count,
        "agent cycle completed"
    );
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
        tracing::warn!(
            status = %status,
            target_id = payload.target_id,
            agent_id = payload.agent_id,
            "measurement upload failed"
        );
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
    let timeout_seconds = timeout_seconds.max(1);
    tracing::info!(
        target_address = %address,
        ping_runs,
        timeout_seconds,
        "starting ping check"
    );
    let ip = match resolve_ip(address).await {
        Some(IpAddr::V4(ip)) => ip,
        _ => {
            tracing::warn!(target_address = %address, "failed to resolve IPv4 address");
            return (false, None, Some(100.0));
        }
    };
    tracing::info!(target_address = %address, ip = %ip, "resolved IPv4 address");
    let timeout = Duration::from_secs(timeout_seconds as u64);
    match tokio::task::spawn_blocking(move || ping_ipv4(ip, ping_runs, timeout)).await {
        Ok(result) => {
            tracing::info!(
                target_address = %address,
                success = result.0,
                avg_ms = result.1,
                packet_loss = result.2,
                "ping check completed"
            );
            result
        }
        Err(error) => {
            tracing::warn!(error = %error, "ping task failed to join");
            (false, None, Some(100.0))
        }
    }
}

async fn resolve_ip(address: &str) -> Option<IpAddr> {
    if let Ok(ip) = address.parse::<IpAddr>() {
        return Some(ip);
    }
    let mut addrs = tokio::net::lookup_host((address, 0)).await.ok()?;
    addrs.next().map(|addr| addr.ip())
}

fn ping_ipv4(ip: Ipv4Addr, ping_runs: i64, timeout: Duration) -> (bool, Option<f64>, Option<f64>) {
    tracing::debug!(
        target_ip = %ip,
        ping_runs,
        timeout_ms = timeout.as_millis(),
        "starting IPv4 ping"
    );
    let (socket, socket_mode) = match create_icmp_socket() {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(error = %error, "failed to create ICMP socket");
            return (false, None, Some(100.0));
        }
    };
    tracing::info!(
        target_ip = %ip,
        socket_mode = %socket_mode.as_str(),
        "icmp socket ready"
    );
    if socket.set_read_timeout(Some(timeout)).is_err() {
        tracing::warn!("failed to set ICMP socket timeout");
        return (false, None, Some(100.0));
    }
    let target = SockAddr::from(SocketAddrV4::new(ip, 0));
    let identifier = (std::process::id() & 0xffff) as u16;
    let mut received = 0i64;
    let mut total_ms = 0f64;
    let mut send_errors = 0i64;
    let mut receive_timeouts = 0i64;
    let mut receive_errors = 0i64;

    for seq in 0..ping_runs {
        let mut packet = [0u8; 16];
        let packet_len = if socket_mode.is_datagram() {
            packet[0..2].copy_from_slice(&(seq as u16).to_be_bytes());
            8
        } else {
            packet[0] = 8;
            packet[1] = 0;
            packet[4..6].copy_from_slice(&identifier.to_be_bytes());
            packet[6..8].copy_from_slice(&(seq as u16).to_be_bytes());
            let checksum = icmp_checksum(&packet);
            packet[2..4].copy_from_slice(&checksum.to_be_bytes());
            16
        };

        match socket.send_to(&packet[..packet_len], &target) {
            Ok(_) => {
                tracing::debug!(target_ip = %ip, seq, "icmp echo request sent");
            }
            Err(error) => {
                tracing::warn!(target_ip = %ip, seq, error = %error, "failed to send icmp request");
                send_errors += 1;
                continue;
            }
        }

        let start = Instant::now();
        let mut buffer = [MaybeUninit::<u8>::uninit(); 1024];
        let mut remaining = timeout;
        loop {
            if socket.set_read_timeout(Some(remaining)).is_err() {
                break;
            }
            match socket.recv_from(&mut buffer) {
                Ok((size, _)) => {
                    let slice = unsafe {
                        std::slice::from_raw_parts(buffer.as_ptr() as *const u8, size)
                    };
                    if let Some((reply_id, reply_seq)) = parse_icmp_reply(slice, &socket_mode) {
                        if socket_mode.is_raw()
                            && reply_id == identifier
                            && reply_seq == seq as u16
                        {
                            tracing::debug!(
                                target_ip = %ip,
                                seq,
                                rtt_ms = start.elapsed().as_secs_f64() * 1000.0,
                                "icmp echo reply received"
                            );
                            received += 1;
                            total_ms += start.elapsed().as_secs_f64() * 1000.0;
                            break;
                        }
                        if socket_mode.is_datagram() && reply_seq == seq as u16 {
                            tracing::debug!(
                                target_ip = %ip,
                                seq,
                                rtt_ms = start.elapsed().as_secs_f64() * 1000.0,
                                "icmp echo reply received (datagram)"
                            );
                            received += 1;
                            total_ms += start.elapsed().as_secs_f64() * 1000.0;
                            break;
                        }
                        tracing::debug!(
                            target_ip = %ip,
                            seq,
                            reply_id,
                            reply_seq,
                            "icmp reply did not match identifier/sequence"
                        );
                    } else {
                        tracing::debug!(
                            target_ip = %ip,
                            seq,
                            packet_size = size,
                            "received non-echo or malformed icmp packet"
                        );
                    }
                }
                Err(error) if is_timeout(&error) => {
                    tracing::debug!(target_ip = %ip, seq, "icmp receive timed out");
                    receive_timeouts += 1;
                    break;
                }
                Err(error) => {
                    tracing::warn!(target_ip = %ip, seq, error = %error, "icmp receive failed");
                    receive_errors += 1;
                    break;
                }
            }
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                tracing::debug!(target_ip = %ip, seq, "icmp receive exceeded timeout");
                break;
            }
            remaining = timeout - elapsed;
        }
    }

    let loss = ((ping_runs - received) as f64 / ping_runs as f64) * 100.0;
    let avg_ms = if received > 0 {
        Some(total_ms / received as f64)
    } else {
        None
    };
    let success = received > 0;
    tracing::info!(
        target_ip = %ip,
        received,
        sent = ping_runs,
        send_errors,
        receive_timeouts,
        receive_errors,
        avg_ms,
        loss,
        "icmp ping summary"
    );
    if received == 0 && socket_mode.is_datagram() {
        tracing::warn!(
            target_ip = %ip,
            "no ICMP replies received using datagram socket; check net.ipv4.ping_group_range or raw socket permissions"
        );
    }
    (success, avg_ms, Some(loss))
}

enum IcmpSocketMode {
    Raw,
    Datagram,
}

impl IcmpSocketMode {
    fn as_str(&self) -> &'static str {
        match self {
            IcmpSocketMode::Raw => "raw",
            IcmpSocketMode::Datagram => "datagram",
        }
    }

    fn is_datagram(&self) -> bool {
        matches!(self, IcmpSocketMode::Datagram)
    }

    fn is_raw(&self) -> bool {
        matches!(self, IcmpSocketMode::Raw)
    }
}

fn create_icmp_socket() -> io::Result<(Socket, IcmpSocketMode)> {
    match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(socket) => Ok((socket, IcmpSocketMode::Raw)),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            tracing::info!("raw ICMP socket denied, falling back to datagram");
            Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
                .map(|socket| (socket, IcmpSocketMode::Datagram))
        }
        Err(error) => Err(error),
    }
}

fn parse_icmp_reply(buffer: &[u8], socket_mode: &IcmpSocketMode) -> Option<(u16, u16)> {
    let icmp = if buffer.len() >= 8 && buffer[0] == 0 && buffer[1] == 0 {
        buffer
    } else {
        if buffer.len() < 28 {
            return None;
        }
        let header_len = (buffer[0] & 0x0f) as usize * 4;
        if buffer.len() < header_len + 8 {
            return None;
        }
        &buffer[header_len..]
    };
    if icmp[0] != 0 || icmp[1] != 0 {
        return None;
    }
    let identifier = u16::from_be_bytes([icmp[4], icmp[5]]);
    let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    if socket_mode.is_datagram() && icmp.len() >= 10 {
        let payload_seq = u16::from_be_bytes([icmp[8], icmp[9]]);
        return Some((identifier, payload_seq));
    }
    Some((identifier, seq))
}

fn icmp_checksum(payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = payload.chunks_exact(2);
    for chunk in &mut chunks {
        let value = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum = sum.wrapping_add(value);
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum = sum.wrapping_add((byte as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

#[cfg(test)]
mod tests {
    use super::{parse_icmp_reply, IcmpSocketMode};

    #[test]
    fn parse_icmp_reply_from_raw_ipv4_packet() {
        let mut buffer = [0u8; 28];
        buffer[0] = 0x45;
        buffer[20] = 0;
        buffer[21] = 0;
        buffer[24] = 0x12;
        buffer[25] = 0x34;
        buffer[26] = 0x00;
        buffer[27] = 0x02;

        let parsed = parse_icmp_reply(&buffer, &IcmpSocketMode::Raw);
        assert_eq!(parsed, Some((0x1234, 2)));
    }

    #[test]
    fn parse_icmp_reply_from_datagram_packet() {
        let buffer = [0, 0, 0, 0, 0xab, 0xcd, 0x00, 0x05];
        let parsed = parse_icmp_reply(&buffer, &IcmpSocketMode::Raw);
        assert_eq!(parsed, Some((0xabcd, 5)));
    }
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
