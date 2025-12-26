# Rust SmokePing

Rust SmokePing is a lightweight SmokePing-like system built with Rust, Axum, and SQLite. It provides a server for configuration, storage, and graphing, plus a separate agent binary that runs ping, mtr, and traceroute to send measurements back to the server.

## Features

- Axum-based server API with SQLite storage.
- Separate `smokeping-server` and `smokeping-agent` binaries.
- Target and agent management from the web UI.
- Latency graphs for 1h, 3h, 1d, 7d, 1m ranges.
- Retention cleanup (last 30 days of measurements).
- Agent-side `ping`, `mtr -rwzbc 10`, `traceroute` data collection.

## Prerequisites

- Rust toolchain (1.75+ recommended).
- SQLite (bundled with `libsqlite3` for `sqlx`).
- Agent hosts must have:
  - `ping`
  - `mtr`
  - `traceroute`

## Build

```bash
cargo build --release
```

This produces two binaries:

- `target/release/smokeping-server`
- `target/release/smokeping-agent`

## Server Configuration

Environment variables:

- `SMOKEPING_DATABASE_URL` (default: `smokeping.db`)
- `SMOKEPING_SERVER_BIND` (default: `0.0.0.0:8080`)
- `SMOKEPING_AUTH_FILE` (default: `smokeping_auth.json`)

Run the server:

```bash
SMOKEPING_DATABASE_URL=smokeping.db \
SMOKEPING_SERVER_BIND=0.0.0.0:8080 \
./target/release/smokeping-server
```

Open the UI at: `http://<server-ip>:8080/`

### First-time authentication setup

If no auth file exists, the server redirects to `/setup` where you can create the initial
admin username and password. After saving, all endpoints require HTTP Basic auth.

### Resetting the password

Delete the auth file to reinitialize credentials:

```bash
rm smokeping_auth.json
```

On the next visit, the web UI will prompt you to set a new username and password.

## Agent Configuration

Environment variables:

- `SMOKEPING_SERVER_URL` (default: `http://127.0.0.1:8080`)
- `SMOKEPING_AGENT_ID` (default: `agent-1`)
- `SMOKEPING_AGENT_IP` (default: `127.0.0.1`)

Run the agent:

```bash
SMOKEPING_SERVER_URL=http://<server-ip>:8080 \
SMOKEPING_AGENT_ID=edge-sg-1 \
SMOKEPING_AGENT_IP=203.0.113.10 \
./target/release/smokeping-agent
```

The agent registers itself on startup and then starts reporting measurements.

## API Summary

- `GET /api/targets` - list targets
- `POST /api/targets` - add target
- `PUT /api/targets/:id` - update target
- `DELETE /api/targets/:id` - delete target and measurements
- `GET /api/targets/unresponsive` - targets with no recent success
- `GET /api/agents` - list agents
- `POST /api/agents` - register agent
- `DELETE /api/agents/:id` - delete agent and measurements
- `GET /api/config` - get interval/timeout
- `PUT /api/config` - update interval/timeout
- `POST /api/measurements` - agent measurement upload
- `GET /graph/:id?range=1h|3h|1d|7d|1m` - latency graph

## Notes

- Measurements are pruned after 30 days.
- Agent registration updates `last_seen` for health monitoring.
