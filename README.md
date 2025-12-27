# Rust SmokePing

[中文](README.zh-CN.md)

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

## Build (single binary)

Use the helper script to build the React frontend, embed it with `include_dir`, and
compile the Rust server binary:

```bash
./build.sh
```

This produces:

- `target/release/smokeping-server` (frontend + API in one binary)
- `target/release/smokeping-agent`

If you prefer manual steps:

```bash
cd frontend
npm install
npm run build
cd ..
cargo build --release
```

> The Rust build expects `frontend/dist` to exist because the assets are embedded.

## Server Configuration

Environment variables:

- `SMOKEPING_DATABASE_URL` (default: `smokeping.db`)
- `SMOKEPING_SERVER_BIND` (default: `0.0.0.0:8080`)
- `SMOKEPING_AUTH_FILE` (default: `.smokeping_auth.json`)
- `SMOKEPING_BASE_PATH` (default: `/smokeping`)

Run the server:

```bash
SMOKEPING_DATABASE_URL=smokeping.db \
SMOKEPING_SERVER_BIND=0.0.0.0:8080 \
SMOKEPING_BASE_PATH=/smokeping \
./target/release/smokeping-server
```

Open the UI at: `http://127.0.0.1:8080/smokeping/`

> Security note: the web UI and all administrative APIs are restricted to localhost.
> Only `POST /smokeping/api/measurements` is reachable from non-localhost clients.

### First-time authentication setup

If no auth file exists, the server redirects to `/smokeping/setup` where you can create the initial
admin username and password. After saving, all endpoints require HTTP Basic auth.

### Resetting the password

Delete the auth file to reinitialize credentials:

```bash
rm .smokeping_auth.json
```

On the next visit, the web UI will prompt you to set a new username and password.

## Agent Configuration

Environment variables:

- `SMOKEPING_SERVER_URL` (default: `http://127.0.0.1:8080`)
- `SMOKEPING_AGENT_ID` (default: `agent-1`)
- `SMOKEPING_AGENT_IP` (default: `127.0.0.1`)
- `SMOKEPING_BASE_PATH` (default: `/smokeping`)
- `SMOKEPING_AUTH_USERNAME` (required when auth is enabled on the server: HTTP Basic auth user)
- `SMOKEPING_AUTH_PASSWORD` (required when auth is enabled on the server: HTTP Basic auth password)

If the server has authentication enabled, provide credentials either via the env vars above
or by embedding them in the server URL (for example, `http://user:pass@server:8080`).

Run the agent:

```bash
SMOKEPING_SERVER_URL=http://<server-ip>:8080/smokeping \
SMOKEPING_AGENT_ID=edge-sg-1 \
SMOKEPING_AGENT_IP=203.0.113.10 \
SMOKEPING_BASE_PATH=/smokeping \
SMOKEPING_AUTH_USERNAME=admin \
SMOKEPING_AUTH_PASSWORD=secret \
./target/release/smokeping-agent
```

The agent registers itself on startup and then starts reporting measurements.

> Note: with localhost-only admin APIs enabled, agents must run on the same host
> (or access the server through an SSH tunnel/port-forward) so they can read
> configuration and targets.

## Development Workflow

For local development with a separate frontend:

```bash
# terminal 1
cargo run -- server --bind 0.0.0.0:8080

# terminal 2
cd frontend
npm install
npm run dev
```

The Vite dev server proxies `/smokeping/api` requests to the Rust backend.

## API Summary

- `GET /smokeping/api/targets` - list targets
- `POST /smokeping/api/targets` - add target
- `POST /smokeping/api/targets/auto` - add auto target from IP range
- `PUT /smokeping/api/targets/:id` - update target
- `DELETE /smokeping/api/targets/:id` - delete target and measurements
- `GET /smokeping/api/targets/unresponsive` - targets with no recent success
- `GET /smokeping/api/agents` - list agents
- `POST /smokeping/api/agents` - register agent
- `DELETE /smokeping/api/agents/:id` - delete agent and measurements
- `GET /smokeping/api/config` - get interval/timeout
- `PUT /smokeping/api/config` - update interval/timeout
- `POST /smokeping/api/measurements` - agent measurement upload
- `GET /smokeping/graph/:id?range=1h|3h|1d|7d|1m` - latency graph

## API Examples (curl)

```bash
# list targets
curl -u admin:secret http://<server-ip>:8080/smokeping/api/targets

# update config
curl -u admin:secret \
  -H "Content-Type: application/json" \
  -X PUT \
  -d '{"interval_seconds":60,"timeout_seconds":10,"mtr_runs":10}' \
  http://<server-ip>:8080/smokeping/api/config

# auto target
curl -u admin:secret \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"octet1":60,"octet2":48,"third_start":183,"third_end":189,"name":"auto-60.48.183-189","sort_order":0}' \
  http://<server-ip>:8080/smokeping/api/targets/auto

# agent measurement upload
curl -u admin:secret \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"target_id":1,"agent_id":1,"avg_ms":12.3,"packet_loss":0.0,"success":1,"mtr":"...","traceroute":"..."}' \
  http://<server-ip>:8080/smokeping/api/measurements
```

## Notes

- Measurements are pruned after 30 days.
- Agent registration updates `last_seen` for health monitoring.
