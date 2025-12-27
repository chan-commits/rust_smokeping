# Rust SmokePing

[English](README.md)

Rust SmokePing 是一个使用 Rust、Axum 和 SQLite 构建的轻量级 SmokePing 类系统。它提供用于配置、存储和绘图的服务器，以及一个独立的 agent 二进制程序，用于运行 ping、mtr 和 traceroute 并将测量数据回传到服务器。

## 特性

- 基于 Axum 的服务器 API 与 SQLite 存储。
- 独立的 `smokeping-server` 和 `smokeping-agent` 二进制程序。
- 通过 Web UI 进行目标与 agent 管理。
- 1h、3h、1d、7d、1m 范围的延迟曲线。
- 保留清理（最近 30 天的测量数据）。
- agent 侧采集 `ping`、`mtr -rwzbc 10`、`traceroute` 数据。

## 前置条件

- Rust 工具链（推荐 1.75+）。
- SQLite（`sqlx` 使用 `libsqlite3` 进行捆绑）。
- agent 主机需要安装：
  - `ping`
  - `mtr`
  - `traceroute`

## 构建（单一二进制）

使用脚本先构建 React 前端并通过 `include_dir` 嵌入，再编译 Rust 服务端：

```bash
./build.sh
```

生成：

- `target/release/smokeping-server`（前后端一体）
- `target/release/smokeping-agent`

如需手动执行：

```bash
cd frontend
npm install
npm run build
cd ..
cargo build --release
```

> Rust 编译时会读取 `frontend/dist`，因此必须先构建前端。

## 服务器配置

环境变量：

- `SMOKEPING_DATABASE_URL`（默认：`smokeping.db`）
- `SMOKEPING_SERVER_BIND`（默认：`0.0.0.0:8080`）
- `SMOKEPING_AUTH_FILE`（默认：`.smokeping_auth.json`）
- `SMOKEPING_BASE_PATH`（默认：`/smokeping`）

运行服务器：

```bash
SMOKEPING_DATABASE_URL=smokeping.db \
SMOKEPING_SERVER_BIND=0.0.0.0:8080 \
SMOKEPING_BASE_PATH=/smokeping \
./target/release/smokeping-server
```

在以下地址打开 UI：`http://127.0.0.1:8080/smokeping/`

> 安全说明：Web UI 与所有管理类接口仅允许从本机访问。
> 非本机访问只保留 `POST /smokeping/api/measurements`。

### 首次认证设置

如果不存在认证文件，服务器会重定向到 `/smokeping/setup`，可创建初始管理员用户名和密码。保存后，所有接口都需要 HTTP Basic 认证。

### 重置密码

删除认证文件以重新初始化凭据：

```bash
rm .smokeping_auth.json
```

下次访问时，Web UI 会提示你设置新的用户名和密码。

## Agent 配置

环境变量：

- `SMOKEPING_SERVER_URL`（默认：`http://127.0.0.1:8080`）
- `SMOKEPING_AGENT_ID`（默认：`agent-1`）
- `SMOKEPING_AGENT_IP`（默认：`127.0.0.1`）
- `SMOKEPING_BASE_PATH`（默认：`/smokeping`）
- `SMOKEPING_AUTH_USERNAME`（当服务器开启认证时必填：HTTP Basic 用户名）
- `SMOKEPING_AUTH_PASSWORD`（当服务器开启认证时必填：HTTP Basic 密码）

如果服务器开启了认证，可以使用上述环境变量，或者在 URL 中内嵌账号密码
（例如：`http://user:pass@server:8080`）。

运行 agent：

```bash
SMOKEPING_SERVER_URL=http://<server-ip>:8080 \
SMOKEPING_AGENT_ID=edge-sg-1 \
SMOKEPING_AGENT_IP=203.0.113.10 \
SMOKEPING_BASE_PATH=/smokeping \
SMOKEPING_AUTH_USERNAME=admin \
SMOKEPING_AUTH_PASSWORD=secret \
./target/release/smokeping-agent
```

agent 在启动时注册自身，然后开始上报测量数据。

> 注意：启用仅本机访问的管理类接口后，agent 需要运行在服务器本机
> （或通过 SSH 隧道/端口转发访问服务器），以便读取配置与目标列表。

## 开发流程

本地开发可前后端分离运行：

```bash
# 终端 1
cargo run -- server --bind 0.0.0.0:8080

# 终端 2
cd frontend
npm install
npm run dev
```

Vite 开发服务器会将 `/smokeping/api` 请求代理到 Rust 后端。

## API 概览

- `GET /smokeping/api/targets` - 列出目标
- `POST /smokeping/api/targets` - 添加目标
- `PUT /smokeping/api/targets/:id` - 更新目标
- `DELETE /smokeping/api/targets/:id` - 删除目标及测量数据
- `GET /smokeping/api/targets/unresponsive` - 最近无成功记录的目标
- `GET /smokeping/api/agents` - 列出 agent
- `POST /smokeping/api/agents` - 注册 agent
- `DELETE /smokeping/api/agents/:id` - 删除 agent 及测量数据
- `GET /smokeping/api/config` - 获取间隔/超时
- `PUT /smokeping/api/config` - 更新间隔/超时
- `POST /smokeping/api/measurements` - agent 上报测量
- `GET /smokeping/graph/:id?range=1h|3h|1d|7d|1m` - 延迟图表

## API 示例（curl）

```bash
# 列出目标
curl -u admin:secret http://<server-ip>:8080/smokeping/api/targets

# 更新配置
curl -u admin:secret \
  -H "Content-Type: application/json" \
  -X PUT \
  -d '{"interval_seconds":60,"timeout_seconds":10,"mtr_runs":10}' \
  http://<server-ip>:8080/smokeping/api/config

# agent 上报测量
curl -u admin:secret \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"target_id":1,"agent_id":1,"avg_ms":12.3,"packet_loss":0.0,"success":1,"mtr":"...","traceroute":"..."}' \
  http://<server-ip>:8080/smokeping/api/measurements
```

## 说明

- 测量数据会在 30 天后清理。
- agent 注册会更新 `last_seen` 以进行健康监控。
