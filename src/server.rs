use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::extract::Form;
use axum::http::{Request, header};
use axum::middleware::Next;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware::from_fn_with_state,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, post},
};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use plotters::prelude::*;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions, sqlite::SqlitePoolOptions};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

type AppResult<T> = Result<T, AppError>;

#[derive(Clone)]
struct AppState {
    pool: SqlitePool,
    auth: Arc<RwLock<Option<AuthConfig>>>,
    auth_path: PathBuf,
}

#[derive(Debug)]
struct AppError(anyhow::Error);

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        AppError(err.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.0.to_string()).into_response()
    }
}

#[derive(Serialize, sqlx::FromRow)]
struct Target {
    id: i64,
    name: String,
    address: String,
    category: String,
    sort_order: i64,
}

#[derive(Serialize, Deserialize, Clone)]
struct AuthConfig {
    username: String,
    password_hash: String,
}

#[derive(Serialize, sqlx::FromRow)]
struct Agent {
    id: i64,
    name: String,
    address: String,
    last_seen: i64,
}

#[derive(Deserialize)]
struct AgentInput {
    name: String,
    address: String,
}

#[derive(Deserialize)]
struct TargetInput {
    name: String,
    address: String,
    category: String,
    sort_order: Option<i64>,
}

#[derive(Deserialize)]
struct TargetUpdate {
    name: Option<String>,
    address: Option<String>,
    category: Option<String>,
    sort_order: Option<i64>,
}

#[derive(Serialize)]
struct Config {
    interval_seconds: i64,
    timeout_seconds: i64,
}

#[derive(Deserialize)]
struct ConfigUpdate {
    interval_seconds: i64,
    timeout_seconds: i64,
}

#[derive(Deserialize)]
struct SetupInput {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct SetupQuery {
    username: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize)]
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

#[derive(sqlx::FromRow)]
struct MeasurementWithAgent {
    timestamp: i64,
    avg_ms: Option<f64>,
    agent_name: String,
}

async fn list_agents(State(state): State<Arc<AppState>>) -> AppResult<Json<Vec<Agent>>> {
    let agents = sqlx::query_as("SELECT id, name, address, last_seen FROM agents ORDER BY name")
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(agents))
}

async fn register_agent(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AgentInput>,
) -> AppResult<Json<Agent>> {
    let now = Utc::now().timestamp();
    let existing: Option<Agent> =
        sqlx::query_as("SELECT id, name, address, last_seen FROM agents WHERE name = ?")
            .bind(&payload.name)
            .fetch_optional(&state.pool)
            .await?;

    if let Some(agent) = existing {
        sqlx::query("UPDATE agents SET address = ?, last_seen = ? WHERE id = ?")
            .bind(&payload.address)
            .bind(now)
            .bind(agent.id)
            .execute(&state.pool)
            .await?;

        let updated: Agent =
            sqlx::query_as("SELECT id, name, address, last_seen FROM agents WHERE id = ?")
                .bind(agent.id)
                .fetch_one(&state.pool)
                .await?;
        return Ok(Json(updated));
    }

    let result = sqlx::query("INSERT INTO agents (name, address, last_seen) VALUES (?, ?, ?)")
        .bind(&payload.name)
        .bind(&payload.address)
        .bind(now)
        .execute(&state.pool)
        .await?;

    let agent_id = result.last_insert_rowid();
    let agent: Agent =
        sqlx::query_as("SELECT id, name, address, last_seen FROM agents WHERE id = ?")
            .bind(agent_id)
            .fetch_one(&state.pool)
            .await?;

    Ok(Json(agent))
}

async fn delete_agent(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> AppResult<StatusCode> {
    sqlx::query("DELETE FROM measurements WHERE agent_id = ?")
        .bind(id)
        .execute(&state.pool)
        .await?;
    let result = sqlx::query("DELETE FROM agents WHERE id = ?")
        .bind(id)
        .execute(&state.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Ok(StatusCode::NOT_FOUND);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct RangeQuery {
    range: Option<String>,
}

pub async fn run(database_url: String, bind: String, auth_file: String) -> anyhow::Result<()> {
    let connect_options = if database_url.starts_with("sqlite:") {
        SqliteConnectOptions::from_str(&database_url)?
    } else {
        SqliteConnectOptions::new().filename(&database_url)
    };
    let connect_options = connect_options.create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(connect_options)
        .await?;
    init_db(&pool).await?;

    let auth_path = PathBuf::from(auth_file);
    let auth = Arc::new(RwLock::new(load_auth(&auth_path).await?));
    let state = Arc::new(AppState {
        pool,
        auth,
        auth_path,
    });

    let protected = Router::new()
        .route("/", get(index))
        .route("/api/targets", get(list_targets).post(add_target))
        .route(
            "/api/targets/{id}",
            delete(delete_target).put(update_target),
        )
        .route("/api/targets/unresponsive", get(unresponsive_targets))
        .route("/api/agents", get(list_agents).post(register_agent))
        .route("/api/agents/{id}", delete(delete_agent))
        .route("/api/config", get(get_config).put(update_config))
        .route("/api/measurements", post(add_measurement))
        .route("/graph/{id}", get(graph))
        .layer(from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state.clone());

    let app = Router::new()
        .route("/setup", get(setup_page).post(setup_auth))
        .route("/setup/", get(setup_page).post(setup_auth))
        .merge(protected)
        .with_state(state);

    let addr: SocketAddr = bind.parse()?;
    tracing::info!("listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

async fn init_db(pool: &SqlitePool) -> anyhow::Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            last_seen INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            category TEXT NOT NULL,
            sort_order INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS measurements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            agent_id INTEGER NOT NULL,
            avg_ms REAL,
            packet_loss REAL,
            success INTEGER NOT NULL,
            mtr TEXT NOT NULL,
            traceroute TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE,
            FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    ensure_setting(pool, "interval_seconds", "60").await?;
    ensure_setting(pool, "timeout_seconds", "10").await?;

    Ok(())
}

async fn load_auth(path: &FsPath) -> anyhow::Result<Option<AuthConfig>> {
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(path).await?;
    let config = serde_json::from_str(&contents)?;
    Ok(Some(config))
}

async fn setup_page(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SetupQuery>,
) -> AppResult<Response> {
    {
        let auth = state.auth.read().await;
        if auth.is_some() {
            return Ok(Redirect::to("/").into_response());
        }
    }
    if query.username.is_some() || query.password.is_some() {
        let Some(username) = query.username else {
            let html = "<html><body><p>Missing username parameter.</p></body></html>";
            return Ok((StatusCode::BAD_REQUEST, Html(html)).into_response());
        };
        let Some(password) = query.password else {
            let html = "<html><body><p>Missing password parameter.</p></body></html>";
            return Ok((StatusCode::BAD_REQUEST, Html(html)).into_response());
        };
        let payload = SetupInput { username, password };
        return setup_auth_inner(&state, payload).await;
    }
    let html = r#"
        <html>
        <head>
            <title>Initialize SmokePing</title>
            <style>
                body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; display: flex; height: 100vh; align-items: center; justify-content: center; }
                .card { background: #1e293b; padding: 24px; border-radius: 16px; border: 1px solid #334155; width: 360px; }
                label { display: flex; flex-direction: column; gap: 6px; margin-bottom: 12px; }
                input { padding: 8px 10px; border-radius: 10px; border: 1px solid #475569; background: #0f172a; color: #e2e8f0; }
                button { background: #38bdf8; color: #0f172a; border: none; border-radius: 10px; padding: 10px 14px; font-weight: 600; width: 100%; }
            </style>
        </head>
        <body>
            <form class=\"card\" method=\"post\" action=\"/setup\">
                <h2>Initialize Admin</h2>
                <label>Username<input name=\"username\" required/></label>
                <label>Password<input name=\"password\" type=\"password\" required/></label>
                <button type=\"submit\">Save</button>
            </form>
        </body>
        </html>
    "#;
    Ok(Html(html.to_string()).into_response())
}

async fn setup_auth(
    State(state): State<Arc<AppState>>,
    Form(payload): Form<SetupInput>,
) -> AppResult<Response> {
    setup_auth_inner(&state, payload).await
}

async fn setup_auth_inner(state: &Arc<AppState>, payload: SetupInput) -> AppResult<Response> {
    {
        let auth = state.auth.read().await;
        if auth.is_some() {
            return Ok(Redirect::to("/").into_response());
        }
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|err| AppError(anyhow::anyhow!(err)))?
        .to_string();
    let config = AuthConfig {
        username: payload.username,
        password_hash: hash,
    };
    let serialized = serde_json::to_string_pretty(&config)?;
    if let Err(err) = write_auth_file(&state.auth_path, &serialized).await {
        tracing::error!(error = %err, path = %state.auth_path.display(), "failed to write auth file");
        let html = format!(
            "<html><body><p>Failed to save auth file at <code>{}</code>: {}</p><p>Check permissions and try again.</p></body></html>",
            state.auth_path.display(),
            err
        );
        return Ok((StatusCode::INTERNAL_SERVER_ERROR, Html(html)).into_response());
    }

    let mut auth = state.auth.write().await;
    *auth = Some(config);

    Ok(Redirect::to("/").into_response())
}

async fn write_auth_file(path: &FsPath, contents: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    let mut options = tokio::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(path).await?;
    file.write_all(contents.as_bytes()).await?;
    file.flush().await?;
    Ok(())
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AppError> {
    let auth = state.auth.read().await.clone();
    let Some(auth) = auth else {
        return Ok(Redirect::to("/setup").into_response());
    };

    let Some(header_value) = req.headers().get(header::AUTHORIZATION) else {
        return Ok(unauthorized());
    };
    let header_str = header_value.to_str().unwrap_or("");
    let Some(encoded) = header_str.strip_prefix("Basic ") else {
        return Ok(unauthorized());
    };

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|err| AppError(anyhow::anyhow!(err)))?;
    let decoded = String::from_utf8(decoded).map_err(|err| AppError(anyhow::anyhow!(err)))?;
    let mut parts = decoded.splitn(2, ':');
    let username = parts.next().unwrap_or("");
    let password = parts.next().unwrap_or("");

    if username != auth.username {
        return Ok(unauthorized());
    }

    let parsed_hash =
        PasswordHash::new(&auth.password_hash).map_err(|err| AppError(anyhow::anyhow!(err)))?;
    if Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return Ok(unauthorized());
    }

    Ok(next.run(req).await)
}

fn unauthorized() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::WWW_AUTHENTICATE,
        "Basic realm=\"SmokePing\"".parse().unwrap(),
    );
    (StatusCode::UNAUTHORIZED, headers, "Unauthorized").into_response()
}

async fn ensure_setting(pool: &SqlitePool, key: &str, value: &str) -> anyhow::Result<()> {
    sqlx::query("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)")
        .bind(key)
        .bind(value)
        .execute(pool)
        .await?;
    Ok(())
}

async fn index(State(state): State<Arc<AppState>>) -> AppResult<Html<String>> {
    let targets: Vec<Target> = sqlx::query_as(
        "SELECT id, name, address, category, sort_order FROM targets ORDER BY category, sort_order, name",
    )
    .fetch_all(&state.pool)
    .await?;

    let agents: Vec<Agent> =
        sqlx::query_as("SELECT id, name, address, last_seen FROM agents ORDER BY name")
            .fetch_all(&state.pool)
            .await?;

    let config = fetch_config(&state.pool).await?;
    let mut grouped: BTreeMap<String, Vec<Target>> = BTreeMap::new();
    for target in targets {
        grouped
            .entry(target.category.clone())
            .or_default()
            .push(target);
    }

    let mut body = String::new();
    body.push_str(
        "<html><head><title>Rust SmokePing</title><style>
        body { font-family: 'Segoe UI', sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }
        header { background: linear-gradient(120deg, #1e293b, #0f172a); padding: 24px 32px; border-bottom: 1px solid #334155; }
        h1 { margin: 0; font-size: 28px; letter-spacing: 0.5px; }
        main { padding: 24px 32px; display: grid; gap: 24px; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 16px; padding: 20px; box-shadow: 0 10px 30px rgba(15, 23, 42, 0.35); }
        .card h2 { margin-top: 0; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
        label { display: flex; flex-direction: column; gap: 6px; font-size: 14px; color: #cbd5f5; }
        input { background: #0f172a; border: 1px solid #475569; border-radius: 10px; padding: 8px 10px; color: #e2e8f0; }
        button { background: #38bdf8; color: #0f172a; border: none; border-radius: 10px; padding: 8px 14px; cursor: pointer; font-weight: 600; }
        button.secondary { background: #f97316; }
        button.danger { background: #ef4444; }
        .pill { display: inline-flex; align-items: center; gap: 8px; padding: 6px 10px; background: #0f172a; border-radius: 999px; border: 1px solid #334155; font-size: 13px; }
        .link { color: #7dd3fc; text-decoration: none; margin-right: 8px; }
        .targets li { margin: 12px 0; }
        .agent-list li { display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid #334155; }
        .graph-links { display: inline-flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
        .graph-links a { font-size: 12px; padding: 4px 8px; border-radius: 6px; background: #0f172a; border: 1px solid #334155; color: #94a3b8; }
        img.graph { width: 100%; border-radius: 12px; border: 1px solid #334155; margin-top: 8px; background: #0f172a; }
        </style></head><body>",
    );
    body.push_str("<header><h1>Rust SmokePing</h1><p>Premium latency observability with agents.</p></header><main>");
    body.push_str(&format!(
        "<div class=\"card\"><h2>Settings</h2><span class=\"pill\">Interval: {}s</span> <span class=\"pill\">Timeout: {}s</span>
        <form class=\"grid\" method=\"post\" action=\"/api/config\" onsubmit=\"return submitConfig(event)\">
            <label>Interval Seconds<input name=\"interval_seconds\" type=\"number\" value=\"{}\"/></label>
            <label>Timeout Seconds<input name=\"timeout_seconds\" type=\"number\" value=\"{}\"/></label>
            <div style=\"display:flex;align-items:flex-end;\"><button type=\"submit\">Update</button></div>
        </form></div>",
        config.interval_seconds, config.timeout_seconds, config.interval_seconds, config.timeout_seconds
    ));

    body.push_str("<div class=\"card\"><h2>Add Target</h2>");
    body.push_str(
        r#"
        <form class="grid" method="post" action="/api/targets" onsubmit="return submitTarget(event)">
            <label>Name<input name="name"/></label>
            <label>Address<input name="address"/></label>
            <label>Category<input name="category"/></label>
            <label>Sort Order<input name="sort_order" type="number" value="0"/></label>
            <div style="display:flex;align-items:flex-end;"><button type="submit">Add</button></div>
        </form>
        "#,
    );
    body.push_str("</div>");

    body.push_str("<div class=\"card\"><h2>Register Agent</h2>");
    body.push_str(
        r#"
        <form class="grid" method="post" action="/api/agents" onsubmit="return submitAgent(event)">
            <label>Name<input name="name" placeholder="edge-sg-1"/></label>
            <label>Agent IP<input name="address" placeholder="203.0.113.10"/></label>
            <div style="display:flex;align-items:flex-end;"><button class="secondary" type="submit">Register</button></div>
        </form>
        "#,
    );
    body.push_str("</div>");

    body.push_str("<div class=\"card\"><h2>Agents</h2><ul class=\"agent-list\">");
    for agent in agents {
        body.push_str(&format!(
            "<li><div><strong>{}</strong><div class=\"pill\">{}</div></div><div><span class=\"pill\">Last seen: {}</span><button class=\"danger\" onclick=\"deleteAgent({})\">Delete</button></div></li>",
            agent.name,
            agent.address,
            DateTime::<Utc>::from_timestamp(agent.last_seen, 0)
                .map(|t| t.to_rfc3339())
                .unwrap_or_else(|| "never".to_string()),
            agent.id
        ));
    }
    body.push_str("</ul></div>");

    body.push_str("<div class=\"card\"><h2>Targets</h2>");

    for (category, items) in grouped {
        body.push_str(&format!("<h3>{}</h3><ul class=\"targets\">", category));
        for item in items {
            body.push_str(&format!(
                "<li><strong>{}</strong> ({})<div class=\"graph-links\">
                <a class=\"link\" href=\"/graph/{}?range=1h\">1h</a>
                <a class=\"link\" href=\"/graph/{}?range=3h\">3h</a>
                <a class=\"link\" href=\"/graph/{}?range=1d\">1d</a>
                <a class=\"link\" href=\"/graph/{}?range=7d\">7d</a>
                <a class=\"link\" href=\"/graph/{}?range=1m\">1m</a>
                <button class=\"danger\" onclick=\"deleteTarget({})\">Delete</button></div>
                <img class=\"graph\" src=\"/graph/{}?range=1h\" alt=\"Latency graph\"/></li>",
                item.name,
                item.address,
                item.id,
                item.id,
                item.id,
                item.id,
                item.id,
                item.id,
                item.id
            ));
        }
        body.push_str("</ul>");
    }
    body.push_str("</div>");

    body.push_str(
        r#"
        </main>
        <script>
        async function deleteTarget(id) {
            await fetch(`/api/targets/${id}`, { method: 'DELETE' });
            location.reload();
        }
        async function deleteAgent(id) {
            await fetch(`/api/agents/${id}`, { method: 'DELETE' });
            location.reload();
        }
        async function submitTarget(event) {
            event.preventDefault();
            const form = event.target;
            const data = {
                name: form.name.value,
                address: form.address.value,
                category: form.category.value,
                sort_order: Number(form.sort_order.value || 0),
            };
            await fetch('/api/targets', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            });
            location.reload();
            return false;
        }
        async function submitConfig(event) {
            event.preventDefault();
            const form = event.target;
            const data = {
                interval_seconds: Number(form.interval_seconds.value || 60),
                timeout_seconds: Number(form.timeout_seconds.value || 10),
            };
            await fetch('/api/config', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            });
            location.reload();
            return false;
        }
        async function submitAgent(event) {
            event.preventDefault();
            const form = event.target;
            const data = {
                name: form.name.value,
                address: form.address.value,
            };
            await fetch('/api/agents', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            });
            location.reload();
            return false;
        }
        </script>
        </body></html>
        "#,
    );
    Ok(Html(body))
}

async fn list_targets(State(state): State<Arc<AppState>>) -> AppResult<Json<Vec<Target>>> {
    let targets = sqlx::query_as(
        "SELECT id, name, address, category, sort_order FROM targets ORDER BY category, sort_order, name",
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(targets))
}

async fn add_target(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TargetInput>,
) -> AppResult<StatusCode> {
    sqlx::query("INSERT INTO targets (name, address, category, sort_order) VALUES (?, ?, ?, ?)")
        .bind(payload.name)
        .bind(payload.address)
        .bind(payload.category)
        .bind(payload.sort_order.unwrap_or(0))
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::CREATED)
}

async fn update_target(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(payload): Json<TargetUpdate>,
) -> AppResult<StatusCode> {
    let target: Option<Target> =
        sqlx::query_as("SELECT id, name, address, category, sort_order FROM targets WHERE id = ?")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?;

    let Some(target) = target else {
        return Ok(StatusCode::NOT_FOUND);
    };

    let name = payload.name.unwrap_or(target.name);
    let address = payload.address.unwrap_or(target.address);
    let category = payload.category.unwrap_or(target.category);
    let sort_order = payload.sort_order.unwrap_or(target.sort_order);

    sqlx::query(
        "UPDATE targets SET name = ?, address = ?, category = ?, sort_order = ? WHERE id = ?",
    )
    .bind(name)
    .bind(address)
    .bind(category)
    .bind(sort_order)
    .bind(id)
    .execute(&state.pool)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn delete_target(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> AppResult<StatusCode> {
    sqlx::query("DELETE FROM measurements WHERE target_id = ?")
        .bind(id)
        .execute(&state.pool)
        .await?;
    let result = sqlx::query("DELETE FROM targets WHERE id = ?")
        .bind(id)
        .execute(&state.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Ok(StatusCode::NOT_FOUND);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn unresponsive_targets(State(state): State<Arc<AppState>>) -> AppResult<Json<Vec<Target>>> {
    let targets = sqlx::query_as(
        "SELECT t.id, t.name, t.address, t.category, t.sort_order
        FROM targets t
        LEFT JOIN (
            SELECT target_id, MAX(timestamp) AS ts
            FROM measurements
            GROUP BY target_id
        ) latest ON t.id = latest.target_id
        LEFT JOIN measurements m ON m.target_id = latest.target_id AND m.timestamp = latest.ts
        WHERE m.success = 0 OR m.success IS NULL",
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(targets))
}

async fn get_config(State(state): State<Arc<AppState>>) -> AppResult<Json<Config>> {
    let config = fetch_config(&state.pool).await?;
    Ok(Json(config))
}

async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ConfigUpdate>,
) -> AppResult<StatusCode> {
    update_setting(
        &state.pool,
        "interval_seconds",
        &payload.interval_seconds.to_string(),
    )
    .await?;
    update_setting(
        &state.pool,
        "timeout_seconds",
        &payload.timeout_seconds.to_string(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn update_setting(pool: &SqlitePool, key: &str, value: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE settings SET value = ? WHERE key = ?")
        .bind(value)
        .bind(key)
        .execute(pool)
        .await?;
    Ok(())
}

async fn fetch_config(pool: &SqlitePool) -> anyhow::Result<Config> {
    let interval: (String,) =
        sqlx::query_as("SELECT value FROM settings WHERE key = 'interval_seconds'")
            .fetch_one(pool)
            .await?;
    let timeout: (String,) =
        sqlx::query_as("SELECT value FROM settings WHERE key = 'timeout_seconds'")
            .fetch_one(pool)
            .await?;

    Ok(Config {
        interval_seconds: interval.0.parse().unwrap_or(60),
        timeout_seconds: timeout.0.parse().unwrap_or(10),
    })
}

async fn add_measurement(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<MeasurementInput>,
) -> AppResult<StatusCode> {
    sqlx::query(
        "INSERT INTO measurements (target_id, agent_id, avg_ms, packet_loss, success, mtr, traceroute, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(payload.target_id)
    .bind(payload.agent_id)
    .bind(payload.avg_ms)
    .bind(payload.packet_loss)
    .bind(if payload.success { 1 } else { 0 })
    .bind(payload.mtr)
    .bind(payload.traceroute)
    .bind(payload.timestamp.timestamp())
    .execute(&state.pool)
    .await?;

    sqlx::query("UPDATE agents SET last_seen = ? WHERE id = ?")
        .bind(payload.timestamp.timestamp())
        .bind(payload.agent_id)
        .execute(&state.pool)
        .await?;

    let cutoff = Utc::now() - Duration::days(30);
    sqlx::query("DELETE FROM measurements WHERE timestamp < ?")
        .bind(cutoff.timestamp())
        .execute(&state.pool)
        .await?;

    Ok(StatusCode::CREATED)
}

async fn graph(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(params): Query<RangeQuery>,
) -> AppResult<Response> {
    let range = params.range.unwrap_or_else(|| "1h".to_string());
    let duration = match range.as_str() {
        "1h" => Duration::hours(1),
        "3h" => Duration::hours(3),
        "1d" => Duration::days(1),
        "7d" => Duration::days(7),
        "1m" => Duration::days(30),
        _ => Duration::hours(1),
    };

    let since = Utc::now() - duration;
    let points: Vec<MeasurementWithAgent> = sqlx::query_as(
        "SELECT m.timestamp, m.avg_ms, a.name as agent_name
        FROM measurements m
        JOIN agents a ON m.agent_id = a.id
        WHERE m.target_id = ? AND m.timestamp >= ?
        ORDER BY m.timestamp",
    )
    .bind(id)
    .bind(since.timestamp())
    .fetch_all(&state.pool)
    .await?;

    let mut buffer = vec![0u8; 800 * 300 * 3];
    {
        let root = BitMapBackend::with_buffer(&mut buffer, (800, 300)).into_drawing_area();
        root.fill(&RGBColor(15, 23, 42))?;
        let max_y = points
            .iter()
            .filter_map(|p| p.avg_ms)
            .fold(1.0_f64, f64::max);
        let y_max = if max_y < 1.0 { 1.0 } else { max_y };
        let mut chart = ChartBuilder::on(&root)
            .margin(10)
            .caption("Latency (ms)", ("sans-serif", 20))
            .x_label_area_size(30)
            .y_label_area_size(50)
            .build_cartesian_2d(since.timestamp()..Utc::now().timestamp(), 0.0..y_max)?;
        chart
            .configure_mesh()
            .label_style(
                ("sans-serif", 12)
                    .into_font()
                    .color(&RGBColor(148, 163, 184)),
            )
            .axis_style(&RGBColor(148, 163, 184))
            .bold_line_style(&RGBColor(51, 65, 85))
            .light_line_style(&RGBColor(30, 41, 59))
            .draw()?;

        let mut by_agent: BTreeMap<String, Vec<(i64, f64)>> = BTreeMap::new();
        for point in points {
            if let Some(avg) = point.avg_ms {
                by_agent
                    .entry(point.agent_name)
                    .or_default()
                    .push((point.timestamp, avg));
            }
        }

        let palette = vec![
            RGBColor(56, 189, 248),
            RGBColor(248, 113, 113),
            RGBColor(129, 140, 248),
            RGBColor(34, 197, 94),
            RGBColor(251, 146, 60),
        ];

        for (idx, (agent, series)) in by_agent.into_iter().enumerate() {
            let color = palette.get(idx % palette.len()).cloned().unwrap_or(BLUE);
            chart
                .draw_series(LineSeries::new(series, &color))?
                .label(agent)
                .legend(move |(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], color));
        }

        chart
            .configure_series_labels()
            .border_style(&RGBColor(51, 65, 85))
            .background_style(&RGBColor(15, 23, 42))
            .label_font(("sans-serif", 12))
            .draw()?;
    }

    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", "image/png".parse().unwrap());
    let png_data = draw_png(buffer, 800, 300)?;
    Ok((headers, png_data).into_response())
}

fn draw_png(buffer: Vec<u8>, width: u32, height: u32) -> anyhow::Result<Vec<u8>> {
    let mut png_bytes = Vec::new();
    {
        let encoder = png::Encoder::new(&mut png_bytes, width, height);
        let mut writer = encoder.write_header()?;
        writer.write_image_data(&buffer)?;
    }
    Ok(png_bytes)
}
