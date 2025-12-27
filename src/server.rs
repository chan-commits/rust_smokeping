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
use std::collections::{BTreeMap, HashMap};
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
    base_path: String,
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
    mtr_runs: i64,
}

#[derive(Deserialize)]
struct ConfigUpdate {
    interval_seconds: i64,
    timeout_seconds: i64,
    mtr_runs: i64,
}

#[derive(Deserialize)]
struct SetupInput {
    username: String,
    password: String,
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

#[derive(sqlx::FromRow)]
struct LatestMeasurement {
    target_id: i64,
    agent_id: i64,
    timestamp: i64,
    avg_ms: Option<f64>,
    packet_loss: Option<f64>,
    success: i64,
    mtr: String,
    traceroute: String,
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

pub async fn run(
    database_url: String,
    bind: String,
    auth_file: String,
    base_path: String,
) -> anyhow::Result<()> {
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
    let base_path = normalize_base_path(&base_path);
    let state = Arc::new(AppState {
        pool,
        auth,
        auth_path,
        base_path: base_path.clone(),
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
        .route("/%22/setup/%22", get(setup_page).post(setup_auth))
        .route("/%22/setup/%22/", get(setup_page).post(setup_auth))
        .merge(protected)
        .with_state(state);

    let app = if base_path.is_empty() {
        app
    } else {
        Router::new().nest(&base_path, app)
    };

    let addr: SocketAddr = bind.parse()?;
    tracing::info!("listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
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

fn with_base(base: &str, path: &str) -> String {
    if base.is_empty() {
        path.to_string()
    } else {
        format!("{}{}", base, path)
    }
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
    ensure_setting(pool, "mtr_runs", "10").await?;

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
    Query(query): Query<HashMap<String, String>>,
) -> AppResult<Response> {
    {
        let auth = state.auth.read().await;
        if auth.is_some() {
            return Ok(Redirect::to(&with_base(&state.base_path, "/")).into_response());
        }
    }
    let username = normalized_setup_value(&query, "username");
    let password = normalized_setup_value(&query, "password");
    if username.is_some() || password.is_some() {
        let Some(username) = username else {
            let html = "<html><body><p>Missing username parameter.</p></body></html>";
            return Ok((StatusCode::BAD_REQUEST, Html(html)).into_response());
        };
        let Some(password) = password else {
            let html = "<html><body><p>Missing password parameter.</p></body></html>";
            return Ok((StatusCode::BAD_REQUEST, Html(html)).into_response());
        };
        let payload = SetupInput { username, password };
        return setup_auth_inner(&state, payload).await;
    }
    let html = r#"
        <html>
        <head>
            <title data-i18n="setup_title">Initialize SmokePing</title>
            <style>
                body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; display: flex; height: 100vh; align-items: center; justify-content: center; }
                .card { background: #1e293b; padding: 24px; border-radius: 16px; border: 1px solid #334155; width: 360px; }
                label { display: flex; flex-direction: column; gap: 6px; margin-bottom: 12px; }
                input { padding: 8px 10px; border-radius: 10px; border: 1px solid #475569; background: #0f172a; color: #e2e8f0; }
                button { background: #38bdf8; color: #0f172a; border: none; border-radius: 10px; padding: 10px 14px; font-weight: 600; width: 100%; }
            </style>
        </head>
        <body>
            <form class=\"card\" method=\"post\" action=\"{setup_path}\">
                <h2 data-i18n="setup_header">Initialize Admin</h2>
                <label><span data-i18n="setup_username">Username</span><input name=\"username\" required/></label>
                <label><span data-i18n="setup_password">Password</span><input name=\"password\" type=\"password\" required/></label>
                <button type=\"submit\" data-i18n="setup_save">Save</button>
            </form>
            <script>
                const setupTranslations = {
                    en: {
                        setup_title: "Initialize SmokePing",
                        setup_header: "Initialize Admin",
                        setup_username: "Username",
                        setup_password: "Password",
                        setup_save: "Save",
                    },
                    zh: {
                        setup_title: "初始化 SmokePing",
                        setup_header: "初始化管理员",
                        setup_username: "用户名",
                        setup_password: "密码",
                        setup_save: "保存",
                    },
                };
                const setupLang = navigator.language || "en";
                const setupDict = setupLang.toLowerCase().startsWith("zh")
                    ? setupTranslations.zh
                    : setupTranslations.en;
                document.querySelectorAll("[data-i18n]").forEach((el) => {
                    const key = el.getAttribute("data-i18n");
                    if (setupDict[key]) {
                        el.textContent = setupDict[key];
                    }
                });
            </script>
        </body>
        </html>
    "#;
    let html = html.replace("{setup_path}", &with_base(&state.base_path, "/setup"));
    Ok(Html(html).into_response())
}

fn normalized_setup_value(query: &HashMap<String, String>, key: &str) -> Option<String> {
    for (raw_key, raw_value) in query {
        let normalized_key = normalize_setup_field(raw_key);
        if normalized_key == key {
            return Some(normalize_setup_field(raw_value));
        }
    }
    None
}

fn normalize_setup_field(value: &str) -> String {
    value.replace("\\\"", "\"").trim_matches('"').to_string()
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
            return Ok(Redirect::to(&with_base(&state.base_path, "/")).into_response());
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

    Ok(Redirect::to(&with_base(&state.base_path, "/")).into_response())
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
        return Ok(Redirect::to(&with_base(&state.base_path, "/setup")).into_response());
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

    let latest_measurements: Vec<LatestMeasurement> = sqlx::query_as(
        "SELECT m.target_id, m.agent_id, m.timestamp, m.avg_ms, m.packet_loss, m.success, m.mtr, m.traceroute, a.name as agent_name
        FROM measurements m
        JOIN (
            SELECT target_id, agent_id, MAX(timestamp) AS ts
            FROM measurements
            GROUP BY target_id, agent_id
        ) latest ON m.target_id = latest.target_id AND m.agent_id = latest.agent_id AND m.timestamp = latest.ts
        JOIN agents a ON m.agent_id = a.id",
    )
    .fetch_all(&state.pool)
    .await?;
    let measurement_map: HashMap<(i64, i64), LatestMeasurement> = latest_measurements
        .into_iter()
        .map(|measurement| ((measurement.agent_id, measurement.target_id), measurement))
        .collect();

    let agents: Vec<Agent> =
        sqlx::query_as("SELECT id, name, address, last_seen FROM agents ORDER BY name")
            .fetch_all(&state.pool)
            .await?;

    let config = fetch_config(&state.pool).await?;

    let base_path = &state.base_path;
    let config_path = with_base(base_path, "/api/config");
    let targets_path = with_base(base_path, "/api/targets");
    let agents_path = with_base(base_path, "/api/agents");

    let mut body = String::new();
    body.push_str(
        "<html><head><title data-i18n=\"app_title\">Rust SmokePing</title><style>
        body { font-family: 'Segoe UI', sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }
        header { background: linear-gradient(120deg, #1e293b, #0f172a); padding: 28px 32px; border-bottom: 1px solid #334155; }
        h1 { margin: 0 0 6px 0; font-size: 28px; letter-spacing: 0.5px; }
        header p { margin: 0; color: #94a3b8; }
        main { padding: 24px 32px 48px; display: grid; gap: 24px; max-width: 1200px; margin: 0 auto; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 16px; padding: 20px; box-shadow: 0 10px 30px rgba(15, 23, 42, 0.35); }
        .card h2 { margin: 0 0 16px 0; font-size: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; align-items: end; }
        label { display: flex; flex-direction: column; gap: 6px; font-size: 14px; color: #cbd5f5; }
        input { background: #0f172a; border: 1px solid #475569; border-radius: 10px; padding: 8px 10px; color: #e2e8f0; }
        button { background: #38bdf8; color: #0f172a; border: none; border-radius: 10px; padding: 8px 14px; cursor: pointer; font-weight: 600; }
        button.secondary { background: #f97316; }
        button.danger { background: #ef4444; }
        .pill { display: inline-flex; align-items: center; gap: 8px; padding: 6px 10px; background: #0f172a; border-radius: 999px; border: 1px solid #334155; font-size: 13px; }
        .pill-group { display: flex; flex-wrap: wrap; gap: 8px; }
        .link { color: #7dd3fc; text-decoration: none; }
        .agent-list { list-style: none; padding: 0; margin: 0; display: grid; gap: 12px; }
        .agent-list li { border: 1px solid #334155; border-radius: 12px; background: #0f172a; }
        .agent-toggle { padding: 12px 16px; }
        .agent-toggle summary { cursor: pointer; list-style: none; }
        .agent-toggle summary::-webkit-details-marker { display: none; }
        .agent-summary { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 16px; }
        .agent-meta { display: flex; flex-direction: column; gap: 6px; }
        .agent-actions { display: inline-flex; flex-wrap: wrap; gap: 8px; align-items: center; }
        .targets { list-style: none; padding: 0; margin: 12px 0 0; display: grid; gap: 12px; }
        .targets li { border: 1px solid #334155; border-radius: 12px; padding: 12px; background: #0f172a; }
        .target-toggle summary { cursor: pointer; list-style: none; }
        .target-toggle summary::-webkit-details-marker { display: none; }
        .target-summary { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px; }
        .target-info { display: flex; flex-direction: column; gap: 4px; }
        .target-name { font-weight: 600; }
        .target-address { font-size: 13px; color: #94a3b8; }
        .graph-links { display: inline-flex; flex-wrap: wrap; gap: 8px; }
        .graph-links a { font-size: 12px; padding: 4px 8px; border-radius: 6px; background: #0f172a; border: 1px solid #334155; color: #94a3b8; }
        img.graph { width: 100%; border-radius: 12px; border: 1px solid #334155; margin-top: 10px; background: #0f172a; }
        .target-body { margin-top: 12px; display: grid; gap: 12px; }
        .measurement { margin-top: 12px; display: grid; gap: 12px; }
        .measurement details { border: 1px solid #334155; border-radius: 12px; padding: 8px 12px; background: #0f172a; }
        .measurement summary { cursor: pointer; color: #7dd3fc; }
        .measurement pre { white-space: pre-wrap; font-size: 12px; color: #cbd5f5; margin: 10px 0 0; }
        </style></head><body>",
    );
    body.push_str("<header><h1 data-i18n=\"app_title\">Rust SmokePing</h1><p data-i18n=\"app_tagline\">Premium latency observability with agents.</p></header><main>");
    body.push_str(&format!(
        "<div class=\"card\"><h2 data-i18n=\"settings_title\">Settings</h2><div class=\"pill-group\"><span class=\"pill\"><span data-i18n=\"interval_label\">Interval</span>: {}s</span> <span class=\"pill\"><span data-i18n=\"timeout_label\">Timeout</span>: {}s</span> <span class=\"pill\"><span data-i18n=\"mtr_runs_label\">MTR Runs</span>: {}</span></div>
        <form class=\"grid\" method=\"post\" action=\"{}\" onsubmit=\"return submitConfig(event)\">
            <label><span data-i18n=\"interval_seconds\">Interval Seconds</span><input name=\"interval_seconds\" type=\"number\" value=\"{}\"/></label>
            <label><span data-i18n=\"timeout_seconds\">Timeout Seconds</span><input name=\"timeout_seconds\" type=\"number\" value=\"{}\"/></label>
            <label><span data-i18n=\"mtr_runs_input\">MTR Runs</span><input name=\"mtr_runs\" type=\"number\" min=\"1\" value=\"{}\"/></label>
            <div><button type=\"submit\" data-i18n=\"update_button\">Update</button></div>
        </form></div>",
        config.interval_seconds,
        config.timeout_seconds,
        config.mtr_runs,
        config_path,
        config.interval_seconds,
        config.timeout_seconds,
        config.mtr_runs
    ));

    body.push_str("<div class=\"card\"><h2 data-i18n=\"add_target_title\">Add Target</h2>");
    body.push_str(&format!(
        r#"
        <form class="grid" method="post" action="{}" onsubmit="return submitTarget(event)">
            <label><span data-i18n="target_name">Name</span><input name="name" data-i18n-placeholder="target_name_placeholder"/></label>
            <label><span data-i18n="target_address">Address</span><input name="address" data-i18n-placeholder="target_address_placeholder"/></label>
            <label><span data-i18n="target_category">Category</span><input name="category" data-i18n-placeholder="target_category_placeholder"/></label>
            <label><span data-i18n="target_sort_order">Sort Order</span><input name="sort_order" type="number" value="0"/></label>
            <div><button type="submit" data-i18n="add_button">Add</button></div>
        </form>
        "#,
        targets_path
    ));
    body.push_str("</div>");

    body.push_str("<div class=\"card\"><h2 data-i18n=\"register_agent_title\">Register Agent</h2>");
    body.push_str(&format!(
        r#"
        <form class="grid" method="post" action="{}" onsubmit="return submitAgent(event)">
            <label><span data-i18n="agent_name">Name</span><input name="name" data-i18n-placeholder="agent_name_placeholder"/></label>
            <label><span data-i18n="agent_ip">Agent IP</span><input name="address" data-i18n-placeholder="agent_ip_placeholder"/></label>
            <div><button class="secondary" type="submit" data-i18n="register_button">Register</button></div>
        </form>
        "#,
        agents_path
    ));
    body.push_str("</div>");

    body.push_str("<div class=\"card\"><h2 data-i18n=\"agents_title\">Agents</h2><ul class=\"agent-list\">");
    for agent in agents {
        body.push_str(&format!(
            "<li><details class=\"agent-toggle\">
                <summary>
                    <div class=\"agent-summary\">
                        <div class=\"agent-meta\"><strong>{}</strong><div class=\"pill\">{}</div></div>
                        <div class=\"agent-actions\">
                            <span class=\"pill\"><span data-i18n=\"last_seen\">Last seen</span>: {}</span>
                            <button class=\"danger\" onclick=\"event.stopPropagation(); deleteAgent({})\" data-i18n=\"delete_button\">Delete</button>
                        </div>
                    </div>
                </summary>
                <ul class=\"targets\">",
            agent.name,
            agent.address,
            DateTime::<Utc>::from_timestamp(agent.last_seen, 0)
                .map(|t| t.to_rfc3339())
                .unwrap_or_else(|| "never".to_string()),
            agent.id
        ));
        for target in &targets {
            let measurement = measurement_map.get(&(agent.id, target.id));
            let measurement_html = if let Some(measurement) = measurement {
                let timestamp = DateTime::<Utc>::from_timestamp(measurement.timestamp, 0)
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_else(|| "never".to_string());
                let avg_ms = measurement
                    .avg_ms
                    .map(|value| format!("{value:.2}"))
                    .unwrap_or_else(|| "-".to_string());
                let packet_loss = measurement
                    .packet_loss
                    .map(|value| format!("{value:.2}%"))
                    .unwrap_or_else(|| "-".to_string());
                let success_label = if measurement.success == 1 {
                    "success_yes"
                } else {
                    "success_no"
                };
                let mtr = escape_html(&measurement.mtr);
                let traceroute = escape_html(&measurement.traceroute);
                format!(
                    "<div class=\"measurement\">
                        <div class=\"pill-group\">
                            <span class=\"pill\"><span data-i18n=\"measurement_time\">Time</span>: {timestamp}</span>
                            <span class=\"pill\"><span data-i18n=\"measurement_agent\">Agent</span>: {agent}</span>
                            <span class=\"pill\"><span data-i18n=\"measurement_latency\">Latency</span>: {avg_ms} ms</span>
                            <span class=\"pill\"><span data-i18n=\"measurement_loss\">Packet loss</span>: {packet_loss}</span>
                            <span class=\"pill\"><span data-i18n=\"measurement_success\">Success</span>: <span data-i18n=\"{success_label}\"></span></span>
                        </div>
                        <details>
                            <summary><span data-i18n=\"measurement_mtr\">MTR Output</span></summary>
                            <pre>{mtr}</pre>
                        </details>
                        <details>
                            <summary><span data-i18n=\"measurement_traceroute\">Traceroute Output</span></summary>
                            <pre>{traceroute}</pre>
                        </details>
                    </div>",
                    timestamp = timestamp,
                    agent = measurement.agent_name,
                    avg_ms = avg_ms,
                    packet_loss = packet_loss,
                    success_label = success_label,
                    mtr = mtr,
                    traceroute = traceroute
                )
            } else {
                "<div class=\"measurement\"><em data-i18n=\"no_measurements\">No measurements yet.</em></div>".to_string()
            };
            body.push_str(&format!(
                "<li><details class=\"target-toggle\">
                    <summary>
                        <div class=\"target-summary\">
                            <div class=\"target-info\">
                                <span class=\"target-name\">{}</span>
                                <span class=\"target-address\">{} · {}</span>
                            </div>
                            <div class=\"graph-links\">
                                <a class=\"link\" href=\"{}\">1h</a>
                                <a class=\"link\" href=\"{}\">3h</a>
                                <a class=\"link\" href=\"{}\">1d</a>
                                <a class=\"link\" href=\"{}\">7d</a>
                                <a class=\"link\" href=\"{}\">1m</a>
                                <button class=\"danger\" onclick=\"event.stopPropagation(); deleteTarget({})\" data-i18n=\"delete_button\">Delete</button>
                            </div>
                        </div>
                    </summary>
                    <div class=\"target-body\">
                        <img class=\"graph\" src=\"{}\" alt=\"Latency graph\"/>
                        {measurement_html}
                    </div>
                </details></li>",
                target.name,
                target.address,
                target.category,
                with_base(base_path, &format!("/graph/{}?range=1h", target.id)),
                with_base(base_path, &format!("/graph/{}?range=3h", target.id)),
                with_base(base_path, &format!("/graph/{}?range=1d", target.id)),
                with_base(base_path, &format!("/graph/{}?range=7d", target.id)),
                with_base(base_path, &format!("/graph/{}?range=1m", target.id)),
                target.id,
                with_base(base_path, &format!("/graph/{}?range=1h", target.id)),
                measurement_html = measurement_html
            ));
        }
        body.push_str("</ul></details></li>");
    }
    body.push_str("</ul></div>");

    body.push_str(
        r#"
        </main>
        <script>
        const basePath = "{base_path}";
        const apiPath = (path) => basePath ? `${basePath}${path}` : path;
        const translations = {
            en: {
                app_title: "Rust SmokePing",
                app_tagline: "Premium latency observability with agents.",
                settings_title: "Settings",
                interval_label: "Interval",
                timeout_label: "Timeout",
                mtr_runs_label: "MTR Runs",
                interval_seconds: "Interval Seconds",
                timeout_seconds: "Timeout Seconds",
                mtr_runs_input: "MTR Runs",
                update_button: "Update",
                add_target_title: "Add Target",
                target_name: "Name",
                target_name_placeholder: "edge-sg-1",
                target_address: "Address",
                target_address_placeholder: "203.0.113.10",
                target_category: "Category",
                target_category_placeholder: "core",
                target_sort_order: "Sort Order",
                add_button: "Add",
                register_agent_title: "Register Agent",
                agent_name: "Name",
                agent_name_placeholder: "edge-sg-1",
                agent_ip: "Agent IP",
                agent_ip_placeholder: "203.0.113.10",
                register_button: "Register",
                agents_title: "Agents",
                targets_title: "Targets",
                delete_button: "Delete",
                last_seen: "Last seen",
                measurements_title: "Measurements",
                measurement_time: "Time",
                measurement_agent: "Agent",
                measurement_latency: "Latency",
                measurement_loss: "Packet loss",
                measurement_success: "Success",
                measurement_mtr: "MTR Output",
                measurement_traceroute: "Traceroute Output",
                no_measurements: "No measurements yet.",
                success_yes: "Yes",
                success_no: "No",
            },
            zh: {
                app_title: "Rust SmokePing",
                app_tagline: "使用代理的高质量延迟观测。",
                settings_title: "设置",
                interval_label: "间隔",
                timeout_label: "超时",
                mtr_runs_label: "MTR 次数",
                interval_seconds: "间隔（秒）",
                timeout_seconds: "超时（秒）",
                mtr_runs_input: "MTR 次数",
                update_button: "更新",
                add_target_title: "添加目标",
                target_name: "名称",
                target_name_placeholder: "edge-sg-1",
                target_address: "地址",
                target_address_placeholder: "203.0.113.10",
                target_category: "分类",
                target_category_placeholder: "core",
                target_sort_order: "排序",
                add_button: "添加",
                register_agent_title: "注册代理",
                agent_name: "名称",
                agent_name_placeholder: "edge-sg-1",
                agent_ip: "代理 IP",
                agent_ip_placeholder: "203.0.113.10",
                register_button: "注册",
                agents_title: "代理列表",
                targets_title: "目标列表",
                delete_button: "删除",
                last_seen: "最近在线",
                measurements_title: "测量结果",
                measurement_time: "时间",
                measurement_agent: "代理",
                measurement_latency: "延迟",
                measurement_loss: "丢包率",
                measurement_success: "成功",
                measurement_mtr: "MTR 输出",
                measurement_traceroute: "Traceroute 输出",
                no_measurements: "暂无测量数据。",
                success_yes: "是",
                success_no: "否",
            },
        };

        function applyTranslations() {
            const lang = navigator.language || "en";
            const dict = lang.toLowerCase().startsWith("zh") ? translations.zh : translations.en;
            document.querySelectorAll("[data-i18n]").forEach((el) => {
                const key = el.getAttribute("data-i18n");
                if (dict[key]) {
                    el.textContent = dict[key];
                }
            });
            document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
                const key = el.getAttribute("data-i18n-placeholder");
                if (dict[key]) {
                    el.setAttribute("placeholder", dict[key]);
                }
            });
        }
        applyTranslations();
        async function deleteTarget(id) {
            await fetch(apiPath(`/api/targets/${id}`), { method: 'DELETE' });
            location.reload();
        }
        async function deleteAgent(id) {
            await fetch(apiPath(`/api/agents/${id}`), { method: 'DELETE' });
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
            await fetch(apiPath('/api/targets'), {
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
                mtr_runs: Number(form.mtr_runs.value || 10),
            };
            await fetch(apiPath('/api/config'), {
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
            await fetch(apiPath('/api/agents'), {
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
    body = body.replace("{base_path}", base_path);
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
    let mtr_runs = payload.mtr_runs.max(1);
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
    update_setting(&state.pool, "mtr_runs", &mtr_runs.to_string()).await?;
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
    let mtr_runs: (String,) = sqlx::query_as("SELECT value FROM settings WHERE key = 'mtr_runs'")
        .fetch_one(pool)
        .await?;

    Ok(Config {
        interval_seconds: interval.0.parse().unwrap_or(60),
        timeout_seconds: timeout.0.parse().unwrap_or(10),
        mtr_runs: mtr_runs.0.parse().unwrap_or(10),
    })
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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

    let mut since = Utc::now() - duration;
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

    if let Some(first_ts) = points.first().map(|point| point.timestamp) {
        if first_ts > since.timestamp() {
            if let Some(first_time) = DateTime::<Utc>::from_timestamp(first_ts, 0) {
                since = first_time;
            }
        }
    }

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
