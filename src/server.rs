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
use chrono::{DateTime, Duration, TimeZone, Utc};
use plotters::prelude::*;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions, sqlite::SqlitePoolOptions};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::process::Stdio;
use std::str::FromStr;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::frontend;

type AppResult<T> = Result<T, AppError>;

const AUTO_CATEGORY: &str = "自动";

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

#[derive(sqlx::FromRow)]
struct AutoTargetConfig {
    id: i64,
    auto_octet1: i64,
    auto_octet2: i64,
    auto_third_start: i64,
    auto_third_end: i64,
    auto_last_scan: Option<i64>,
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
struct AutoTargetInput {
    octet1: i64,
    octet2: i64,
    third_start: i64,
    third_end: i64,
    name: Option<String>,
    category: Option<String>,
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
    packet_loss: Option<f64>,
    agent_name: String,
}

#[derive(sqlx::FromRow)]
struct MeasurementSummaryPoint {
    timestamp: i64,
    avg_ms: Option<f64>,
    packet_loss: Option<f64>,
}

#[derive(Serialize)]
struct SummaryStats {
    min: Option<f64>,
    max: Option<f64>,
    avg: Option<f64>,
    median: Option<f64>,
    latest: Option<f64>,
}

#[derive(Serialize)]
struct GraphSummary {
    latency: SummaryStats,
    loss: SummaryStats,
    sample_count: usize,
    last_timestamp: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
struct LatestMeasurement {
    target_id: i64,
    agent_id: i64,
    timestamp: i64,
    avg_ms: Option<f64>,
    packet_loss: Option<f64>,
    last_loss_timestamp: Option<i64>,
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
    agent_id: Option<i64>,
}

pub async fn run(
    database_url: String,
    bind: String,
    auth_file: String,
    base_path: String,
) -> anyhow::Result<()> {
    let base_path = normalize_base_path(&base_path);
    let app = build_api_app(database_url, auth_file, base_path.clone()).await?;
    let app = if base_path.is_empty() {
        Router::new()
            .route("/%22/{*path}", get(quoted_path_redirect))
            .merge(app)
    } else {
        let base_with_slash = format!("{}/", base_path);
        let base_path_redirect = base_path.clone();
        Router::new()
            .route(
                &base_with_slash,
                get(move || {
                    let base_path_redirect = base_path_redirect.clone();
                    async move { Redirect::to(&base_path_redirect) }
                }),
            )
            .route("/%22/{*path}", get(quoted_path_redirect))
            .nest(&base_path, app)
    };

    let addr: SocketAddr = bind.parse()?;
    tracing::info!("listening on {}", addr);
    axum::serve(
        tokio::net::TcpListener::bind(addr).await?,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

pub async fn build_api_app(
    database_url: String,
    auth_file: String,
    base_path: String,
) -> anyhow::Result<Router> {
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
        base_path: base_path.clone(),
    });

    let agent_report = Router::new()
        .route("/api/measurements", post(add_measurement))
        .layer(from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state.clone());

    let protected = Router::new()
        .route("/api/targets", get(list_targets).post(add_target))
        .route("/api/targets/auto", post(add_auto_target))
        .route(
            "/api/targets/{id}",
            delete(delete_target).put(update_target),
        )
        .route("/api/targets/unresponsive", get(unresponsive_targets))
        .route("/api/agents", get(list_agents).post(register_agent))
        .route("/api/agents/{id}", delete(delete_agent))
        .route("/api/config", get(get_config).put(update_config))
        .route("/api/measurements/latest", get(latest_measurements))
        .route("/api/targets/{id}/summary", get(graph_summary))
        .route("/graph/{id}", get(graph))
        .layer(from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state.clone());

    let frontend_protected = frontend::router()
        .with_state::<Arc<AppState>>(())
        .layer(from_fn_with_state(state.clone(), auth_middleware));

    let setup_routes = Router::new()
        .route("/setup", get(setup_page).post(setup_auth))
        .route("/setup/", get(setup_page).post(setup_auth))
        .route("/%22/setup/%22", get(setup_page).post(setup_auth))
        .route("/%22/setup/%22/", get(setup_page).post(setup_auth));

    let app = Router::new()
        .merge(setup_routes)
        .merge(frontend_protected)
        .merge(agent_report)
        .merge(protected)
        .with_state(state);

    Ok(app)
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

async fn quoted_path_redirect(Path(path): Path<String>, uri: axum::http::Uri) -> Redirect {
    let normalized = path.replace('"', "");
    let trimmed = normalized.trim_start_matches('/');
    let mut location = if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", trimmed)
    };
    if let Some(query) = uri.query() {
        if !query.is_empty() {
            location.push('?');
            location.push_str(query);
        }
    }
    Redirect::to(&location)
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
            sort_order INTEGER NOT NULL DEFAULT 0,
            is_auto INTEGER NOT NULL DEFAULT 0,
            auto_octet1 INTEGER,
            auto_octet2 INTEGER,
            auto_third_start INTEGER,
            auto_third_end INTEGER,
            auto_last_scan INTEGER
        )",
    )
    .execute(pool)
    .await?;

    ensure_target_column(pool, "is_auto INTEGER NOT NULL DEFAULT 0").await?;
    ensure_target_column(pool, "auto_octet1 INTEGER").await?;
    ensure_target_column(pool, "auto_octet2 INTEGER").await?;
    ensure_target_column(pool, "auto_third_start INTEGER").await?;
    ensure_target_column(pool, "auto_third_end INTEGER").await?;
    ensure_target_column(pool, "auto_last_scan INTEGER").await?;

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

async fn sync_auth(state: &Arc<AppState>) -> Result<Option<AuthConfig>, AppError> {
    if !state.auth_path.exists() {
        let mut auth = state.auth.write().await;
        *auth = None;
        return Ok(None);
    }

    let contents = fs::read_to_string(&state.auth_path)
        .await
        .map_err(|err| AppError(anyhow::anyhow!(err)))?;
    let config: AuthConfig =
        serde_json::from_str(&contents).map_err(|err| AppError(anyhow::anyhow!(err)))?;
    let mut auth = state.auth.write().await;
    *auth = Some(config.clone());
    Ok(Some(config))
}

async fn setup_page(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HashMap<String, String>>,
) -> AppResult<Response> {
    {
        let auth = sync_auth(&state).await?;
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
        let auth = sync_auth(state).await?;
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
    let auth = sync_auth(&state).await?;
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

async fn ensure_target_column(pool: &SqlitePool, column: &str) -> anyhow::Result<()> {
    let sql = format!("ALTER TABLE targets ADD COLUMN {}", column);
    match sqlx::query(&sql).execute(pool).await {
        Ok(_) => Ok(()),
        Err(err) => {
            if err.to_string().contains("duplicate column name") {
                Ok(())
            } else {
                Err(err.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn local_request(uri: &str) -> Request<Body> {
        let mut req = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request");
        req.extensions_mut()
            .insert(SocketAddr::from(([127, 0, 0, 1], 0)));
        req
    }

    async fn build_test_app(base_path: &str, auth: Option<AuthConfig>) -> (Router, TempDir) {
        let tempdir = TempDir::new().expect("create tempdir");
        let db_path = tempdir.path().join("smokeping.db");
        let auth_path = tempdir.path().join("auth.json");
        if let Some(auth) = auth {
            let serialized = serde_json::to_string_pretty(&auth).expect("serialize auth");
            std::fs::write(&auth_path, serialized).expect("write auth");
        }
        let normalized_base = normalize_base_path(base_path);
        let app = build_api_app(
            db_path.to_string_lossy().to_string(),
            auth_path.to_string_lossy().to_string(),
            normalized_base.clone(),
        )
        .await
        .expect("build app");
        let app = if normalized_base.is_empty() {
            Router::new()
                .route("/%22/{*path}", get(quoted_path_redirect))
                .merge(app)
        } else {
            let base_with_slash = format!("{}/", normalized_base);
            let base_path_redirect = normalized_base.clone();
            Router::new()
                .route(
                    &base_with_slash,
                    get(move || {
                        let base_path_redirect = base_path_redirect.clone();
                        async move { Redirect::to(&base_path_redirect) }
                    }),
                )
                .route("/%22/{*path}", get(quoted_path_redirect))
                .nest(&normalized_base, app)
        };
        (app, tempdir)
    }

    fn build_auth() -> AuthConfig {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(b"secret", &salt)
            .expect("hash password")
            .to_string();
        AuthConfig {
            username: "admin".to_string(),
            password_hash: hash,
        }
    }

    fn basic_auth_header(username: &str, password: &str) -> String {
        let raw = format!("{}:{}", username, password);
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        format!("Basic {}", encoded)
    }

    #[tokio::test]
    async fn frontend_redirects_to_setup_when_auth_missing() {
        let (app, _tempdir) = build_test_app("", None).await;
        let response = app
            .oneshot(local_request("/"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(header::LOCATION)
            .expect("location header");
        assert_eq!(location, "/setup");
    }

    #[tokio::test]
    async fn frontend_requires_auth_when_configured() {
        let (app, _tempdir) = build_test_app("", Some(build_auth())).await;
        let response = app
            .oneshot(local_request("/"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn api_redirects_to_setup_without_auth_file() {
        let (app, _tempdir) = build_test_app("", None).await;
        let response = app
            .oneshot(local_request("/api/config"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(header::LOCATION)
            .expect("location header");
        assert_eq!(location, "/setup");
    }

    #[tokio::test]
    async fn api_allows_authenticated_requests() {
        let (app, _tempdir) = build_test_app("", Some(build_auth())).await;
        let mut request = local_request("/api/config");
        request.headers_mut().insert(
            header::AUTHORIZATION,
            basic_auth_header("admin", "secret")
                .parse()
                .expect("auth header"),
        );
        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn quoted_setup_path_redirects() {
        let (app, _tempdir) = build_test_app("/smokeping", None).await;
        let response = app
            .oneshot(local_request("/%22/smokeping/setup/%22"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(header::LOCATION)
            .expect("location header");
        assert_eq!(location, "/smokeping/setup/");
    }

    #[tokio::test]
    async fn quoted_setup_path_preserves_query() {
        let (app, _tempdir) = build_test_app("/smokeping", None).await;
        let response = app
            .oneshot(local_request(
                "/%22/smokeping/setup/%22?%5C%22username%5C%22=admin&%5C%22password%5C%22=admin",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(header::LOCATION)
            .expect("location header");
        assert_eq!(
            location,
            "/smokeping/setup/?%5C%22username%5C%22=admin&%5C%22password%5C%22=admin"
        );
    }

}

async fn latest_measurements(
    State(state): State<Arc<AppState>>,
) -> AppResult<Json<Vec<LatestMeasurement>>> {
    let cutoff = Utc::now().timestamp() - 3 * 60 * 60;
    let latest_measurements: Vec<LatestMeasurement> = sqlx::query_as(
        "SELECT m.target_id, m.agent_id, m.timestamp, m.avg_ms, m.packet_loss,
            (
                SELECT MAX(timestamp)
                FROM measurements ml
                WHERE ml.target_id = m.target_id
                    AND ml.agent_id = m.agent_id
                    AND ml.packet_loss > 10
                    AND ml.timestamp >= ?
            ) AS last_loss_timestamp,
            m.success, m.mtr, m.traceroute, a.name as agent_name
        FROM measurements m
        JOIN (
            SELECT target_id, agent_id, MAX(timestamp) AS ts
            FROM measurements
            GROUP BY target_id, agent_id
        ) latest ON m.target_id = latest.target_id AND m.agent_id = latest.agent_id AND m.timestamp = latest.ts
        JOIN agents a ON m.agent_id = a.id",
    )
    .bind(cutoff)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(latest_measurements))
}

async fn list_targets(State(state): State<Arc<AppState>>) -> AppResult<Json<Vec<Target>>> {
    let targets = sqlx::query_as(
        "SELECT id, name, address, category, sort_order FROM targets ORDER BY category, sort_order, name",
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(targets))
}

async fn add_auto_target(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AutoTargetInput>,
) -> AppResult<Response> {
    if let Err(response) = validate_octet("octet1", payload.octet1) {
        return Ok(response);
    }
    if let Err(response) = validate_octet("octet2", payload.octet2) {
        return Ok(response);
    }
    if let Err(response) = validate_octet("third_start", payload.third_start) {
        return Ok(response);
    }
    if let Err(response) = validate_octet("third_end", payload.third_end) {
        return Ok(response);
    }
    if payload.third_start > payload.third_end {
        return Ok((
            StatusCode::BAD_REQUEST,
            "third_start must be <= third_end",
        )
            .into_response());
    }

    let ip = match scan_range(
        payload.octet1,
        payload.octet2,
        payload.third_start,
        payload.third_end,
    )
    .await?
    {
        Some(ip) => ip,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                "no reachable IPs found in range",
            )
                .into_response());
        }
    };

    let name = payload.name.unwrap_or_else(|| {
        format!(
            "auto-{}.{}.{}-{}",
            payload.octet1, payload.octet2, payload.third_start, payload.third_end
        )
    });
    let category = payload
        .category
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| AUTO_CATEGORY.to_string());
    let now = Utc::now().timestamp();
    let existing: Option<Target> = sqlx::query_as(
        "SELECT id, name, address, category, sort_order
        FROM targets
        WHERE is_auto = 1 AND auto_octet1 = ? AND auto_octet2 = ?
            AND auto_third_start = ? AND auto_third_end = ?",
    )
    .bind(payload.octet1)
    .bind(payload.octet2)
    .bind(payload.third_start)
    .bind(payload.third_end)
    .fetch_optional(&state.pool)
    .await?;

    let target = if let Some(existing) = existing {
        sqlx::query(
            "UPDATE targets
            SET name = ?, address = ?, category = ?, sort_order = ?, auto_last_scan = ?
            WHERE id = ?",
        )
        .bind(&name)
        .bind(&ip)
        .bind(&category)
        .bind(payload.sort_order.unwrap_or(existing.sort_order))
        .bind(now)
        .bind(existing.id)
        .execute(&state.pool)
        .await?;

        Target {
            id: existing.id,
            name,
            address: ip,
            category,
            sort_order: payload.sort_order.unwrap_or(existing.sort_order),
        }
    } else {
        let result = sqlx::query(
            "INSERT INTO targets (name, address, category, sort_order, is_auto, auto_octet1, auto_octet2, auto_third_start, auto_third_end, auto_last_scan)
            VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)",
        )
        .bind(&name)
        .bind(&ip)
        .bind(&category)
        .bind(payload.sort_order.unwrap_or(0))
        .bind(payload.octet1)
        .bind(payload.octet2)
        .bind(payload.third_start)
        .bind(payload.third_end)
        .bind(now)
        .execute(&state.pool)
        .await?;

        Target {
            id: result.last_insert_rowid(),
            name,
            address: ip,
            category,
            sort_order: payload.sort_order.unwrap_or(0),
        }
    };

    Ok(Json(target).into_response())
}

fn validate_octet(name: &str, value: i64) -> Result<(), Response> {
    if (0..=255).contains(&value) {
        Ok(())
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            format!("{} must be between 0 and 255", name),
        )
            .into_response())
    }
}

async fn scan_range(
    octet1: i64,
    octet2: i64,
    third_start: i64,
    third_end: i64,
) -> AppResult<Option<String>> {
    let semaphore = Arc::new(Semaphore::new(20));
    let mut join_set = JoinSet::new();

    for third in third_start..=third_end {
        for fourth in 0..=255 {
            let ip = format!("{}.{}.{}.{}", octet1, octet2, third, fourth);
            let semaphore = semaphore.clone();
            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.ok()?;
                if ping_ip(&ip).await {
                    Some(ip)
                } else {
                    None
                }
            });
        }
    }

    while let Some(result) = join_set.join_next().await {
        if let Some(ip) = result.map_err(|err| AppError(anyhow::anyhow!(err)))? {
            join_set.abort_all();
            return Ok(Some(ip));
        }
    }

    Ok(None)
}

async fn ping_ip(ip: &str) -> bool {
    let status = Command::new("ping")
        .arg("-c")
        .arg("1")
        .arg("-W")
        .arg("1")
        .arg(ip)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    matches!(status, Ok(exit) if exit.success())
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

async fn add_measurement(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<MeasurementInput>,
) -> AppResult<StatusCode> {
    let now = payload.timestamp.timestamp();
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
    .bind(now)
    .execute(&state.pool)
    .await?;

    sqlx::query("UPDATE agents SET last_seen = ? WHERE id = ?")
        .bind(now)
        .bind(payload.agent_id)
        .execute(&state.pool)
        .await?;

    let cutoff = Utc::now() - Duration::days(30);
    sqlx::query("DELETE FROM measurements WHERE timestamp < ?")
        .bind(cutoff.timestamp())
        .execute(&state.pool)
        .await?;

    if !payload.success {
        if let Some(auto_target) = sqlx::query_as::<_, AutoTargetConfig>(
            "SELECT id, auto_octet1, auto_octet2, auto_third_start, auto_third_end, auto_last_scan
            FROM targets
            WHERE id = ? AND is_auto = 1",
        )
        .bind(payload.target_id)
        .fetch_optional(&state.pool)
        .await?
        {
            let last_scan = auto_target.auto_last_scan.unwrap_or(0);
            if now - last_scan >= 300 {
                sqlx::query("UPDATE targets SET auto_last_scan = ? WHERE id = ?")
                    .bind(now)
                    .bind(auto_target.id)
                    .execute(&state.pool)
                    .await?;
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Ok(Some(ip)) = scan_range(
                        auto_target.auto_octet1,
                        auto_target.auto_octet2,
                        auto_target.auto_third_start,
                        auto_target.auto_third_end,
                    )
                    .await
                    {
                        let _ = sqlx::query("UPDATE targets SET address = ? WHERE id = ?")
                            .bind(ip)
                            .bind(auto_target.id)
                            .execute(&state.pool)
                            .await;
                    }
                });
            }
        }
    }

    Ok(StatusCode::CREATED)
}

fn range_duration(range: &str) -> Duration {
    match range {
        "1h" => Duration::hours(1),
        "3h" => Duration::hours(3),
        "1d" => Duration::days(1),
        "7d" => Duration::days(7),
        "1m" => Duration::days(30),
        _ => Duration::hours(1),
    }
}

fn range_title(range: &str) -> &'static str {
    match range {
        "1h" => "Last 1 Hour",
        "3h" => "Last 3 Hours",
        "1d" => "Last 24 Hours",
        "7d" => "Last 7 Days",
        "1m" => "Last 30 Days",
        _ => "Last Hour",
    }
}

fn median(values: &mut [f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        Some(values[mid])
    } else {
        Some((values[mid - 1] + values[mid]) / 2.0)
    }
}

fn summarize_series(values: &[f64], latest: Option<f64>) -> SummaryStats {
    if values.is_empty() {
        return SummaryStats {
            min: None,
            max: None,
            avg: None,
            median: None,
            latest,
        };
    }
    let min = values
        .iter()
        .copied()
        .fold(f64::INFINITY, f64::min);
    let max = values
        .iter()
        .copied()
        .fold(f64::NEG_INFINITY, f64::max);
    let avg = values.iter().sum::<f64>() / values.len() as f64;
    let mut sorted = values.to_vec();
    let median = median(&mut sorted);
    SummaryStats {
        min: Some(min),
        max: Some(max),
        avg: Some(avg),
        median,
        latest,
    }
}

async fn graph_summary(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(params): Query<RangeQuery>,
) -> AppResult<Json<GraphSummary>> {
    let range = params.range.unwrap_or_else(|| "1h".to_string());
    let duration = range_duration(&range);
    let since = Utc::now() - duration;
    let points: Vec<MeasurementSummaryPoint> = if let Some(agent_id) = params.agent_id {
        sqlx::query_as(
            "SELECT timestamp, avg_ms, packet_loss
            FROM measurements
            WHERE target_id = ? AND timestamp >= ? AND agent_id = ?
            ORDER BY timestamp",
        )
        .bind(id)
        .bind(since.timestamp())
        .bind(agent_id)
        .fetch_all(&state.pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT timestamp, avg_ms, packet_loss
            FROM measurements
            WHERE target_id = ? AND timestamp >= ?
            ORDER BY timestamp",
        )
        .bind(id)
        .bind(since.timestamp())
        .fetch_all(&state.pool)
        .await?
    };

    let latency_values: Vec<f64> = points.iter().filter_map(|p| p.avg_ms).collect();
    let loss_values: Vec<f64> = points.iter().filter_map(|p| p.packet_loss).collect();
    let latest_latency = points.iter().rev().find_map(|p| p.avg_ms);
    let latest_loss = points.iter().rev().find_map(|p| p.packet_loss);

    let summary = GraphSummary {
        latency: summarize_series(&latency_values, latest_latency),
        loss: summarize_series(&loss_values, latest_loss),
        sample_count: points.len(),
        last_timestamp: points.last().map(|point| point.timestamp),
    };

    Ok(Json(summary))
}

async fn graph(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(params): Query<RangeQuery>,
) -> AppResult<Response> {
    let range = params.range.unwrap_or_else(|| "1h".to_string());
    let duration = range_duration(&range);

    let mut since = Utc::now() - duration;
    let points: Vec<MeasurementWithAgent> = if let Some(agent_id) = params.agent_id {
        sqlx::query_as(
            "SELECT m.timestamp, m.avg_ms, m.packet_loss, a.name as agent_name
            FROM measurements m
            JOIN agents a ON m.agent_id = a.id
            WHERE m.target_id = ? AND m.timestamp >= ? AND m.agent_id = ?
            ORDER BY m.timestamp",
        )
        .bind(id)
        .bind(since.timestamp())
        .bind(agent_id)
        .fetch_all(&state.pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT m.timestamp, m.avg_ms, m.packet_loss, a.name as agent_name
            FROM measurements m
            JOIN agents a ON m.agent_id = a.id
            WHERE m.target_id = ? AND m.timestamp >= ?
            ORDER BY m.timestamp",
        )
        .bind(id)
        .bind(since.timestamp())
        .fetch_all(&state.pool)
        .await?
    };

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
        let latency_values: Vec<f64> = points.iter().filter_map(|p| p.avg_ms).collect();
        let (y_min, y_max) = if latency_values.is_empty() {
            (0.0, 1.0)
        } else {
            let min_y = latency_values
                .iter()
                .copied()
                .fold(f64::INFINITY, f64::min);
            let max_y = latency_values
                .iter()
                .copied()
                .fold(f64::NEG_INFINITY, f64::max);
            let span = (max_y - min_y).abs();
            let padding = if span < 1.0 { 1.0 } else { span * 0.1 };
            let padded_min = (min_y - padding).max(0.0);
            let padded_max = (max_y + padding).max(1.0);
            (padded_min, padded_max)
        };
        let chart_title = range_title(&range);
        let mut chart = ChartBuilder::on(&root)
            .margin(10)
            .caption(
                chart_title,
                ("sans-serif", 20).into_font().color(&RGBColor(226, 232, 240)),
            )
            .x_label_area_size(30)
            .y_label_area_size(50)
            .build_cartesian_2d(
                since.timestamp()..Utc::now().timestamp(),
                y_min..y_max,
            )?;
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
            .x_label_formatter(&|timestamp| {
                let date = chrono::Local.timestamp_opt(*timestamp, 0);
                date.single()
                    .map(|dt| dt.format("%m/%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "-".to_string())
            })
            .draw()?;

        let mut by_agent_latency: BTreeMap<String, Vec<(i64, f64)>> = BTreeMap::new();
        let mut by_agent_loss: BTreeMap<String, Vec<(i64, f64)>> = BTreeMap::new();
        for point in points {
            let agent_name = point.agent_name.clone();
            if let Some(avg) = point.avg_ms {
                by_agent_latency
                    .entry(agent_name.clone())
                    .or_default()
                    .push((point.timestamp, avg));
            }
            if let Some(loss) = point.packet_loss {
                by_agent_loss
                    .entry(agent_name)
                    .or_default()
                    .push((point.timestamp, loss));
            }
        }

        let latency_palette = vec![
            RGBColor(56, 189, 248),
            RGBColor(248, 113, 113),
            RGBColor(129, 140, 248),
            RGBColor(34, 197, 94),
            RGBColor(251, 146, 60),
        ];
        let loss_palette = vec![
            RGBColor(251, 191, 36),
            RGBColor(244, 114, 182),
            RGBColor(167, 139, 250),
            RGBColor(74, 222, 128),
            RGBColor(96, 165, 250),
        ];

        let mut chart = chart.set_secondary_coord(
            since.timestamp()..Utc::now().timestamp(),
            0.0..100.0,
        );

        for (idx, (agent, series)) in by_agent_latency.into_iter().enumerate() {
            let color = latency_palette
                .get(idx % latency_palette.len())
                .cloned()
                .unwrap_or(BLUE);
            let style = ShapeStyle::from(&color).stroke_width(3);
            chart
                .draw_series(LineSeries::new(series.clone(), style))?
                .label(agent)
                .legend(move |(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], color));
            chart.draw_series(series.iter().map(|(x, y)| {
                Circle::new((*x, *y), 2, ShapeStyle::from(&color).filled())
            }))?;
        }

        for (idx, (agent, series)) in by_agent_loss.into_iter().enumerate() {
            let color = loss_palette
                .get(idx % loss_palette.len())
                .cloned()
                .unwrap_or(RED);
            let style = ShapeStyle::from(&color).stroke_width(2);
            chart
                .draw_secondary_series(LineSeries::new(series, style))?
                .label(format!("{} Loss%", agent))
                .legend(move |(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], color));
        }

        chart
            .configure_secondary_axes()
            .axis_style(&RGBColor(148, 163, 184))
            .label_style(
                ("sans-serif", 12)
                    .into_font()
                    .color(&RGBColor(148, 163, 184)),
            )
            .draw()?;

        chart
            .configure_series_labels()
            .border_style(&RGBColor(51, 65, 85))
            .background_style(&RGBColor(15, 23, 42))
            .label_font(("sans-serif", 12).into_font().color(&RGBColor(226, 232, 240)))
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
        let mut encoder = encoder;
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        writer.write_image_data(&buffer)?;
    }
    Ok(png_bytes)
}
