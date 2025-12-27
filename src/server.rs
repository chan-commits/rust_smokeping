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
use chrono::{DateTime, Duration, Local, TimeZone, Utc};
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

use crate::frontend;

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
    packet_loss: Option<f64>,
    agent_name: String,
}

#[derive(Serialize, sqlx::FromRow)]
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
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
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

    let protected = Router::new()
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
        .route("/api/measurements/latest", get(latest_measurements))
        .route("/graph/{id}", get(graph))
        .layer(from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state.clone());

    let frontend_protected = frontend::router()
        .with_state::<Arc<AppState>>(())
        .layer(from_fn_with_state(state.clone(), auth_middleware));

    let app = Router::new()
        .route("/setup", get(setup_page).post(setup_auth))
        .route("/setup/", get(setup_page).post(setup_auth))
        .route("/%22/setup/%22", get(setup_page).post(setup_auth))
        .route("/%22/setup/%22/", get(setup_page).post(setup_auth))
        .merge(frontend_protected)
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tempfile::TempDir;
    use tower::ServiceExt;

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
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("request"),
            )
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
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn api_redirects_to_setup_without_auth_file() {
        let (app, _tempdir) = build_test_app("", None).await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/config")
                    .body(Body::empty())
                    .expect("request"),
            )
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
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/config")
                    .header(
                        header::AUTHORIZATION,
                        basic_auth_header("admin", "secret"),
                    )
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn quoted_setup_path_redirects() {
        let (app, _tempdir) = build_test_app("/smokeping", None).await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/%22/smokeping/setup/%22")
                    .body(Body::empty())
                    .expect("request"),
            )
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
            .oneshot(
                Request::builder()
                    .uri("/%22/smokeping/setup/%22?%5C%22username%5C%22=admin&%5C%22password%5C%22=admin")
                    .body(Body::empty())
                    .expect("request"),
            )
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
        "SELECT m.timestamp, m.avg_ms, m.packet_loss, a.name as agent_name
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
            .caption(
                "Latency (ms)",
                ("sans-serif", 20).into_font().color(&RGBColor(226, 232, 240)),
            )
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
            chart
                .draw_series(LineSeries::new(series, &color))?
                .label(agent)
                .legend(move |(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], color));
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
