use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use plotters::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqliteConnectOptions, sqlite::SqlitePoolOptions, SqlitePool};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::str::FromStr;

type AppResult<T> = Result<T, AppError>;

#[derive(Clone)]
struct AppState {
    pool: SqlitePool,
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
struct MeasurementInput {
    target_id: i64,
    avg_ms: Option<f64>,
    packet_loss: Option<f64>,
    success: bool,
    mtr: String,
    traceroute: String,
    timestamp: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct MeasurementPoint {
    timestamp: i64,
    avg_ms: Option<f64>,
}

#[derive(Deserialize)]
struct RangeQuery {
    range: Option<String>,
}

pub async fn run(database_url: String, bind: String) -> anyhow::Result<()> {
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

    let state = Arc::new(AppState { pool });
    let app = Router::new()
        .route("/", get(index))
        .route("/api/targets", get(list_targets).post(add_target))
        .route("/api/targets/:id", delete(delete_target).put(update_target))
        .route("/api/targets/unresponsive", get(unresponsive_targets))
        .route("/api/config", get(get_config).put(update_config))
        .route("/api/measurements", post(add_measurement))
        .route("/graph/:id", get(graph))
        .with_state(state);

    let addr: SocketAddr = bind.parse()?;
    tracing::info!("listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

async fn init_db(pool: &SqlitePool) -> anyhow::Result<()> {
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
            avg_ms REAL,
            packet_loss REAL,
            success INTEGER NOT NULL,
            mtr TEXT NOT NULL,
            traceroute TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
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

    let config = fetch_config(&state.pool).await?;
    let mut grouped: BTreeMap<String, Vec<Target>> = BTreeMap::new();
    for target in targets {
        grouped
            .entry(target.category.clone())
            .or_default()
            .push(target);
    }

    let mut body = String::new();
    body.push_str("<html><head><title>Rust SmokePing</title></head><body>");
    body.push_str("<h1>Rust SmokePing</h1>");
    body.push_str(&format!(
        "<p>Interval: {}s, Timeout: {}s</p>",
        config.interval_seconds, config.timeout_seconds
    ));
    body.push_str("<h2>Settings</h2>");
    body.push_str(&format!(
        r#"
        <form method="post" action="/api/config" onsubmit="return submitConfig(event)">
            <label>Interval Seconds: <input name="interval_seconds" type="number" value="{}"/></label>
            <label>Timeout Seconds: <input name="timeout_seconds" type="number" value="{}"/></label>
            <button type="submit">Update</button>
        </form>
        "#,
        config.interval_seconds, config.timeout_seconds
    ));
    body.push_str("<h2>Add Target</h2>");
    body.push_str(
        r#"
        <form method="post" action="/api/targets" onsubmit="return submitTarget(event)">
            <label>Name: <input name="name"/></label>
            <label>Address: <input name="address"/></label>
            <label>Category: <input name="category"/></label>
            <label>Sort Order: <input name="sort_order" type="number" value="0"/></label>
            <button type="submit">Add</button>
        </form>
        <script>
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
        </script>
        "#,
    );

    for (category, items) in grouped {
        body.push_str(&format!("<h2>{}</h2>", category));
        body.push_str("<ul>");
        for item in items {
            body.push_str(&format!(
                "<li><strong>{}</strong> ({}) - <a href=\"/graph/{}?range=1h\">1h</a> <a href=\"/graph/{}?range=3h\">3h</a> <a href=\"/graph/{}?range=1d\">1d</a> <a href=\"/graph/{}?range=7d\">7d</a> <a href=\"/graph/{}?range=1m\">1m</a> \
                <button onclick=\"deleteTarget({})\">Delete</button></li>",
                item.name,
                item.address,
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

    body.push_str(
        r#"
        <script>
        async function deleteTarget(id) {
            await fetch(`/api/targets/${id}`, { method: 'DELETE' });
            location.reload();
        }
        </script>
        "#,
    );

    body.push_str("</body></html>");
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
    sqlx::query(
        "INSERT INTO targets (name, address, category, sort_order) VALUES (?, ?, ?, ?)",
    )
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
    let target: Option<Target> = sqlx::query_as(
        "SELECT id, name, address, category, sort_order FROM targets WHERE id = ?",
    )
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

async fn unresponsive_targets(
    State(state): State<Arc<AppState>>,
) -> AppResult<Json<Vec<Target>>> {
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
    update_setting(&state.pool, "interval_seconds", &payload.interval_seconds.to_string()).await?;
    update_setting(&state.pool, "timeout_seconds", &payload.timeout_seconds.to_string()).await?;
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
    let interval: (String,) = sqlx::query_as("SELECT value FROM settings WHERE key = 'interval_seconds'")
        .fetch_one(pool)
        .await?;
    let timeout: (String,) = sqlx::query_as("SELECT value FROM settings WHERE key = 'timeout_seconds'")
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
        "INSERT INTO measurements (target_id, avg_ms, packet_loss, success, mtr, traceroute, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(payload.target_id)
    .bind(payload.avg_ms)
    .bind(payload.packet_loss)
    .bind(if payload.success { 1 } else { 0 })
    .bind(payload.mtr)
    .bind(payload.traceroute)
    .bind(payload.timestamp.timestamp())
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
    let points: Vec<MeasurementPoint> = sqlx::query_as(
        "SELECT timestamp, avg_ms FROM measurements WHERE target_id = ? AND timestamp >= ? ORDER BY timestamp",
    )
    .bind(id)
    .bind(since.timestamp())
    .fetch_all(&state.pool)
    .await?;

    let mut buffer = vec![0u8; 800 * 300 * 3];
    {
        let root = BitMapBackend::with_buffer(&mut buffer, (800, 300)).into_drawing_area();
        root.fill(&WHITE)?;
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
        chart.configure_mesh().draw()?;

        let series = points.iter().filter_map(|p| p.avg_ms.map(|avg| (p.timestamp, avg)));
        chart.draw_series(LineSeries::new(series, &BLUE))?;
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
