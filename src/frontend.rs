use axum::extract::Path;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Router, http::StatusCode};
use include_dir::{Dir, include_dir};
use mime_guess::MimeGuess;
use tower_http::compression::CompressionLayer;

static FRONTEND_DIST: Dir = include_dir!("$CARGO_MANIFEST_DIR/frontend/dist");

pub fn router() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/static/{*path}", get(static_asset))
        .layer(CompressionLayer::new())
}

async fn index() -> Response {
    serve_file("index.html")
}

async fn static_asset(Path(path): Path<String>) -> Response {
    let trimmed = path.trim_start_matches('/');
    let asset_path = format!("static/{}", trimmed);
    serve_file(&asset_path)
}

fn serve_file(path: &str) -> Response {
    let file = FRONTEND_DIST.get_file(path);
    let Some(file) = file else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let mime = MimeGuess::from_path(path).first_or_octet_stream();
    (
        [(header::CONTENT_TYPE, mime.as_ref())],
        file.contents(),
    )
        .into_response()
}
