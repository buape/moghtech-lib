use std::path::{Path, PathBuf};

use anyhow::Context;
use axum::{
  Router,
  http::{HeaderValue, StatusCode, header},
};
use sha2::Digest as _;
use tower_http::{
  services::{ServeDir, ServeFile},
  set_header::SetResponseHeaderLayer,
  set_status::SetStatus,
};
use tracing::warn;

/// Serves the index fallback with 200 OK status.
/// Note. `ServeDir::not_found_service` would force the
/// fallback response status to 404, which breaks browser
/// caching (the ETag / Cache-Control headers on the index)
/// for client side routed paths.
fn with_index_fallback(
  directory: PathBuf,
  index: Router,
) -> ServeDir<SetStatus<Router>> {
  ServeDir::new(directory)
    .fallback(SetStatus::new(index, StatusCode::OK))
}

/// The static UI must have an `index.html` to use as the root.
///
/// Tries to hash index contents to use as ETag, falls
/// back to 'Cache-Control: no-cache' if this fails.
///
/// If `force_no_cache` is passed, the `index.html` will
/// always be served with no-cache header.
pub fn serve_static_ui(
  ui_path: &str,
  force_no_cache: bool,
) -> ServeDir<SetStatus<Router>> {
  let directory = PathBuf::from(ui_path);
  let index = directory.join("index.html");

  let index_router =
    Router::new().fallback_service(ServeFile::new(&index));

  if force_no_cache {
    return with_index_fallback(
      directory,
      add_no_cache_layer(index_router),
    );
  }

  let index = match hash_encode_contents(&index) {
    Ok(header_value) => {
      index_router
        // The ETag header helps browser know when the
        // contents have changed / invalidate cache.
        .layer(SetResponseHeaderLayer::overriding(
          header::ETAG,
          header_value,
        ))
    }
    Err(e) => {
      warn!(
        "Failed to create ETag header for index.html, using 'Cache-Control: no-cache' | {e:#}"
      );
      add_no_cache_layer(index_router)
    }
  };

  with_index_fallback(directory, index)
}

fn hash_encode_contents(path: &Path) -> anyhow::Result<HeaderValue> {
  let contents = std::fs::read(path).context(
    "Failed to read static UI index.html for content hash",
  )?;
  let mut hasher = sha2::Sha256::new();
  hasher.update(&contents);
  let digest = hasher.finalize();
  let value = data_encoding::BASE64URL.encode(&digest);
  // ETag values must be wrapped in double quotes (RFC 9110).
  HeaderValue::from_bytes(format!("\"{value}\"").as_bytes())
    .context("Invalid index hash for ETag header value")
}

fn add_no_cache_layer(router: Router) -> Router {
  router.layer(SetResponseHeaderLayer::overriding(
    header::CACHE_CONTROL,
    HeaderValue::from_static("no-cache"),
  ))
}
