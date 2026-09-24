use std::path::{Path, PathBuf};

use anyhow::Context;
use axum::{
  Router,
  extract::Request,
  http::{HeaderValue, StatusCode, header},
  middleware::{map_request, map_response},
  response::Response,
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
///
/// Every index response comes out as 200 OK, so the index router
/// must never produce a 304 / 206 / 412 from request conditions
/// (it would become an empty or partial 200),
/// see [strip_conditional_headers].
fn with_index_fallback(
  directory: PathBuf,
  index: Router,
) -> ServeDir<SetStatus<Router>> {
  ServeDir::new(directory)
    // Otherwise `/` (what browsers actually request) is answered by
    // ServeDir itself with the plain `index.html` file, skipping the
    // index router below and with it the content hash ETag /
    // `no-cache` header. The file ETag is built from mtime and size,
    // which can be identical between two builds of a UI (fixed image
    // timestamps, same length hashed asset names), leaving browsers
    // on a stale index after an upgrade.
    .append_index_html_on_directories(false)
    .fallback(SetStatus::new(index, StatusCode::OK))
}

/// Serves the static UI directory, which must have an `index.html`
/// to use as the root. Paths without a file (`/`, client side
/// routes) get the index.
///
/// The index is always served in full with `Cache-Control: no-cache`,
/// so browsers revalidate it on every load and never run a stale
/// index (referencing hashed assets which no longer exist) after an
/// upgrade. It carries the content hash of `index.html` (computed on
/// startup) as ETag, the file's mtime based validators
/// (`Last-Modified`, its own ETag) are not sent.
///
/// If `force_no_cache` is passed, or hashing fails, the index is
/// served without ETag, eg when `index.html` changes without a
/// restart.
pub fn serve_static_ui(
  ui_path: &str,
  force_no_cache: bool,
) -> ServeDir<SetStatus<Router>> {
  let directory = PathBuf::from(ui_path);
  let index = directory.join("index.html");

  let mut index_router = Router::new()
    .fallback_service(ServeFile::new(&index))
    .layer(map_response(strip_file_validators))
    .layer(map_request(strip_conditional_headers));

  if !force_no_cache {
    match hash_encode_contents(&index) {
      Ok(header_value) => {
        index_router = index_router
          // The ETag header helps browser know when the
          // contents have changed / invalidate cache.
          .layer(SetResponseHeaderLayer::overriding(
            header::ETAG,
            header_value,
          ))
      }
      Err(e) => {
        warn!(
          "Failed to create ETag header for index.html, serving it without | {e:#}"
        );
      }
    }
  }

  with_index_fallback(directory, add_no_cache_layer(index_router))
}

/// Request headers `ServeFile` evaluates against the file mtime /
/// size, answering 304 / 206 / 412. The index is always served in
/// full instead: the outer `SetStatus(200)` would turn those into
/// empty or partial 200s (a blank UI), and the mtime / size
/// validators can't tell two UI builds apart.
const CONDITIONAL_HEADERS: [header::HeaderName; 6] = [
  header::IF_MATCH,
  header::IF_NONE_MATCH,
  header::IF_MODIFIED_SINCE,
  header::IF_UNMODIFIED_SINCE,
  header::IF_RANGE,
  header::RANGE,
];

async fn strip_conditional_headers(mut req: Request) -> Request {
  let headers = req.headers_mut();
  for name in CONDITIONAL_HEADERS {
    headers.remove(name);
  }
  req
}

/// Removes the `ServeFile` validators the index router doesn't
/// honor (see [CONDITIONAL_HEADERS]), so browsers don't send them.
/// The content hash ETag is set after this.
async fn strip_file_validators(mut res: Response) -> Response {
  let headers = res.headers_mut();
  headers.remove(header::ETAG);
  headers.remove(header::LAST_MODIFIED);
  headers.remove(header::ACCEPT_RANGES);
  res
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
