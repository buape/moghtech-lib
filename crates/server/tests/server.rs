#![allow(unused_crate_dependencies)]

use std::path::PathBuf;

use axum::{
  Router,
  body::Body,
  http::{Method, Request, StatusCode, header},
  routing::get,
};
use mogh_server::{
  ServerConfig,
  cors::{CorsConfig, cors_layer},
  session::{SessionConfig, memory_session_layer},
  ui::serve_static_ui,
};
use tower::ServiceExt as _;

struct Cors {
  origins: Vec<String>,
  credentials: bool,
}

impl CorsConfig for Cors {
  fn allowed_origins(&self) -> &[String] {
    &self.origins
  }
  fn allow_credentials(&self) -> bool {
    self.credentials
  }
}

fn cors_app(origins: &[&str], credentials: bool) -> Router {
  Router::new()
    .route("/", get(async || "ok"))
    .layer(cors_layer(Cors {
      origins: origins.iter().map(|o| o.to_string()).collect(),
      credentials,
    }))
}

fn request_with_origin(origin: &str) -> Request<Body> {
  Request::builder()
    .uri("/")
    .header(header::ORIGIN, origin)
    .body(Body::empty())
    .unwrap()
}

#[tokio::test]
async fn cors_allows_configured_origins_only() {
  let app = cors_app(&["https://example.com"], true);
  let response = app
    .clone()
    .oneshot(request_with_origin("https://example.com"))
    .await
    .unwrap();
  assert_eq!(
    response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
    "https://example.com"
  );
  assert_eq!(
    response.headers()[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
    "true"
  );

  let response = app
    .oneshot(request_with_origin("https://evil.example.org"))
    .await
    .unwrap();
  assert!(
    !response
      .headers()
      .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
  );
}

#[tokio::test]
async fn cors_wildcard_without_credentials_uses_any() {
  let app = cors_app(&["*"], false);
  let response = app
    .oneshot(request_with_origin("https://example.com"))
    .await
    .unwrap();
  assert_eq!(
    response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
    "*"
  );
}

#[tokio::test]
async fn cors_wildcard_with_credentials_mirrors_origin() {
  // tower-http panics at request time on
  // `Access-Control-Allow-Origin: *` + credentials,
  // so the wildcard origin must be mirrored instead.
  let app = cors_app(&["*"], true);
  let response = app
    .oneshot(request_with_origin("https://example.com"))
    .await
    .unwrap();
  assert_eq!(
    response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
    "https://example.com"
  );
  assert_eq!(
    response.headers()[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
    "true"
  );
}

#[tokio::test]
async fn cors_invalid_origins_are_skipped() {
  let app = cors_app(&["bad\norigin", "https://example.com"], false);
  let response = app
    .oneshot(request_with_origin("https://example.com"))
    .await
    .unwrap();
  assert_eq!(
    response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
    "https://example.com"
  );
}

/// Creates a unique static ui directory for a test
/// and cleans it up on drop.
struct UiDir(PathBuf);

impl UiDir {
  fn new(name: &str) -> UiDir {
    let path = std::env::temp_dir().join(format!(
      "mogh_server_test_{}_{name}",
      std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("index.html"), "<html>index</html>")
      .unwrap();
    std::fs::write(path.join("asset.js"), "console.log(1)").unwrap();
    UiDir(path)
  }
}

impl Drop for UiDir {
  fn drop(&mut self) {
    let _ = std::fs::remove_dir_all(&self.0);
  }
}

async fn body_string(body: Body) -> String {
  let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
  String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn static_ui_serves_files_and_index_fallback() {
  let dir = UiDir::new("static_ui");
  let service = serve_static_ui(dir.0.to_str().unwrap(), false);

  // Existing files are served directly.
  let response = service
    .clone()
    .oneshot(
      Request::builder()
        .uri("/asset.js")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::OK);
  assert_eq!(
    body_string(Body::new(response.into_body())).await,
    "console.log(1)"
  );

  // Unknown paths fall back to index.html with an ETag.
  let response = service
    .oneshot(
      Request::builder()
        .uri("/unknown/route")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::OK);
  let etag = response.headers()[header::ETAG].to_str().unwrap();
  // ETag values must be quoted (RFC 9110).
  assert!(etag.starts_with('"') && etag.ends_with('"'));
  assert!(etag.len() > 2);
  assert_eq!(
    body_string(Body::new(response.into_body())).await,
    "<html>index</html>"
  );
}

#[tokio::test]
async fn static_ui_force_no_cache_sets_cache_control() {
  let dir = UiDir::new("static_ui_no_cache");
  let service = serve_static_ui(dir.0.to_str().unwrap(), true);
  let response = service
    .oneshot(
      Request::builder()
        .uri("/unknown/route")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::OK);
  assert_eq!(response.headers()[header::CACHE_CONTROL], "no-cache");
}

struct Session {
  host: &'static str,
}

impl SessionConfig for Session {
  fn host(&self) -> &str {
    self.host
  }
}

#[tokio::test]
async fn session_layer_sets_cookie_for_modified_sessions() {
  let app = Router::new()
    .route(
      "/",
      get(async |session: mogh_server::session::Session| {
        session.insert("counter", 1).await.unwrap();
        "ok"
      }),
    )
    .layer(memory_session_layer(Session {
      host: "https://example.com",
    }));
  let response = app
    .oneshot(
      Request::builder()
        .method(Method::GET)
        .uri("/")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::OK);
  let cookie =
    response.headers()[header::SET_COOKIE].to_str().unwrap();
  assert!(cookie.contains("Domain=example.com"));
  assert!(cookie.contains("Secure"));
  assert!(cookie.contains("SameSite=Lax"));
}

struct Server {
  bind_ip: &'static str,
  x_frame_options: &'static str,
}

impl ServerConfig for Server {
  fn bind_ip(&self) -> &str {
    self.bind_ip
  }
  fn port(&self) -> u16 {
    41339
  }
  fn x_frame_options(&self) -> &str {
    self.x_frame_options
  }
}

#[tokio::test]
async fn serve_app_rejects_invalid_bind_address() {
  let error = mogh_server::serve_app(
    Router::new(),
    Server {
      bind_ip: "not an ip",
      x_frame_options: "DENY",
    },
    None,
  )
  .await
  .unwrap_err();
  assert!(
    error.to_string().contains("Failed to parse listen address")
  );
}

#[tokio::test]
async fn serve_app_rejects_invalid_header_values() {
  let error = mogh_server::serve_app(
    Router::new(),
    Server {
      bind_ip: "127.0.0.1",
      x_frame_options: "bad\nvalue",
    },
    None,
  )
  .await
  .unwrap_err();
  assert!(
    error.to_string().contains("Invalid x_frame_options value")
  );
}
