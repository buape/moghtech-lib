#![allow(unused_crate_dependencies)]

use std::path::PathBuf;

use axum::{
  Router,
  body::Body,
  http::{Request, StatusCode, header},
  routing::get,
};
use mogh_server::{
  ServerConfig, TrustedProxies,
  cors::{CorsConfig, cors_layer},
  session::{
    ExpiredDeletion as _, MemorySessionStore, SessionConfig,
    memory_session_layer, session_layer,
  },
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

/// The headers of the index as served for `uri`.
async fn index_headers(
  service: &tower_http::services::ServeDir<
    tower_http::set_status::SetStatus<Router>,
  >,
  uri: &str,
) -> axum::http::HeaderMap {
  let response = service
    .clone()
    .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::OK, "{uri}");
  let headers = response.headers().clone();
  assert_eq!(
    body_string(Body::new(response.into_body())).await,
    "<html>index</html>",
    "{uri}"
  );
  headers
}

#[tokio::test]
async fn static_ui_root_gets_the_same_cache_headers_as_routes() {
  // `/` is what browsers request, it must not be served
  // around the content hash ETag / no-cache handling.
  let dir = UiDir::new("static_ui_root");
  let service = serve_static_ui(dir.0.to_str().unwrap(), false);
  let route = index_headers(&service, "/unknown/route").await;
  let root = index_headers(&service, "/").await;
  assert_eq!(root[header::ETAG], route[header::ETAG]);

  let service = serve_static_ui(dir.0.to_str().unwrap(), true);
  let root = index_headers(&service, "/").await;
  assert_eq!(root[header::CACHE_CONTROL], "no-cache");
}

#[tokio::test]
async fn static_ui_etag_follows_the_index_contents() {
  let dir = UiDir::new("static_ui_etag");
  let service = serve_static_ui(dir.0.to_str().unwrap(), false);
  let before = index_headers(&service, "/").await;
  // Same contents, same ETag (eg. after a restart).
  let service = serve_static_ui(dir.0.to_str().unwrap(), false);
  assert_eq!(
    index_headers(&service, "/").await[header::ETAG],
    before[header::ETAG]
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

#[tokio::test]
async fn static_ui_index_is_never_cached_heuristically() {
  // Without Cache-Control, browsers reuse the index without asking,
  // for a tenth of its age, and run a stale UI after an upgrade.
  let dir = UiDir::new("static_ui_heuristic");
  let service = serve_static_ui(dir.0.to_str().unwrap(), false);
  for uri in ["/", "/unknown/route"] {
    let headers = index_headers(&service, uri).await;
    assert_eq!(headers[header::CACHE_CONTROL], "no-cache", "{uri}");
    assert!(headers.contains_key(header::ETAG), "{uri}");
    // The mtime isn't a validator the index honors.
    assert!(!headers.contains_key(header::LAST_MODIFIED), "{uri}");
  }
}

#[tokio::test]
async fn static_ui_index_ignores_conditional_and_range_requests() {
  // The index fallback always answers 200: a 304 / 206 from the
  // file server would come out as an empty / partial 200,
  // replacing the browser's cached index with a blank page.
  let dir = UiDir::new("static_ui_conditional");
  for force_no_cache in [false, true] {
    let service =
      serve_static_ui(dir.0.to_str().unwrap(), force_no_cache);
    let etag = index_headers(&service, "/")
      .await
      .get(header::ETAG)
      .map(|etag| etag.to_str().unwrap().to_string());
    let mut conditions = vec![
      (header::IF_NONE_MATCH, "*".to_string()),
      (
        header::IF_MODIFIED_SINCE,
        "Fri, 01 Jan 2100 00:00:00 GMT".to_string(),
      ),
      (header::IF_MATCH, "\"other\"".to_string()),
      (
        header::IF_UNMODIFIED_SINCE,
        "Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
      ),
      (header::RANGE, "bytes=0-3".to_string()),
    ];
    if let Some(etag) = etag {
      conditions.push((header::IF_NONE_MATCH, etag));
    }
    for uri in ["/", "/unknown/route"] {
      for (name, value) in &conditions {
        let response = service
          .clone()
          .oneshot(
            Request::builder()
              .uri(uri)
              .header(name, value)
              .body(Body::empty())
              .unwrap(),
          )
          .await
          .unwrap();
        let context = format!("{uri} {name}: {value}");
        assert_eq!(response.status(), StatusCode::OK, "{context}");
        assert_eq!(
          response.headers()[header::CACHE_CONTROL],
          "no-cache",
          "{context}"
        );
        assert_eq!(
          body_string(Body::new(response.into_body())).await,
          "<html>index</html>",
          "{context}"
        );
      }
    }
  }
}

#[derive(Default)]
struct Session {
  host: &'static str,
  cookie_domain: Option<&'static str>,
  allow_cross_site: bool,
  expiry_seconds: Option<i64>,
}

impl SessionConfig for Session {
  fn host(&self) -> &str {
    self.host
  }
  fn cookie_domain(&self) -> Option<&str> {
    self.cookie_domain
  }
  fn allow_cross_site(&self) -> bool {
    self.allow_cross_site
  }
  fn expiry_seconds(&self) -> i64 {
    self.expiry_seconds.unwrap_or(60 * 3)
  }
}

fn session_app(
  layer: mogh_server::session::SessionManagerLayer<
    MemorySessionStore,
  >,
) -> Router {
  Router::new()
    .route(
      "/",
      get(async |session: mogh_server::session::Session| {
        session.insert("counter", 1).await.unwrap();
        "ok"
      }),
    )
    .route(
      "/counter",
      get(async |session: mogh_server::session::Session| {
        session
          .get::<i32>("counter")
          .await
          .unwrap()
          .unwrap_or_default()
          .to_string()
      }),
    )
    .layer(layer)
}

/// The Set-Cookie of a request modifying the session
/// (without a session cookie).
async fn session_cookie(app: &Router) -> String {
  let response = app
    .clone()
    .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::OK);
  response.headers()[header::SET_COOKIE]
    .to_str()
    .unwrap()
    .to_string()
}

async fn counter(app: &Router, cookie: &str) -> String {
  let cookie = cookie.split(';').next().unwrap();
  let response = app
    .clone()
    .oneshot(
      Request::builder()
        .uri("/counter")
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  body_string(response.into_body()).await
}

#[tokio::test]
async fn session_layer_sets_cookie_for_modified_sessions() {
  let app = session_app(memory_session_layer(Session {
    host: "https://example.com",
    ..Default::default()
  }));
  let cookie = session_cookie(&app).await;
  // Host-only: not sent to (nor settable by) other subdomains.
  assert!(!cookie.contains("Domain="), "{cookie}");
  assert!(cookie.starts_with("__Host-id="), "{cookie}");
  assert!(cookie.contains("Path=/"), "{cookie}");
  assert!(cookie.contains("HttpOnly"), "{cookie}");
  assert!(cookie.contains("Secure"), "{cookie}");
  assert!(cookie.contains("SameSite=Lax"), "{cookie}");
  assert_eq!(counter(&app, &cookie).await, "1");

  // Plain http: no `__Host-` prefix (needs Secure).
  let app = session_app(memory_session_layer(Session {
    host: "http://example.com",
    ..Default::default()
  }));
  let cookie = session_cookie(&app).await;
  assert!(cookie.starts_with("id="), "{cookie}");
  assert!(!cookie.contains("Domain="), "{cookie}");
  assert!(!cookie.contains("Secure"), "{cookie}");
}

#[tokio::test]
async fn session_cookie_domain_is_opt_in() {
  let app = session_app(memory_session_layer(Session {
    host: "https://app.example.com",
    cookie_domain: Some("example.com"),
    ..Default::default()
  }));
  let cookie = session_cookie(&app).await;
  assert!(cookie.starts_with("id="), "{cookie}");
  assert!(cookie.contains("Domain=example.com"), "{cookie}");
  assert!(cookie.contains("Secure"), "{cookie}");
}

#[tokio::test]
async fn session_cookie_secure_follows_the_host_scheme() {
  let app = session_app(memory_session_layer(Session {
    host: "HTTPS://example.com",
    ..Default::default()
  }));
  let cookie = session_cookie(&app).await;
  assert!(cookie.contains("Secure"), "{cookie}");
}

#[tokio::test]
async fn cross_site_session_cookie_is_secure() {
  // Browsers reject SameSite=None without Secure,
  // and accept Secure cookies from localhost over http.
  let app = session_app(memory_session_layer(Session {
    host: "http://localhost:9220",
    allow_cross_site: true,
    ..Default::default()
  }));
  let cookie = session_cookie(&app).await;
  assert!(cookie.contains("SameSite=None"), "{cookie}");
  assert!(cookie.contains("Secure"), "{cookie}");
}

#[tokio::test]
async fn memory_sessions_are_bounded() {
  // Every request without a session cookie starting a
  // session (eg a login flow) must not grow memory forever.
  let store = MemorySessionStore::new(10);
  let app = session_app(session_layer(
    store.clone(),
    Session {
      host: "https://example.com",
      ..Default::default()
    },
  ));
  for _ in 0..100 {
    session_cookie(&app).await;
    assert!(store.len() <= 10, "{}", store.len());
  }
  // The most recent sessions keep working.
  let cookie = session_cookie(&app).await;
  assert_eq!(counter(&app, &cookie).await, "1");
}

#[tokio::test]
async fn memory_sessions_free_expired_sessions() {
  let store = MemorySessionStore::default();
  let app = session_app(session_layer(
    store.clone(),
    Session {
      host: "https://example.com",
      expiry_seconds: Some(1),
      ..Default::default()
    },
  ));
  let mut cookies = Vec::new();
  for _ in 0..5 {
    cookies.push(session_cookie(&app).await);
  }
  assert_eq!(store.len(), 5);
  tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
  // Loading an expired session removes it.
  assert_eq!(counter(&app, &cookies[0]).await, "0");
  assert_eq!(store.len(), 4);
  // And the sweep removes the rest.
  store.delete_expired().await.unwrap();
  assert!(store.is_empty());
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

struct ProxyServer(TrustedProxies);

impl ServerConfig for ProxyServer {
  fn port(&self) -> u16 {
    0
  }
  fn trusted_proxies(&self) -> TrustedProxies {
    self.0.clone()
  }
}

/// Echoes the client ip resolved by the RequestIp extractor.
fn ip_app(trusted: TrustedProxies) -> Router {
  mogh_server::configure_app(
    Router::new().route(
      "/",
      get(async |mogh_request_ip::RequestIp(ip)| ip.to_string()),
    ),
    &ProxyServer(trusted),
  )
  .unwrap()
}

fn forwarded_request(peer: &str) -> Request<Body> {
  Request::builder()
    .uri("/")
    .header("x-forwarded-for", "203.0.113.7")
    .extension(axum::extract::ConnectInfo(
      format!("{peer}:1234")
        .parse::<std::net::SocketAddr>()
        .unwrap(),
    ))
    .body(Body::empty())
    .unwrap()
}

#[tokio::test]
async fn configure_app_attaches_trusted_proxies() {
  // Default: private peer is trusted, headers believed.
  let response = ip_app(TrustedProxies::default())
    .oneshot(forwarded_request("10.0.0.1"))
    .await
    .unwrap();
  assert_eq!(body_string(response.into_body()).await, "203.0.113.7");
  // Default: public peer is not trusted, headers ignored.
  let response = ip_app(TrustedProxies::default())
    .oneshot(forwarded_request("198.51.100.1"))
    .await
    .unwrap();
  assert_eq!(body_string(response.into_body()).await, "198.51.100.1");
  // Configured: the public proxy range is trusted.
  let response =
    ip_app(TrustedProxies::from_config(["198.51.100.0/24"]).unwrap())
      .oneshot(forwarded_request("198.51.100.1"))
      .await
      .unwrap();
  assert_eq!(body_string(response.into_body()).await, "203.0.113.7");
  // Configured none: even private peers are not trusted.
  let response = ip_app(TrustedProxies::None)
    .oneshot(forwarded_request("10.0.0.1"))
    .await
    .unwrap();
  assert_eq!(body_string(response.into_body()).await, "10.0.0.1");
  // Security headers still applied.
  let response = ip_app(TrustedProxies::default())
    .oneshot(forwarded_request("10.0.0.1"))
    .await
    .unwrap();
  assert_eq!(
    response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
    "DENY"
  );
}

struct TlsServer;

impl ServerConfig for TlsServer {
  fn bind_ip(&self) -> &str {
    "127.0.0.1"
  }
  fn port(&self) -> u16 {
    0
  }
  fn ssl_enabled(&self) -> bool {
    true
  }
  fn ssl_cert_file(&self) -> &str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/tls/cert.pem")
  }
  fn ssl_key_file(&self) -> &str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/tls/key.pem")
  }
}

#[tokio::test]
async fn serve_app_serves_https_with_both_rustls_providers() {
  // The rustls dev dependency enables 'ring' next to aws-lc-rs, as
  // apps also using mogh_auth_server do. rustls can't pick a crypto
  // provider from its features then, and used to panic on startup.
  let handle = mogh_server::axum_server::Handle::new();
  let mut server = tokio::spawn(mogh_server::serve_app(
    Router::new().route("/", get(async || "ok")),
    TlsServer,
    handle.clone(),
  ));
  let addr = tokio::select! {
    addr = handle.listening() => addr.expect("https server failed to bind"),
    res = &mut server => panic!("https server stopped: {res:?}"),
  };
  let client = reqwest::Client::builder()
    .tls_danger_accept_invalid_certs(true)
    .build()
    .unwrap();
  let response = client
    .get(format!("https://localhost:{}/", addr.port()))
    .send()
    .await
    .unwrap();
  assert_eq!(response.status(), reqwest::StatusCode::OK);
  assert_eq!(response.text().await.unwrap(), "ok");
  handle.shutdown();
  server.await.unwrap().unwrap();
}

#[tokio::test]
async fn serve_app_rejects_invalid_tls_files() {
  struct MissingTls;
  impl ServerConfig for MissingTls {
    fn bind_ip(&self) -> &str {
      "127.0.0.1"
    }
    fn port(&self) -> u16 {
      0
    }
    fn ssl_enabled(&self) -> bool {
      true
    }
    fn ssl_cert_file(&self) -> &str {
      concat!(env!("CARGO_MANIFEST_DIR"), "/tests/tls/key.pem")
    }
    fn ssl_key_file(&self) -> &str {
      concat!(env!("CARGO_MANIFEST_DIR"), "/tests/tls/missing.pem")
    }
  }
  let error = mogh_server::serve_app(Router::new(), MissingTls, None)
    .await
    .unwrap_err();
  let error = format!("{error:#}");
  assert!(error.contains("Invalid ssl cert / key"), "{error}");
  assert!(error.contains("No certificate"), "{error}");
}
