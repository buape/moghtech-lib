use std::{net::SocketAddr, str::FromStr as _};

use anyhow::Context as _;
use axum::{
  Router,
  http::{HeaderValue, header},
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::info;

pub use axum_server;

// Dev dependencies used by the integration tests only.
#[cfg(test)]
use tokio as _;
#[cfg(test)]
use tower as _;

pub mod cors;
pub mod session;
pub mod ui;

pub trait ServerConfig {
  fn bind_ip(&self) -> &str {
    "[::]"
  }
  fn port(&self) -> u16;
  fn ssl_enabled(&self) -> bool {
    false
  }
  fn ssl_key_file(&self) -> &str {
    "/config/ssl/key.pem"
  }
  fn ssl_cert_file(&self) -> &str {
    "/config/ssl/cert.pem"
  }
  /// `X-Content-Type-Options` header value.
  /// Default is `nosniff`. Set as empty string
  /// to omit the header.
  fn x_content_type_options(&self) -> &str {
    "nosniff"
  }
  /// `X-Frame-Options` header value. Return an empty string to
  /// omit the header entirely and allow iframe on any origin. Use `"SAMEORIGIN"` to allow
  /// same-origin embedding only. Defaults to `"DENY"`.
  fn x_frame_options(&self) -> &str {
    "DENY"
  }
  /// `X-XSS-PROTECTION` header value. Return an empty string to
  /// omit the header entirely. Default: `1; mode=block`
  fn x_xss_protection(&self) -> &str {
    "1; mode=block"
  }
  /// Apply Referrer Policy directives.
  /// If empty string, no header is applied.
  /// Default: `strict-origin-when-cross-origin`
  fn referrer_policy(&self) -> &str {
    "strict-origin-when-cross-origin"
  }
  /// Apply Content Security Policy directives.
  /// If empty string, no header is applied.
  /// Default: None
  ///
  /// Example:
  /// `default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'`
  fn content_security_policy(&self) -> &str {
    ""
  }
}

/// Applies a security header layer to the app,
/// unless the configured value is an empty string.
fn apply_security_header(
  app: Router,
  name: header::HeaderName,
  value: &str,
  error_context: &'static str,
) -> anyhow::Result<Router> {
  if value.is_empty() {
    return Ok(app);
  }
  let value = HeaderValue::from_str(value).context(error_context)?;
  Ok(app.layer(SetResponseHeaderLayer::overriding(name, value)))
}

/// Serves the app with socket connect info
/// and security headers applied.
pub async fn serve_app(
  mut app: Router,
  config: impl ServerConfig,
  handle: impl Into<Option<Handle<SocketAddr>>>,
) -> anyhow::Result<()> {
  app = apply_security_header(
    app,
    header::X_CONTENT_TYPE_OPTIONS,
    config.x_content_type_options(),
    "Invalid x_content_type_options value",
  )?;
  app = apply_security_header(
    app,
    header::X_FRAME_OPTIONS,
    config.x_frame_options(),
    "Invalid x_frame_options value",
  )?;
  app = apply_security_header(
    app,
    header::X_XSS_PROTECTION,
    config.x_xss_protection(),
    "Invalid x_xss_protection value",
  )?;
  app = apply_security_header(
    app,
    header::CONTENT_SECURITY_POLICY,
    config.content_security_policy(),
    "Invalid content_security_policy value",
  )?;
  app = apply_security_header(
    app,
    header::REFERRER_POLICY,
    config.referrer_policy(),
    "Invalid referrer_policy value",
  )?;

  let app = app.into_make_service_with_connect_info::<SocketAddr>();

  // Construct the bind socket addr
  let addr = format!("{}:{}", config.bind_ip(), config.port());
  let socket_addr = SocketAddr::from_str(&addr)
    .context("Failed to parse listen address")?;

  // Run the server
  if config.ssl_enabled() {
    // Run the server with TLS (https)
    info!("🔒 Server SSL Enabled");
    info!("Server starting on https://{socket_addr}");
    let ssl_config = RustlsConfig::from_pem_file(
      config.ssl_cert_file(),
      config.ssl_key_file(),
    )
    .await
    .context("Invalid ssl cert / key")?;
    let mut server =
      axum_server::bind_rustls(socket_addr, ssl_config);
    if let Some(handle) = handle.into() {
      server = server.handle(handle);
    }
    server
      .serve(app)
      .await
      .context("Failed to start https server")
  } else {
    // Run the server without TLS (http)
    info!("🔓 Server SSL Disabled");
    info!("Server starting on http://{socket_addr}");
    let mut server = axum_server::bind(socket_addr);
    if let Some(handle) = handle.into() {
      server = server.handle(handle);
    }
    server
      .serve(app)
      .await
      .context("Failed to start http server")
  }
}
