use std::{net::SocketAddr, str::FromStr as _, sync::Arc};

use anyhow::Context as _;
use axum::{
  Router,
  http::{HeaderValue, header},
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use rustls::{
  ServerConfig as TlsServerConfig,
  crypto::CryptoProvider,
  pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::info;

pub use axum_server;
pub use mogh_request_ip::TrustedProxies;

// Dev dependencies used by the integration tests only.
#[cfg(test)]
use reqwest as _;
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
  /// Serve https with the PEM [cert][Self::ssl_cert_file] /
  /// [key][Self::ssl_key_file] files. The rustls crypto provider
  /// installed as the process default is used, else aws-lc-rs.
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
  /// Which socket peers are trusted to set the client ip through
  /// `X-Forwarded-For` / `X-Real-IP` headers, eg the app's internal
  /// CIDR ranges. Attached to every request by [serve_app], where
  /// the `mogh_request_ip::RequestIp` extractor (and the Mogh Auth
  /// server) pick it up.
  ///
  /// Pipe a config list through with [TrustedProxies::from_config]:
  /// empty means private ranges, `all` / `none` / `private`
  /// keywords are supported, else the CIDR ranges given.
  /// Default: [TrustedProxies::private].
  ///
  /// ⚠️ The default believes **any** private peer, not only the
  /// proxy. When public clients can reach the app from a private
  /// address (a port published through Docker's userland proxy,
  /// rootless Docker / Podman, Kubernetes SNAT, hosts on the same
  /// network / VPN), they choose their own ip. Narrow it to the
  /// proxy address, or [TrustedProxies::None] when nothing is in
  /// front of the app, see [TrustedProxies::default].
  fn trusted_proxies(&self) -> TrustedProxies {
    TrustedProxies::default()
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

/// Applies the security headers and
/// [trusted proxies][ServerConfig::trusted_proxies] layers
/// to the app. Used by [serve_app].
pub fn configure_app(
  mut app: Router,
  config: &impl ServerConfig,
) -> anyhow::Result<Router> {
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
  Ok(app.layer(config.trusted_proxies().layer()))
}

/// Serves the app with socket connect info,
/// security headers, and trusted proxies applied.
pub async fn serve_app(
  app: Router,
  config: impl ServerConfig,
  handle: impl Into<Option<Handle<SocketAddr>>>,
) -> anyhow::Result<()> {
  let app = configure_app(app, &config)?
    .into_make_service_with_connect_info::<SocketAddr>();

  // Construct the bind socket addr
  let addr = format!("{}:{}", config.bind_ip(), config.port());
  let socket_addr = SocketAddr::from_str(&addr)
    .context("Failed to parse listen address")?;

  // Run the server
  if config.ssl_enabled() {
    // Run the server with TLS (https)
    info!("🔒 Server SSL Enabled");
    info!("Server starting on https://{socket_addr}");
    let ssl_config =
      rustls_config(config.ssl_cert_file(), config.ssl_key_file())
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

/// Builds the https config from the PEM cert / key files.
///
/// `RustlsConfig::from_pem_file` lets rustls pick the crypto
/// provider from its crate features, which panics when both
/// `ring` and `aws-lc-rs` end up in the binary (eg together with
/// mogh_auth_server). Instead use the provider the app installed
/// as process default, else aws-lc-rs (what axum-server enables).
fn rustls_config(
  cert_file: &str,
  key_file: &str,
) -> anyhow::Result<RustlsConfig> {
  let certs = CertificateDer::pem_file_iter(cert_file)
    .with_context(|| {
      format!("Failed to read ssl cert file at {cert_file}")
    })?
    .collect::<Result<Vec<_>, _>>()
    .with_context(|| {
      format!("Failed to parse ssl cert file at {cert_file}")
    })?;
  anyhow::ensure!(
    !certs.is_empty(),
    "No certificate in ssl cert file at {cert_file}"
  );
  let key =
    PrivateKeyDer::from_pem_file(key_file).with_context(|| {
      format!("Failed to read ssl key file at {key_file}")
    })?;
  let provider =
    CryptoProvider::get_default().cloned().unwrap_or_else(|| {
      Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    });
  let mut config = TlsServerConfig::builder_with_provider(provider)
    .with_safe_default_protocol_versions()
    .context("Unsupported TLS crypto provider")?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("Failed to use ssl cert / key")?;
  // Same as axum-server's own configs.
  config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
  Ok(RustlsConfig::from_config(Arc::new(config)))
}
