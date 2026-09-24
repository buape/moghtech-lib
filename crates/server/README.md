# Mogh Server

Configurable axum server including TLS, Session, CORS, common security headers, and static file hosting.

```rust
struct Config;

impl mogh_server::ServerConfig for Config {
  fn port(&self) -> u16 {
    3100
  }
  fn ssl_enabled(&self) -> bool {
    true
  }
  fn ssl_key_file(&self) -> &str {
    "./ssl/key.pem"
  }
  fn ssl_cert_file(&self) -> &str {
    "./ssl/cert.pem"
  }
}

let app = Router::new()
  .route("/version", get(|| async { env!("CARGO_PKG_VERSION") }));

// Pass an `axum_server::Handle` instead of `None`
// for graceful shutdown.
mogh_server::serve_app(app, Config, None).await?;
```

`serve_app` applies the security headers (`X-Content-Type-Options`,
`X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, optional
`Content-Security-Policy`) and the `ServerConfig::trusted_proxies` layer, which
decides which socket peers may set the client ip through `X-Forwarded-For` /
`X-Real-IP`. Use `configure_app` to apply the same layers when serving the app
yourself.

⚠️ The default trusted proxies are all loopback and private addresses, not only
the proxy. When public clients can reach the app from a private address (a port
published through Docker's userland proxy, rootless Docker / Podman, Kubernetes
SNAT, hosts on the same network / VPN), they choose their own ip. Narrow it to
the proxy address with `TrustedProxies::from_config`, or `TrustedProxies::None`
when nothing is in front of the app.

### TLS

With `ssl_enabled`, the PEM cert / key files are served with rustls, using the
crypto provider the app installed as process default
(`CryptoProvider::install_default`), else aws-lc-rs. This also works when both
of rustls' `ring` and `aws-lc-rs` features end up in the binary (eg together
with `mogh_auth_server`), where rustls can't pick one by itself.

### Session

`session::memory_session_layer` adds the session layer used by the Mogh Auth
login flows, backed by `session::MemorySessionStore`:

- Sessions expire after `expiry_seconds` of inactivity (default 3 minutes).
  Expired sessions are removed from memory (when loaded, and swept at most once
  a minute when sessions are saved).
- The store holds at most `max_sessions` (default 10,000). When full, the
  sessions closest to expiry are evicted, so clients starting sessions without
  authentication (eg login flows) can't grow the memory without limit.
- The cookie is host-only (no `Domain` attribute), and named with the
  `__Host-` prefix on https hosts, so other subdomains neither receive nor
  set it. Set `cookie_domain` only if several subdomains must share the
  session.
- `SameSite=Lax`, or `None` with `allow_cross_site` (UI development), which
  also makes the cookie `Secure` as browsers require. That works on https
  hosts and `localhost`, not on other plain http hosts.

`session::session_layer` configures the same cookie for another
`SessionStore`.

### CORS

`cors::cors_layer` allows the configured origins, with credentials by default.
⚠️ `*` with credentials mirrors any request origin: any site can then make
requests carrying the user's cookies and read the responses. List the exact
origins instead, or disable credentials.

### Static UI

`ui::serve_static_ui` serves a static UI directory, answering paths without a
file (`/`, client side routes) with its `index.html`. The index is always served
in full with `Cache-Control: no-cache` and the content hash as `ETag`, so
browsers pick up a new UI right after an upgrade.
