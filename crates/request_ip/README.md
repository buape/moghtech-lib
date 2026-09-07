# Mogh Request IP

Axum extractor for client request IP.

Forwarding headers (`X-Forwarded-For`, `X-Real-IP`) are only believed
when the socket peer is a trusted proxy, so clients cannot spoof their ip.
The default policy trusts loopback and private ranges.

```rust
use mogh_request_ip::{RequestIp, TrustedProxies};

// Use as axum extractor
async fn auth_request(
  RequestIp(ip): RequestIp,
  req: Request
) -> mogh_error::Result<String> {
  println!("Client IP: {ip:?}");
  Ok(ip.to_string())
}

// Configure which proxies are trusted, and serve
// with connect info so the socket peer is known.
let app = Router::new()
  .route("/", get(auth_request))
  .layer(TrustedProxies::parse(["10.0.0.0/8"])?.layer())
  .into_make_service_with_connect_info::<SocketAddr>();
```
```rust
// Restrict requests to a CIDR whitelist. Entries may be
// CIDR ranges or bare ips, and an empty whitelist allows all.
use mogh_request_ip::cidr::check_cidr_whitelist;

async fn restricted_request(
  RequestIp(ip): RequestIp,
) -> mogh_error::Result<()> {
  let whitelist = ["10.0.0.0/8".to_string(), "::1".to_string()];
  // Returns 403 Forbidden if the ip is not whitelisted.
  check_cidr_whitelist(ip, &whitelist)
}
```
