//! This library includes an axum extractor for client ip, [RequestIp],
//! as well as functions to help with extracting the client ip from requests.
//!
//! # Trusted proxies
//!
//! Forwarding headers (`X-Forwarded-For`, `X-Real-IP`) are only
//! believed when the connecting socket peer is a [TrustedProxies]
//! member, since anything else could have written them itself.
//! `X-Forwarded-For` is walked from the right (the entry appended by
//! the nearest proxy), skipping trusted proxy hops, and the first
//! untrusted address is the client. Entries further left were
//! written by untrusted parties and are ignored.
//!
//! The [RequestIp] extractor reads the [TrustedProxies] policy from
//! the request extensions (add it with [TrustedProxies::layer]),
//! falling back to [TrustedProxies::default] (private ranges).
//!
//! The [cidr] module provides CIDR set parsing and matching,
//! also used to restrict requests by source ip.

use std::{
  net::{IpAddr, SocketAddr},
  sync::LazyLock,
};

use anyhow::{Context as _, anyhow};
use axum::{
  Extension,
  extract::{ConnectInfo, FromRequestParts},
  http::{Extensions, HeaderMap, StatusCode},
};
use mogh_error::{AddStatusCode as _, AddStatusCodeError as _};

pub mod cidr;

pub use cidr::CidrSet;

/// Which socket peers are trusted to set the client ip
/// through `X-Forwarded-For` / `X-Real-IP` headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedProxies {
  /// Never trust forwarding headers.
  /// The client ip is always the socket peer.
  None,
  /// Trust forwarding headers only when the socket peer
  /// is within one of the networks.
  Cidrs(CidrSet),
  /// Trust forwarding headers from any peer, and every
  /// `X-Forwarded-For` hop. Only safe when the server is
  /// unreachable except through a proxy which sets the headers.
  All,
}

impl Default for TrustedProxies {
  /// Trusts loopback and private (RFC 1918 / ULA) peers,
  /// which covers a reverse proxy on the same host or
  /// container network.
  fn default() -> Self {
    Self::private()
  }
}

/// Loopback and private (RFC 1918 / ULA) ranges,
/// the `private` keyword of [TrustedProxies::from_config].
pub const PRIVATE_RANGES: [&str; 6] = [
  "127.0.0.0/8",
  "::1",
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "fc00::/7",
];

static DEFAULT_TRUSTED_PROXIES: LazyLock<TrustedProxies> =
  LazyLock::new(TrustedProxies::default);

impl TrustedProxies {
  /// Loopback and private (RFC 1918 / ULA) ranges ([PRIVATE_RANGES]).
  pub fn private() -> Self {
    Self::Cidrs(
      CidrSet::parse(PRIVATE_RANGES)
        .expect("private ranges are valid"),
    )
  }

  /// Build the policy from a config list, for piping an app's
  /// `trusted_proxies` / internal CIDR config through.
  ///
  /// - Empty: [Self::private] (the default).
  /// - `all` (alone): [Self::All].
  /// - `none` (alone): [Self::None].
  /// - Otherwise the CIDR ranges / ips given, where the keyword
  ///   `private` expands to [PRIVATE_RANGES] (eg
  ///   `["private", "203.0.113.10"]`).
  ///
  /// Keywords are case-insensitive. `all` / `none` combined with
  /// any other entry is an error rather than a guess.
  pub fn from_config<I>(entries: I) -> anyhow::Result<Self>
  where
    I: IntoIterator,
    I::Item: AsRef<str>,
  {
    let mut cidrs: Vec<String> = Vec::new();
    let mut all = false;
    let mut none = false;
    let mut count = 0;
    for entry in entries {
      let entry = entry.as_ref().trim();
      if entry.is_empty() {
        continue;
      }
      count += 1;
      match entry.to_ascii_lowercase().as_str() {
        "all" => all = true,
        "none" => none = true,
        "private" => {
          cidrs.extend(PRIVATE_RANGES.iter().map(|s| s.to_string()))
        }
        _ => cidrs.push(entry.to_string()),
      }
    }
    if (all || none) && count > 1 {
      return Err(anyhow!(
        "Trusted proxies 'all' / 'none' cannot be combined with other entries"
      ));
    }
    if all {
      return Ok(Self::All);
    }
    if none {
      return Ok(Self::None);
    }
    if cidrs.is_empty() {
      return Ok(Self::private());
    }
    Self::parse(&cidrs)
  }

  /// The policy attached to the request (by [TrustedProxies::layer],
  /// eg through `mogh_server::serve_app`), or the default.
  pub fn from_extensions(extensions: &Extensions) -> &TrustedProxies {
    extensions
      .get::<TrustedProxies>()
      .unwrap_or(&DEFAULT_TRUSTED_PROXIES)
  }

  /// Parse trusted proxy CIDR ranges / ip addresses.
  /// Empty means no proxies are trusted ([Self::None]).
  pub fn parse<I>(entries: I) -> anyhow::Result<Self>
  where
    I: IntoIterator,
    I::Item: AsRef<str>,
  {
    let set = CidrSet::parse(entries)?;
    Ok(if set.is_empty() {
      Self::None
    } else {
      Self::Cidrs(set)
    })
  }

  /// Whether the ip is a trusted proxy.
  pub fn trusts(&self, ip: IpAddr) -> bool {
    match self {
      Self::None => false,
      Self::Cidrs(set) => set.contains(ip),
      Self::All => true,
    }
  }

  /// Axum layer which attaches this policy to every request,
  /// for use by the [RequestIp] extractor.
  pub fn layer(self) -> Extension<Self> {
    Extension(self)
  }
}

/// Extract the client IP, believing forwarding headers only
/// when the socket peer is in the request's [TrustedProxies]
/// (default: [TrustedProxies::private]). See [get_client_ip].
///
/// Requires the app to be served with
/// `into_make_service_with_connect_info::<SocketAddr>()`
/// unless the policy is [TrustedProxies::All].
pub struct RequestIp(pub IpAddr);

impl From<RequestIp> for IpAddr {
  fn from(value: RequestIp) -> Self {
    value.0
  }
}

impl From<IpAddr> for RequestIp {
  fn from(value: IpAddr) -> Self {
    RequestIp(value)
  }
}

impl<S: Send + Sync> FromRequestParts<S> for RequestIp {
  type Rejection = mogh_error::Error;

  async fn from_request_parts(
    parts: &mut axum::http::request::Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    get_ip_from_headers_and_extensions(
      &parts.headers,
      &parts.extensions,
      TrustedProxies::from_extensions(&parts.extensions),
    )
    .map(RequestIp)
  }
}

/// [get_client_ip] with the socket peer taken from the
/// `ConnectInfo<SocketAddr>` request extension.
pub fn get_ip_from_headers_and_extensions(
  headers: &HeaderMap,
  extensions: &Extensions,
  trusted_proxies: &TrustedProxies,
) -> mogh_error::Result<IpAddr> {
  let peer = extensions
    .get::<ConnectInfo<SocketAddr>>()
    .map(|info| info.0.ip());
  get_client_ip(headers, peer, trusted_proxies)
}

/// Determine the client ip from the socket `peer` and
/// forwarding headers, according to `trusted_proxies`:
///
/// 1. If the peer is not a trusted proxy, the peer is the client
///    and headers are ignored.
/// 2. Otherwise `X-Forwarded-For` is walked right to left, and the
///    first entry which is not a trusted proxy is the client. If every
///    entry is trusted, the leftmost is used.
/// 3. Otherwise `X-Real-IP` is used.
/// 4. Otherwise the peer is the client.
///
/// Errors with `401 Unauthorized` when the peer is unknown (no
/// `ConnectInfo`, ie the app is not served with
/// `into_make_service_with_connect_info`) and the policy is not
/// [TrustedProxies::All], or when a header value from a trusted
/// proxy is malformed (not valid UTF-8, or an entry which must be
/// examined is not an ip). Under [TrustedProxies::All], malformed
/// values and entries are skipped instead, matching the legacy
/// behavior of only reading the leftmost entry.
pub fn get_client_ip(
  headers: &HeaderMap,
  peer: Option<IpAddr>,
  trusted_proxies: &TrustedProxies,
) -> mogh_error::Result<IpAddr> {
  let peer = peer.map(|ip| ip.to_canonical());

  let peer_trusted = match (trusted_proxies, peer) {
    (TrustedProxies::All, _) => true,
    // The peer cannot be verified, so its headers cannot be trusted.
    (_, None) => false,
    (trusted, Some(peer)) => trusted.trusts(peer),
  };

  if !peer_trusted {
    return peer
      .context("No socket peer address available for the request (serve the app with 'into_make_service_with_connect_info', eg via mogh_server::serve_app), and forwarding headers cannot be trusted without one.")
      .status_code(StatusCode::UNAUTHORIZED);
  }

  // Under `All` malformed header values / entries are skipped,
  // otherwise they fail closed: a trusted proxy sent something
  // which cannot be attributed, so nothing left of it is either.
  let lenient = matches!(trusted_proxies, TrustedProxies::All);

  // Walk X-Forwarded-For from the nearest hop back to the client,
  // across possibly multiple header instances.
  let mut leftmost = None;
  for value in headers.get_all("x-forwarded-for").iter().rev() {
    let value = match value.to_str() {
      Ok(value) => value,
      Err(_) if lenient => continue,
      Err(_) => {
        return Err(
          anyhow!("X-Forwarded-For header is not valid UTF-8")
            .status_code(StatusCode::UNAUTHORIZED),
        );
      }
    };
    for entry in value.split(',').map(str::trim).rev() {
      if entry.is_empty() {
        continue;
      }
      let ip = match parse_forwarded_ip(entry) {
        Ok(ip) => ip,
        Err(_) if lenient => continue,
        Err(e) => return Err(e),
      };
      if !trusted_proxies.trusts(ip) {
        return Ok(ip);
      }
      leftmost = Some(ip);
    }
  }
  if let Some(ip) = leftmost {
    return Ok(ip);
  }

  if let Some(real_ip) = headers.get("x-real-ip") {
    match real_ip.to_str().map(str::trim) {
      Ok("") => {}
      Ok(real_ip) => return parse_forwarded_ip(real_ip),
      Err(_) if lenient => {}
      Err(_) => {
        return Err(
          anyhow!("X-Real-IP header is not valid UTF-8")
            .status_code(StatusCode::UNAUTHORIZED),
        );
      }
    }
  }

  peer
    .context("No socket peer address available for the request, and no forwarding headers were sent.")
    .status_code(StatusCode::UNAUTHORIZED)
}

/// Parse a forwarding header entry as an ip, tolerating
/// a port suffix (`1.2.3.4:5678`, `[::1]:5678`) which
/// some proxies include.
fn parse_forwarded_ip(entry: &str) -> mogh_error::Result<IpAddr> {
  if let Ok(ip) = entry.parse::<IpAddr>() {
    return Ok(ip.to_canonical());
  }
  if let Ok(addr) = entry.parse::<SocketAddr>() {
    return Ok(addr.ip().to_canonical());
  }
  Err(
    anyhow!("Invalid ip address '{entry}' in forwarding header")
      .status_code(StatusCode::UNAUTHORIZED),
  )
}

#[cfg(test)]
mod tests {
  use axum::http::HeaderValue;

  use super::*;

  fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
  }

  fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
      headers.append(*name, HeaderValue::from_str(value).unwrap());
    }
    headers
  }

  fn proxies(entries: &[&str]) -> TrustedProxies {
    TrustedProxies::parse(entries).unwrap()
  }

  const PROXY: &str = "10.0.0.1";
  const CLIENT: &str = "203.0.113.7";

  #[test]
  fn untrusted_peer_ignores_headers() {
    // Client connects directly and claims to be someone else.
    let h = headers(&[
      ("x-forwarded-for", "1.1.1.1"),
      ("x-real-ip", "2.2.2.2"),
    ]);
    let trusted = proxies(&["10.0.0.0/8"]);
    assert_eq!(
      get_client_ip(&h, Some(ip(CLIENT)), &trusted).unwrap(),
      ip(CLIENT)
    );
    assert_eq!(
      get_client_ip(&h, Some(ip(CLIENT)), &TrustedProxies::None)
        .unwrap(),
      ip(CLIENT)
    );
  }

  #[test]
  fn trusted_peer_uses_last_untrusted_forwarded_for() {
    let trusted = proxies(&["10.0.0.0/8"]);
    // Client injected a spoofed entry, proxy appended the real one.
    let h = headers(&[("x-forwarded-for", "1.1.1.1, 203.0.113.7")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(CLIENT)
    );
    // Two trusted proxy hops after the client.
    let h = headers(&[(
      "x-forwarded-for",
      "1.1.1.1, 203.0.113.7, 10.0.0.2",
    )]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(CLIENT)
    );
    // Spread over multiple header instances.
    let h = headers(&[
      ("x-forwarded-for", "1.1.1.1"),
      ("x-forwarded-for", "203.0.113.7, 10.0.0.2"),
    ]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(CLIENT)
    );
  }

  #[test]
  fn all_hops_trusted_uses_leftmost() {
    let trusted = proxies(&["10.0.0.0/8"]);
    let h = headers(&[("x-forwarded-for", "10.0.0.5, 10.0.0.2")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip("10.0.0.5")
    );
  }

  #[test]
  fn trusted_peer_falls_back_to_real_ip_then_peer() {
    let trusted = proxies(&["10.0.0.0/8"]);
    let h = headers(&[("x-real-ip", " 203.0.113.7 ")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(CLIENT)
    );
    // Empty forwarding headers fall through.
    let h = headers(&[("x-forwarded-for", " , "), ("x-real-ip", "")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(PROXY)
    );
    assert_eq!(
      get_client_ip(&HeaderMap::new(), Some(ip(PROXY)), &trusted)
        .unwrap(),
      ip(PROXY)
    );
  }

  #[test]
  fn unknown_peer_is_unauthorized_unless_all_trusted() {
    let h = headers(&[("x-forwarded-for", CLIENT)]);
    let err =
      get_client_ip(&h, None, &proxies(&["10.0.0.0/8"])).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    let err =
      get_client_ip(&h, None, &TrustedProxies::None).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    // Legacy behavior: headers believed without a peer.
    assert_eq!(
      get_client_ip(&h, None, &TrustedProxies::All).unwrap(),
      ip(CLIENT)
    );
    let err =
      get_client_ip(&HeaderMap::new(), None, &TrustedProxies::All)
        .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn all_trusted_takes_leftmost_forwarded_for() {
    let h = headers(&[("x-forwarded-for", "1.2.3.4, 10.0.0.1")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &TrustedProxies::All)
        .unwrap(),
      ip("1.2.3.4")
    );
  }

  #[test]
  fn malformed_header_from_trusted_peer_fails_closed() {
    let trusted = proxies(&["10.0.0.0/8"]);
    // Not valid UTF-8: must not fall through to the peer address,
    // which would satisfy an "internal only" whitelist.
    let mut h = HeaderMap::new();
    h.append(
      "x-forwarded-for",
      HeaderValue::from_bytes(b"\xff, 203.0.113.7").unwrap(),
    );
    let err =
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    let mut h = HeaderMap::new();
    h.append("x-real-ip", HeaderValue::from_bytes(b"\xff").unwrap());
    let err =
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    // From an untrusted peer the headers are simply ignored.
    assert_eq!(
      get_client_ip(&h, Some(ip(CLIENT)), &trusted).unwrap(),
      ip(CLIENT)
    );
    // Under `All` malformed values are skipped.
    let mut h = HeaderMap::new();
    h.append(
      "x-forwarded-for",
      HeaderValue::from_bytes(b"\xff").unwrap(),
    );
    h.append("x-forwarded-for", HeaderValue::from_static(CLIENT));
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &TrustedProxies::All)
        .unwrap(),
      ip(CLIENT)
    );
  }

  #[test]
  fn all_skips_unparseable_entries() {
    // Legacy leniency: proxies like Apache may emit 'unknown'.
    let h = headers(&[("x-forwarded-for", "203.0.113.7, unknown")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &TrustedProxies::All)
        .unwrap(),
      ip(CLIENT)
    );
    let h = headers(&[("x-forwarded-for", "unknown")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &TrustedProxies::All)
        .unwrap(),
      ip(PROXY)
    );
  }

  #[test]
  fn invalid_examined_entry_is_unauthorized() {
    let trusted = proxies(&["10.0.0.0/8"]);
    let h = headers(&[("x-forwarded-for", "not-an-ip")]);
    let err =
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    let h = headers(&[("x-forwarded-for", "203.0.113.7, unknown")]);
    let err =
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    // A garbage entry left of the real client is never examined.
    let h = headers(&[("x-forwarded-for", "garbage, 203.0.113.7")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(CLIENT)
    );
    // Garbage from an untrusted peer is ignored entirely.
    let h = headers(&[("x-forwarded-for", "garbage")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(CLIENT)), &trusted).unwrap(),
      ip(CLIENT)
    );
  }

  #[test]
  fn ports_and_mapped_ipv6_are_tolerated() {
    let trusted = proxies(&["10.0.0.0/8"]);
    let h = headers(&[("x-forwarded-for", "203.0.113.7:4567")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(CLIENT)
    );
    let h = headers(&[("x-forwarded-for", "[2001:db8::1]:4567")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip("2001:db8::1")
    );
    // Dual-stack socket reports the proxy as ipv4-mapped ipv6.
    let h = headers(&[("x-forwarded-for", CLIENT)]);
    assert_eq!(
      get_client_ip(&h, Some(ip("::ffff:10.0.0.1")), &trusted)
        .unwrap(),
      ip(CLIENT)
    );
    // Mapped client addresses are canonicalized.
    assert_eq!(
      get_client_ip(
        &HeaderMap::new(),
        Some(ip("::ffff:203.0.113.7")),
        &trusted
      )
      .unwrap(),
      ip(CLIENT)
    );
  }

  #[test]
  fn default_policy_trusts_private_ranges_only() {
    let trusted = TrustedProxies::default();
    for peer in [
      "127.0.0.1",
      "::1",
      "10.1.1.1",
      "172.16.0.1",
      "192.168.1.1",
      "fd12::1",
    ] {
      assert!(trusted.trusts(ip(peer)), "{peer}");
    }
    for peer in ["8.8.8.8", "172.32.0.1", "2001:db8::1", "100.64.0.1"]
    {
      assert!(!trusted.trusts(ip(peer)), "{peer}");
    }
    assert_eq!(
      TrustedProxies::parse(Vec::<String>::new()).unwrap(),
      TrustedProxies::None
    );
    assert!(TrustedProxies::parse(["garbage"]).is_err());
  }

  #[test]
  fn from_config_keywords_and_cidrs() {
    assert_eq!(
      TrustedProxies::from_config(Vec::<String>::new()).unwrap(),
      TrustedProxies::private()
    );
    assert_eq!(
      TrustedProxies::from_config(["", " "]).unwrap(),
      TrustedProxies::private()
    );
    assert_eq!(
      TrustedProxies::from_config(["ALL"]).unwrap(),
      TrustedProxies::All
    );
    assert_eq!(
      TrustedProxies::from_config(["none"]).unwrap(),
      TrustedProxies::None
    );
    assert!(
      TrustedProxies::from_config(["none", "10.0.0.0/8"]).is_err()
    );
    assert!(TrustedProxies::from_config(["none", "all"]).is_err());
    assert!(
      TrustedProxies::from_config(["all", "10.0.0.0/8"]).is_err()
    );
    assert!(TrustedProxies::from_config(["garbage", "all"]).is_err());
    assert!(TrustedProxies::from_config(["garbage"]).is_err());
    let mixed =
      TrustedProxies::from_config(["Private", "203.0.113.10"])
        .unwrap();
    assert!(mixed.trusts(ip("10.1.1.1")));
    assert!(mixed.trusts(ip("203.0.113.10")));
    assert!(!mixed.trusts(ip("203.0.113.11")));
    let only =
      TrustedProxies::from_config(["203.0.113.0/24"]).unwrap();
    assert!(only.trusts(ip("203.0.113.10")));
    assert!(!only.trusts(ip("10.1.1.1")));
  }

  #[test]
  fn from_extensions_falls_back_to_default() {
    assert_eq!(
      TrustedProxies::from_extensions(&Extensions::new()),
      &TrustedProxies::private()
    );
    let mut extensions = Extensions::new();
    extensions.insert(TrustedProxies::None);
    assert_eq!(
      TrustedProxies::from_extensions(&extensions),
      &TrustedProxies::None
    );
  }

  #[test]
  fn extensions_socket_addr_is_peer() {
    let mut extensions = Extensions::new();
    extensions.insert(ConnectInfo::<SocketAddr>(
      "203.0.113.7:1234".parse().unwrap(),
    ));
    let h = headers(&[("x-forwarded-for", "1.1.1.1")]);
    // Public peer: headers ignored.
    assert_eq!(
      get_ip_from_headers_and_extensions(
        &h,
        &extensions,
        &TrustedProxies::default()
      )
      .unwrap(),
      ip(CLIENT)
    );
    let err = get_ip_from_headers_and_extensions(
      &HeaderMap::new(),
      &Extensions::new(),
      &TrustedProxies::default(),
    )
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn request_ip_extractor() {
    // Private peer with default policy: headers believed.
    let request = axum::http::Request::builder()
      .uri("/")
      .header("x-forwarded-for", CLIENT)
      .extension(ConnectInfo::<SocketAddr>(
        "10.0.0.1:1234".parse().unwrap(),
      ))
      .body(())
      .unwrap();
    let (mut parts, _) = request.into_parts();
    let RequestIp(extracted) =
      RequestIp::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    assert_eq!(extracted, ip(CLIENT));

    // Policy from extension overrides the default.
    let request = axum::http::Request::builder()
      .uri("/")
      .header("x-forwarded-for", CLIENT)
      .extension(ConnectInfo::<SocketAddr>(
        "10.0.0.1:1234".parse().unwrap(),
      ))
      .extension(TrustedProxies::None)
      .body(())
      .unwrap();
    let (mut parts, _) = request.into_parts();
    let RequestIp(extracted) =
      RequestIp::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    assert_eq!(extracted, ip("10.0.0.1"));

    // Conversions
    assert_eq!(IpAddr::from(RequestIp(ip(CLIENT))), ip(CLIENT));
    assert_eq!(RequestIp::from(ip("::1")).0, ip("::1"));
  }
}
