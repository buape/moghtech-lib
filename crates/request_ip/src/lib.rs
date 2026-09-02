//! This library includes an axum extractor for client ip, [RequestIp],
//! as well as functions to help with extracting the client ip from requests.

use std::net::{IpAddr, SocketAddr};

use anyhow::Context as _;
use axum::{
  extract::{ConnectInfo, FromRequestParts},
  http::{Extensions, HeaderMap, StatusCode},
};
use mogh_error::AddStatusCode as _;

/// Extract the client IP in the following order:
///
/// 1. X-FORWARDED-FOR header
/// 2. X-REAL-IP header
/// 3. Connection SocketAddr (will be reverse proxy ip if using one)
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
    )
    .map(RequestIp)
  }
}

pub fn get_ip_from_headers_and_extensions(
  headers: &HeaderMap,
  extensions: &Extensions,
) -> mogh_error::Result<IpAddr> {
  if let Some(ip) = get_ip_from_headers(headers)? {
    return Ok(ip);
  }

  let info = extensions.get::<ConnectInfo<SocketAddr>>()
    .context("'x-forwarded-for' and 'x-real-ip' headers are both missing, and no fallback ip could be extracted from the request.")
    .status_code(StatusCode::UNAUTHORIZED)?;

  Ok(info.0.ip())
}

pub fn get_ip_from_headers(
  headers: &HeaderMap,
) -> mogh_error::Result<Option<IpAddr>> {
  // Check X-Forwarded-For header (first IP in chain)
  if let Some(forwarded) = headers.get("x-forwarded-for")
    && let Ok(forwarded_str) = forwarded.to_str()
    && let Some(ip) = forwarded_str.split(',').next()
    && !ip.trim().is_empty()
  {
    return Ok(Some(
      ip.trim().parse().status_code(StatusCode::UNAUTHORIZED)?,
    ));
  }

  // Check X-Real-IP header
  if let Some(real_ip) = headers.get("x-real-ip")
    && let Ok(ip) = real_ip.to_str()
    && !ip.trim().is_empty()
  {
    return Ok(Some(
      ip.trim().parse().status_code(StatusCode::UNAUTHORIZED)?,
    ));
  }

  Ok(None)
}

#[cfg(test)]
mod tests {
  use axum::http::HeaderValue;

  use super::*;

  fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
  }

  #[test]
  fn forwarded_for_takes_first_ip_in_chain() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "x-forwarded-for",
      HeaderValue::from_static(" 1.2.3.4 , 10.0.0.1, 10.0.0.2"),
    );
    headers.insert("x-real-ip", HeaderValue::from_static("9.9.9.9"));
    assert_eq!(
      get_ip_from_headers(&headers).unwrap(),
      Some(ip("1.2.3.4"))
    );
  }

  #[test]
  fn real_ip_used_when_forwarded_for_missing() {
    let mut headers = HeaderMap::new();
    headers
      .insert("x-real-ip", HeaderValue::from_static(" 9.9.9.9 "));
    assert_eq!(
      get_ip_from_headers(&headers).unwrap(),
      Some(ip("9.9.9.9"))
    );
  }

  #[test]
  fn ipv6_is_supported() {
    let mut headers = HeaderMap::new();
    headers
      .insert("x-forwarded-for", HeaderValue::from_static("::1"));
    assert_eq!(
      get_ip_from_headers(&headers).unwrap(),
      Some(ip("::1"))
    );
  }

  #[test]
  fn no_headers_returns_none() {
    assert_eq!(get_ip_from_headers(&HeaderMap::new()).unwrap(), None);
  }

  #[test]
  fn empty_header_values_fall_through() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("  "));
    headers.insert("x-real-ip", HeaderValue::from_static(""));
    assert_eq!(get_ip_from_headers(&headers).unwrap(), None);

    // Empty x-forwarded-for still falls through to x-real-ip
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static(""));
    headers.insert("x-real-ip", HeaderValue::from_static("9.9.9.9"));
    assert_eq!(
      get_ip_from_headers(&headers).unwrap(),
      Some(ip("9.9.9.9"))
    );
  }

  #[test]
  fn invalid_ip_is_unauthorized_error() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "x-forwarded-for",
      HeaderValue::from_static("not-an-ip"),
    );
    let err = get_ip_from_headers(&headers).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn extensions_socket_addr_fallback() {
    let mut extensions = Extensions::new();
    extensions.insert(ConnectInfo::<SocketAddr>(
      "5.6.7.8:1234".parse().unwrap(),
    ));
    assert_eq!(
      get_ip_from_headers_and_extensions(
        &HeaderMap::new(),
        &extensions
      )
      .unwrap(),
      ip("5.6.7.8")
    );
    // Headers take precedence over the socket addr.
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", HeaderValue::from_static("9.9.9.9"));
    assert_eq!(
      get_ip_from_headers_and_extensions(&headers, &extensions)
        .unwrap(),
      ip("9.9.9.9")
    );
  }

  #[test]
  fn missing_everything_is_unauthorized_error() {
    let err = get_ip_from_headers_and_extensions(
      &HeaderMap::new(),
      &Extensions::new(),
    )
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn request_ip_extractor() {
    let request = axum::http::Request::builder()
      .uri("/")
      .header("x-forwarded-for", "1.2.3.4")
      .body(())
      .unwrap();
    let (mut parts, _) = request.into_parts();
    let RequestIp(extracted) =
      RequestIp::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    assert_eq!(extracted, ip("1.2.3.4"));
    // Conversions
    assert_eq!(IpAddr::from(RequestIp(ip("1.2.3.4"))), ip("1.2.3.4"));
    assert_eq!(RequestIp::from(ip("::1")).0, ip("::1"));
  }
}
