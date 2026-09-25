use std::{
  net::IpAddr,
  time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, anyhow};
use axum::{
  body::{Body, Bytes},
  extract::{FromRequest as _, OriginalUri, Request},
  http::{HeaderMap, Method, Uri, header::AUTHORIZATION},
  middleware::Next,
  response::Response,
};
use http_body_util::Limited;
use mogh_auth_client::signature::{
  API_SIGNATURE_HEADER, API_TIMESTAMP_HEADER,
};
use mogh_error::{AddStatusCode, AddStatusCodeError as _};
use mogh_pki::{Pkcs8PrivateKey, one_way::OneWayNoiseHandshake};
use mogh_rate_limit::WithFailureRateLimit;
use mogh_request_ip::RequestIp;
use reqwest::StatusCode;
use tracing::{debug, error};

use crate::{
  AuthImpl, RequestAuthentication,
  api_key::AuthApiKeyImpl,
  bcrypt_pool::spawn_api_key_bcrypt,
  user::{AuthUserImpl, BoxAuthUser},
};

pub use mogh_request_ip::cidr::check_cidr_whitelist;

const API_KEY_HEADER: &str = "x-api-key";

/// Authenticates the request with
/// [AuthImpl::handle_request_authentication], for use with
/// `axum::middleware::from_fn`.
///
/// The body of a request signed with a signing key is read first,
/// the signature covers it ([read_signed_request_body]). A signed
/// request which can't verify (eg. a stale timestamp) is refused
/// before that.
pub async fn authenticate_request<
  I: AuthImpl,
  const REQUIRE_USER_ENABLED: bool,
>(
  RequestIp(ip): RequestIp,
  OriginalUri(uri): OriginalUri,
  req: Request,
  next: Next,
) -> mogh_error::Result<Response> {
  let auth = I::new();

  let (req, body) = read_signed_request_body(&auth, ip, req).await?;

  let req_auth = extract_request_authentication_rate_limited(
    &auth,
    ip,
    req.method(),
    &uri,
    req.headers(),
    &body,
  )
  .await?;

  let req = auth
    .handle_request_authentication(
      req_auth,
      ip,
      REQUIRE_USER_ENABLED,
      req,
    )
    .with_failure_rate_limit_using_ip(
      auth.general_rate_limiter(),
      &ip,
    )
    .await?;

  Ok(next.run(req).await)
}

/// Reads the body of a request signed with a signing key (it carries
/// X-API-SIGNATURE), which the signature covers, and puts it back.
/// Returns the request and the body to verify the signature with
/// ([extract_request_authentication]).
///
/// The X-API-TIMESTAMP is checked here, once, when the headers have
/// arrived and before the body is read. The signature is verified
/// against that timestamp afterwards ([SignedRequestBody]), so the
/// time the body takes to arrive (eg. a large body over a slow link)
/// doesn't count against [AuthImpl::signing_key_timestamp_tolerance_ms].
///
/// Other requests are returned as they are, with an empty body: theirs
/// isn't read. So is a signed request which also carries a jwt or an
/// api key: [extract_request_authentication] takes those first,
/// its signature isn't checked.
///
/// A signed request which fails for a reason known without the body
/// is refused right away (UNAUTHORIZED, as [extract_request_public_key]
/// would): the server has no [AuthImpl::server_private_key], or the
/// X-API-TIMESTAMP is missing or not ~now. These refusals cost the
/// server nothing, they don't count against
/// [AuthImpl::general_rate_limiter]. Passing such a request on without
/// its body would not do: its signature would be checked against the
/// empty body while the handler gets the unread one. A client which
/// the [AuthImpl::general_rate_limiter] has locked out for the `ip` is
/// refused (TOO_MANY_REQUESTS) before its body is read too, as it
/// would be right after.
///
/// Anybody can send a current timestamp though: the body of a request
/// which gets this far is read (up to the limit), even when its
/// signature turns out to be invalid, like any JSON endpoint reads it.
///
/// The body of a CONNECT request (eg. a websocket over HTTP/2) is the
/// tunnel, it isn't read either: it is signed as empty.
///
/// The body is limited to [AuthImpl::signed_request_body_limit]
/// (2 MB by default), and like axum's body extractors to the
/// `axum::extract::DefaultBodyLimit` of the router when it is applied
/// outside of the middleware, else 2 MB: whichever is smaller. A
/// router which raises or disables its limit (eg. for uploads)
/// doesn't raise how much of an unauthenticated signed request is
/// buffered, and raising only the knob doesn't get past the router's
/// limit (or the 2 MB default). A larger body is PAYLOAD_TOO_LARGE.
pub async fn read_signed_request_body<I: AuthImpl>(
  auth: &I,
  ip: IpAddr,
  req: Request,
) -> mogh_error::Result<(Request, SignedRequestBody)> {
  let headers = req.headers();
  if !headers.contains_key(API_SIGNATURE_HEADER)
    || headers.contains_key(AUTHORIZATION)
    || headers.contains_key(API_KEY_HEADER)
  {
    return Ok((req, SignedRequestBody::default()));
  }
  let (_, timestamp) = check_signed_request(auth, headers)?;
  let timestamp = Some(timestamp);
  if req.method() == Method::CONNECT {
    let body = SignedRequestBody {
      body: Bytes::new(),
      timestamp,
    };
    return Ok((req, body));
  }
  // Only looked up: an attempt which succeeds records nothing.
  async { Ok::<_, mogh_error::Error>(()) }
    .with_failure_rate_limit_using_ip(
      auth.general_rate_limiter(),
      &ip,
    )
    .await?;
  // The router's limit (if any) still applies inside
  // read_request_body, the smaller one refuses.
  let limit = auth.signed_request_body_limit();
  let req = req.map(|body| Body::new(Limited::new(body, limit)));
  let (req, body) = read_request_body(req).await?;
  Ok((req, SignedRequestBody { body, timestamp }))
}

/// The body of a request as [read_signed_request_body] read it, to
/// verify its signature with ([extract_request_authentication]).
/// Empty when it wasn't read.
///
/// It carries the X-API-TIMESTAMP of the request which was found ~now
/// when the headers arrived, and the signature is verified against it
/// without checking it again. A body made from [Bytes] (`.into()`)
/// carries none, the timestamp is then checked when the signature is
/// verified.
#[derive(Debug, Clone, Default)]
pub struct SignedRequestBody {
  body: Bytes,
  /// Checked by [read_signed_request_body].
  timestamp: Option<i64>,
}

impl SignedRequestBody {
  /// The request body the signature covers.
  pub fn body(&self) -> &Bytes {
    &self.body
  }
}

impl From<Bytes> for SignedRequestBody {
  fn from(body: Bytes) -> Self {
    SignedRequestBody {
      body,
      timestamp: None,
    }
  }
}

/// Reads the body of the request (limited like axum's body
/// extractors, by the router's `axum::extract::DefaultBodyLimit`,
/// else 2 MB) and puts it back. A body which is too large (also for
/// a `Limited` wrapped around it) is PAYLOAD_TOO_LARGE.
pub(crate) async fn read_request_body(
  req: Request,
) -> mogh_error::Result<(Request, Bytes)> {
  let (parts, body) = req.into_parts();
  let body = Bytes::from_request(
    Request::from_parts(parts.clone(), body),
    &(),
  )
  .await
  .map_err(|rejection| {
    anyhow!(rejection.body_text()).status_code(rejection.status())
  })?;
  Ok((Request::from_parts(parts, Body::from(body.clone())), body))
}

/// [extract_request_authentication] for middleware: requests without
/// credentials are UNAUTHORIZED, and credentials which are presented
/// but unusable count against [AuthImpl::general_rate_limiter] for the
/// `ip`. That is most of all an invalid request signature, which
/// costs the server a key exchange to find out about, so it shouldn't
/// be free to send them in a loop.
///
/// Requests without any credentials are not counted: a UI which isn't
/// logged in yet sends those, and would lock its own login out.
///
/// `body` is the request body for the signature of a signed request
/// to be verified with, see [read_signed_request_body].
pub async fn extract_request_authentication_rate_limited<
  I: AuthImpl,
>(
  auth: &I,
  ip: IpAddr,
  method: &Method,
  uri: &Uri,
  headers: &HeaderMap,
  body: &SignedRequestBody,
) -> mogh_error::Result<RequestAuthentication> {
  async {
    extract_request_authentication(auth, method, uri, headers, body)
  }
  .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), &ip)
  .await?
  .context("Invalid client credentials")
  .status_code(StatusCode::UNAUTHORIZED)
}

/// Maps the request credential headers to [RequestAuthentication],
/// trying [extract_request_jwt], [extract_request_api_key],
/// and [extract_request_public_key] in order.
///
/// `body` is only used to verify a request signature, which covers
/// it: pass what [read_signed_request_body] read for requests carrying
/// X-API-SIGNATURE. Its X-API-TIMESTAMP was checked then, the signature
/// is verified against it ([SignedRequestBody]).
///
/// DANGER ⚠️ This does not authenticate the credentials
/// (see [RequestAuthentication]). Authentication happens downstream
/// in [AuthImpl::handle_request_authentication] /
/// [AuthImpl::get_user_id_from_request_authentication].
///
/// Returns `Ok(None)` when the request carries no credentials.
pub fn extract_request_authentication<I: AuthImpl>(
  auth: &I,
  method: &Method,
  uri: &Uri,
  headers: &HeaderMap,
  body: &SignedRequestBody,
) -> mogh_error::Result<Option<RequestAuthentication>> {
  if let Some(jwt) = extract_request_jwt(headers)? {
    return Ok(Some(RequestAuthentication::Jwt(jwt)));
  }

  if let Some((key, secret)) = extract_request_api_key(headers)? {
    return Ok(Some(RequestAuthentication::ApiKey { key, secret }));
  }

  if let Some(public_key) = verify_request_signature(
    auth,
    method,
    uri,
    headers,
    &body.body,
    body.timestamp,
  )? {
    return Ok(Some(RequestAuthentication::PublicKey(public_key)));
  }

  Ok(None)
}

/// Extracts the jwt from the AUTHORIZATION header, stripping the
/// `Bearer` scheme, which is matched case insensitively
/// (RFC 7235). A value without a scheme is taken as the jwt.
///
/// DANGER ⚠️ The jwt is not validated here, see
/// [get_jwt_user_id].
pub fn extract_request_jwt(
  headers: &HeaderMap,
) -> mogh_error::Result<Option<String>> {
  let Some(authorization) = headers.get(AUTHORIZATION) else {
    return Ok(None);
  };
  let maybe_bearer = authorization
    .to_str()
    .context("AUTHORIZATION is not valid UTF-8")
    .status_code(StatusCode::UNAUTHORIZED)?
    .trim();
  let jwt = match maybe_bearer
    .split_once(|c: char| c.is_ascii_whitespace())
  {
    Some((scheme, jwt)) if scheme.eq_ignore_ascii_case("bearer") => {
      jwt.trim_start()
    }
    _ => maybe_bearer,
  };
  Ok(Some(jwt.to_string()))
}

/// Extracts the (key, secret) from the
/// X-API-KEY / X-API-SECRET headers.
///
/// DANGER ⚠️ The secret is not validated here, see
/// [verify_api_key_secret].
pub fn extract_request_api_key(
  headers: &HeaderMap,
) -> mogh_error::Result<Option<(String, String)>> {
  let Some(key) = headers.get(API_KEY_HEADER) else {
    return Ok(None);
  };
  let key = key
    .to_str()
    .context("X-API-KEY is not valid UTF-8")
    .status_code(StatusCode::UNAUTHORIZED)?
    .trim()
    .to_string();
  let secret = headers
    .get("x-api-secret")
    .context(
      "Request headers have X-API-KEY but missing X-API-SECRET",
    )
    .status_code(StatusCode::UNAUTHORIZED)?
    .to_str()
    .context("X-API-SECRET is not valid UTF-8")
    .status_code(StatusCode::UNAUTHORIZED)?
    .trim()
    .to_string();
  Ok(Some((key, secret)))
}

/// Extracts the client public key from the
/// X-API-SIGNATURE / X-API-TIMESTAMP headers.
///
/// The server must have a private key
/// ([AuthImpl::server_private_key]), else signing keys are not enabled
/// and the request is UNAUTHORIZED. The timestamp must be ~now
/// ([AuthImpl::signing_key_timestamp_tolerance_ms]), and the signature
/// must complete a noise handshake against the server private key over
/// a prologue binding the method, path and query, timestamp and `body`
/// ([pki_auth_prologue]). This proves the client holds the private key
/// for the returned public key, and signed this request, nothing more.
///
/// `body` is the request body, as read by [read_signed_request_body]
/// (empty for a CONNECT request).
///
/// The timestamp is checked against the time this is called at. The
/// middleware checks it when the headers arrive instead, before it
/// reads the body ([read_signed_request_body]), so the time the body
/// takes to arrive doesn't count.
///
/// DANGER ⚠️ The public key must still be matched to a known client.
pub fn extract_request_public_key<I: AuthImpl>(
  auth: &I,
  method: &Method,
  uri: &Uri,
  headers: &HeaderMap,
  body: &[u8],
) -> mogh_error::Result<Option<String>> {
  verify_request_signature(auth, method, uri, headers, body, None)
}

/// [extract_request_public_key], verifying the signature against the
/// X-API-TIMESTAMP [read_signed_request_body] already `checked` when
/// the headers arrived, without checking it against the time again.
/// With `None`, it is checked now.
fn verify_request_signature<I: AuthImpl>(
  auth: &I,
  method: &Method,
  uri: &Uri,
  headers: &HeaderMap,
  body: &[u8],
  checked: Option<i64>,
) -> mogh_error::Result<Option<String>> {
  let Some(signature) = headers.get(API_SIGNATURE_HEADER) else {
    return Ok(None);
  };
  let signature = signature
    .to_str()
    .context("X-API-SIGNATURE is not valid UTF-8")
    .status_code(StatusCode::UNAUTHORIZED)?;

  // The signature covers the timestamp, it only verifies for the
  // one the client signed.
  let (server_keys, timestamp) = match checked {
    Some(timestamp) => (server_keys(auth)?, timestamp),
    None => check_signed_request(auth, headers)?,
  };

  let prologue = pki_auth_prologue(method, uri, timestamp, body);

  // A configured server private key which can't be used is a
  // misconfiguration, not the clients fault. Logged, the client
  // only learns that much.
  let mut handshake =
    Pkcs8PrivateKey::maybe_raw_bytes(server_keys.load().private())
      .and_then(|private_key| {
        OneWayNoiseHandshake::new_responder(
          &private_key,
          prologue.as_bytes(),
        )
      })
      .map_err(|e| {
        error!(
          "Failed to set up the signed request handshake | {e:#}"
        );
        mogh_error::Error::msg(
          "Failed to verify the request signature",
        )
      })?;

  // Fails for anything which wasn't signed for this exact request
  // (method, path and query, timestamp, body) and this server.
  let public_key = handshake
    .validate_signature(signature)
    .map_err(|_| {
      anyhow!("Invalid client credentials")
        .status_code(StatusCode::UNAUTHORIZED)
    })?
    .into_inner();

  Ok(Some(public_key))
}

/// What a signed request needs to verify, found out without the
/// body (see [read_signed_request_body]): the server private key and
/// the X-API-TIMESTAMP, once it is ~now. UNAUTHORIZED otherwise.
fn check_signed_request<'a, I: AuthImpl>(
  auth: &'a I,
  headers: &HeaderMap,
) -> mogh_error::Result<(&'a mogh_pki::RotatableKeyPair, i64)> {
  let server_keys = server_keys(auth)?;
  let now =
    SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
  let timestamp = check_request_timestamp(auth, headers, now)?;
  Ok((server_keys, timestamp))
}

/// The [AuthImpl::server_private_key] signed requests are verified
/// with, UNAUTHORIZED without one.
fn server_keys<I: AuthImpl>(
  auth: &I,
) -> mogh_error::Result<&mogh_pki::RotatableKeyPair> {
  // Apps which don't use signing keys have no key (the default),
  // which is not an error of the server. Anybody can send the
  // header, so this isn't worth more than a debug log.
  auth.server_private_key().ok_or_else(|| {
    debug!(
      "Refused a request signed with a signing key | AuthImpl::server_private_key is not configured"
    );
    anyhow!("Signing keys are not enabled")
      .status_code(StatusCode::UNAUTHORIZED)
  })
}

/// The X-API-TIMESTAMP of a signed request, once it is within
/// [AuthImpl::signing_key_timestamp_tolerance_ms] of `now` (unix
/// milliseconds), UNAUTHORIZED otherwise.
fn check_request_timestamp<I: AuthImpl>(
  auth: &I,
  headers: &HeaderMap,
  now: i64,
) -> mogh_error::Result<i64> {
  let timestamp = headers
    .get(API_TIMESTAMP_HEADER)
    .context("Request headers have X-API-SIGNATURE but missing X-API-TIMESTAMP")
    .status_code(StatusCode::UNAUTHORIZED)?
    .to_str()
    .context("X-API-TIMESTAMP is not valid UTF-8")
    .status_code(StatusCode::UNAUTHORIZED)?
    .trim()
    .parse::<i64>()
    .context("X-API-TIMESTAMP is not a unix timestamp in milliseconds")
    .status_code(StatusCode::UNAUTHORIZED)?;

  // Ensure timestamp is ~now. The subtraction saturates,
  // the timestamp is untrusted and can be anything.
  let tolerance =
    i64::try_from(auth.signing_key_timestamp_tolerance_ms())
      .unwrap_or(i64::MAX);
  if now.saturating_sub(timestamp).saturating_abs() > tolerance {
    return Err(
      anyhow!("Invalid client credentials")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  Ok(timestamp)
}

/// Authenticates the request credentials with
/// [AuthImpl::get_user_id_from_request_authentication] (which enforces
/// the api key cidr whitelist), loads the user with [AuthImpl::get_user],
/// and checks the request `ip` against the user's
/// [AuthUserImpl::cidr_whitelist] with [check_user_cidr_whitelist].
///
/// Used by the auth management API middleware, and can be used
/// to implement [AuthImpl::handle_request_authentication].
pub async fn get_user_from_request_authentication<
  I: AuthImpl + ?Sized,
>(
  auth: &I,
  req_auth: RequestAuthentication,
  ip: IpAddr,
) -> mogh_error::Result<BoxAuthUser> {
  let user_id = auth
    .get_user_id_from_request_authentication(req_auth, ip)
    .await?;
  let user = auth.get_user(user_id).await?;
  check_user_cidr_whitelist(user.as_ref(), ip)?;
  Ok(user)
}

/// Ensure the request `ip` is allowed by the user's
/// [AuthUserImpl::cidr_whitelist], returning FORBIDDEN if not.
/// An empty whitelist allows all ips.
pub fn check_user_cidr_whitelist(
  user: &dyn AuthUserImpl,
  ip: IpAddr,
) -> mogh_error::Result<()> {
  check_cidr_whitelist(ip, user.cidr_whitelist())
}

/// Ensure the request `ip` is allowed by the api key's
/// [AuthApiKeyImpl::cidr_whitelist], returning FORBIDDEN if not.
/// An empty whitelist allows all ips.
pub fn check_api_key_cidr_whitelist(
  api_key: &dyn AuthApiKeyImpl,
  ip: IpAddr,
) -> mogh_error::Result<()> {
  check_cidr_whitelist(ip, api_key.cidr_whitelist())
}

/// Helper for authenticating [RequestAuthentication::Jwt]:
/// validates the jwt (signature, expiry, iss / aud) with
/// [AuthImpl::jwt_provider] and returns the user id (`sub`),
/// returning UNAUTHORIZED if invalid.
pub fn get_jwt_user_id<I: AuthImpl + ?Sized>(
  auth: &I,
  jwt: &str,
) -> mogh_error::Result<String> {
  auth
    .jwt_provider()
    .decode_sub(jwt)
    .status_code(StatusCode::UNAUTHORIZED)
}

/// Helper for implementing [AuthImpl::get_api_key]:
/// bcrypt verifies the incoming secret against the stored hash,
/// returning UNAUTHORIZED for an unknown key or non-matching secret.
///
/// Pass `None` when the key does not exist: a dummy hash is still
/// run so response timing does not reveal whether the key exists.
///
/// ⚠️ This blocks for as long as bcrypt takes at the cost (tens of
/// milliseconds by default), for every request carrying X-API-KEY,
/// whether the key exists or not, and isn't bounded. Use
/// [verify_api_key_secret_async] in async code, so requests with made
/// up keys can't stall the async runtime nor take up the blocking
/// thread pool.
pub fn verify_api_key_secret<I: AuthImpl + ?Sized>(
  auth: &I,
  secret: &str,
  hashed_secret: Option<&str>,
) -> mogh_error::Result<()> {
  verify_api_key_secret_with_cost(
    auth.api_secret_bcrypt_cost(),
    secret,
    hashed_secret,
  )
}

/// [verify_api_key_secret] on tokio's blocking thread pool, for
/// implementing [AuthImpl::get_api_key] in async code.
///
/// At most one api key secret is verified per available core at a
/// time, the other requests wait their turn without holding a thread.
/// Api keys have a budget of their own: a flood of requests with made
/// up keys waits behind itself, not ahead of password logins or other
/// blocking work (file io, the DNS lookups of outgoing requests).
/// A request dropped while it waits (the client disconnects) doesn't
/// run its bcrypt.
pub async fn verify_api_key_secret_async<I: AuthImpl + ?Sized>(
  auth: &I,
  secret: String,
  hashed_secret: Option<String>,
) -> mogh_error::Result<()> {
  let cost = auth.api_secret_bcrypt_cost();
  spawn_api_key_bcrypt(move || {
    verify_api_key_secret_with_cost(
      cost,
      &secret,
      hashed_secret.as_deref(),
    )
  })
  .await
  .context("Failed to run api secret verification")?
}

fn verify_api_key_secret_with_cost(
  cost: u32,
  secret: &str,
  hashed_secret: Option<&str>,
) -> mogh_error::Result<()> {
  let Some(hashed_secret) = hashed_secret else {
    let _ = bcrypt::hash(secret, cost);
    return Err(
      anyhow!("Invalid client credentials")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  };
  let verified = bcrypt::verify(secret, hashed_secret)
    .context("Invalid client credentials")
    .status_code(StatusCode::UNAUTHORIZED)?;
  if verified {
    Ok(())
  } else {
    Err(
      anyhow!("Invalid client credentials")
        .status_code(StatusCode::UNAUTHORIZED),
    )
  }
}

/// What a request signature covers, shared with the client:
/// [mogh_auth_client::signature::pki_auth_prologue].
///
/// Only the path and query of `uri` are covered, never the scheme and
/// host: an HTTP/2 request (or an HTTP/1.1 request in absolute form)
/// has them in its uri, while the client signs the path and query.
pub fn pki_auth_prologue(
  method: &Method,
  uri: &Uri,
  timestamp: i64,
  body: &[u8],
) -> String {
  let path_and_query = uri
    .path_and_query()
    .map(|path_and_query| path_and_query.as_str())
    .unwrap_or("/");
  mogh_auth_client::signature::pki_auth_prologue(
    method.as_str(),
    path_and_query,
    timestamp,
    body,
  )
}

#[cfg(test)]
mod tests {
  use axum::http::HeaderValue;

  use super::*;
  use crate::{DynFuture, provider::jwt::JwtProvider};

  struct TestAuth;

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      TestAuth
    }
    fn get_user(
      &self,
      _user_id: String,
    ) -> DynFuture<mogh_error::Result<crate::user::BoxAuthUser>> {
      Box::pin(async { Err(anyhow!("unimplemented").into()) })
    }
    fn handle_request_authentication(
      &self,
      _auth: RequestAuthentication,
      _ip: IpAddr,
      _require_user_enabled: bool,
      req: Request,
    ) -> DynFuture<mogh_error::Result<Request>> {
      Box::pin(async { Ok(req) })
    }
    fn jwt_provider(&self) -> &JwtProvider {
      static PROVIDER: std::sync::LazyLock<JwtProvider> =
        std::sync::LazyLock::new(|| {
          JwtProvider::new(b"secret", 60_000)
        });
      &PROVIDER
    }
    // Low cost to keep the unknown-key dummy hash fast.
    fn api_secret_bcrypt_cost(&self) -> u32 {
      4
    }
  }

  /// Compile-time assertion that [authenticate_request] remains
  /// compatible with `axum::middleware::from_fn`, since it is only
  /// instantiated that way downstream.
  #[allow(dead_code)]
  fn assert_authenticate_request_layers<I: AuthImpl>() -> axum::Router
  {
    axum::Router::new()
      .layer(axum::middleware::from_fn(
        authenticate_request::<I, true>,
      ))
      .layer(axum::middleware::from_fn(
        authenticate_request::<I, false>,
      ))
  }

  #[test]
  fn test_extract_api_key_missing_key() {
    let headers = HeaderMap::new();
    assert!(extract_request_api_key(&headers).unwrap().is_none());
  }

  #[test]
  fn test_extract_api_key_missing_secret_errors() {
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("K_abc_K"));
    let err = extract_request_api_key(&headers).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_extract_malformed_headers_are_unauthorized() {
    // Header values are bytes, not necessarily UTF-8.
    let not_utf8 = HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap();

    let mut headers = HeaderMap::new();
    headers.insert("authorization", not_utf8.clone());
    let err = extract_request_jwt(&headers).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);

    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", not_utf8.clone());
    headers.insert("x-api-secret", HeaderValue::from_static("S"));
    let err = extract_request_api_key(&headers).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);

    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("K"));
    headers.insert("x-api-secret", not_utf8);
    let err = extract_request_api_key(&headers).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_extract_api_key_trims_values() {
    let mut headers = HeaderMap::new();
    headers
      .insert("x-api-key", HeaderValue::from_static(" K_abc_K "));
    headers
      .insert("x-api-secret", HeaderValue::from_static(" S_def_S "));
    let (key, secret) =
      extract_request_api_key(&headers).unwrap().unwrap();
    assert_eq!(key, "K_abc_K");
    assert_eq!(secret, "S_def_S");
  }

  #[test]
  fn test_extract_jwt_no_authorization_header() {
    let headers = HeaderMap::new();
    assert!(extract_request_jwt(&headers).unwrap().is_none());
  }

  #[test]
  fn test_extract_jwt_strips_bearer_prefix() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "authorization",
      HeaderValue::from_static(" Bearer some.jwt.token "),
    );
    assert_eq!(
      extract_request_jwt(&headers).unwrap().unwrap(),
      "some.jwt.token"
    );
  }

  #[test]
  fn test_extract_jwt_bearer_scheme_is_case_insensitive() {
    // RFC 7235: the scheme is case insensitive, and any
    // whitespace may separate it from the token.
    for authorization in [
      "bearer some.jwt.token",
      "BEARER some.jwt.token",
      "Bearer  some.jwt.token",
      "Bearer\tsome.jwt.token",
    ] {
      let mut headers = HeaderMap::new();
      headers.insert(
        "authorization",
        HeaderValue::from_static(authorization),
      );
      assert_eq!(
        extract_request_jwt(&headers).unwrap().unwrap(),
        "some.jwt.token",
        "{authorization:?}"
      );
    }
  }

  #[test]
  fn test_extract_jwt_without_bearer_prefix() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "authorization",
      HeaderValue::from_static("some.jwt.token"),
    );
    assert_eq!(
      extract_request_jwt(&headers).unwrap().unwrap(),
      "some.jwt.token"
    );
  }

  #[test]
  fn test_extract_jwt_does_not_validate() {
    // Extraction is a pure header mapping; validation is downstream.
    let mut headers = HeaderMap::new();
    headers
      .insert("authorization", HeaderValue::from_static("not-a-jwt"));
    assert_eq!(
      extract_request_jwt(&headers).unwrap().unwrap(),
      "not-a-jwt"
    );
  }

  #[test]
  fn test_get_jwt_user_id_round_trip() {
    let jwt =
      TestAuth.jwt_provider().encode_sub("user-1").unwrap().jwt;
    assert_eq!(get_jwt_user_id(&TestAuth, &jwt).unwrap(), "user-1");
  }

  #[test]
  fn test_get_jwt_user_id_rejects_forged() {
    let forged = JwtProvider::new(b"other", 60_000)
      .encode_sub("user-1")
      .unwrap()
      .jwt;
    let err = get_jwt_user_id(&TestAuth, &forged).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_get_jwt_user_id_rejects_garbage() {
    let err = get_jwt_user_id(&TestAuth, "not-a-jwt").unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_verify_api_key_secret_accepts_matching_secret() {
    let hashed = bcrypt::hash("S_def_S", 4).unwrap();
    verify_api_key_secret(&TestAuth, "S_def_S", Some(&hashed))
      .unwrap();
  }

  #[test]
  fn test_verify_api_key_secret_rejects_wrong_secret() {
    let hashed = bcrypt::hash("S_def_S", 4).unwrap();
    let err =
      verify_api_key_secret(&TestAuth, "S_wrong_S", Some(&hashed))
        .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_verify_api_key_secret_rejects_unknown_key() {
    // None means the key does not exist: must reject.
    let err =
      verify_api_key_secret(&TestAuth, "S_def_S", None).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn test_verify_api_key_secret_async() {
    let hashed = bcrypt::hash("S_def_S", 4).unwrap();
    verify_api_key_secret_async(
      &TestAuth,
      "S_def_S".into(),
      Some(hashed.clone()),
    )
    .await
    .unwrap();
    for (secret, hashed) in [
      ("S_wrong_S", Some(hashed)),
      // Unknown key
      ("S_def_S", None),
    ] {
      let err =
        verify_api_key_secret_async(&TestAuth, secret.into(), hashed)
          .await
          .unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
  }

  /// Api key secrets are verified on the bounded budget of api keys:
  /// with every permit taken, a verification waits.
  #[tokio::test]
  async fn test_verify_api_key_secret_async_is_bounded() {
    let held = crate::bcrypt_pool::hold_api_key_permits().await;
    // A made up key, anybody can send them.
    let verify = tokio::spawn(verify_api_key_secret_async(
      &TestAuth,
      "S_def_S".into(),
      None,
    ));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!verify.is_finished(), "verified without a permit");
    drop(held);
    let err = verify.await.unwrap().unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  /// [TestAuth] with a server private key, so signatures are checked.
  #[derive(Clone, Copy)]
  struct KeyedAuth {
    timestamp_tolerance_ms: u64,
    signed_body_limit: usize,
  }

  const KEYED: KeyedAuth = KeyedAuth {
    timestamp_tolerance_ms: 1_000,
    signed_body_limit: 2 * 1024 * 1024,
  };

  fn server_keys() -> &'static mogh_pki::RotatableKeyPair {
    static KEYS: std::sync::LazyLock<mogh_pki::RotatableKeyPair> =
      std::sync::LazyLock::new(|| {
        let keys = mogh_pki::EncodedKeyPair::generate(
          mogh_pki::PkiKind::OneWay,
        )
        .unwrap();
        mogh_pki::RotatableKeyPair::from_private_key_spec(
          mogh_pki::PkiKind::OneWay,
          keys.private(),
        )
        .unwrap()
      });
    &KEYS
  }

  impl AuthImpl for KeyedAuth {
    fn new() -> Self {
      KEYED
    }
    fn signing_key_timestamp_tolerance_ms(&self) -> u64 {
      self.timestamp_tolerance_ms
    }
    fn signed_request_body_limit(&self) -> usize {
      self.signed_body_limit
    }
    fn general_rate_limiter(&self) -> &mogh_rate_limit::RateLimiter {
      static LIMITER: std::sync::LazyLock<
        std::sync::Arc<mogh_rate_limit::RateLimiter>,
      > = std::sync::LazyLock::new(|| {
        mogh_rate_limit::RateLimiter::new(
          false,
          2,
          std::time::Duration::from_secs(60),
        )
      });
      &LIMITER
    }
    fn get_user(
      &self,
      user_id: String,
    ) -> DynFuture<mogh_error::Result<crate::user::BoxAuthUser>> {
      TestAuth.get_user(user_id)
    }
    fn handle_request_authentication(
      &self,
      auth: RequestAuthentication,
      ip: IpAddr,
      require_user_enabled: bool,
      req: Request,
    ) -> DynFuture<mogh_error::Result<Request>> {
      TestAuth.handle_request_authentication(
        auth,
        ip,
        require_user_enabled,
        req,
      )
    }
    fn jwt_provider(&self) -> &JwtProvider {
      TestAuth.jwt_provider()
    }
    fn server_private_key(
      &self,
    ) -> Option<&mogh_pki::RotatableKeyPair> {
      Some(server_keys())
    }
  }

  fn now_ms() -> i64 {
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap()
      .as_millis() as i64
  }

  fn signature_headers(
    signature: &str,
    timestamp: &str,
  ) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
      "x-api-signature",
      HeaderValue::from_str(signature).unwrap(),
    );
    headers.insert(
      "x-api-timestamp",
      HeaderValue::from_str(timestamp).unwrap(),
    );
    headers
  }

  /// A client key pair and its signature for the request.
  fn sign(
    method: &Method,
    uri: &Uri,
    timestamp: i64,
    body: &[u8],
  ) -> (String, String) {
    let client =
      mogh_pki::EncodedKeyPair::generate(mogh_pki::PkiKind::OneWay)
        .unwrap();
    let signature = OneWayNoiseHandshake::new_initiator(
      &Pkcs8PrivateKey::maybe_raw_bytes(client.private()).unwrap(),
      &mogh_pki::SpkiPublicKey::maybe_pem_to_raw_bytes(
        server_keys().load().public(),
      )
      .unwrap(),
      pki_auth_prologue(method, uri, timestamp, body).as_bytes(),
    )
    .unwrap()
    .generate_signature()
    .unwrap();
    (client.public().to_string(), signature)
  }

  /// A request body, eg. of `POST /auth/manage`.
  const BODY: &[u8] = br#"{"type":"ListTrustedIssuers","params":{}}"#;

  /// `body` not read by [read_signed_request_body]: the timestamp is
  /// checked when the signature is verified.
  fn unchecked_body(body: &'static [u8]) -> SignedRequestBody {
    Bytes::from_static(body).into()
  }

  #[test]
  fn test_extract_public_key_round_trip() {
    let uri = Uri::from_static("/read");
    let now = now_ms();
    let (public_key, signature) =
      sign(&Method::POST, &uri, now, BODY);
    let extracted = extract_request_public_key(
      &KEYED,
      &Method::POST,
      &uri,
      &signature_headers(&signature, &now.to_string()),
      BODY,
    )
    .unwrap()
    .unwrap();
    assert_eq!(extracted, public_key);
  }

  #[test]
  fn test_extract_public_key_ignores_scheme_and_host() {
    // Over HTTP/2 the server sees the scheme and authority in the
    // request uri, the client signs the path and query only.
    let now = now_ms();
    let (public_key, signature) = sign(
      &Method::POST,
      &Uri::from_static("/auth/manage?x=1"),
      now,
      BODY,
    );
    for uri in [
      "/auth/manage?x=1",
      "https://example.com/auth/manage?x=1",
      "http://127.0.0.1:9120/auth/manage?x=1",
    ] {
      let extracted = extract_request_public_key(
        &KEYED,
        &Method::POST,
        &Uri::from_static(uri),
        &signature_headers(&signature, &now.to_string()),
        BODY,
      )
      .unwrap_or_else(|e| panic!("{uri}: {:#}", e.error))
      .unwrap();
      assert_eq!(extracted, public_key, "{uri}");
    }
    // The path and query are still covered.
    let err = extract_request_public_key(
      &KEYED,
      &Method::POST,
      &Uri::from_static("https://example.com/auth/manage?x=2"),
      &signature_headers(&signature, &now.to_string()),
      BODY,
    )
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_extract_public_key_rejections_are_unauthorized() {
    let uri = Uri::from_static("/read");
    let now = now_ms();
    let (_, signature) = sign(&Method::POST, &uri, now, BODY);
    let stale = now - 60_000;
    let (_, stale_signature) = sign(&Method::POST, &uri, stale, BODY);
    let other_body: &[u8] =
      br#"{"type":"CreateTrustedIssuer","params":{}}"#;

    let cases = [
      // Signed for another uri / method
      (
        Method::POST,
        Uri::from_static("/write"),
        signature.clone(),
        now.to_string(),
        BODY,
      ),
      (
        Method::GET,
        uri.clone(),
        signature.clone(),
        now.to_string(),
        BODY,
      ),
      // Signed for another body on the same method and path
      (
        Method::POST,
        uri.clone(),
        signature.clone(),
        now.to_string(),
        other_body,
      ),
      (
        Method::POST,
        uri.clone(),
        signature.clone(),
        now.to_string(),
        b"",
      ),
      // The timestamp doesn't match the signed one
      (
        Method::POST,
        uri.clone(),
        signature.clone(),
        (now + 1).to_string(),
        BODY,
      ),
      // A correctly signed, but old request (replay)
      (
        Method::POST,
        uri.clone(),
        stale_signature,
        stale.to_string(),
        BODY,
      ),
      // Garbage
      (
        Method::POST,
        uri.clone(),
        "not-base64!".to_string(),
        now.to_string(),
        BODY,
      ),
      (
        Method::POST,
        uri.clone(),
        "AAAA".to_string(),
        now.to_string(),
        BODY,
      ),
      (
        Method::POST,
        uri.clone(),
        signature.clone(),
        "soon".to_string(),
        BODY,
      ),
      (
        Method::POST,
        uri.clone(),
        signature.clone(),
        String::new(),
        BODY,
      ),
      // Must not overflow
      (
        Method::POST,
        uri.clone(),
        signature.clone(),
        i64::MIN.to_string(),
        BODY,
      ),
      (
        Method::POST,
        uri.clone(),
        signature.clone(),
        i64::MAX.to_string(),
        BODY,
      ),
    ];
    for (method, uri, signature, timestamp, body) in cases {
      let err = extract_request_public_key(
        &KEYED,
        &method,
        &uri,
        &signature_headers(&signature, &timestamp),
        body,
      )
      .unwrap_err();
      assert_eq!(
        err.status,
        StatusCode::UNAUTHORIZED,
        "{method} {uri} {timestamp:?} {body:?}"
      );
    }

    // Missing timestamp
    let mut headers = HeaderMap::new();
    headers.insert(
      "x-api-signature",
      HeaderValue::from_str(&signature).unwrap(),
    );
    let err = extract_request_public_key(
      &KEYED,
      &Method::POST,
      &uri,
      &headers,
      BODY,
    )
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_extract_public_key_timestamp_tolerance_is_configurable() {
    let uri = Uri::from_static("/read");
    // Eg. a client whose clock is 20 seconds behind.
    let timestamp = now_ms() - 20_000;
    let (public_key, signature) =
      sign(&Method::POST, &uri, timestamp, b"");
    let headers =
      signature_headers(&signature, &timestamp.to_string());
    let err = extract_request_public_key(
      &KEYED,
      &Method::POST,
      &uri,
      &headers,
      b"",
    )
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);

    let tolerant = KeyedAuth {
      timestamp_tolerance_ms: 30_000,
      ..KEYED
    };
    let extracted = extract_request_public_key(
      &tolerant,
      &Method::POST,
      &uri,
      &headers,
      b"",
    )
    .unwrap()
    .unwrap();
    assert_eq!(extracted, public_key);
    // Still bounded.
    let timestamp = now_ms() - 40_000;
    let (_, signature) = sign(&Method::POST, &uri, timestamp, b"");
    assert!(
      extract_request_public_key(
        &tolerant,
        &Method::POST,
        &uri,
        &signature_headers(&signature, &timestamp.to_string()),
        b"",
      )
      .is_err()
    );
  }

  #[tokio::test]
  async fn test_unusable_credentials_are_rate_limited() {
    let uri = Uri::from_static("/read");
    let ip: IpAddr = "203.0.113.50".parse().unwrap();
    let invalid = signature_headers("AAAA", &now_ms().to_string());
    // The limiter of KeyedAuth allows 2 failures.
    for _ in 0..2 {
      let err = extract_request_authentication_rate_limited(
        &KEYED,
        ip,
        &Method::POST,
        &uri,
        &invalid,
        &unchecked_body(BODY),
      )
      .await
      .err()
      .unwrap();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
    // Now even a valid signature isn't looked at.
    let now = now_ms();
    let (_, signature) = sign(&Method::POST, &uri, now, BODY);
    let err = extract_request_authentication_rate_limited(
      &KEYED,
      ip,
      &Method::POST,
      &uri,
      &signature_headers(&signature, &now.to_string()),
      &unchecked_body(BODY),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
  }

  #[tokio::test]
  async fn test_missing_credentials_are_not_rate_limited() {
    let uri = Uri::from_static("/read");
    let ip: IpAddr = "203.0.113.51".parse().unwrap();
    // Eg. a UI which isn't logged in yet.
    for _ in 0..10 {
      let err = extract_request_authentication_rate_limited(
        &KEYED,
        ip,
        &Method::POST,
        &uri,
        &HeaderMap::new(),
        &SignedRequestBody::default(),
      )
      .await
      .err()
      .unwrap();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
    let now = now_ms();
    let (public_key, signature) =
      sign(&Method::POST, &uri, now, BODY);
    let extracted = extract_request_authentication_rate_limited(
      &KEYED,
      ip,
      &Method::POST,
      &uri,
      &signature_headers(&signature, &now.to_string()),
      &unchecked_body(BODY),
    )
    .await
    .ok()
    .unwrap();
    assert!(matches!(
      extracted,
      RequestAuthentication::PublicKey(key) if key == public_key
    ));
  }

  /// The default for apps which don't use signing keys: a signed
  /// request is refused as such, it is not a server error.
  #[test]
  fn test_extract_public_key_without_server_key_is_not_enabled() {
    let uri = Uri::from_static("/read");
    let now = now_ms();
    let (_, signature) = sign(&Method::POST, &uri, now, b"");
    // TestAuth has no server private key.
    for timestamp in [now.to_string(), String::from("garbage")] {
      let err = extract_request_public_key(
        &TestAuth,
        &Method::POST,
        &uri,
        &signature_headers(&signature, &timestamp),
        b"",
      )
      .unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
      assert_eq!(
        err.error.to_string(),
        "Signing keys are not enabled"
      );
    }
  }

  #[test]
  fn test_pki_auth_prologue_format() {
    // sha256 of the empty body.
    let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    for uri in [
      "/auth/manage?x=1",
      // HTTP/2
      "https://example.com:9120/auth/manage?x=1",
    ] {
      let uri = Uri::from_static(uri);
      let prologue =
        pki_auth_prologue(&Method::POST, &uri, 1234, b"");
      assert_eq!(
        prologue,
        format!("POST|/auth/manage?x=1|1234|{empty}")
      );
    }
    assert_eq!(
      pki_auth_prologue(
        &Method::POST,
        &Uri::from_static("/read"),
        1234,
        b"{}"
      ),
      "POST|/read|1234|44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    );
  }

  /// A request with a signature (not a valid one) at `timestamp`.
  fn signed_request(
    timestamp: Option<i64>,
    body: impl Into<Body>,
  ) -> Request {
    let mut request =
      Request::post("/read").header(API_SIGNATURE_HEADER, "AAAA");
    if let Some(timestamp) = timestamp {
      request =
        request.header(API_TIMESTAMP_HEADER, timestamp.to_string());
    }
    request.body(body.into()).unwrap()
  }

  fn unsigned_request(body: impl Into<Body>) -> Request {
    Request::post("/read").body(body.into()).unwrap()
  }

  /// Not locked out by the limiter of [KeyedAuth].
  const READ_IP: IpAddr =
    IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 52));

  #[tokio::test]
  async fn test_read_signed_request_body() {
    // Put back for the handler.
    let (req, body) = read_signed_request_body(
      &KEYED,
      READ_IP,
      signed_request(Some(now_ms()), BODY),
    )
    .await
    .unwrap();
    assert_eq!(body.body(), BODY);
    let (_, handler_body) = read_request_body(req).await.unwrap();
    assert_eq!(handler_body, BODY);

    // The body of other requests isn't read.
    let (req, body) = read_signed_request_body(
      &KEYED,
      READ_IP,
      unsigned_request(BODY),
    )
    .await
    .unwrap();
    assert!(body.body().is_empty());
    let (_, handler_body) = read_request_body(req).await.unwrap();
    assert_eq!(handler_body, BODY);

    // Nor the tunnel of a CONNECT request.
    let mut connect = signed_request(Some(now_ms()), BODY);
    *connect.method_mut() = Method::CONNECT;
    let (req, body) =
      read_signed_request_body(&KEYED, READ_IP, connect)
        .await
        .unwrap();
    assert!(body.body().is_empty());
    let (_, handler_body) = read_request_body(req).await.unwrap();
    assert_eq!(handler_body, BODY);
  }

  /// The signature of a request which also carries a jwt or an api
  /// key isn't checked: passed on without its body being read.
  #[tokio::test]
  async fn test_read_signed_request_body_with_other_credentials() {
    // Whatever the timestamp.
    for timestamp in [Some(now_ms()), Some(0), None] {
      let mut with_jwt = signed_request(timestamp, BODY);
      with_jwt
        .headers_mut()
        .insert(AUTHORIZATION, HeaderValue::from_static("Bearer x"));
      let mut with_api_key = signed_request(timestamp, BODY);
      with_api_key
        .headers_mut()
        .insert(API_KEY_HEADER, HeaderValue::from_static("K"));
      for (case, req) in
        [("jwt", with_jwt), ("api key", with_api_key)]
      {
        let (req, body) =
          read_signed_request_body(&KEYED, READ_IP, req)
            .await
            .unwrap_or_else(|e| panic!("{case}: {:#}", e.error));
        assert!(body.body().is_empty(), "{case} {timestamp:?}");
        // Left for the handler.
        let (_, handler_body) = read_request_body(req).await.unwrap();
        assert_eq!(handler_body, BODY, "{case} {timestamp:?}");
      }
    }
  }

  /// A signed request which can't verify is refused before its body
  /// is read, never passed on without it: the signature would then
  /// be checked against an empty body if a later timestamp check
  /// passed, while the handler gets the unread one.
  #[tokio::test]
  async fn test_read_signed_request_body_refuses_unverifiable() {
    let tolerance = KEYED.timestamp_tolerance_ms as i64;
    // Eg. a client whose clock runs ahead, which a later check
    // would find within the tolerance.
    let early = now_ms() + tolerance + 500;
    let mut connect = signed_request(Some(early), BODY);
    *connect.method_mut() = Method::CONNECT;
    let cases = [
      ("missing timestamp", signed_request(None, BODY)),
      ("early timestamp", signed_request(Some(early), BODY)),
      (
        "stale timestamp",
        signed_request(Some(now_ms() - 60_000), BODY),
      ),
      (
        "early empty body",
        signed_request(Some(early), b"".as_slice()),
      ),
      ("early connect", connect),
    ];
    for (case, req) in cases {
      let err = read_signed_request_body(&KEYED, READ_IP, req)
        .await
        .err()
        .unwrap_or_else(|| panic!("{case}"));
      assert_eq!(err.status, StatusCode::UNAUTHORIZED, "{case}");
    }
    let mut garbage = signed_request(None, BODY);
    garbage.headers_mut().insert(
      API_TIMESTAMP_HEADER,
      HeaderValue::from_static("garbage"),
    );
    let err = read_signed_request_body(&KEYED, READ_IP, garbage)
      .await
      .err()
      .unwrap();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);

    // Without a server private key, whatever the timestamp.
    for timestamp in [Some(now_ms()), None] {
      let err = read_signed_request_body(
        &TestAuth,
        READ_IP,
        signed_request(timestamp, BODY),
      )
      .await
      .err()
      .unwrap();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
      assert_eq!(
        err.error.to_string(),
        "Signing keys are not enabled"
      );
    }
  }

  #[test]
  fn test_check_request_timestamp_boundaries() {
    let now = 1_700_000_000_000;
    let tolerance = KEYED.timestamp_tolerance_ms as i64;
    let check = |timestamp: i64| {
      check_request_timestamp(
        &KEYED,
        &signature_headers("AAAA", &timestamp.to_string()),
        now,
      )
    };
    for timestamp in [now, now - tolerance, now + tolerance] {
      assert_eq!(check(timestamp).unwrap(), timestamp);
    }
    for timestamp in [now - tolerance - 1, now + tolerance + 1] {
      let err = check(timestamp).unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED, "{timestamp}");
    }
  }

  #[tokio::test]
  async fn test_read_signed_request_body_is_limited() {
    // axum's default body limit, 2 MB.
    let large = vec![b'a'; 2 * 1024 * 1024 + 1];
    let err = read_signed_request_body(
      &KEYED,
      READ_IP,
      signed_request(Some(now_ms()), large.clone()),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
    // Not read without a signature, the handler decides.
    let (_, body) = read_signed_request_body(
      &KEYED,
      READ_IP,
      unsigned_request(large),
    )
    .await
    .unwrap();
    assert!(body.body().is_empty());
  }

  /// [read_signed_request_body] for `auth` behind the router's
  /// `route_limit`, as a handler sees it. Answers OK when the body
  /// was read, else with the status of the error.
  async fn read_behind_route_limit(
    auth: KeyedAuth,
    route_limit: axum::extract::DefaultBodyLimit,
    req: Request,
  ) -> StatusCode {
    use axum::handler::Handler as _;
    let handler = (move |req: Request| async move {
      match read_signed_request_body(&auth, READ_IP, req).await {
        Ok(_) => StatusCode::OK,
        Err(e) => e.status,
      }
    })
    .layer(route_limit);
    handler.call(req, ()).await.status()
  }

  #[tokio::test]
  async fn test_read_signed_request_body_has_its_own_limit() {
    let limited = KeyedAuth {
      signed_body_limit: 64,
      ..KEYED
    };
    let (_, body) = read_signed_request_body(
      &limited,
      READ_IP,
      signed_request(Some(now_ms()), vec![b'a'; 64]),
    )
    .await
    .unwrap();
    assert_eq!(body.body().len(), 64);
    let err = read_signed_request_body(
      &limited,
      READ_IP,
      signed_request(Some(now_ms()), vec![b'a'; 65]),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
  }

  /// A router which raises or disables its body limit (eg. for
  /// uploads) doesn't raise how much of an unauthenticated signed
  /// request is read, and one which lowers it still applies.
  #[tokio::test]
  async fn test_read_signed_request_body_limit_is_the_smaller() {
    use axum::extract::DefaultBodyLimit;
    const MB: usize = 1024 * 1024;
    let raised = KeyedAuth {
      signed_body_limit: 4 * MB,
      ..KEYED
    };
    let cases = [
      // The default limit (2 MB), whatever the router's.
      (KEYED, DefaultBodyLimit::disable(), 2 * MB, StatusCode::OK),
      (
        KEYED,
        DefaultBodyLimit::disable(),
        2 * MB + 1,
        StatusCode::PAYLOAD_TOO_LARGE,
      ),
      (
        KEYED,
        DefaultBodyLimit::max(64 * MB),
        2 * MB + 1,
        StatusCode::PAYLOAD_TOO_LARGE,
      ),
      // Raised for signed requests too.
      (raised, DefaultBodyLimit::disable(), 3 * MB, StatusCode::OK),
      (
        raised,
        DefaultBodyLimit::disable(),
        4 * MB + 1,
        StatusCode::PAYLOAD_TOO_LARGE,
      ),
      // A router's lower limit applies.
      (raised, DefaultBodyLimit::max(64), 64, StatusCode::OK),
      (
        raised,
        DefaultBodyLimit::max(64),
        65,
        StatusCode::PAYLOAD_TOO_LARGE,
      ),
      (
        KEYED,
        DefaultBodyLimit::max(64),
        65,
        StatusCode::PAYLOAD_TOO_LARGE,
      ),
    ];
    for (i, (auth, route_limit, len, expected)) in
      cases.into_iter().enumerate()
    {
      let status = read_behind_route_limit(
        auth,
        route_limit,
        signed_request(Some(now_ms()), vec![b'a'; len]),
      )
      .await;
      assert_eq!(status, expected, "case {i}: {len} bytes");
    }
    // Unsigned requests are left to the handler.
    let status = read_behind_route_limit(
      KEYED,
      DefaultBodyLimit::disable(),
      unsigned_request(vec![b'a'; 3 * MB]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Without a DefaultBodyLimit, axum's 2 MB default still applies:
    // raising only the knob doesn't get a signed body past it.
    for (len, expected) in [
      (2 * MB, StatusCode::OK),
      (2 * MB + 1, StatusCode::PAYLOAD_TOO_LARGE),
    ] {
      let status = match read_signed_request_body(
        &raised,
        READ_IP,
        signed_request(Some(now_ms()), vec![b'a'; len]),
      )
      .await
      {
        Ok(_) => StatusCode::OK,
        Err(e) => e.status,
      };
      assert_eq!(status, expected, "no route limit: {len} bytes");
    }
  }

  /// [KeyedAuth] as [authenticate_request] makes it ([AuthImpl::new]),
  /// with a tolerance short enough for a test to wait it out. Shares
  /// the limiter of [KeyedAuth].
  struct ServedAuth(KeyedAuth);

  const SERVED_TOLERANCE_MS: u64 = 200;

  impl AuthImpl for ServedAuth {
    fn new() -> Self {
      ServedAuth(KeyedAuth {
        timestamp_tolerance_ms: SERVED_TOLERANCE_MS,
        ..KEYED
      })
    }
    fn signing_key_timestamp_tolerance_ms(&self) -> u64 {
      self.0.signing_key_timestamp_tolerance_ms()
    }
    fn general_rate_limiter(&self) -> &mogh_rate_limit::RateLimiter {
      self.0.general_rate_limiter()
    }
    fn get_user(
      &self,
      user_id: String,
    ) -> DynFuture<mogh_error::Result<crate::user::BoxAuthUser>> {
      self.0.get_user(user_id)
    }
    fn handle_request_authentication(
      &self,
      auth: RequestAuthentication,
      ip: IpAddr,
      require_user_enabled: bool,
      req: Request,
    ) -> DynFuture<mogh_error::Result<Request>> {
      self.0.handle_request_authentication(
        auth,
        ip,
        require_user_enabled,
        req,
      )
    }
    fn jwt_provider(&self) -> &JwtProvider {
      self.0.jwt_provider()
    }
    fn server_private_key(
      &self,
    ) -> Option<&mogh_pki::RotatableKeyPair> {
      self.0.server_private_key()
    }
  }

  /// Serves [authenticate_request] for [ServedAuth] in front of a
  /// `POST /read` handler which echoes the body.
  async fn serve_authenticated() -> std::net::SocketAddr {
    async fn echo(body: Bytes) -> Bytes {
      body
    }
    let router = axum::Router::new()
      .route("/read", axum::routing::post(echo))
      .layer(axum::middleware::from_fn(
        authenticate_request::<ServedAuth, false>,
      ));
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
      axum::serve(
        listener,
        router.into_make_service_with_connect_info::<
          std::net::SocketAddr,
        >(),
      )
      .await
      .unwrap()
    });
    address
  }

  /// Sends `POST /read` with [BODY] from `client_ip` (the loopback
  /// peer is a trusted proxy by default) signed at `timestamp`, by
  /// hand: the headers right away, the body after `body_after`, or
  /// never with `None`. Returns the response status and body.
  async fn send_signed(
    address: std::net::SocketAddr,
    client_ip: &str,
    timestamp: i64,
    body_after: Option<std::time::Duration>,
  ) -> (StatusCode, Vec<u8>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let uri = Uri::from_static("/read");
    let (_, signature) = sign(&Method::POST, &uri, timestamp, BODY);
    let head = format!(
      "POST /read HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\ncontent-length: {}\r\nx-forwarded-for: {client_ip}\r\n{API_SIGNATURE_HEADER}: {signature}\r\n{API_TIMESTAMP_HEADER}: {timestamp}\r\n\r\n",
      BODY.len()
    );
    let mut stream =
      tokio::net::TcpStream::connect(address).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    let response = async {
      if let Some(delay) = body_after {
        tokio::time::sleep(delay).await;
        stream.write_all(BODY).await.unwrap();
      }
      // The response head, then as much body as it announces.
      let mut response = Vec::new();
      loop {
        let head_end = response
          .windows(4)
          .position(|window| window == b"\r\n\r\n");
        if let Some(head_end) = head_end {
          let head = String::from_utf8_lossy(&response[..head_end])
            .to_lowercase();
          let length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .map(|length| length.trim().parse::<usize>().unwrap())
            .unwrap_or_default();
          let body_start = head_end + 4;
          if response.len() >= body_start + length {
            let status = StatusCode::from_bytes(&response[9..12])
              .unwrap_or_else(|_| panic!("{head}"));
            let body =
              response[body_start..body_start + length].to_vec();
            return (status, body);
          }
        }
        let read = stream.read_buf(&mut response).await.unwrap();
        assert_ne!(read, 0, "closed without a response");
      }
    };
    // Refusals don't wait for a body which never arrives.
    tokio::time::timeout(std::time::Duration::from_secs(5), response)
      .await
      .expect("no response, the server waited for the body")
  }

  /// The timestamp is checked when the headers arrive, the signature
  /// is verified against it once the body has: the time the body takes
  /// doesn't count against the tolerance.
  #[tokio::test]
  async fn test_authenticate_request_body_arriving_late() {
    let address = serve_authenticated().await;
    let tolerance = std::time::Duration::from_millis(
      ServedAuth::new().signing_key_timestamp_tolerance_ms(),
    );
    let timestamp = now_ms();
    let (status, body) = send_signed(
      address,
      "203.0.113.53",
      timestamp,
      Some(tolerance * 3),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, BODY);
    // Checked now, the timestamp is stale.
    let (_, signature) = sign(
      &Method::POST,
      &Uri::from_static("/read"),
      timestamp,
      BODY,
    );
    let err = extract_request_public_key(
      &ServedAuth::new(),
      &Method::POST,
      &Uri::from_static("/read"),
      &signature_headers(&signature, &timestamp.to_string()),
      BODY,
    )
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  /// A stale timestamp in the headers is refused right away, without
  /// waiting for the body.
  #[tokio::test]
  async fn test_authenticate_request_stale_timestamp_body_not_read() {
    let address = serve_authenticated().await;
    let stale = now_ms() - 2 * SERVED_TOLERANCE_MS as i64;
    let (status, _) =
      send_signed(address, "203.0.113.54", stale, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
  }

  /// A client the general rate limiter has locked out is refused
  /// before its body is read, even with a current timestamp.
  #[tokio::test]
  async fn test_authenticate_request_locked_out_body_not_read() {
    let address = serve_authenticated().await;
    let client_ip = "203.0.113.55";
    let invalid = signature_headers("AAAA", &now_ms().to_string());
    // The limiter of KeyedAuth allows 2 failures.
    for _ in 0..2 {
      let err = extract_request_authentication_rate_limited(
        &KEYED,
        client_ip.parse().unwrap(),
        &Method::POST,
        &Uri::from_static("/read"),
        &invalid,
        &unchecked_body(BODY),
      )
      .await
      .err()
      .unwrap();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) =
      send_signed(address, client_ip, now_ms(), None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // Another client gets through.
    let (status, _) = send_signed(
      address,
      "203.0.113.56",
      now_ms(),
      Some(std::time::Duration::ZERO),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
  }
}
