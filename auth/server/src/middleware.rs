use std::{
  net::IpAddr,
  time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, anyhow};
use axum::{
  extract::{OriginalUri, Request},
  http::{HeaderMap, Method, Uri},
  middleware::Next,
  response::Response,
};
use mogh_error::{AddStatusCode, AddStatusCodeError as _};
use mogh_pki::{Pkcs8PrivateKey, one_way::OneWayNoiseHandshake};
use mogh_rate_limit::WithFailureRateLimit;
use mogh_request_ip::RequestIp;
use reqwest::StatusCode;

use crate::{
  AuthImpl, RequestAuthentication,
  api_key::AuthApiKeyImpl,
  user::{AuthUserImpl, BoxAuthUser},
};

pub use mogh_request_ip::cidr::check_cidr_whitelist;

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

  let req_auth = extract_request_authentication_rate_limited(
    &auth,
    ip,
    req.method(),
    &uri,
    req.headers(),
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

/// [extract_request_authentication] for middleware: requests without
/// credentials are UNAUTHORIZED, and credentials which are presented
/// but unusable count against [AuthImpl::general_rate_limiter] for the
/// `ip`. That is most of all an invalid api key (v2) signature, which
/// costs the server a key exchange to find out about, so it shouldn't
/// be free to send them in a loop.
///
/// Requests without any credentials are not counted: a UI which isn't
/// logged in yet sends those, and would lock its own login out.
pub async fn extract_request_authentication_rate_limited<
  I: AuthImpl,
>(
  auth: &I,
  ip: IpAddr,
  method: &Method,
  uri: &Uri,
  headers: &HeaderMap,
) -> mogh_error::Result<RequestAuthentication> {
  async { extract_request_authentication(auth, method, uri, headers) }
    .with_failure_rate_limit_using_ip(
      auth.general_rate_limiter(),
      &ip,
    )
    .await?
    .context("Invalid client credentials")
    .status_code(StatusCode::UNAUTHORIZED)
}

/// Maps the request credential headers to [RequestAuthentication],
/// trying [extract_request_jwt], [extract_request_api_key],
/// and [extract_request_public_key] in order.
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
) -> mogh_error::Result<Option<RequestAuthentication>> {
  if let Some(jwt) = extract_request_jwt(headers)? {
    return Ok(Some(RequestAuthentication::Jwt(jwt)));
  }

  if let Some((key, secret)) = extract_request_api_key(headers)? {
    return Ok(Some(RequestAuthentication::ApiKey { key, secret }));
  }

  if let Some(public_key) =
    extract_request_public_key(auth, method, uri, headers)?
  {
    return Ok(Some(RequestAuthentication::PublicKey(public_key)));
  }

  Ok(None)
}

/// Extracts the jwt from the AUTHORIZATION header,
/// stripping any `Bearer ` prefix.
///
/// DANGER ⚠️ The jwt is not validated here, see
/// [get_jwt_user_id].
pub fn extract_request_jwt(
  headers: &HeaderMap,
) -> mogh_error::Result<Option<String>> {
  let Some(authorization) = headers.get("authorization") else {
    return Ok(None);
  };
  let maybe_bearer = authorization
    .to_str()
    .context("AUTHORIZATION is not valid UTF-8")
    .status_code(StatusCode::UNAUTHORIZED)?
    .trim();
  let jwt =
    maybe_bearer.strip_prefix("Bearer ").unwrap_or(maybe_bearer);
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
  let Some(key) = headers.get("x-api-key") else {
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
/// The timestamp must be ~now
/// ([AuthImpl::api_key_v2_timestamp_tolerance_ms]), and the signature must complete a
/// noise handshake against the server private key over a prologue
/// binding method, uri, and timestamp. This proves the client holds
/// the private key for the returned public key, nothing more.
///
/// DANGER ⚠️ The public key must still be matched to a known client.
pub fn extract_request_public_key<I: AuthImpl>(
  auth: &I,
  method: &Method,
  uri: &Uri,
  headers: &HeaderMap,
) -> mogh_error::Result<Option<String>> {
  let Some(signature) = headers.get("x-api-signature") else {
    return Ok(None);
  };
  let signature = signature
    .to_str()
    .context("X-API-SIGNATURE is not valid UTF-8")
    .status_code(StatusCode::UNAUTHORIZED)?;
  let timestamp = headers
    .get("x-api-timestamp")
    .context("Request headers have X-API-SIGNATURE but missing X-API-TIMESTAMP")
    .status_code(StatusCode::UNAUTHORIZED)?
    .to_str()
    .context("X-API-TIMESTAMP is not valid UTF-8")
    .status_code(StatusCode::UNAUTHORIZED)?
    .trim()
    .parse::<i64>()
    .context("X-API-TIMESTAMP is not a unix timestamp in milliseconds")
    .status_code(StatusCode::UNAUTHORIZED)?;

  let now =
    SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;

  // Ensure timestamp is ~now. The subtraction saturates,
  // the timestamp is untrusted and can be anything.
  let tolerance =
    i64::try_from(auth.api_key_v2_timestamp_tolerance_ms())
      .unwrap_or(i64::MAX);
  if now.saturating_sub(timestamp).saturating_abs() > tolerance {
    return Err(
      anyhow!("Invalid client credentials")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  let prologue = pki_auth_prologue(method, uri, timestamp);

  // Without a server private key the server is misconfigured
  // for these credentials, which is not the clients fault.
  let mut handshake = OneWayNoiseHandshake::new_responder(
    &Pkcs8PrivateKey::maybe_raw_bytes(
      auth
        .server_private_key()
        .context("Missing server private key for request handshake")?
        .load()
        .private(),
    )?,
    prologue.as_bytes(),
  )?;

  // Fails for anything which wasn't signed for this exact
  // request (method, uri, timestamp) and this server.
  let public_key = handshake
    .validate_signature(signature)
    .map_err(|_| {
      anyhow!("Invalid client credentials")
        .status_code(StatusCode::UNAUTHORIZED)
    })?
    .into_inner();

  Ok(Some(public_key))
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
pub fn verify_api_key_secret<I: AuthImpl>(
  auth: &I,
  secret: &str,
  hashed_secret: Option<&str>,
) -> mogh_error::Result<()> {
  let Some(hashed_secret) = hashed_secret else {
    let _ = bcrypt::hash(secret, auth.api_secret_bcrypt_cost());
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
pub fn pki_auth_prologue(
  method: &Method,
  uri: &Uri,
  timestamp: i64,
) -> String {
  mogh_auth_client::signature::pki_auth_prologue(
    method.as_str(),
    &uri.to_string(),
    timestamp,
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

  /// [TestAuth] with a server private key, so signatures are checked.
  struct KeyedAuth {
    timestamp_tolerance_ms: u64,
  }

  const KEYED: KeyedAuth = KeyedAuth {
    timestamp_tolerance_ms: 1_000,
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
    fn api_key_v2_timestamp_tolerance_ms(&self) -> u64 {
      self.timestamp_tolerance_ms
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
      pki_auth_prologue(method, uri, timestamp).as_bytes(),
    )
    .unwrap()
    .generate_signature()
    .unwrap();
    (client.public().to_string(), signature)
  }

  #[test]
  fn test_extract_public_key_round_trip() {
    let uri = Uri::from_static("/read");
    let now = now_ms();
    let (public_key, signature) = sign(&Method::POST, &uri, now);
    let extracted = extract_request_public_key(
      &KEYED,
      &Method::POST,
      &uri,
      &signature_headers(&signature, &now.to_string()),
    )
    .unwrap()
    .unwrap();
    assert_eq!(extracted, public_key);
  }

  #[test]
  fn test_extract_public_key_rejections_are_unauthorized() {
    let uri = Uri::from_static("/read");
    let now = now_ms();
    let (_, signature) = sign(&Method::POST, &uri, now);
    let stale = now - 60_000;
    let (_, stale_signature) = sign(&Method::POST, &uri, stale);

    let cases = [
      // Signed for another uri / method
      (
        Method::POST,
        Uri::from_static("/write"),
        signature.clone(),
        now.to_string(),
      ),
      (Method::GET, uri.clone(), signature.clone(), now.to_string()),
      // The timestamp doesn't match the signed one
      (
        Method::POST,
        uri.clone(),
        signature.clone(),
        (now + 1).to_string(),
      ),
      // A correctly signed, but old request (replay)
      (
        Method::POST,
        uri.clone(),
        stale_signature,
        stale.to_string(),
      ),
      // Garbage
      (
        Method::POST,
        uri.clone(),
        "not-base64!".to_string(),
        now.to_string(),
      ),
      (
        Method::POST,
        uri.clone(),
        "AAAA".to_string(),
        now.to_string(),
      ),
      (
        Method::POST,
        uri.clone(),
        signature.clone(),
        "soon".to_string(),
      ),
      (Method::POST, uri.clone(), signature.clone(), String::new()),
      // Must not overflow
      (
        Method::POST,
        uri.clone(),
        signature.clone(),
        i64::MIN.to_string(),
      ),
      (
        Method::POST,
        uri.clone(),
        signature.clone(),
        i64::MAX.to_string(),
      ),
    ];
    for (method, uri, signature, timestamp) in cases {
      let err = extract_request_public_key(
        &KEYED,
        &method,
        &uri,
        &signature_headers(&signature, &timestamp),
      )
      .unwrap_err();
      assert_eq!(
        err.status,
        StatusCode::UNAUTHORIZED,
        "{method} {uri} {timestamp:?}"
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
      sign(&Method::POST, &uri, timestamp);
    let headers =
      signature_headers(&signature, &timestamp.to_string());
    let err = extract_request_public_key(
      &KEYED,
      &Method::POST,
      &uri,
      &headers,
    )
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);

    let tolerant = KeyedAuth {
      timestamp_tolerance_ms: 30_000,
    };
    let extracted = extract_request_public_key(
      &tolerant,
      &Method::POST,
      &uri,
      &headers,
    )
    .unwrap()
    .unwrap();
    assert_eq!(extracted, public_key);
    // Still bounded.
    let timestamp = now_ms() - 40_000;
    let (_, signature) = sign(&Method::POST, &uri, timestamp);
    assert!(
      extract_request_public_key(
        &tolerant,
        &Method::POST,
        &uri,
        &signature_headers(&signature, &timestamp.to_string()),
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
      )
      .await
      .err()
      .unwrap();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
    // Now even a valid signature isn't looked at.
    let now = now_ms();
    let (_, signature) = sign(&Method::POST, &uri, now);
    let err = extract_request_authentication_rate_limited(
      &KEYED,
      ip,
      &Method::POST,
      &uri,
      &signature_headers(&signature, &now.to_string()),
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
      )
      .await
      .err()
      .unwrap();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
    let now = now_ms();
    let (public_key, signature) = sign(&Method::POST, &uri, now);
    let extracted = extract_request_authentication_rate_limited(
      &KEYED,
      ip,
      &Method::POST,
      &uri,
      &signature_headers(&signature, &now.to_string()),
    )
    .await
    .ok()
    .unwrap();
    assert!(matches!(
      extracted,
      RequestAuthentication::PublicKey(key) if key == public_key
    ));
  }

  #[test]
  fn test_extract_public_key_without_server_key_is_server_error() {
    let uri = Uri::from_static("/read");
    let now = now_ms();
    let (_, signature) = sign(&Method::POST, &uri, now);
    // TestAuth has no server private key.
    let err = extract_request_public_key(
      &TestAuth,
      &Method::POST,
      &uri,
      &signature_headers(&signature, &now.to_string()),
    )
    .unwrap_err();
    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
  }

  #[test]
  fn test_pki_auth_prologue_format() {
    let uri = Uri::from_static("/auth/manage?x=1");
    let prologue = pki_auth_prologue(&Method::POST, &uri, 1234);
    assert_eq!(prologue, "POST|/auth/manage?x=1|1234");
  }
}
