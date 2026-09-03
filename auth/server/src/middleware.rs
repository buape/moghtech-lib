use std::time::{SystemTime, UNIX_EPOCH};

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

use crate::{AuthImpl, RequestAuthentication};

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

  let req_auth = extract_request_authentication(
    &auth,
    req.method(),
    &uri,
    req.headers(),
  )?
  .context("Invalid client credentials")
  .status_code(StatusCode::UNAUTHORIZED)?;

  let req = auth
    .handle_request_authentication(
      req_auth,
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
    .context("AUTHORIZATION is not valid UTF-8")?
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
    .context("X-API-KEY is not valid UTF-8")?
    .trim()
    .to_string();
  let secret = headers
    .get("x-api-secret")
    .context(
      "Request headers have X-API-KEY but missing X-API-SECRET",
    )?
    .to_str()
    .context("X-API-SECRET is not valid UTF-8")?
    .trim()
    .to_string();
  Ok(Some((key, secret)))
}

/// Extracts the client public key from the
/// X-API-SIGNATURE / X-API-TIMESTAMP headers.
///
/// The timestamp must be ~now, and the signature must complete a
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
    .context("X-API-SIGNATURE is not valid UTF-8")?;
  let timestamp = headers
    .get("x-api-timestamp")
    .context("Request headers have X-API-SIGNATURE but missing X-API-TIMESTAMP")?
    .to_str()
    .context("X-API-TIMESTAMP is not valid UTF-8")?
    .parse::<i64>()?;

  let now =
    SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;

  // Ensure timestamp is ~now
  if (now - timestamp).abs() > 1_000 {
    return Err(anyhow!("Invalid client credentials").into());
  }

  let prologue = pki_auth_prologue(method, uri, timestamp);

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

  let public_key =
    handshake.validate_signature(signature)?.into_inner();

  Ok(Some(public_key))
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

/// Helper for implementing [AuthImpl::get_api_key_user_id]:
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

pub fn pki_auth_prologue(
  method: &Method,
  uri: &Uri,
  timestamp: i64,
) -> String {
  format!("{method}|{uri}|{timestamp}")
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
    assert!(extract_request_api_key(&headers).is_err());
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

  #[test]
  fn test_pki_auth_prologue_format() {
    let uri = Uri::from_static("/auth/manage?x=1");
    let prologue = pki_auth_prologue(&Method::POST, &uri, 1234);
    assert_eq!(prologue, "POST|/auth/manage?x=1|1234");
  }
}
