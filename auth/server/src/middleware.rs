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

use crate::{
  AuthImpl, RequestAuthentication, provider::jwt::JwtProvider,
};

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

  let req = {
    let auth = &auth;
    async move {
      let req_auth = extract_authenticate_request(
        auth,
        req.method(),
        &uri,
        req.headers(),
      )
      .await?
      .context("Invalid client credentials")
      .status_code(StatusCode::UNAUTHORIZED)?;

      auth
        .handle_request_authentication(
          req_auth,
          REQUIRE_USER_ENABLED,
          req,
        )
        .await
    }
  }
  .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), &ip)
  .await?;

  Ok(next.run(req).await)
}

/// Extracts and authenticates the request credentials, trying
/// [extract_authenticate_user_id], [extract_authenticate_api_key],
/// and [extract_authenticate_public_key] in order.
///
/// Returns `Ok(None)` when the request carries no credentials.
pub async fn extract_authenticate_request<I: AuthImpl>(
  auth: &I,
  method: &Method,
  uri: &Uri,
  headers: &HeaderMap,
) -> mogh_error::Result<Option<RequestAuthentication>> {
  if let Some(user_id) =
    extract_authenticate_user_id(auth.jwt_provider(), headers)?
  {
    return Ok(Some(RequestAuthentication::UserId(user_id)));
  }

  if let Some(key) =
    extract_authenticate_api_key(auth, headers).await?
  {
    return Ok(Some(RequestAuthentication::ApiKey(key)));
  }

  if let Some(public_key) =
    extract_authenticate_public_key(auth, method, uri, headers)?
  {
    return Ok(Some(RequestAuthentication::PublicKey(public_key)));
  }

  Ok(None)
}

/// Extracts the user id from the AUTHORIZATION header.
///
/// This performs authentication: the JWT signature and expiry
/// are validated by the [JwtProvider].
pub fn extract_authenticate_user_id(
  jwt_provider: &JwtProvider,
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
  let user_id = jwt_provider.decode_sub(jwt)?;
  Ok(Some(user_id))
}

/// Extracts the api key from the X-API-KEY / X-API-SECRET headers.
///
/// This performs authentication: the secret is bcrypt-verified
/// against the stored hash from [AuthImpl::get_api_key_hashed_secret],
/// and is not needed after this returns. Unknown keys are rejected.
pub async fn extract_authenticate_api_key<I: AuthImpl>(
  auth: &I,
  headers: &HeaderMap,
) -> mogh_error::Result<Option<String>> {
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

  let Some(hashed_secret) =
    auth.get_api_key_hashed_secret(key.clone()).await?
  else {
    // Unknown key: still run bcrypt before failing so response
    // timing does not reveal whether the api key exists.
    let _ = bcrypt::hash(&secret, auth.api_secret_bcrypt_cost());
    return Err(
      anyhow!("Invalid client credentials")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  };

  let verified = bcrypt::verify(&secret, &hashed_secret)
    .context("Invalid client credentials")
    .status_code(StatusCode::UNAUTHORIZED)?;
  if !verified {
    return Err(
      anyhow!("Invalid client credentials")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  Ok(Some(key))
}

/// Extracts the client public key from the
/// X-API-SIGNATURE / X-API-TIMESTAMP headers.
///
/// This performs authentication: the timestamp must be ~now, and the
/// signature must complete a noise handshake against the server
/// private key over a prologue binding method, uri, and timestamp.
/// The resulting public key still must be matched to a known client.
pub fn extract_authenticate_public_key<I: AuthImpl>(
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

  struct TestAuth {
    jwt_provider: JwtProvider,
    /// Simulates the stored bcrypt hash for any api key.
    /// None simulates an unknown api key.
    hashed_secret: Option<String>,
  }

  impl TestAuth {
    fn new(hashed_secret: Option<String>) -> Self {
      Self {
        jwt_provider: JwtProvider::new(b"secret", 60_000),
        hashed_secret,
      }
    }
  }

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      Self::new(None)
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
      &self.jwt_provider
    }
    fn get_api_key_hashed_secret(
      &self,
      _key: String,
    ) -> DynFuture<mogh_error::Result<Option<String>>> {
      let hashed_secret = self.hashed_secret.clone();
      Box::pin(async move { Ok(hashed_secret) })
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

  #[tokio::test]
  async fn test_extract_key_and_secret_missing_key() {
    let auth = TestAuth::new(None);
    let headers = HeaderMap::new();
    assert!(
      extract_authenticate_api_key(&auth, &headers)
        .await
        .unwrap()
        .is_none()
    );
  }

  #[tokio::test]
  async fn test_extract_key_and_secret_missing_secret_errors() {
    let auth = TestAuth::new(None);
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("K_abc_K"));
    assert!(
      extract_authenticate_api_key(&auth, &headers).await.is_err()
    );
  }

  #[tokio::test]
  async fn test_extract_key_and_secret_trims_values() {
    // Verification runs against the trimmed secret,
    // and the trimmed key is returned.
    let hashed = bcrypt::hash("S_def_S", 4).unwrap();
    let auth = TestAuth::new(Some(hashed));
    let mut headers = HeaderMap::new();
    headers
      .insert("x-api-key", HeaderValue::from_static(" K_abc_K "));
    headers
      .insert("x-api-secret", HeaderValue::from_static(" S_def_S "));
    let key = extract_authenticate_api_key(&auth, &headers)
      .await
      .unwrap()
      .unwrap();
    assert_eq!(key, "K_abc_K");
  }

  #[tokio::test]
  async fn test_extract_key_and_secret_verifies_secret() {
    let hashed = bcrypt::hash("S_def_S", 4).unwrap();
    let auth = TestAuth::new(Some(hashed));
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("K_abc_K"));
    headers
      .insert("x-api-secret", HeaderValue::from_static("S_def_S"));
    let key = extract_authenticate_api_key(&auth, &headers)
      .await
      .unwrap()
      .unwrap();
    assert_eq!(key, "K_abc_K");
  }

  #[tokio::test]
  async fn test_extract_key_and_secret_rejects_unknown_key() {
    // get_api_key_hashed_secret returning None means the key
    // does not exist: must reject, not pass through.
    let auth = TestAuth::new(None);
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("K_abc_K"));
    headers
      .insert("x-api-secret", HeaderValue::from_static("S_def_S"));
    let err = extract_authenticate_api_key(&auth, &headers)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn test_extract_key_and_secret_rejects_wrong_secret() {
    let hashed = bcrypt::hash("S_def_S", 4).unwrap();
    let auth = TestAuth::new(Some(hashed));
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("K_abc_K"));
    headers
      .insert("x-api-secret", HeaderValue::from_static("S_wrong_S"));
    let err = extract_authenticate_api_key(&auth, &headers)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_extract_user_id_no_authorization_header() {
    let provider = JwtProvider::new(b"secret", 60_000);
    let headers = HeaderMap::new();
    assert!(
      extract_authenticate_user_id(&provider, &headers)
        .unwrap()
        .is_none()
    );
  }

  #[test]
  fn test_extract_user_id_with_bearer_prefix() {
    let provider = JwtProvider::new(b"secret", 60_000);
    let jwt = provider.encode_sub("user-1").unwrap().jwt;
    let mut headers = HeaderMap::new();
    headers.insert(
      "authorization",
      HeaderValue::from_str(&format!("Bearer {jwt}")).unwrap(),
    );
    assert_eq!(
      extract_authenticate_user_id(&provider, &headers)
        .unwrap()
        .unwrap(),
      "user-1"
    );
  }

  #[test]
  fn test_extract_user_id_without_bearer_prefix() {
    let provider = JwtProvider::new(b"secret", 60_000);
    let jwt = provider.encode_sub("user-1").unwrap().jwt;
    let mut headers = HeaderMap::new();
    headers
      .insert("authorization", HeaderValue::from_str(&jwt).unwrap());
    assert_eq!(
      extract_authenticate_user_id(&provider, &headers)
        .unwrap()
        .unwrap(),
      "user-1"
    );
  }

  #[test]
  fn test_extract_user_id_invalid_jwt_errors() {
    let provider = JwtProvider::new(b"secret", 60_000);
    let forged =
      JwtProvider::new(b"other", 60_000).encode_sub("user-1");
    let mut headers = HeaderMap::new();
    headers.insert(
      "authorization",
      HeaderValue::from_str(&format!(
        "Bearer {}",
        forged.unwrap().jwt
      ))
      .unwrap(),
    );
    assert!(
      extract_authenticate_user_id(&provider, &headers).is_err()
    );
  }

  #[test]
  fn test_pki_auth_prologue_format() {
    let uri = Uri::from_static("/auth/manage?x=1");
    let prologue = pki_auth_prologue(&Method::POST, &uri, 1234);
    assert_eq!(prologue, "POST|/auth/manage?x=1|1234");
  }
}
