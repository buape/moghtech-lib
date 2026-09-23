use std::sync::Arc;

use anyhow::Context;
use axum::{
  extract::{FromRequestParts, OriginalUri, Request},
  http::StatusCode,
  middleware::Next,
  response::Response,
};
use mogh_error::AddStatusCode;
use mogh_rate_limit::WithFailureRateLimit as _;
use mogh_request_ip::RequestIp;

use crate::{
  AuthImpl, RequestAuthentication,
  middleware::{
    extract_request_authentication_rate_limited,
    get_user_from_request_authentication,
  },
  user::BoxAuthUser,
};

#[derive(Clone)]
pub struct UserExtractor(pub Arc<BoxAuthUser>);

impl<S: Send + Sync> FromRequestParts<S> for UserExtractor {
  type Rejection = mogh_error::Error;

  async fn from_request_parts(
    parts: &mut axum::http::request::Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    parts
      .extensions
      .get()
      .cloned()
      .context("Missing authorization credentials")
      .status_code(StatusCode::UNAUTHORIZED)
  }
}

/// When the token the request is authenticated with was issued (unix
/// seconds). `None` for credentials without a login: api keys, and
/// tokens not issued by [AuthImpl::jwt_provider].
#[derive(Clone, Copy)]
pub struct AuthenticatedAt(pub Option<u64>);

impl<S: Send + Sync> FromRequestParts<S> for AuthenticatedAt {
  type Rejection = mogh_error::Error;

  async fn from_request_parts(
    parts: &mut axum::http::request::Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    parts
      .extensions
      .get()
      .copied()
      .context("Missing authorization credentials")
      .status_code(StatusCode::UNAUTHORIZED)
  }
}

pub async fn attach_user<I: AuthImpl>(
  RequestIp(ip): RequestIp,
  OriginalUri(uri): OriginalUri,
  mut req: Request,
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

  let authenticated_at = match &req_auth {
    RequestAuthentication::Jwt(jwt) => auth
      .jwt_provider()
      .decode_claims(jwt)
      .ok()
      .map(|claims| claims.iat),
    RequestAuthentication::ApiKey { .. }
    | RequestAuthentication::PublicKey(_) => None,
  };

  // Enforces the api key and user cidr whitelists.
  let user =
    get_user_from_request_authentication(&auth, req_auth, ip)
      .with_failure_rate_limit_using_ip(
        auth.general_rate_limiter(),
        &ip,
      )
      .await?;

  req.extensions_mut().insert(UserExtractor(Arc::new(user)));
  req
    .extensions_mut()
    .insert(AuthenticatedAt(authenticated_at));

  Ok(next.run(req).await)
}
