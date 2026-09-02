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
  AuthImpl, middleware::extract_authenticate_request,
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

pub async fn attach_user<I: AuthImpl>(
  RequestIp(ip): RequestIp,
  OriginalUri(uri): OriginalUri,
  req: Request,
  next: Next,
) -> mogh_error::Result<Response> {
  let auth = I::new();

  // The request is split apart because holding `&Request`
  // across an await makes the future !Send (Body is !Sync).
  let (mut parts, body) = req.into_parts();

  let user = async {
    let req_auth = extract_authenticate_request(
      &auth,
      &parts.method,
      &uri,
      &parts.headers,
    )
    .await?
    .context("Invalid client credentials")
    .status_code(StatusCode::UNAUTHORIZED)?;
    let user_id = auth
      .get_user_id_from_request_authentication(req_auth)
      .await?;
    auth.get_user(user_id).await
  }
  .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), &ip)
  .await?;

  parts.extensions.insert(UserExtractor(Arc::new(user)));

  Ok(next.run(Request::from_parts(parts, body)).await)
}
