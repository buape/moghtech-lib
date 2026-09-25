//! mogh_error's server error detail setting is process wide, so it
//! is tested in its own test binary, in one test, to keep other
//! tests from seeing it change.
#![allow(unused_crate_dependencies)]

use std::{net::IpAddr, time::Duration};

use axum::{http::StatusCode, response::IntoResponse as _};
use mogh_error::{
  AddStatusCodeError as _, Serror, ServerErrorDetail,
  set_server_error_detail,
};
use mogh_rate_limit::{RateLimiter, WithFailureRateLimit as _};

const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4));

/// A failing lookup, as a login fails with the database down.
async fn failing(status: StatusCode) -> mogh_error::Result<()> {
  Err(
    anyhow::anyhow!("connection refused (db.internal:27017)")
      .context("Failed to query users collection")
      .context("Failed to get user")
      .status_code(status),
  )
}

async fn body(error: mogh_error::Error) -> Serror {
  let bytes = axum::body::to_bytes(
    error.into_response().into_body(),
    usize::MAX,
  )
  .await
  .unwrap();
  mogh_error::try_deserialize_serror_bytes(&bytes).unwrap()
}

/// Runs a failing attempt through the best effort, then the strict
/// limiter (sharing one budget), returning both errors.
async fn attempts(
  limiter: &RateLimiter,
  status: StatusCode,
) -> [mogh_error::Error; 2] {
  let lax = failing(status)
    .with_failure_rate_limit_using_ip(limiter, &IP)
    .await
    .unwrap_err();
  let strict = failing(status)
    .with_strict_failure_rate_limit_using_ip(limiter, &IP)
    .await
    .unwrap_err();
  [lax, strict]
}

#[tokio::test]
async fn rate_limited_server_errors_follow_the_detail_setting() {
  // Full (the default): the causes are in the message too.
  let limiter = RateLimiter::new(false, 100, Duration::from_secs(60));
  for error in
    attempts(&limiter, StatusCode::INTERNAL_SERVER_ERROR).await
  {
    let message = error.error.to_string();
    assert!(message.contains("db.internal"), "{message}");
    let serror = body(error).await;
    assert!(serror.error.contains("db.internal"), "{serror:?}");
    assert!(!serror.trace.is_empty());
  }

  // Message: the response carries the message alone, which used
  // to be the whole flattened chain.
  set_server_error_detail(ServerErrorDetail::Message);
  let limiter = RateLimiter::new(false, 100, Duration::from_secs(60));
  let [lax, strict] =
    attempts(&limiter, StatusCode::INTERNAL_SERVER_ERROR).await;
  for (error, remaining) in [(lax, 99), (strict, 98)] {
    let expected = format!(
      "Failed to get user | You have {remaining} attempts remaining"
    );
    assert_eq!(error.error.to_string(), expected);
    // Still in the chain, for logs.
    assert!(format!("{:#}", error.error).contains("db.internal"));
    let serror = body(error).await;
    assert_eq!(serror.error, expected);
    assert!(serror.trace.is_empty(), "{serror:?}");
  }
  // Client errors keep their causes, which are meant for the
  // caller.
  for error in attempts(&limiter, StatusCode::UNAUTHORIZED).await {
    let serror = body(error).await;
    assert!(serror.error.contains("db.internal"), "{serror:?}");
  }

  // Generic: only the status reason.
  set_server_error_detail(ServerErrorDetail::Generic);
  for error in attempts(&limiter, StatusCode::BAD_GATEWAY).await {
    assert!(!error.error.to_string().contains("db.internal"));
    let serror = body(error).await;
    assert_eq!(serror.error, "Bad Gateway");
    assert!(serror.trace.is_empty(), "{serror:?}");
  }

  set_server_error_detail(ServerErrorDetail::Full);
}
