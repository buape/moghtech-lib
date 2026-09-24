//! The server error detail setting is process wide, so it is tested
//! in its own test binary, in one test, to keep other tests from
//! seeing it change.
#![allow(unused_crate_dependencies)]
#![cfg(feature = "axum")]

use axum::response::IntoResponse as _;
use mogh_error::{
  HiddenServerError, Serror, ServerErrorDetail, StatusCode,
  server_error_detail, set_server_error_detail,
};

/// The response bodies here are fully buffered,
/// so they resolve without a runtime.
fn block_on<F: Future>(fut: F) -> F::Output {
  let mut fut = std::pin::pin!(fut);
  let waker = std::task::Waker::noop();
  let mut cx = std::task::Context::from_waker(waker);
  loop {
    match fut.as_mut().poll(&mut cx) {
      std::task::Poll::Ready(value) => return value,
      std::task::Poll::Pending => std::thread::yield_now(),
    }
  }
}

/// Returns the body and whether the full error was attached
/// as a [HiddenServerError] extension.
fn respond(status: StatusCode) -> (Serror, bool) {
  let error: mogh_error::Error =
    anyhow::anyhow!("connection refused (db.internal:5432)")
      .context("Failed to query users")
      .into();
  let response = error.status_code(status).into_response();
  let hidden =
    response.extensions().get::<HiddenServerError>().is_some();
  let bytes =
    block_on(axum::body::to_bytes(response.into_body(), usize::MAX))
      .unwrap();
  (serde_json::from_slice(&bytes).unwrap(), hidden)
}

#[test]
fn set_server_error_detail_applies_to_server_errors() {
  // Default sends everything
  assert_eq!(server_error_detail(), ServerErrorDetail::Full);
  let (serror, hidden) = respond(StatusCode::INTERNAL_SERVER_ERROR);
  assert_eq!(serror.error, "Failed to query users");
  assert_eq!(
    serror.trace,
    vec!["connection refused (db.internal:5432)"]
  );
  assert!(!hidden);

  set_server_error_detail(ServerErrorDetail::Message);
  assert_eq!(server_error_detail(), ServerErrorDetail::Message);
  let (serror, hidden) = respond(StatusCode::INTERNAL_SERVER_ERROR);
  assert_eq!(serror.error, "Failed to query users");
  assert!(serror.trace.is_empty());
  assert!(hidden);

  set_server_error_detail(ServerErrorDetail::Generic);
  assert_eq!(server_error_detail(), ServerErrorDetail::Generic);
  let (serror, hidden) = respond(StatusCode::BAD_GATEWAY);
  assert_eq!(serror.error, "Bad Gateway");
  assert!(serror.trace.is_empty());
  assert!(hidden);

  // Client errors keep their details
  let (serror, hidden) = respond(StatusCode::NOT_FOUND);
  assert_eq!(serror.error, "Failed to query users");
  assert_eq!(serror.trace.len(), 1);
  assert!(!hidden);

  set_server_error_detail(ServerErrorDetail::Full);
  let (serror, hidden) = respond(StatusCode::INTERNAL_SERVER_ERROR);
  assert_eq!(serror.trace.len(), 1);
  assert!(!hidden);
}
