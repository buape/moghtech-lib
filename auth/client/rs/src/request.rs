use anyhow::{Context, anyhow};
use mogh_error::deserialize_error;
use mogh_resolver::HasResponse;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;

use crate::api::{
  login::MoghAuthLoginRequest, manage::MoghAuthManageRequest,
};

#[cfg(not(feature = "blocking"))]
pub async fn login<T>(
  reqwest: &reqwest::Client,
  address: &str,
  request: T,
) -> anyhow::Result<T::Response>
where
  T: Serialize + MoghAuthLoginRequest,
  T::Response: DeserializeOwned,
{
  post(reqwest, address, "/login", request_body(&request)).await
}

#[cfg(feature = "blocking")]
pub fn login<T>(
  reqwest: &reqwest::blocking::Client,
  address: &str,
  request: T,
) -> anyhow::Result<T::Response>
where
  T: Serialize + MoghAuthLoginRequest,
  T::Response: DeserializeOwned,
{
  post(reqwest, address, "/login", request_body(&request))
}

#[cfg(not(feature = "blocking"))]
pub async fn manage<T>(
  reqwest: &reqwest::Client,
  address: &str,
  request: T,
) -> anyhow::Result<T::Response>
where
  T: Serialize + MoghAuthManageRequest,
  T::Response: DeserializeOwned,
{
  post(reqwest, address, "/manage", request_body(&request)).await
}

#[cfg(feature = "blocking")]
pub fn manage<T>(
  reqwest: &reqwest::blocking::Client,
  address: &str,
  request: T,
) -> anyhow::Result<T::Response>
where
  T: Serialize + MoghAuthManageRequest,
  T::Response: DeserializeOwned,
{
  post(reqwest, address, "/manage", request_body(&request))
}

/// Builds the tagged request body expected by the auth server:
/// `{ "type": "<RequestType>", "params": <request> }`
fn request_body<T: Serialize + HasResponse>(
  request: &T,
) -> serde_json::Value {
  json!({
    "type": T::req_type(),
    "params": request
  })
}

/// Joins the server address and endpoint path,
/// tolerating a trailing slash on the address.
fn request_url(address: &str, endpoint: &str) -> String {
  format!("{}{endpoint}", address.trim_end_matches('/'))
}

/// Parses the response body, or converts it into
/// an error which retains the body contents.
fn parse_response<R: DeserializeOwned>(
  status: reqwest::StatusCode,
  body: String,
) -> anyhow::Result<R> {
  if status.is_success() {
    serde_json::from_str(&body).map_err(|e| {
      anyhow!("{e:#?}")
        .context(format!(
          "failed to deserialize response body: {body}"
        ))
        .context(status)
    })
  } else {
    Err(deserialize_error(body).context(status))
  }
}

#[cfg(not(feature = "blocking"))]
async fn post<B: Serialize, R: DeserializeOwned>(
  reqwest: &reqwest::Client,
  address: &str,
  endpoint: &str,
  body: B,
) -> anyhow::Result<R> {
  let res = reqwest
    .post(request_url(address, endpoint))
    .json(&body)
    .send()
    .await
    .context("failed to reach Mogh Auth API")?;
  let status = res.status();
  match res.text().await {
    Ok(body) => parse_response(status, body),
    Err(e) => Err(anyhow!("{e:?}").context(status)),
  }
}

#[cfg(feature = "blocking")]
fn post<B: Serialize, R: DeserializeOwned>(
  reqwest: &reqwest::blocking::Client,
  address: &str,
  endpoint: &str,
  body: B,
) -> anyhow::Result<R> {
  let res = reqwest
    .post(request_url(address, endpoint))
    .json(&body)
    .send()
    .context("failed to reach Mogh Auth API")?;
  let status = res.status();
  match res.text() {
    Ok(body) => parse_response(status, body),
    Err(e) => Err(anyhow!("{e:?}").context(status)),
  }
}

#[cfg(test)]
mod tests {
  use reqwest::StatusCode;
  use serde_json::json;

  use super::*;
  use crate::api::login::{
    GetLoginOptions, JwtResponse, LoginLocalUser,
  };
  use crate::api::manage::UpdateUsername;

  #[test]
  fn test_request_body_tags_type_and_params() {
    let body = request_body(&LoginLocalUser {
      username: "user".into(),
      password: "pass".into(),
    });
    assert_eq!(
      body,
      json!({
        "type": "LoginLocalUser",
        "params": {
          "username": "user",
          "password": "pass",
        }
      })
    );
  }

  #[test]
  fn test_request_body_empty_params() {
    let body = request_body(&GetLoginOptions {});
    assert_eq!(
      body,
      json!({
        "type": "GetLoginOptions",
        "params": {}
      })
    );
  }

  #[test]
  fn test_request_body_manage_request() {
    let body = request_body(&UpdateUsername {
      username: "new-name".into(),
    });
    assert_eq!(
      body,
      json!({
        "type": "UpdateUsername",
        "params": { "username": "new-name" }
      })
    );
  }

  #[test]
  fn test_request_url() {
    assert_eq!(
      request_url("http://localhost:9120", "/login"),
      "http://localhost:9120/login"
    );
    // A trailing slash on the address must not
    // produce a double slash in the url.
    assert_eq!(
      request_url("http://localhost:9120/", "/manage"),
      "http://localhost:9120/manage"
    );
  }

  #[test]
  fn test_parse_response_success() {
    let res: JwtResponse =
      parse_response(StatusCode::OK, r#"{"jwt":"abc123"}"#.into())
        .unwrap();
    assert_eq!(res.jwt, "abc123");
  }

  #[test]
  fn test_parse_response_success_status_bad_body_keeps_body() {
    let err = parse_response::<JwtResponse>(
      StatusCode::OK,
      "unexpected html".into(),
    )
    .unwrap_err();
    // The error must retain the unparseable body for debugging.
    assert!(format!("{err:#}").contains("unexpected html"));
  }

  #[test]
  fn test_parse_response_error_status_keeps_body() {
    let err = parse_response::<JwtResponse>(
      StatusCode::UNAUTHORIZED,
      r#"{"error":"invalid token"}"#.into(),
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("invalid token"));
    assert!(msg.contains("401"));
  }
}
