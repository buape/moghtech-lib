//! Calling the auth api with [reqwest].
//!
//! The functions here are async and take a [reqwest::Client]. The
//! `blocking` feature adds the same functions for a
//! `reqwest::blocking::Client` in `request::blocking`.
//!
//! `address` is where the auth api is mounted, eg.
//! `https://example.com/auth`. The requests carry no credentials:
//! [manage] needs them added to the client's default headers.
//!
//! That only works for a jwt (`Authorization: Bearer <jwt>`) or an api
//! key (`X-API-KEY` / `X-API-SECRET`). A request with a signing key
//! is signed on its own, with `signature::signed_request_headers`
//! (`pki` feature) over its exact path, query and body, so [manage]
//! can't send it: send `POST {address}/manage` yourself, with the
//! JSON body `{"type": "<request>", "params": <request>}` and the
//! headers signed for it.

use anyhow::{Context, anyhow};
use mogh_error::deserialize_error;
use mogh_resolver::HasResponse;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;

use crate::api::{
  login::MoghAuthLoginRequest,
  manage::MoghAuthManageRequest,
  token::{
    TokenExchangeError, TokenExchangeRequest, TokenExchangeResponse,
  },
};

/// Call the unauthenticated login api.
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

/// Call the authenticated management api.
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

/// RFC 8693 Token Exchange: exchange a token issued by an external
/// login provider for an app token at the `/token` endpoint.
pub async fn token_exchange(
  reqwest: &reqwest::Client,
  address: &str,
  request: &TokenExchangeRequest,
) -> anyhow::Result<TokenExchangeResponse> {
  let res = reqwest
    .post(request_url(address, "/token"))
    .form(request)
    .send()
    .await
    .context("failed to reach Mogh Auth API")?;
  let status = res.status();
  match res.text().await {
    Ok(body) => parse_token_response(status, body),
    Err(e) => Err(anyhow!("{e:?}").context(status)),
  }
}

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

/// The request functions for a [reqwest::blocking::Client],
/// with the same names and behavior as the async ones.
#[cfg(feature = "blocking")]
pub mod blocking {
  use anyhow::{Context, anyhow};
  use serde::{Serialize, de::DeserializeOwned};

  use crate::api::{
    login::MoghAuthLoginRequest,
    manage::MoghAuthManageRequest,
    token::{TokenExchangeRequest, TokenExchangeResponse},
  };

  use super::{
    parse_response, parse_token_response, request_body, request_url,
  };

  /// Call the unauthenticated login api.
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

  /// Call the authenticated management api.
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

  /// RFC 8693 Token Exchange: exchange a token issued by an external
  /// login provider for an app token at the `/token` endpoint.
  pub fn token_exchange(
    reqwest: &reqwest::blocking::Client,
    address: &str,
    request: &TokenExchangeRequest,
  ) -> anyhow::Result<TokenExchangeResponse> {
    let res = reqwest
      .post(request_url(address, "/token"))
      .form(request)
      .send()
      .context("failed to reach Mogh Auth API")?;
    let status = res.status();
    match res.text() {
      Ok(body) => parse_token_response(status, body),
      Err(e) => Err(anyhow!("{e:?}").context(status)),
    }
  }

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
}

/// The token endpoint uses the OAuth error format,
/// the returned error can be downcast to [TokenExchangeError].
///
/// A successful response which fails to parse is not included
/// in the error, it carries the app token.
fn parse_token_response(
  status: reqwest::StatusCode,
  body: String,
) -> anyhow::Result<TokenExchangeResponse> {
  if status.is_success() {
    return serde_json::from_str(&body).map_err(|e| {
      success_body_error(&e, &body)
        .context("failed to deserialize token response")
        .context(status)
    });
  }
  match serde_json::from_str::<TokenExchangeError>(&body) {
    Ok(error) => Err(anyhow::Error::new(error).context(status)),
    Err(_) => Err(anyhow!("{body}").context(status)),
  }
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

/// Parses the response body, or converts it into an error.
///
/// An error status keeps the body (the error message). A successful
/// response carries credentials (a JWT, an api key secret, recovery
/// codes), so when it fails to parse, the error only keeps the body
/// if it isn't json, eg. an html page from a proxy.
fn parse_response<R: DeserializeOwned>(
  status: reqwest::StatusCode,
  body: String,
) -> anyhow::Result<R> {
  if status.is_success() {
    serde_json::from_str(&body).map_err(|e| {
      success_body_error(&e, &body)
        .context("failed to deserialize response body")
        .context(status)
    })
  } else {
    Err(deserialize_error(body).context(status))
  }
}

/// How much of a successful non json body the error keeps.
const BODY_PREVIEW_CHARS: usize = 200;

/// The error for a successful response body which failed to parse,
/// without any of the values it contains. The serde error message
/// quotes values (`invalid type: string "..."`), so they are redacted.
/// A body which doesn't look like json is kept up to
/// [BODY_PREVIEW_CHARS] characters.
fn success_body_error(
  e: &serde_json::Error,
  body: &str,
) -> anyhow::Error {
  let message = redact_serde_message(&e.to_string());
  let trimmed = body.trim_start();
  if trimmed.is_empty()
    || trimmed.starts_with(['{', '[', '"'])
    || matches!(e.classify(), serde_json::error::Category::Data)
  {
    return anyhow!("{message} ({} bytes)", body.len());
  }
  let preview = match body.char_indices().nth(BODY_PREVIEW_CHARS) {
    Some((end, _)) => format!("{}...", &body[..end]),
    None => body.to_string(),
  };
  anyhow!("{message} | body: {preview}")
}

/// Replaces the quoted parts of a serde error message, which can be
/// values of the input: strings in double quotes, other values in
/// backticks. The field of a `missing field` error is kept, it comes
/// from the type.
fn redact_serde_message(message: &str) -> String {
  let mut out = String::with_capacity(message.len());
  let mut rest = message;
  // Both quotes are ascii, so `quoted[1..]` is on a char boundary.
  while let Some(start) = rest.find(['"', '`']) {
    let (before, quoted) = rest.split_at(start);
    let quote = if quoted.starts_with('"') { '"' } else { '`' };
    out.push_str(before);
    // The closing quote, skipping escaped characters in strings.
    let mut escaped = false;
    let end = quoted[1..].char_indices().find_map(|(i, c)| {
      if escaped {
        escaped = false;
      } else if c == '\\' && quote == '"' {
        escaped = true;
      } else if c == quote {
        return Some(i + 2);
      }
      None
    });
    let Some(end) = end else {
      // Unterminated, redact the rest.
      out.push_str("[redacted]");
      return out;
    };
    if quote == '`' && before.ends_with("missing field ") {
      out.push_str(&quoted[..end]);
    } else {
      out.push_str("[redacted]");
    }
    rest = &quoted[end..];
  }
  out.push_str(rest);
  out
}

#[cfg(test)]
mod tests {
  use reqwest::StatusCode;
  use serde_json::json;

  use super::*;
  use crate::api::login::{
    GetLoginOptions, JwtOrTwoFactor, JwtResponse, LoginLocalUser,
  };
  use crate::api::manage::{
    ConfirmTotpEnrollmentResponse, CreateApiKeyResponse,
    UpdateUsername,
  };

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
    // The error keeps a body which isn't json for debugging,
    // eg. the html page of a proxy.
    let msg = format!("{err:#}");
    assert!(msg.contains("unexpected html"), "{msg}");
    assert!(msg.contains("200"), "{msg}");
    // Truncated
    let err = parse_response::<JwtResponse>(
      StatusCode::OK,
      format!("<html>{}", "é".repeat(1000)),
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("<html>"), "{msg}");
    assert!(msg.len() < 800, "{msg}");
  }

  #[test]
  fn test_parse_response_success_status_json_body_is_not_kept() {
    // A 200 with credentials the client can't parse, eg. after a
    // server update changed the response.
    let err = parse_response::<CreateApiKeyResponse>(
      StatusCode::OK,
      r#"{"result":{"key":"K_abc_K","secret":"S_s3cr3t_S"}}"#.into(),
    )
    .unwrap_err();
    for msg in [format!("{err:#}"), format!("{err:?}")] {
      assert!(!msg.contains("s3cr3t"), "{msg}");
      assert!(!msg.contains("K_abc_K"), "{msg}");
      assert!(msg.contains("200"), "{msg}");
      // The missing field helps to debug the mismatch.
      assert!(msg.contains("missing field `key`"), "{msg}");
    }

    // The serde error quotes a scalar of the wrong type
    // (invalid type: integer `1234567`, expected a string).
    let err = parse_response::<JwtResponse>(
      StatusCode::OK,
      r#"{"jwt":1234567}"#.into(),
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(!msg.contains("1234567"), "{msg}");
    assert!(msg.contains("invalid type"), "{msg}");
    let err = parse_response::<ConfirmTotpEnrollmentResponse>(
      StatusCode::OK,
      r#"{"recovery_codes":"code-1,code-2"}"#.into(),
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(!msg.contains("code-1"), "{msg}");
    assert!(msg.contains("invalid type"), "{msg}");

    // Truncated json isn't kept either.
    let err = parse_response::<JwtOrTwoFactor>(
      StatusCode::OK,
      r#"{"type":"Jwt","data":{"jwt":"secret.app.jw"#.into(),
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(!msg.contains("secret.app"), "{msg}");
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

  #[test]
  fn test_redact_serde_message() {
    assert_eq!(
      redact_serde_message(
        r#"invalid type: string "a \"quoted\" secret", expected u64 at line 1 column 3"#
      ),
      "invalid type: string [redacted], expected u64 at line 1 column 3"
    );
    assert_eq!(
      redact_serde_message(
        "invalid value: integer `123`, expected x"
      ),
      "invalid value: integer [redacted], expected x"
    );
    assert_eq!(
      redact_serde_message(
        "unknown variant `secret`, expected `Jwt`"
      ),
      "unknown variant [redacted], expected [redacted]"
    );
    assert_eq!(
      redact_serde_message("missing field `jwt` at line 1 column 2"),
      "missing field `jwt` at line 1 column 2"
    );
    assert_eq!(
      redact_serde_message(r#"unterminated "secret"#),
      "unterminated [redacted]"
    );
    assert_eq!(redact_serde_message("no quotes"), "no quotes");
  }

  #[test]
  fn test_parse_token_response_error_is_downcastable() {
    let err = parse_token_response(
      reqwest::StatusCode::BAD_REQUEST,
      r#"{"error":"invalid_grant","error_description":"expired"}"#
        .to_string(),
    )
    .unwrap_err();
    let error = err.downcast_ref::<TokenExchangeError>().unwrap();
    assert_eq!(error.error, "invalid_grant");
    assert_eq!(error.error_description.as_deref(), Some("expired"));
    assert!(
      parse_token_response(
        reqwest::StatusCode::OK,
        "not json".to_string()
      )
      .is_err()
    );
  }

  #[test]
  fn test_parse_token_response_success_status_bad_body() {
    // Does not include the successful response on a parse failure
    let err = parse_token_response(
      reqwest::StatusCode::OK,
      r#"{"access_token":"secret.app.jwt","expires_in":"soon"}"#
        .to_string(),
    )
    .unwrap_err();
    for msg in [format!("{err:#}"), format!("{err:?}")] {
      assert!(!msg.contains("secret.app.jwt"), "{msg}");
      assert!(!msg.contains("soon"), "{msg}");
      assert!(msg.contains("200"), "{msg}");
    }
  }

  #[test]
  fn test_parse_token_response_success() {
    let response = parse_token_response(
      reqwest::StatusCode::OK,
      r#"{"access_token":"jwt","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}"#.to_string(),
    )
    .unwrap();
    assert_eq!(response.access_token, "jwt");
    assert_eq!(response.expires_in, 3600);
  }

  /// The async functions exist next to the blocking ones, so a
  /// build enabling `blocking` for one crate doesn't break another
  /// using the async functions.
  #[cfg(feature = "blocking")]
  #[allow(unused)]
  fn test_blocking_is_additive() {
    async fn login_async(
      client: &reqwest::Client,
    ) -> anyhow::Result<crate::api::login::GetLoginOptionsResponse>
    {
      login(client, "http://localhost", GetLoginOptions {}).await
    }
    fn login_blocking(
      client: &reqwest::blocking::Client,
    ) -> anyhow::Result<crate::api::login::GetLoginOptionsResponse>
    {
      blocking::login(client, "http://localhost", GetLoginOptions {})
    }
    async fn token_async(
      client: &reqwest::Client,
    ) -> anyhow::Result<TokenExchangeResponse> {
      token_exchange(
        client,
        "http://localhost",
        &TokenExchangeRequest::id_token("t"),
      )
      .await
    }
    fn token_blocking(
      client: &reqwest::blocking::Client,
    ) -> anyhow::Result<TokenExchangeResponse> {
      blocking::token_exchange(
        client,
        "http://localhost",
        &TokenExchangeRequest::id_token("t"),
      )
    }
  }
}
