//! # Example Client
//!
//! API types and a client for the Mogh example app.

use anyhow::{Context as _, anyhow};
use mogh_auth_client::{
  api::{login::MoghAuthLoginRequest, manage::MoghAuthManageRequest},
  signature::signed_request_headers,
};

pub use mogh_auth_client::signature::sign_request;
use mogh_error::deserialize_error;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use typeshare::typeshare;

pub mod api;
pub mod entities;

pub use mogh_auth_client as auth;

use crate::api::{
  execute::ExampleExecuteRequest, read::ExampleReadRequest,
  write::ExampleWriteRequest,
};

#[typeshare(serialized_as = "number")]
pub type I64 = i64;

/// How the client authenticates its requests.
#[derive(Clone)]
pub enum ClientAuth {
  /// No credentials, only the login api can be used.
  None,
  /// `Authorization: Bearer <jwt>`
  Jwt(String),
  /// `X-API-KEY` / `X-API-SECRET`
  ApiKey { key: String, secret: String },
  /// `X-API-SIGNATURE` / `X-API-TIMESTAMP`, signed with
  /// the private key for the server public key.
  PrivateKey {
    private_key: String,
    server_public_key: String,
  },
}

#[derive(Clone)]
pub struct ExampleClient {
  /// Keeps cookies, login flows using
  /// multiple requests depend on the session.
  pub reqwest: reqwest::Client,
  pub address: String,
  pub auth: ClientAuth,
  /// Added to every request.
  pub headers: reqwest::header::HeaderMap,
}

impl ExampleClient {
  pub fn new(
    address: impl Into<String>,
    auth: ClientAuth,
  ) -> anyhow::Result<ExampleClient> {
    let reqwest = reqwest::Client::builder()
      .cookie_store(true)
      .redirect(reqwest::redirect::Policy::none())
      .build()
      .context("Failed to build reqwest client")?;
    Ok(ExampleClient {
      reqwest,
      address: address.into().trim_end_matches('/').to_string(),
      auth,
      headers: Default::default(),
    })
  }

  /// The same client (and session) sending an additional header.
  pub fn with_header(
    &self,
    name: &'static str,
    value: &str,
  ) -> anyhow::Result<ExampleClient> {
    let mut client = self.clone();
    client
      .headers
      .insert(name, value.parse().context("Invalid header value")?);
    Ok(client)
  }

  /// The same client (and session) with other credentials.
  pub fn with_auth(&self, auth: ClientAuth) -> ExampleClient {
    ExampleClient {
      reqwest: self.reqwest.clone(),
      address: self.address.clone(),
      auth,
      headers: self.headers.clone(),
    }
  }

  pub fn auth_address(&self) -> String {
    format!("{}/auth", self.address)
  }

  pub async fn read<T>(
    &self,
    request: T,
  ) -> anyhow::Result<T::Response>
  where
    T: Serialize + ExampleReadRequest,
    T::Response: DeserializeOwned,
  {
    self.post("/read", T::req_type(), &request).await
  }

  pub async fn write<T>(
    &self,
    request: T,
  ) -> anyhow::Result<T::Response>
  where
    T: Serialize + ExampleWriteRequest,
    T::Response: DeserializeOwned,
  {
    self.post("/write", T::req_type(), &request).await
  }

  pub async fn execute<T>(
    &self,
    request: T,
  ) -> anyhow::Result<T::Response>
  where
    T: Serialize + ExampleExecuteRequest,
    T::Response: DeserializeOwned,
  {
    self.post("/execute", T::req_type(), &request).await
  }

  /// The unauthenticated auth login api.
  pub async fn login<T>(
    &self,
    request: T,
  ) -> anyhow::Result<T::Response>
  where
    T: Serialize + MoghAuthLoginRequest,
    T::Response: DeserializeOwned,
  {
    self.post("/auth/login", T::req_type(), &request).await
  }

  /// The authenticated auth management api.
  pub async fn manage<T>(
    &self,
    request: T,
  ) -> anyhow::Result<T::Response>
  where
    T: Serialize + MoghAuthManageRequest,
    T::Response: DeserializeOwned,
  {
    self.post("/auth/manage", T::req_type(), &request).await
  }

  /// Adds the credential headers for a request to `path`.
  pub fn authenticate(
    &self,
    method: &reqwest::Method,
    path: &str,
    request: reqwest::RequestBuilder,
  ) -> anyhow::Result<reqwest::RequestBuilder> {
    let request = request.headers(self.headers.clone());
    let request = match &self.auth {
      ClientAuth::None => request,
      ClientAuth::Jwt(jwt) => {
        request.header("authorization", format!("Bearer {jwt}"))
      }
      ClientAuth::ApiKey { key, secret } => request
        .header("x-api-key", key)
        .header("x-api-secret", secret),
      ClientAuth::PrivateKey {
        private_key,
        server_public_key,
      } => {
        let mut request = request;
        for (header, value) in signed_request_headers(
          private_key,
          server_public_key,
          method.as_str(),
          path,
        )? {
          request = request.header(header, value);
        }
        request
      }
    };
    Ok(request)
  }

  async fn post<B: Serialize, R: DeserializeOwned>(
    &self,
    path: &str,
    req_type: &str,
    params: &B,
  ) -> anyhow::Result<R> {
    let request = self
      .reqwest
      .post(format!("{}{path}", self.address))
      .json(&json!({ "type": req_type, "params": params }));
    let res = self
      .authenticate(&reqwest::Method::POST, path, request)?
      .send()
      .await
      .context("Failed to reach Example API")?;
    let status = res.status();
    let body = res
      .text()
      .await
      .map_err(|e| anyhow!("{e:?}").context(status))?;
    if status.is_success() {
      serde_json::from_str(&body).map_err(|e| {
        anyhow!("{e:#?}")
          .context(format!(
            "Failed to deserialize response body: {body}"
          ))
          .context(status)
      })
    } else {
      Err(deserialize_error(body).context(status))
    }
  }
}

/// The http status an error returned by [ExampleClient] carries.
pub fn error_status(
  e: &anyhow::Error,
) -> Option<reqwest::StatusCode> {
  e.downcast_ref::<reqwest::StatusCode>().copied()
}
