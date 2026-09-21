use anyhow::{Context, anyhow};
use mogh_auth_client::config::NamedOauthConfig;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::{
  provider::named::{STATE_LENGTH, handle_response},
  rand::random_string,
};

pub struct GithubProvider {
  http: reqwest::Client,
  client_id: String,
  /// Wiped from memory when the provider is dropped,
  /// eg. after its configuration is updated or deleted.
  client_secret: Zeroizing<String>,
  redirect_uri: String,
  scopes: String,
  user_agent: String,
}

impl GithubProvider {
  pub fn new(
    redirect_uri: String,
    NamedOauthConfig {
      enabled,
      client_id,
      client_secret,
    }: &NamedOauthConfig,
  ) -> anyhow::Result<GithubProvider> {
    if !enabled {
      return Err(anyhow!("Github login is not enabled"));
    }
    if client_id.is_empty() {
      return Err(anyhow!(
        "Github login is enabled, but 'client_id' is not configured"
      ));
    }
    if client_secret.is_empty() {
      return Err(anyhow!(
        "Github login is enabled, but 'client_secret' is not configured"
      ));
    }
    Ok(GithubProvider {
      http: reqwest::Client::new(),
      client_id: client_id.clone(),
      client_secret: Zeroizing::new(client_secret.clone()),
      redirect_uri,
      // The Github API rejects requests without a User-Agent header.
      user_agent: concat!(
        env!("CARGO_PKG_NAME"),
        "/",
        env!("CARGO_PKG_VERSION")
      )
      .to_string(),
      scopes: Default::default(),
    })
  }

  /// Returns (state, login redirect url)
  pub fn get_state_and_login_redirect_url(&self) -> (String, String) {
    let state = random_string(STATE_LENGTH);
    let redirect_url = format!(
      "https://github.com/login/oauth/authorize?state={}&client_id={}&redirect_uri={}&scope={}",
      urlencoding::encode(&state),
      urlencoding::encode(&self.client_id),
      urlencoding::encode(&self.redirect_uri),
      self.scopes
    );
    (state, redirect_url)
  }

  pub async fn get_access_token(
    &self,
    code: &str,
  ) -> anyhow::Result<AccessTokenResponse> {
    self
      .post::<(), _>(
        "https://github.com/login/oauth/access_token",
        &[
          ("client_id", self.client_id.as_str()),
          ("client_secret", self.client_secret.as_str()),
          ("redirect_uri", self.redirect_uri.as_str()),
          ("code", code),
        ],
        None,
        None,
      )
      .await
      .context("failed to get github access token using code")
  }

  pub async fn get_github_user(
    &self,
    token: &str,
  ) -> anyhow::Result<GithubUserResponse> {
    self
      .get("https://api.github.com/user", &[], Some(token))
      .await
      .context("failed to get github user using access token")
  }

  async fn get<R: DeserializeOwned>(
    &self,
    endpoint: &str,
    query: &[(&str, &str)],
    bearer_token: Option<&str>,
  ) -> anyhow::Result<R> {
    let mut req = self
      .http
      .get(endpoint)
      .query(query)
      .header("User-Agent", &self.user_agent);

    if let Some(bearer_token) = bearer_token {
      req =
        req.header("Authorization", format!("Bearer {bearer_token}"));
    }

    let res = req.send().await.context("failed to reach github")?;

    handle_response(res).await
  }

  async fn post<B: Serialize, R: DeserializeOwned>(
    &self,
    endpoint: &str,
    query: &[(&str, &str)],
    body: Option<&B>,
    bearer_token: Option<&str>,
  ) -> anyhow::Result<R> {
    let mut req = self
      .http
      .post(endpoint)
      .query(query)
      .header("Accept", "application/json")
      .header("User-Agent", &self.user_agent);

    if let Some(body) = body {
      req = req.json(body);
    }

    if let Some(bearer_token) = bearer_token {
      req =
        req.header("Authorization", format!("Bearer {bearer_token}"));
    }

    let res = req.send().await.context("Failed to reach Github")?;

    handle_response(res).await
  }
}

#[derive(Deserialize)]
pub struct AccessTokenResponse {
  pub access_token: String,
  // pub scope: String,
  // pub token_type: String,
}

#[derive(Deserialize)]
pub struct GithubUserResponse {
  pub login: String,
  pub id: u128,
  pub avatar_url: String,
  // pub email: Option<String>,
}

#[cfg(test)]
mod tests {
  use super::*;

  const REDIRECT_URI: &str =
    "https://example.com/auth/external/abc/callback";

  fn config(
    enabled: bool,
    client_id: &str,
    client_secret: &str,
  ) -> NamedOauthConfig {
    NamedOauthConfig {
      enabled,
      client_id: client_id.to_string(),
      client_secret: client_secret.to_string(),
    }
  }

  fn test_provider() -> GithubProvider {
    GithubProvider::new(
      REDIRECT_URI.to_string(),
      &config(true, "test-client-id", "test-client-secret"),
    )
    .unwrap()
  }

  #[test]
  fn test_provider_disabled_or_misconfigured_errors() {
    for config in [
      config(false, "id", "secret"),
      config(true, "", "secret"),
      config(true, "id", ""),
    ] {
      assert!(
        GithubProvider::new(REDIRECT_URI.to_string(), &config)
          .is_err()
      );
    }
  }

  #[test]
  fn test_state_and_login_redirect_url() {
    let provider = test_provider();
    let (state, url) = provider.get_state_and_login_redirect_url();
    assert_eq!(state.len(), STATE_LENGTH);
    assert!(state.chars().all(|c| c.is_ascii_alphanumeric()));
    assert!(
      url.starts_with("https://github.com/login/oauth/authorize?")
    );
    assert!(url.contains(&format!("state={state}")));
    assert!(url.contains("client_id=test-client-id"));
    // Redirect uri is urlencoded.
    assert!(url.contains(urlencoding::encode(REDIRECT_URI).as_ref()));
    // The client secret must never appear in the user-facing URL.
    assert!(!url.contains("test-client-secret"));
  }

  #[test]
  fn test_client_id_cannot_inject_query_params() {
    let provider = GithubProvider::new(
      REDIRECT_URI.to_string(),
      &config(true, "id&redirect_uri=https://evil", "secret"),
    )
    .unwrap();
    let (_, url) = provider.get_state_and_login_redirect_url();
    assert!(!url.contains("&redirect_uri=https://evil"));
  }

  #[test]
  fn test_states_are_unique() {
    let provider = test_provider();
    let (state_a, _) = provider.get_state_and_login_redirect_url();
    let (state_b, _) = provider.get_state_and_login_redirect_url();
    assert_ne!(state_a, state_b);
  }
}
