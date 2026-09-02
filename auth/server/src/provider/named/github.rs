use std::sync::OnceLock;

use anyhow::Context;
use mogh_auth_client::config::NamedOauthConfig;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::warn;

use crate::{
  provider::named::{STATE_PREFIX_LENGTH, handle_response},
  rand::random_string,
};

pub fn github_provider(
  host: &str,
  path: &str,
  config: &NamedOauthConfig,
) -> Option<&'static GithubProvider> {
  static GITHUB_PROVIDER: OnceLock<Option<GithubProvider>> =
    OnceLock::new();
  GITHUB_PROVIDER
    .get_or_init(|| GithubProvider::new(host, path, config))
    .as_ref()
}

pub struct GithubProvider {
  http: reqwest::Client,
  client_id: String,
  client_secret: String,
  redirect_uri: String,
  scopes: String,
  user_agent: String,
}

impl GithubProvider {
  pub fn new(
    host: &str,
    path: &str,
    NamedOauthConfig {
      enabled,
      client_id,
      client_secret,
    }: &NamedOauthConfig,
  ) -> Option<GithubProvider> {
    if !enabled {
      return None;
    }
    if host.is_empty() {
      warn!("Github oauth is enabled, but 'host' is not configured");
      return None;
    }
    if client_id.is_empty() {
      warn!(
        "Github oauth is enabled, but 'github_oauth.client_id' is not configured"
      );
      return None;
    }
    if client_secret.is_empty() {
      warn!(
        "Github oauth is enabled, but 'github_oauth.client_secret' is not configured"
      );
      return None;
    }
    GithubProvider {
      http: reqwest::Client::new(),
      client_id: client_id.clone(),
      client_secret: client_secret.clone(),
      redirect_uri: format!("{host}{path}/github/callback"),
      // The Github API rejects requests without a User-Agent header.
      user_agent: concat!(
        env!("CARGO_PKG_NAME"),
        "/",
        env!("CARGO_PKG_VERSION")
      )
      .to_string(),
      scopes: Default::default(),
    }
    .into()
  }

  pub async fn get_state_and_login_redirect_url(
    &self,
    redirect: Option<String>,
  ) -> (String, String) {
    let state_prefix = random_string(STATE_PREFIX_LENGTH);
    let state = match redirect {
      Some(redirect) => state_prefix + &redirect,
      None => state_prefix,
    };
    let redirect_url = format!(
      "https://github.com/login/oauth/authorize?state={}&client_id={}&redirect_uri={}&scope={}",
      urlencoding::encode(&state),
      self.client_id,
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

  fn test_provider() -> GithubProvider {
    GithubProvider::new(
      "https://example.com",
      "/auth",
      &NamedOauthConfig {
        enabled: true,
        client_id: "test-client-id".to_string(),
        client_secret: "test-client-secret".to_string(),
      },
    )
    .unwrap()
  }

  #[test]
  fn test_provider_disabled_or_misconfigured_returns_none() {
    let config = NamedOauthConfig {
      enabled: false,
      client_id: "id".to_string(),
      client_secret: "secret".to_string(),
    };
    assert!(
      GithubProvider::new("https://example.com", "/auth", &config)
        .is_none()
    );
    let config = NamedOauthConfig {
      enabled: true,
      client_id: String::new(),
      client_secret: "secret".to_string(),
    };
    assert!(
      GithubProvider::new("https://example.com", "/auth", &config)
        .is_none()
    );
    let config = NamedOauthConfig {
      enabled: true,
      client_id: "id".to_string(),
      client_secret: String::new(),
    };
    assert!(
      GithubProvider::new("https://example.com", "/auth", &config)
        .is_none()
    );
    let config = NamedOauthConfig {
      enabled: true,
      client_id: "id".to_string(),
      client_secret: "secret".to_string(),
    };
    assert!(GithubProvider::new("", "/auth", &config).is_none());
  }

  #[tokio::test]
  async fn test_state_without_redirect() {
    let provider = test_provider();
    let (state, url) =
      provider.get_state_and_login_redirect_url(None).await;
    assert_eq!(state.len(), STATE_PREFIX_LENGTH);
    assert!(state.chars().all(|c| c.is_ascii_alphanumeric()));
    assert!(
      url.starts_with("https://github.com/login/oauth/authorize?")
    );
    assert!(url.contains(&format!("state={state}")));
    assert!(url.contains("client_id=test-client-id"));
    // Redirect uri is urlencoded and derived from host + path.
    assert!(
      url.contains(
        urlencoding::encode(
          "https://example.com/auth/github/callback"
        )
        .as_ref()
      )
    );
    // The client secret must never appear in the user-facing URL.
    assert!(!url.contains("test-client-secret"));
  }

  #[tokio::test]
  async fn test_state_embeds_redirect_and_is_recoverable() {
    let provider = test_provider();
    let redirect = "https://example.com/dest?a=1&b=2";
    let (state, url) = provider
      .get_state_and_login_redirect_url(Some(redirect.to_string()))
      .await;
    // Random prefix + raw redirect suffix
    assert_eq!(state.len(), STATE_PREFIX_LENGTH + redirect.len());
    assert_eq!(&state[STATE_PREFIX_LENGTH..], redirect);
    // The state must be urlencoded in the authorize URL so the
    // redirect cannot inject additional query parameters.
    assert!(
      url.contains(&format!("state={}", urlencoding::encode(&state)))
    );
    assert!(!url.contains("&b=2"));
  }

  #[tokio::test]
  async fn test_state_prefixes_are_unique() {
    let provider = test_provider();
    let (state_a, _) =
      provider.get_state_and_login_redirect_url(None).await;
    let (state_b, _) =
      provider.get_state_and_login_redirect_url(None).await;
    assert_ne!(state_a, state_b);
  }
}
