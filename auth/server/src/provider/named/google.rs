use anyhow::{Context, anyhow};
use mogh_auth_client::config::{
  NamedOauthConfig, TokenExchangeConfig,
};
use openidconnect::{
  ClientId, ClientSecret, EndpointMaybeSet, EndpointNotSet,
  EndpointSet, IssuerUrl, Nonce, RedirectUrl,
  core::{CoreIdTokenClaims, CoreProviderMetadata},
  reqwest as oidc_reqwest,
};

use crate::{
  provider::{
    REQUEST_TIMEOUT, named::STATE_LENGTH, oidc::http_client,
    token_exchange::TokenVerificationKeys,
  },
  rand::random_string,
};

type GoogleOidcClient = openidconnect::core::CoreClient<
  EndpointSet,
  EndpointNotSet,
  EndpointNotSet,
  EndpointNotSet,
  EndpointMaybeSet,
  EndpointMaybeSet,
>;

pub struct GoogleProvider {
  http_client: oidc_reqwest::Client,
  oidc_client: GoogleOidcClient,
  client_id: String,
  redirect_uri: String,
  scopes: String,
  /// To verify tokens presented for token exchange
  verification_keys: TokenVerificationKeys,
}

impl GoogleProvider {
  /// Initialize a new Google provider using Googles
  /// OpenID discovery endpoint, which includes the
  /// signing keys used to verify the ID token.
  pub async fn new(
    app_user_agent: &'static str,
    redirect_uri: String,
    NamedOauthConfig {
      enabled,
      client_id,
      client_secret,
    }: &NamedOauthConfig,
  ) -> anyhow::Result<GoogleProvider> {
    if !enabled {
      return Err(anyhow!("Google login is not enabled"));
    }
    if client_id.is_empty() {
      return Err(anyhow!(
        "Google login is enabled, but 'client_id' is not configured"
      ));
    }
    if client_secret.is_empty() {
      return Err(anyhow!(
        "Google login is enabled, but 'client_secret' is not configured"
      ));
    }

    let http_client = http_client(app_user_agent, REQUEST_TIMEOUT)
      .context("Failed to build Google HTTP client")?;

    let issuer_url =
      IssuerUrl::new("https://accounts.google.com".to_string())
        .context("Failed to initialize Google issuer url")?;

    let provider_metadata =
      CoreProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .context("Failed to discover Google OpenID configuration")?;

    Self::from_metadata(
      http_client,
      redirect_uri,
      client_id,
      client_secret,
      provider_metadata,
    )
  }

  /// Initialize the provider from already discovered metadata.
  fn from_metadata(
    http_client: oidc_reqwest::Client,
    redirect_uri: String,
    client_id: &str,
    client_secret: &str,
    provider_metadata: CoreProviderMetadata,
  ) -> anyhow::Result<GoogleProvider> {
    let scopes = urlencoding::encode(
      &[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
      ]
      .join(" "),
    )
    .to_string();

    let verification_keys =
      TokenVerificationKeys::from_metadata(&provider_metadata);

    let oidc_client =
      openidconnect::core::CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id.to_string()),
        Some(ClientSecret::new(client_secret.to_string())),
      )
      .set_redirect_uri(
        RedirectUrl::new(redirect_uri.clone())
          .context("Invalid Google redirect URI")?,
      );

    Ok(GoogleProvider {
      http_client,
      oidc_client,
      client_id: client_id.to_string(),
      redirect_uri,
      scopes,
      verification_keys,
    })
  }

  /// Verifies a Google ID token presented for RFC 8693 token exchange,
  /// which must be issued to the client id or one of the exchange audiences.
  pub fn verify_exchange_token(
    &self,
    exchange: &TokenExchangeConfig,
    token: &str,
  ) -> anyhow::Result<GoogleUser> {
    let mut audiences = vec![self.client_id.clone()];
    audiences.extend(exchange.audiences.iter().cloned());
    let claims = self
      .verification_keys
      .verify::<openidconnect::EmptyAdditionalClaims>(
      token,
      &audiences,
      &[],
      exchange.max_token_age_secs,
    )?;
    Ok(GoogleUser::from_claims(&claims))
  }

  /// Returns (state, nonce, login redirect url)
  pub fn get_state_and_login_redirect_url(
    &self,
  ) -> (String, Nonce, String) {
    let state = random_string(STATE_LENGTH);
    let nonce = Nonce::new(random_string(32));
    let redirect_url = format!(
      "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&state={}&nonce={}&client_id={}&redirect_uri={}&scope={}",
      urlencoding::encode(&state),
      urlencoding::encode(nonce.secret()),
      urlencoding::encode(&self.client_id),
      urlencoding::encode(&self.redirect_uri),
      self.scopes
    );
    (state, nonce, redirect_url)
  }

  pub async fn get_google_user(
    &self,
    code: String,
    nonce: String,
  ) -> anyhow::Result<GoogleUser> {
    let token_response = self
      .oidc_client
      .exchange_code(openidconnect::AuthorizationCode::new(code))?
      .request_async(&self.http_client)
      .await
      .context("Failed to exchange Google authorization code")?;

    let id_token = token_response
      .extra_fields()
      .id_token()
      .context("Google did not return an ID token")?;

    let verifier = self.oidc_client.id_token_verifier();
    let claims = id_token
      .claims(&verifier, &Nonce::new(nonce))
      .context("Failed to verify Google ID token")?;

    Ok(GoogleUser::from_claims(claims))
  }
}

pub struct GoogleUser {
  pub id: String,
  pub email: String,
  pub picture: String,
}

impl GoogleUser {
  fn from_claims(claims: &CoreIdTokenClaims) -> GoogleUser {
    GoogleUser {
      id: claims.subject().as_str().to_string(),
      email: claims
        .email()
        .map(|e| e.as_str().to_string())
        .unwrap_or_default(),
      picture: claims
        .picture()
        .and_then(|p| p.get(None))
        .map(|p| p.as_str().to_string())
        .unwrap_or_default(),
    }
  }
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use openidconnect::TokenUrl;

  use super::*;
  use crate::provider::{
    stalled_server, token_exchange::test_tokens::metadata,
  };

  /// A Google which accepts the connection but never answers
  /// fails the login, instead of leaving the callback hanging.
  #[tokio::test]
  async fn test_stalled_token_endpoint_fails_the_login() {
    let stalled = stalled_server().await;
    let provider = GoogleProvider::from_metadata(
      http_client("test", Duration::from_millis(200)).unwrap(),
      "https://app.example.com/auth/google/callback".to_string(),
      "client-id",
      "client-secret",
      metadata().set_token_endpoint(Some(
        TokenUrl::new(format!("{stalled}/token")).unwrap(),
      )),
    )
    .unwrap();
    let login = provider
      .get_google_user("code".to_string(), "nonce".to_string());
    let Err(err) =
      tokio::time::timeout(Duration::from_secs(10), login)
        .await
        .expect("the login must fail, not hang")
    else {
      panic!("a login without an answer must fail");
    };
    let message = format!("{err:#}");
    assert!(message.contains("timed out"), "{message}");
  }
}
