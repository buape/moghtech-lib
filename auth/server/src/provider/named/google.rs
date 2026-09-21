use anyhow::{Context, anyhow};
use mogh_auth_client::config::NamedOauthConfig;
use openidconnect::{
  ClientId, ClientSecret, EndpointMaybeSet, EndpointNotSet,
  EndpointSet, IssuerUrl, Nonce, RedirectUrl,
  core::CoreProviderMetadata, reqwest as oidc_reqwest,
};

use crate::{provider::named::STATE_LENGTH, rand::random_string};

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

    let scopes = urlencoding::encode(
      &[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
      ]
      .join(" "),
    )
    .to_string();

    let http_client = oidc_reqwest::ClientBuilder::new()
      .redirect(oidc_reqwest::redirect::Policy::none())
      .user_agent(app_user_agent)
      .build()
      .context("Failed to build Google HTTP client")?;

    let issuer_url =
      IssuerUrl::new("https://accounts.google.com".to_string())
        .context("Failed to initialize Google issuer url")?;

    let provider_metadata =
      CoreProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .context("Failed to discover Google OpenID configuration")?;

    let oidc_client =
      openidconnect::core::CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id.clone()),
        Some(ClientSecret::new(client_secret.clone())),
      )
      .set_redirect_uri(
        RedirectUrl::new(redirect_uri.clone())
          .context("Invalid Google redirect URI")?,
      );

    Ok(GoogleProvider {
      http_client,
      oidc_client,
      client_id: client_id.clone(),
      redirect_uri,
      scopes,
    })
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

    Ok(GoogleUser {
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
    })
  }
}

pub struct GoogleUser {
  pub id: String,
  pub email: String,
  pub picture: String,
}
