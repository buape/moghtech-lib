use std::{collections::HashMap, sync::OnceLock};

use anyhow::{Context, anyhow};
use axum::http::StatusCode;
use mogh_auth_client::config::{OidcConfig, TokenExchangeConfig};
use mogh_error::{AddStatusCode as _, AddStatusCodeError};
use openidconnect::{
  AccessTokenHash, AdditionalClaims, AuthorizationCode, Client,
  ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
  EndpointMaybeSet, EndpointNotSet, EndpointSet, IdTokenFields,
  IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
  PkceCodeVerifier, RedirectUrl, Scope, StandardErrorResponse,
  StandardTokenResponse, TokenResponse as _,
  core::*,
  reqwest::{self, Url},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::{
  provider::token_exchange::TokenVerificationKeys,
  validations::url_has_credentials,
};

pub use openidconnect::SubjectIdentifier;

/// Some OIDC providers use 'username' additional claim
/// rather than the standard 'preferred_username'
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameAdditionalClaims {
  pub username: Option<String>,
  /// All other non standard claims.
  /// The configured 'groups_claim' is extracted from here.
  #[serde(flatten)]
  pub extra: HashMap<String, serde_json::Value>,
}

impl AdditionalClaims for UsernameAdditionalClaims {}

pub type TokenResponse = StandardTokenResponse<
  IdTokenFields<
    UsernameAdditionalClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
  >,
  CoreTokenType,
>;

fn reqwest(app_user_agent: &str) -> &'static reqwest::Client {
  static REQWEST: OnceLock<reqwest::Client> = OnceLock::new();
  REQWEST.get_or_init(|| {
    reqwest::Client::builder()
      .redirect(reqwest::redirect::Policy::none())
      .user_agent(app_user_agent)
      .build()
      .expect("Invalid OIDC reqwest client")
  })
}

pub type InnerOidcProvider = Client<
  UsernameAdditionalClaims,
  CoreAuthDisplay,
  CoreGenderClaim,
  CoreJweContentEncryptionAlgorithm,
  CoreJsonWebKey,
  CoreAuthPrompt,
  StandardErrorResponse<CoreErrorResponseType>,
  TokenResponse,
  CoreTokenIntrospectionResponse,
  CoreRevocableToken,
  CoreRevocationErrorResponse,
  EndpointSet,
  EndpointNotSet,
  EndpointNotSet,
  EndpointNotSet,
  EndpointMaybeSet,
  EndpointMaybeSet,
>;

pub struct OidcProvider {
  app_user_agent: &'static str,
  client: InnerOidcProvider,
  use_full_email: bool,
  additional_scopes: Vec<String>,
  /// Audiences besides the client id which
  /// the ID tokens of logins may carry.
  additional_audiences: Vec<String>,
  /// To verify tokens presented for token exchange
  verification_keys: TokenVerificationKeys,
}

impl OidcProvider {
  /// Initialize a new OIDC provider using the configured provider's
  /// discovery endpoint.
  pub async fn new(
    app_user_agent: &'static str,
    redirect_uri: String,
    config: &OidcConfig,
  ) -> anyhow::Result<OidcProvider> {
    if !config.enabled() {
      return Err(anyhow!(
        "OIDC provider is disabled or not configured."
      ));
    }

    // Refused by the management api. Configured elsewhere, they
    // would be sent to the discovery endpoint, and end up in the
    // errors of the discovery (eg. the issuer mismatch, as the
    // provider's issuer can't carry them).
    if Url::parse(&config.provider)
      .is_ok_and(|url| url_has_credentials(&url))
    {
      return Err(anyhow!(
        "OIDC 'provider' url must not carry credentials (scheme://user:password@host)"
      ));
    }

    // Use OpenID Connect Discovery to fetch the provider metadata.
    let provider_metadata = CoreProviderMetadata::discover_async(
      IssuerUrl::new(config.provider.clone())?,
      reqwest(app_user_agent),
    )
    .await
    .context(
      "Failed to get OIDC /.well-known/openid-configuration",
    )?;

    Self::from_metadata(
      app_user_agent,
      redirect_uri,
      config,
      provider_metadata,
    )
  }

  /// Initialize the provider from already discovered metadata.
  pub fn from_metadata(
    app_user_agent: &'static str,
    redirect_uri: String,
    config: &OidcConfig,
    provider_metadata: CoreProviderMetadata,
  ) -> anyhow::Result<OidcProvider> {
    let verification_keys =
      TokenVerificationKeys::from_metadata(&provider_metadata);

    let additional_scopes = additional_scopes(
      config,
      provider_metadata.scopes_supported().map(Vec::as_slice),
    );

    let client = InnerOidcProvider::from_provider_metadata(
      provider_metadata,
      ClientId::new(config.client_id.to_string()),
      // The secret may be empty / ommitted if auth provider supports PKCE
      if config.client_secret.is_empty() {
        None
      } else {
        Some(ClientSecret::new(config.client_secret.to_string()))
      },
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(
      RedirectUrl::new(redirect_uri)
        .context("Invalid OIDC redirect URI")?,
    );

    Ok(OidcProvider {
      client,
      app_user_agent,
      use_full_email: config.use_full_email,
      additional_scopes,
      additional_audiences: config.additional_audiences.clone(),
      verification_keys,
    })
  }

  /// Verifies the ID tokens of logins. Some providers attach
  /// additional audiences, which are trusted when configured
  /// ('additional_audiences'). Every verification of a login's
  /// ID token uses this, otherwise its claims would be verified
  /// by one step and refused by the next.
  fn id_token_verifier(&self) -> CoreIdTokenVerifier<'_> {
    let verifier = self.client.id_token_verifier();
    if self.additional_audiences.is_empty() {
      verifier
    } else {
      verifier.set_other_audience_verifier_fn(|aud| {
        self.additional_audiences.contains(aud)
      })
    }
  }

  /// Verifies a token presented for RFC 8693 token exchange, which
  /// must be signed by the provider and issued to the client id or one
  /// of the exchange audiences. Enforces 'allowed_groups'.
  ///
  /// Groups can only come from the token itself here,
  /// there is no access token to get the networked user info with.
  pub fn verify_exchange_token(
    &self,
    config: &OidcConfig,
    exchange: &TokenExchangeConfig,
    token: &str,
  ) -> mogh_error::Result<OidcLoginInfo> {
    let mut audiences = vec![config.client_id.clone()];
    audiences.extend(exchange.audiences.iter().cloned());

    let claims = self
      .verification_keys
      .verify::<UsernameAdditionalClaims>(
        token,
        &audiences,
        &config.additional_audiences,
        exchange.max_token_age_secs,
      )
      .status_code(StatusCode::BAD_REQUEST)?;

    let groups = config.groups_claim().and_then(|claim| {
      extract_groups(&claims.additional_claims().extra, claim)
    });

    let info =
      OidcLoginInfo::new(config, claims.subject().clone(), groups);
    info.check_allowed_groups(config)?;

    Ok(info)
  }

  pub fn authorize_url(
    &self,
    pkce_challenge: PkceCodeChallenge,
  ) -> (Url, CsrfToken, Nonce) {
    self
      .client
      .authorize_url(
        CoreAuthenticationFlow::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
      )
      .set_pkce_challenge(pkce_challenge)
      .add_scope(Scope::new("openid".to_string()))
      .add_scope(Scope::new("profile".to_string()))
      .add_scope(Scope::new("email".to_string()))
      .add_scopes(
        self.additional_scopes.iter().cloned().map(Scope::new),
      )
      .url()
  }

  /// Applies security validations and extracts the
  /// oidc user info, including groups if configured.
  ///
  /// Enforces 'allowed_groups', so every flow
  /// using the validated login is gated.
  pub async fn validate_extract_login_info_and_token(
    &self,
    config: &OidcConfig,
    (client, server): (CsrfToken, String),
    code: String,
    pkce_verifier: PkceCodeVerifier,
    nonce: &Nonce,
  ) -> mogh_error::Result<(OidcLoginInfo, TokenResponse)> {
    // Validate CSRF tokens match
    if !crate::validations::constant_time_eq(client.secret(), &server)
    {
      return Err(anyhow!("CSRF token invalid").into());
    }

    let reqwest_client = reqwest(self.app_user_agent);
    let token_response = self
      .client
      .exchange_code(AuthorizationCode::new(code))
      .context("Failed to get Oauth token at exchange code")?
      .set_pkce_verifier(pkce_verifier)
      .request_async(reqwest_client)
      .await
      .context("Failed to get Oauth token")?;

    // Extract the ID token claims after verifying its authenticity and nonce.
    let id_token = token_response
      .id_token()
      .context("OIDC Server did not return an ID token")?;

    let verifier = self.id_token_verifier();

    // The login can't be trusted, which is not a server error.
    let claims = id_token
      .claims(&verifier, nonce)
      .context("Failed to verify token claims. This issue may be temporary (60 seconds max).")
      .status_code(StatusCode::UNAUTHORIZED)?;

    // Verify the access token hash to ensure that the access token hasn't been substituted for
    // another user's.
    if let Some(expected_access_token_hash) =
      claims.access_token_hash()
    {
      let actual_access_token_hash = AccessTokenHash::from_token(
        &token_response.access_token().clone(),
        id_token.signing_alg()?,
        id_token.signing_key(&verifier)?,
      )?;
      if actual_access_token_hash != *expected_access_token_hash {
        return Err(anyhow!("Invalid access token").into());
      }
    }

    let subject = claims.subject().clone();

    let groups = match config.groups_claim() {
      Some(claim) => {
        // Priority 1: groups from id_token.
        match extract_groups(&claims.additional_claims().extra, claim)
        {
          Some(groups) => Some(groups),
          // Priority 2: groups from user_info.
          None => {
            self
              .get_user_info_groups(&subject, &token_response, claim)
              .await
          }
        }
      }
      None => None,
    };

    let info = OidcLoginInfo::new(config, subject, groups);
    info.check_allowed_groups(config)?;

    Ok((info, token_response))
  }

  /// Some providers only include the groups claim
  /// in the networked user info.
  async fn get_user_info_groups(
    &self,
    subject: &SubjectIdentifier,
    token: &TokenResponse,
    claim: &str,
  ) -> Option<Vec<String>> {
    let user_info = self
      .client
      .user_info(token.access_token().clone(), Some(subject.clone()))
      .inspect_err(|e| {
        warn!("OIDC groups claim '{claim}' not in id token and user info not available | {e:#}")
      })
      .ok()?
      .request_async::<UsernameAdditionalClaims, _, CoreGenderClaim>(
        reqwest(self.app_user_agent),
      )
      .await
      .inspect(|user_info| debug!("OIDC USER INFO: {user_info:?}"))
      .inspect_err(|e| {
        warn!("OIDC groups claim '{claim}' not in id token and failed to get user info | {e:#}")
      })
      .ok()?;
    let groups =
      extract_groups(&user_info.additional_claims().extra, claim);
    if groups.is_none() {
      warn!(
        "OIDC groups claim '{claim}' not found in id token or user info. The scope providing it may need to be added to 'additional_scopes'."
      );
    }
    groups
  }

  pub async fn get_username(
    &self,
    subject: &SubjectIdentifier,
    token: &TokenResponse,
    nonce: &Nonce,
  ) -> String {
    if self.use_full_email {
      return self
        .get_username_prioritize_email(subject, token, nonce)
        .await;
    }

    let id_claims = token.id_token().and_then(|token| {
      token
        .claims(&self.id_token_verifier(), nonce)
        .inspect(|claims| debug!("OIDC ID TOKEN CLAIMS: {claims:?}"))
        .ok()
    });

    // Priority 1: preferred_username from id_token.
    if let Some(username) = id_claims.as_ref().and_then(|claims| {
      claims.preferred_username()?.to_string().into()
    }) {
      return username;
    }

    // Get networked user info
    let user_info = async {
      self
        .client
        .user_info(
          token.access_token().clone(),
          Some(subject.clone()),
        )
        .ok()?
        .request_async::<UsernameAdditionalClaims, _, CoreGenderClaim>(
          reqwest(self.app_user_agent),
        )
        .await
        .inspect(|user_info| debug!("OIDC USER INFO: {user_info:?}"))
        .ok()
    }
    .await;

    // Priority 2: preferred_username from user_info
    if let Some(username) = user_info.as_ref().and_then(|user_info| {
      user_info.preferred_username()?.to_string().into()
    }) {
      return username;
    }

    // Priority 3: username additional claim from id claims, then user info
    if let Some(username) = id_claims
      .as_ref()
      .and_then(|id_claims| {
        id_claims.additional_claims().username.clone()
      })
      .or_else(|| {
        user_info.as_ref()?.additional_claims().username.clone()
      })
    {
      return username;
    }

    // Priority 4: name from id claims, then user info
    if let Some(username) = id_claims
      .as_ref()
      .and_then(|id_claims| {
        id_claims.name()?.get(None)?.to_string().into()
      })
      .or_else(|| {
        user_info.as_ref()?.name()?.get(None)?.to_string().into()
      })
    {
      return username;
    }

    // Priority 5: username part of email from id claims, then user info
    if let Some(email) = id_claims
      .as_ref()
      .and_then(|id_claims| id_claims.email()?.to_string().into())
      .or_else(|| user_info.as_ref()?.email()?.to_string().into())
    {
      let username = email
        .split_once('@')
        .map(|(username, _)| username)
        .unwrap_or(email.as_str())
        .to_string();
      return username;
    }

    // Priority 6 (fallback): use the subject if no others available
    subject.to_string()
  }

  /// Used with 'use_full_email' option
  pub async fn get_username_prioritize_email(
    &self,
    subject: &SubjectIdentifier,
    token: &TokenResponse,
    nonce: &Nonce,
  ) -> String {
    let id_claims = token.id_token().and_then(|token| {
      token
        .claims(&self.id_token_verifier(), nonce)
        .inspect(|claims| debug!("OIDC ID TOKEN CLAIMS: {claims:?}"))
        .ok()
    });

    // Priority 1: email from id_token.
    if let Some(email) = id_claims
      .as_ref()
      .and_then(|claims| claims.email()?.to_string().into())
    {
      return email;
    }

    // Get networked user info
    let user_info = async {
      self
        .client
        .user_info(
          token.access_token().clone(),
          Some(subject.clone()),
        )
        .ok()?
        .request_async::<UsernameAdditionalClaims, _, CoreGenderClaim>(
          reqwest(self.app_user_agent),
        )
        .await
        .inspect(|user_info| debug!("OIDC USER INFO: {user_info:?}"))
        .ok()
    }
    .await;

    // Priority 2: email from user_info
    if let Some(username) = user_info
      .as_ref()
      .and_then(|user_info| user_info.email()?.to_string().into())
    {
      return username;
    }

    // Priority 3: preferred_username from id claims, then user info
    if let Some(username) = id_claims
      .as_ref()
      .and_then(|id_claims| {
        id_claims.preferred_username()?.to_string().into()
      })
      .or_else(|| {
        user_info.as_ref()?.preferred_username()?.to_string().into()
      })
    {
      return username;
    }

    // Priority 4: username additional claim from id claims, then user info
    if let Some(username) = id_claims
      .as_ref()
      .and_then(|id_claims| {
        id_claims.additional_claims().username.clone()
      })
      .or_else(|| {
        user_info.as_ref()?.additional_claims().username.clone()
      })
    {
      return username;
    }

    // Priority 5: name from id claims, then user info
    if let Some(username) = id_claims
      .as_ref()
      .and_then(|id_claims| {
        id_claims.name()?.get(None)?.to_string().into()
      })
      .or_else(|| {
        user_info.as_ref()?.name()?.get(None)?.to_string().into()
      })
    {
      return username;
    }

    // Priority 6 (fallback): use the subject if no others available
    subject.to_string()
  }
}

/// Information about the user authenticated with the OIDC provider,
/// passed to the app level [AuthImpl][crate::AuthImpl]
/// on signup, login and link.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OidcLoginInfo {
  /// The unique, stable id of the user at the provider.
  pub subject: SubjectIdentifier,
  /// The groups the provider reports for the user.
  ///
  /// - `None`: No group information is available. Either group
  ///   extraction is not configured, or the provider didn't send
  ///   the claim (eg. missing scope, or Azure group overage).
  ///   Apps should leave existing memberships as they are.
  /// - `Some(groups)`: The full list of groups, which may be empty.
  ///
  /// Note. Some providers omit the claim entirely for users
  /// without any groups, which shows up as `None` here.
  pub groups: Option<Vec<String>>,
  /// Whether the user is in one of the configured 'admin_groups'.
  ///
  /// `None` if 'admin_groups' is not configured or no group
  /// information is available, apps should then leave the
  /// users admin status as it is.
  ///
  /// ⚠️ Revoking admin through the provider relies on it sending the
  /// groups claim. A provider which omits the claim for a user left
  /// without any (matching) group reports `None`, and the user keeps
  /// admin. Configure 'allowed_groups' as well: such a user is then
  /// refused the login instead.
  pub admin: Option<bool>,
}

impl OidcLoginInfo {
  pub fn new(
    config: &OidcConfig,
    subject: SubjectIdentifier,
    groups: Option<Vec<String>>,
  ) -> OidcLoginInfo {
    let admin = if config.admin_groups.is_empty() {
      None
    } else {
      groups.as_ref().map(|groups| {
        groups
          .iter()
          .any(|group| config.admin_groups.contains(group))
      })
    };
    OidcLoginInfo {
      subject,
      groups,
      admin,
    }
  }

  /// Enforces 'allowed_groups'. Users in 'admin_groups' are also allowed.
  /// Fails closed if the provider didn't send any group information.
  pub fn check_allowed_groups(
    &self,
    config: &OidcConfig,
  ) -> mogh_error::Result<()> {
    if config.allowed_groups.is_empty() {
      return Ok(());
    }
    let Some(groups) = &self.groups else {
      return Err(
        anyhow!(
          "Provider did not send user groups, which are required for login. The groups scope or claim may be misconfigured."
        )
        .status_code(StatusCode::UNAUTHORIZED),
      );
    };
    let allowed = groups.iter().any(|group| {
      config.allowed_groups.contains(group)
        || config.admin_groups.contains(group)
    });
    if allowed {
      Ok(())
    } else {
      Err(
        anyhow!("User is not a member of any allowed group")
          .status_code(StatusCode::UNAUTHORIZED),
      )
    }
  }
}

/// The scopes to request on top of `openid`, `profile` and `email`.
///
/// The `groups` scope is added automatically if the `groups` claim
/// is used and the provider advertises the scope in its discovery
/// metadata. It is never requested blindly, as some providers
/// reject the whole login on unknown scopes (`invalid_scope`).
fn additional_scopes(
  config: &OidcConfig,
  scopes_supported: Option<&[Scope]>,
) -> Vec<String> {
  let mut scopes = Vec::<String>::new();
  for scope in &config.additional_scopes {
    if !scope.is_empty()
      && !["openid", "profile", "email"].contains(&scope.as_str())
      && !scopes.contains(scope)
    {
      scopes.push(scope.clone());
    }
  }
  let groups_scope_supported =
    scopes_supported.is_some_and(|scopes| {
      scopes.iter().any(|scope| scope.as_str() == "groups")
    });
  if config.groups_claim() == Some("groups")
    && groups_scope_supported
    && !scopes.iter().any(|scope| scope == "groups")
  {
    scopes.push("groups".to_string());
  }
  scopes
}

/// Extracts the groups at the given claim.
/// The exact claim name is tried first (namespaced claims like
/// `https://example.com/groups` include dots), then as a
/// dotted path into nested claims (eg. `realm_access.roles`).
///
/// Accepts a list of strings, or a single string.
/// Returns None if the claim is missing or has another shape.
fn extract_groups(
  claims: &HashMap<String, serde_json::Value>,
  claim: &str,
) -> Option<Vec<String>> {
  let value = claims.get(claim).or_else(|| {
    let mut path = claim.split('.');
    let mut value = claims.get(path.next()?)?;
    for key in path {
      value = value.get(key)?;
    }
    Some(value)
  })?;
  let mut groups = match value {
    serde_json::Value::String(group) => vec![group.clone()],
    serde_json::Value::Array(values) => values
      .iter()
      .map(|value| value.as_str().map(str::to_string))
      .collect::<Option<Vec<_>>>()
      .or_else(|| {
        warn!(
          "OIDC groups claim '{claim}' contains non string values, ignoring"
        );
        None
      })?,
    _ => {
      warn!(
        "OIDC groups claim '{claim}' is not a list of strings, ignoring"
      );
      return None;
    }
  };
  groups.sort();
  groups.dedup();
  Some(groups)
}

#[cfg(test)]
mod tests {
  use openidconnect::IdTokenClaims;
  use serde_json::json;

  use super::*;

  fn claims(
    value: serde_json::Value,
  ) -> HashMap<String, serde_json::Value> {
    serde_json::from_value(value).unwrap()
  }

  fn config(allowed: &[&str], admin: &[&str]) -> OidcConfig {
    OidcConfig {
      allowed_groups: allowed.iter().map(|g| g.to_string()).collect(),
      admin_groups: admin.iter().map(|g| g.to_string()).collect(),
      ..Default::default()
    }
  }

  fn info(
    config: &OidcConfig,
    groups: Option<&[&str]>,
  ) -> OidcLoginInfo {
    OidcLoginInfo::new(
      config,
      SubjectIdentifier::new("subject".to_string()),
      groups
        .map(|groups| groups.iter().map(|g| g.to_string()).collect()),
    )
  }

  fn exchange_provider(config: &OidcConfig) -> OidcProvider {
    use crate::provider::token_exchange::test_tokens::metadata;
    OidcProvider::from_metadata(
      "test",
      "https://app.example.com/auth/oidc/callback".to_string(),
      config,
      metadata(),
    )
    .unwrap()
  }

  fn exchange_token(
    groups: Option<&[&str]>,
  ) -> crate::provider::token_exchange::test_tokens::TestToken<
    UsernameAdditionalClaims,
  > {
    let mut extra = HashMap::new();
    if let Some(groups) = groups {
      extra.insert("groups".to_string(), json!(groups));
    }
    crate::provider::token_exchange::test_tokens::TestToken::new(
      UsernameAdditionalClaims {
        username: None,
        extra,
      },
    )
  }

  fn exchange_config(allowed: &[&str], admin: &[&str]) -> OidcConfig {
    use crate::provider::token_exchange::test_tokens::{
      CLIENT_ID, ISSUER,
    };
    OidcConfig {
      enabled: true,
      provider: ISSUER.to_string(),
      client_id: CLIENT_ID.to_string(),
      // Present, but never used to verify exchanged tokens
      client_secret: "client-secret".to_string(),
      ..config(allowed, admin)
    }
  }

  #[test]
  fn test_exchange_token_subject_groups_and_admin() {
    let config = exchange_config(&[], &["admins"]);
    let provider = exchange_provider(&config);
    let info = provider
      .verify_exchange_token(
        &config,
        &Default::default(),
        &exchange_token(Some(&["users", "admins"])).mint(),
      )
      .unwrap();
    assert_eq!(info.subject.as_str(), "subject-123");
    assert_eq!(
      info.groups,
      Some(vec!["admins".to_string(), "users".to_string()])
    );
    assert_eq!(info.admin, Some(true));
  }

  #[test]
  fn test_exchange_token_enforces_allowed_groups() {
    let config = exchange_config(&["users"], &[]);
    let provider = exchange_provider(&config);
    assert!(
      provider
        .verify_exchange_token(
          &config,
          &Default::default(),
          &exchange_token(Some(&["users"])).mint()
        )
        .is_ok()
    );
    // Not a member, and no group information at all (fails closed)
    for groups in [Some(&["other"][..]), None] {
      let err = provider
        .verify_exchange_token(
          &config,
          &Default::default(),
          &exchange_token(groups).mint(),
        )
        .unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
  }

  #[test]
  fn test_exchange_token_audiences() {
    let config = exchange_config(&[], &[]);
    let provider = exchange_provider(&config);
    let cli_token = || {
      let mut token = exchange_token(None);
      token.audiences = vec!["cli-client".to_string()];
      token.mint()
    };
    // Only the providers own client id by default
    let err = provider
      .verify_exchange_token(
        &config,
        &Default::default(),
        &cli_token(),
      )
      .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert!(
      provider
        .verify_exchange_token(
          &config,
          &TokenExchangeConfig {
            audiences: vec!["cli-client".to_string()],
            ..Default::default()
          },
          &cli_token()
        )
        .is_ok()
    );
  }

  /// A confidential client would normally accept HS256 tokens signed
  /// with the client secret, exchanged tokens never do.
  #[test]
  fn test_exchange_token_rejects_client_secret_signature() {
    use crate::provider::token_exchange::test_tokens::Signer;
    let config = exchange_config(&[], &[]);
    let provider = exchange_provider(&config);
    let mut token = exchange_token(None);
    token.signer = Signer::Hmac("client-secret");
    assert!(
      provider
        .verify_exchange_token(
          &config,
          &Default::default(),
          &token.mint()
        )
        .is_err()
    );
  }

  /// The ID token of a login, as the provider of the test
  /// metadata signs it, for `audiences`.
  fn login_id_token(audiences: &[&str], nonce: &Nonce) -> String {
    use crate::provider::token_exchange::test_tokens::{
      CLIENT_ID, ISSUER,
    };
    use chrono::{Duration, Utc};
    use openidconnect::{
      Audience, EndUserEmail, EndUserUsername, IdToken, JsonWebKeyId,
      StandardClaims,
    };
    let claims = IdTokenClaims::<
      UsernameAdditionalClaims,
      CoreGenderClaim,
    >::new(
      IssuerUrl::new(ISSUER.to_string()).unwrap(),
      audiences
        .iter()
        .map(|audience| Audience::new(audience.to_string()))
        .collect(),
      Utc::now() + Duration::minutes(5),
      Utc::now(),
      StandardClaims::new(SubjectIdentifier::new(
        "subject-123".to_string(),
      ))
      .set_preferred_username(Some(EndUserUsername::new(
        "alice".to_string(),
      )))
      .set_email(Some(EndUserEmail::new(
        "alice@example.com".to_string(),
      ))),
      UsernameAdditionalClaims {
        username: None,
        extra: HashMap::new(),
      },
    )
    .set_nonce(Some(nonce.clone()))
    .set_authorized_party(Some(ClientId::new(CLIENT_ID.to_string())));
    let key = CoreRsaPrivateSigningKey::from_pem(
      include_str!("test_keys/rsa_a.pem"),
      Some(JsonWebKeyId::new("test-key".to_string())),
    )
    .unwrap();
    IdToken::<
      UsernameAdditionalClaims,
      CoreGenderClaim,
      CoreJweContentEncryptionAlgorithm,
      CoreJwsSigningAlgorithm,
    >::new(
      claims,
      &key,
      CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
      None,
      None,
    )
    .unwrap()
    .to_string()
  }

  /// The username is resolved from the login's ID token, verified
  /// again with the audiences the login was verified with. Without
  /// them its claims were dropped for providers attaching another
  /// audience, and the name fell back to the user info / subject.
  #[tokio::test]
  async fn test_username_from_id_token_with_additional_audiences() {
    use crate::provider::token_exchange::test_tokens::CLIENT_ID;
    let config = OidcConfig {
      additional_audiences: vec!["project-id".to_string()],
      ..exchange_config(&[], &[])
    };
    let nonce = Nonce::new("login-nonce".to_string());
    let token: TokenResponse = serde_json::from_value(json!({
      "access_token": "access-token",
      "token_type": "bearer",
      "id_token": login_id_token(&[CLIENT_ID, "project-id"], &nonce),
    }))
    .unwrap();
    let subject = SubjectIdentifier::new("subject-123".to_string());

    let provider = exchange_provider(&config);
    assert_eq!(
      provider.get_username(&subject, &token, &nonce).await,
      "alice"
    );
    let provider = exchange_provider(&OidcConfig {
      use_full_email: true,
      ..config.clone()
    });
    assert_eq!(
      provider.get_username(&subject, &token, &nonce).await,
      "alice@example.com"
    );
    // An audience which isn't configured is still refused. The
    // test provider has no user info, which leaves the subject.
    let provider = exchange_provider(&exchange_config(&[], &[]));
    assert_eq!(
      provider.get_username(&subject, &token, &nonce).await,
      "subject-123"
    );
  }

  #[tokio::test]
  async fn test_provider_url_with_credentials_is_refused() {
    // Refused before any request: nothing listens there
    let listener =
      std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let config = OidcConfig {
      enabled: true,
      provider: format!("http://user:hunter2@{address}"),
      client_id: "client-id".to_string(),
      ..Default::default()
    };
    let err = OidcProvider::new(
      "test",
      "https://app.example.com/auth/oidc/callback".to_string(),
      &config,
    )
    .await
    .err()
    .unwrap();
    let err = format!("{err:#}");
    assert!(err.contains("must not carry credentials"), "{err}");
    assert!(!err.contains("hunter2"), "{err}");
  }

  #[test]
  fn test_id_token_claims_capture_non_standard_claims() {
    let claims: IdTokenClaims<
      UsernameAdditionalClaims,
      CoreGenderClaim,
    > = serde_json::from_value(json!({
      "iss": "https://idp.example.com",
      "sub": "subject",
      "aud": ["client-id"],
      "exp": 2000000000,
      "iat": 1000000000,
      "email": "user@example.com",
      "username": "user",
      "groups": ["users", "admins"],
      "realm_access": { "roles": ["role"] },
    }))
    .unwrap();
    let additional = claims.additional_claims();
    assert_eq!(additional.username.as_deref(), Some("user"));
    assert_eq!(
      extract_groups(&additional.extra, "groups"),
      Some(vec!["admins".to_string(), "users".to_string()])
    );
    assert_eq!(
      extract_groups(&additional.extra, "realm_access.roles"),
      Some(vec!["role".to_string()])
    );
    // Standard claims are not duplicated into the extra claims
    assert!(!additional.extra.contains_key("email"));
  }

  fn scopes(scopes: &[&str]) -> Vec<Scope> {
    scopes.iter().map(|s| Scope::new(s.to_string())).collect()
  }

  #[test]
  fn test_groups_scope_added_when_advertised() {
    let supported = scopes(&["openid", "profile", "groups"]);
    // Default claim via 'allowed_groups' / 'admin_groups'
    assert_eq!(
      additional_scopes(&config(&["users"], &[]), Some(&supported)),
      vec!["groups".to_string()]
    );
    // Explicit 'groups' claim behaves the same
    let explicit = OidcConfig {
      groups_claim: "groups".into(),
      additional_scopes: vec!["groups".into(), "offline".into()],
      ..Default::default()
    };
    assert_eq!(
      additional_scopes(&explicit, Some(&supported)),
      vec!["groups".to_string(), "offline".to_string()]
    );
  }

  #[test]
  fn test_groups_scope_not_added_blindly() {
    let config = config(&["users"], &[]);
    // Provider doesn't advertise the scope, or any scopes
    assert!(
      additional_scopes(&config, Some(&scopes(&["openid"])))
        .is_empty()
    );
    assert!(additional_scopes(&config, None).is_empty());
  }

  #[test]
  fn test_groups_scope_not_added_when_not_needed() {
    let supported = scopes(&["openid", "groups"]);
    // Group extraction disabled
    assert!(
      additional_scopes(&OidcConfig::default(), Some(&supported))
        .is_empty()
    );
    // Custom claim, scopes are up to the user
    let custom = OidcConfig {
      groups_claim: "realm_access.roles".into(),
      additional_scopes: vec!["roles".into(), "openid".into()],
      ..Default::default()
    };
    assert_eq!(
      additional_scopes(&custom, Some(&supported)),
      vec!["roles".to_string()]
    );
  }

  #[test]
  fn test_extract_groups_list_sorted_and_deduped() {
    let claims = claims(json!({ "groups": ["b", "a", "b"] }));
    assert_eq!(
      extract_groups(&claims, "groups"),
      Some(vec!["a".to_string(), "b".to_string()])
    );
  }

  #[test]
  fn test_extract_groups_empty_list_is_some() {
    let claims = claims(json!({ "groups": [] }));
    assert_eq!(extract_groups(&claims, "groups"), Some(Vec::new()));
  }

  #[test]
  fn test_extract_groups_single_string() {
    let claims = claims(json!({ "groups": "users" }));
    assert_eq!(
      extract_groups(&claims, "groups"),
      Some(vec!["users".to_string()])
    );
  }

  #[test]
  fn test_extract_groups_exact_name_with_dots_before_path() {
    let claims = claims(json!({
      "https://example.com/groups": ["namespaced"],
      "https://example": { "com/groups": ["nested"] },
    }));
    assert_eq!(
      extract_groups(&claims, "https://example.com/groups"),
      Some(vec!["namespaced".to_string()])
    );
  }

  #[test]
  fn test_extract_groups_missing_claim() {
    let claims = claims(json!({ "other": ["users"] }));
    assert_eq!(extract_groups(&claims, "groups"), None);
    assert_eq!(extract_groups(&claims, "other.nested"), None);
    assert_eq!(extract_groups(&claims, ""), None);
  }

  #[test]
  fn test_extract_groups_rejects_other_shapes() {
    let claims = claims(json!({
      "mixed": ["users", 1],
      "objects": [{ "name": "users" }],
      "number": 1,
    }));
    assert_eq!(extract_groups(&claims, "mixed"), None);
    assert_eq!(extract_groups(&claims, "objects"), None);
    assert_eq!(extract_groups(&claims, "number"), None);
  }

  #[test]
  fn test_admin_none_when_not_configured_or_no_groups() {
    assert_eq!(
      info(&config(&[], &[]), Some(&["admins"])).admin,
      None
    );
    assert_eq!(info(&config(&[], &["admins"]), None).admin, None);
  }

  #[test]
  fn test_admin_resolved_from_groups() {
    let config = config(&[], &["admins"]);
    assert_eq!(
      info(&config, Some(&["users", "admins"])).admin,
      Some(true)
    );
    assert_eq!(info(&config, Some(&["users"])).admin, Some(false));
    assert_eq!(info(&config, Some(&[])).admin, Some(false));
  }

  #[test]
  fn test_allowed_groups_not_configured_allows_all() {
    let config = config(&[], &["admins"]);
    assert!(
      info(&config, None).check_allowed_groups(&config).is_ok()
    );
    assert!(
      info(&config, Some(&["other"]))
        .check_allowed_groups(&config)
        .is_ok()
    );
  }

  #[test]
  fn test_allowed_groups_fails_closed_without_group_info() {
    let config = config(&["users"], &[]);
    let err = info(&config, None)
      .check_allowed_groups(&config)
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_allowed_groups_membership() {
    let config = config(&["users"], &["admins"]);
    assert!(
      info(&config, Some(&["users"]))
        .check_allowed_groups(&config)
        .is_ok()
    );
    // Admin groups are implicitly allowed
    assert!(
      info(&config, Some(&["admins"]))
        .check_allowed_groups(&config)
        .is_ok()
    );
    for groups in [&["other"][..], &[]] {
      let err = info(&config, Some(groups))
        .check_allowed_groups(&config)
        .unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
  }
}
