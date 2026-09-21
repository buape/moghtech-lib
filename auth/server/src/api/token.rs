//! The OAuth 2.0 token endpoint, implementing
//! [RFC 8693 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693):
//! a token issued by an external login provider is
//! exchanged for an app token, without any user interaction.
//!
//! - Only providers which opt in with `token_exchange.enabled` take part.
//! - Only tokens signed by the provider are accepted (ID tokens / JWTs),
//!   and they must be issued to an accepted audience.
//! - The user must already exist, the endpoint never signs anyone up.
//! - Users who need a second factor for external logins are rejected,
//!   there is nobody to ask for it.

use std::{net::IpAddr, sync::Arc};

use axum::{
  Form, Json, Router,
  extract::rejection::FormRejection,
  http::{HeaderValue, StatusCode, header},
  response::{IntoResponse, Response},
  routing::post,
};
use mogh_auth_client::{
  api::token::{
    GRANT_TYPE_TOKEN_EXCHANGE, TOKEN_TYPE_ACCESS_TOKEN,
    TOKEN_TYPE_ID_TOKEN, TOKEN_TYPE_JWT, TokenExchangeError,
    TokenExchangeRequest, TokenExchangeResponse,
  },
  config::{ExternalLoginProvider, ExternalLoginProviderConfig},
};
use mogh_error::AddStatusCodeError as _;
use mogh_rate_limit::WithFailureRateLimit as _;
use mogh_request_ip::RequestIp;
use tracing::{error, info, instrument};

use crate::{
  AuthImpl,
  api::{
    external::load_provider_client,
    external_login_requires_two_factor,
  },
  middleware::check_user_cidr_whitelist,
  provider::{
    external::{
      BuiltProvider, ExternalLoginInfo, list_external_providers,
    },
    token_exchange::{
      MAX_SUBJECT_TOKEN_LENGTH, issuers_match, unverified_issuer,
    },
  },
  user::BoxAuthUser,
};

const GOOGLE_ISSUERS: [&str; 2] =
  ["https://accounts.google.com", "accounts.google.com"];

pub fn router<I: AuthImpl>() -> Router {
  Router::new().route("/token", post(token::<I>))
}

/// An error with the OAuth error code to report it as (RFC 6749 section 5.2).
#[derive(Debug)]
struct OauthError {
  code: &'static str,
  description: String,
}

impl std::fmt::Display for OauthError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.description)
  }
}

impl std::error::Error for OauthError {}

fn oauth_error(
  code: &'static str,
  description: impl Into<String>,
) -> mogh_error::Error {
  anyhow::Error::new(OauthError {
    code,
    description: description.into(),
  })
  .status_code(StatusCode::BAD_REQUEST)
}

fn invalid_request(
  description: impl Into<String>,
) -> mogh_error::Error {
  oauth_error("invalid_request", description)
}

fn invalid_grant(
  description: impl Into<String>,
) -> mogh_error::Error {
  oauth_error("invalid_grant", description)
}

/// Converts any error into the OAuth error format.
fn error_response(e: mogh_error::Error) -> Response {
  let (status, error) =
    if let Some(oauth) = e.error.downcast_ref::<OauthError>() {
      (
        StatusCode::BAD_REQUEST,
        TokenExchangeError {
          error: oauth.code.to_string(),
          error_description: Some(oauth.description.clone()),
        },
      )
    } else if e.status == StatusCode::TOO_MANY_REQUESTS {
      (
        StatusCode::TOO_MANY_REQUESTS,
        TokenExchangeError {
          error: "temporarily_unavailable".to_string(),
          error_description: Some(e.error.to_string()),
        },
      )
    } else if e.status.is_client_error() {
      // Rejections by the login rules, eg. the group or ip restrictions.
      (
        StatusCode::BAD_REQUEST,
        TokenExchangeError {
          error: "invalid_grant".to_string(),
          error_description: Some(e.error.to_string()),
        },
      )
    } else {
      // May include internal details, which this
      // unauthenticated endpoint must not hand out.
      error!("Token exchange failed | {:#}", e.error);
      (
        StatusCode::INTERNAL_SERVER_ERROR,
        TokenExchangeError {
          error: "server_error".to_string(),
          error_description: None,
        },
      )
    };
  no_store((status, Json(error)).into_response())
}

/// Token responses must not be cached (RFC 6749 section 5.1).
fn no_store(mut response: Response) -> Response {
  let headers = response.headers_mut();
  headers.insert(
    header::CACHE_CONTROL,
    HeaderValue::from_static("no-store"),
  );
  headers
    .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
  response
}

async fn token<I: AuthImpl>(
  RequestIp(ip): RequestIp,
  form: Result<Form<TokenExchangeRequest>, FormRejection>,
) -> Response {
  let auth = I::new();
  let res = async {
    let Form(request) = form.map_err(|e| {
      invalid_request(format!("Invalid token request | {e}"))
    })?;
    let auth = &auth;
    exchange(auth, ip, request, |provider| async move {
      load_provider_client(auth, &provider).await
    })
    .await
  }
  .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), &ip)
  .await;
  match res {
    Ok(response) => no_store(Json(response).into_response()),
    Err(e) => error_response(e),
  }
}

/// Checks the request parameters, returning the token type to issue.
fn validate_request(
  request: &TokenExchangeRequest,
) -> mogh_error::Result<&'static str> {
  if request.grant_type != GRANT_TYPE_TOKEN_EXCHANGE {
    return Err(oauth_error(
      "unsupported_grant_type",
      format!("Only '{GRANT_TYPE_TOKEN_EXCHANGE}' is supported"),
    ));
  }
  if ![TOKEN_TYPE_ID_TOKEN, TOKEN_TYPE_JWT]
    .contains(&request.subject_token_type.as_str())
  {
    return Err(invalid_request(format!(
      "'subject_token_type' must be '{TOKEN_TYPE_ID_TOKEN}' or '{TOKEN_TYPE_JWT}'. Only tokens signed by the provider can be exchanged."
    )));
  }
  if request.actor_token.is_some()
    || request.actor_token_type.is_some()
  {
    return Err(invalid_request(
      "'actor_token' (delegation) is not supported",
    ));
  }
  if request.subject_token.is_empty() {
    return Err(invalid_request("'subject_token' is empty"));
  }
  if request.subject_token.len() > MAX_SUBJECT_TOKEN_LENGTH {
    return Err(invalid_request("'subject_token' is too large"));
  }
  match request.requested_token_type.as_deref() {
    None | Some(TOKEN_TYPE_ACCESS_TOKEN) => {
      Ok(TOKEN_TYPE_ACCESS_TOKEN)
    }
    Some(TOKEN_TYPE_JWT) => Ok(TOKEN_TYPE_JWT),
    Some(_) => Err(invalid_request(format!(
      "'requested_token_type' must be '{TOKEN_TYPE_ACCESS_TOKEN}' or '{TOKEN_TYPE_JWT}'"
    ))),
  }
}

/// The providers which may verify a token claiming to be from `issuer`:
/// enabled, opted in to token exchange, and of that issuer.
///
/// The issuer is not verified at this point, it only selects who
/// verifies the token. Trusted issuers which aren't login providers
/// (workload identity) would be further candidates here.
fn exchange_candidates(
  providers: impl IntoIterator<Item = ExternalLoginProvider>,
  issuer: &str,
) -> Vec<ExternalLoginProvider> {
  providers
    .into_iter()
    .filter(|provider| {
      provider.enabled() && provider.token_exchange.enabled
    })
    .filter(|provider| match &provider.config {
      ExternalLoginProviderConfig::Oidc(config) => {
        issuers_match(&config.provider, issuer)
      }
      ExternalLoginProviderConfig::Google(_) => GOOGLE_ISSUERS
        .iter()
        .any(|google| issuers_match(google, issuer)),
      ExternalLoginProviderConfig::Github(_) => false,
    })
    .collect()
}

/// The RFC 8693 exchange of the `/token` endpoint.
/// `load_client` loads the client which verifies tokens of a provider.
#[instrument("TokenExchange", skip_all, fields(ip = ip.to_string()))]
async fn exchange<I, L, F>(
  auth: &I,
  ip: IpAddr,
  request: TokenExchangeRequest,
  load_client: L,
) -> mogh_error::Result<TokenExchangeResponse>
where
  I: AuthImpl + ?Sized,
  L: Fn(ExternalLoginProvider) -> F,
  F: Future<Output = mogh_error::Result<Arc<BuiltProvider>>>,
{
  let issued_token_type = validate_request(&request)?;
  let verified =
    verify_exchange(auth, &request.subject_token, load_client)
      .await?;
  complete_exchange(auth, ip, verified, issued_token_type).await
}

/// A verified token, and the user it belongs to.
pub(crate) struct VerifiedExchange {
  pub provider: ExternalLoginProvider,
  pub user: BoxAuthUser,
  pub info: ExternalLoginInfo,
}

/// The part shared by the `/token` endpoint and the login api: finds
/// the provider which accepts the token and has its user linked.
///
/// The login rules for the user (cidr whitelist, second
/// factor, sync) are still up to the caller.
pub(crate) async fn verify_exchange<I, L, F>(
  auth: &I,
  token: &str,
  load_client: L,
) -> mogh_error::Result<VerifiedExchange>
where
  I: AuthImpl + ?Sized,
  // Takes the provider by value, a future borrowing its
  // argument can't be named in these bounds.
  L: Fn(ExternalLoginProvider) -> F,
  F: Future<Output = mogh_error::Result<Arc<BuiltProvider>>>,
{
  if token.is_empty() {
    return Err(invalid_request("The token is empty"));
  }
  if token.len() > MAX_SUBJECT_TOKEN_LENGTH {
    return Err(invalid_request("The token is too large"));
  }

  let issuer = unverified_issuer(token).ok_or_else(|| {
    invalid_grant("The token is not a JWT with an issuer")
  })?;

  let candidates = exchange_candidates(
    list_external_providers(auth)
      .await?
      .into_iter()
      .map(|resolved| resolved.provider),
    &issuer,
  );

  if candidates.is_empty() {
    return Err(invalid_grant(
      "No login provider accepts tokens of this issuer for token exchange",
    ));
  }

  // Providers can share an issuer (several clients at the same
  // provider). The first which accepts the token and has the
  // user linked decides. A provider rejecting the token, or not
  // knowing the user, leaves it to the next one.
  let mut unavailable = None;
  let mut rejected = None;
  let mut unknown_user = None;
  for provider in candidates {
    let client = match load_client(provider.clone()).await {
      Ok(client) => client,
      // Already logged
      Err(e) => {
        unavailable.get_or_insert(e);
        continue;
      }
    };
    let info = match client.verify_exchange_token(&provider, token) {
      Ok(info) => info,
      Err(e) => {
        rejected = Some(e);
        continue;
      }
    };
    let Some(user) = auth
      .find_user_with_external_login(
        info.provider_id.clone(),
        info.external_id.clone(),
      )
      .await?
    else {
      unknown_user.get_or_insert(invalid_grant(format!(
        "No user is linked to this identity. Log in with '{}' once before exchanging tokens.",
        provider.name
      )));
      continue;
    };
    return Ok(VerifiedExchange {
      provider,
      user,
      info,
    });
  }

  // Report the furthest any provider got.
  if let Some(e) = unknown_user {
    return Err(e);
  }
  match rejected.or(unavailable) {
    // Only describes the token the caller presented
    Some(e) if e.status.is_client_error() => {
      Err(invalid_grant(format!("{:#}", e.error)))
    }
    Some(e) => Err(e),
    None => Err(invalid_grant("Token was rejected")),
  }
}

/// Applies the login rules to the user the verified
/// identity belongs to, and issues the app token.
async fn complete_exchange<I: AuthImpl + ?Sized>(
  auth: &I,
  ip: IpAddr,
  VerifiedExchange {
    provider,
    user,
    info,
  }: VerifiedExchange,
  issued_token_type: &str,
) -> mogh_error::Result<TokenExchangeResponse> {
  // Users outside their whitelist are rejected
  // before the exchange has any effect on them.
  check_user_cidr_whitelist(user.as_ref(), ip)?;

  // There is nobody to ask for it here, and no way to continue.
  if external_login_requires_two_factor(user.as_ref()) {
    return Err(invalid_grant(
      "The user requires a second factor for external logins, which this endpoint can't provide. Use 'ExchangeExternalForJwt' of the login api instead.",
    ));
  }

  // Sync before the token is issued, like for a login.
  auth.sync_external_user(user.id().to_string(), info).await?;

  let jwt = auth.jwt_provider().encode_sub(user.id())?;

  info!(
    user_id = user.id(),
    username = user.username(),
    provider_id = provider.id,
    provider = provider.name,
    "User logged in (token exchange)"
  );

  Ok(TokenExchangeResponse {
    access_token: jwt.jwt,
    issued_token_type: issued_token_type.to_string(),
    token_type: "Bearer".to_string(),
    expires_in: u64::try_from(auth.jwt_provider().ttl_ms() / 1000)
      .unwrap_or(u64::MAX),
  })
}

#[cfg(test)]
mod tests {
  use std::sync::Mutex;

  use anyhow::anyhow;

  use mogh_auth_client::{
    config::{NamedOauthConfig, OidcConfig, TokenExchangeConfig},
    passkey::Passkey,
  };

  use super::*;
  use crate::{
    provider::{
      jwt::JwtProvider,
      oidc::{OidcProvider, UsernameAdditionalClaims},
      token_exchange::test_tokens::{
        CLIENT_ID, ISSUER, TestToken, metadata,
      },
    },
    user::AuthUserImpl,
  };

  const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
  const JWT_TTL_MS: u128 = 60 * 60 * 1000;

  #[derive(Clone, Default)]
  struct TestUser {
    external_skip_2fa: bool,
    totp: bool,
    cidr_whitelist: Vec<String>,
  }

  impl AuthUserImpl for TestUser {
    fn id(&self) -> &str {
      "user-id"
    }
    fn username(&self) -> &str {
      "user"
    }
    fn external_skip_2fa(&self) -> bool {
      self.external_skip_2fa
    }
    fn passkey(&self) -> Option<Passkey> {
      None
    }
    fn totp_secret(&self) -> Option<&str> {
      self.totp.then_some("totp-secret")
    }
    fn cidr_whitelist(&self) -> &[String] {
      &self.cidr_whitelist
    }
  }

  struct TestAuth {
    providers: Vec<ExternalLoginProvider>,
    /// The user linked to ("oidc", "subject-123"), if any
    user: Option<TestUser>,
    sync_fails: bool,
    synced: Arc<Mutex<Vec<ExternalLoginInfo>>>,
    jwt: JwtProvider,
  }

  impl TestAuth {
    fn with_user(user: Option<TestUser>) -> TestAuth {
      TestAuth {
        providers: vec![oidc_provider("oidc", true)],
        user,
        sync_fails: false,
        synced: Default::default(),
        jwt: JwtProvider::new(b"test-jwt-secret", JWT_TTL_MS),
      }
    }
  }

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      unreachable!()
    }

    fn static_external_providers(
      &self,
    ) -> Vec<ExternalLoginProvider> {
      self.providers.clone()
    }

    fn find_user_with_external_login(
      &self,
      provider_id: String,
      external_id: String,
    ) -> crate::DynFuture<mogh_error::Result<Option<BoxAuthUser>>>
    {
      let user = self
        .user
        .clone()
        .filter(|_| {
          provider_id == "oidc" && external_id == "subject-123"
        })
        .map(|user| Box::new(user) as BoxAuthUser);
      Box::pin(async move { Ok(user) })
    }

    fn sync_external_user(
      &self,
      _user_id: String,
      info: ExternalLoginInfo,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      if self.sync_fails {
        return Box::pin(async {
          Err(anyhow!("sync failed").into())
        });
      }
      self.synced.lock().unwrap().push(info);
      Box::pin(async { Ok(()) })
    }

    fn get_user(
      &self,
      _user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<BoxAuthUser>> {
      Box::pin(async { Err(anyhow!("not implemented").into()) })
    }

    fn handle_request_authentication(
      &self,
      _auth: crate::RequestAuthentication,
      _ip: IpAddr,
      _require_user_enabled: bool,
      _req: axum::extract::Request,
    ) -> crate::DynFuture<mogh_error::Result<axum::extract::Request>>
    {
      Box::pin(async { Err(anyhow!("not implemented").into()) })
    }

    fn jwt_provider(&self) -> &JwtProvider {
      &self.jwt
    }
  }

  fn oidc_config() -> OidcConfig {
    OidcConfig {
      enabled: true,
      provider: ISSUER.to_string(),
      client_id: CLIENT_ID.to_string(),
      ..Default::default()
    }
  }

  fn oidc_provider(
    id: &str,
    exchange: bool,
  ) -> ExternalLoginProvider {
    ExternalLoginProvider {
      id: id.to_string(),
      name: "OIDC".to_string(),
      registration_disabled: false,
      token_exchange: TokenExchangeConfig {
        enabled: exchange,
        ..Default::default()
      },
      config: ExternalLoginProviderConfig::Oidc(oidc_config()),
    }
  }

  fn named_provider(id: &str, github: bool) -> ExternalLoginProvider {
    let config = NamedOauthConfig {
      enabled: true,
      client_id: "client-id".to_string(),
      client_secret: "secret".to_string(),
    };
    ExternalLoginProvider {
      id: id.to_string(),
      name: id.to_string(),
      registration_disabled: false,
      token_exchange: TokenExchangeConfig {
        enabled: true,
        ..Default::default()
      },
      config: if github {
        ExternalLoginProviderConfig::Github(config)
      } else {
        ExternalLoginProviderConfig::Google(config)
      },
    }
  }

  fn token() -> TestToken<UsernameAdditionalClaims> {
    TestToken::new(UsernameAdditionalClaims {
      username: None,
      extra: Default::default(),
    })
  }

  /// Builds the client from fixed metadata, in place of network discovery.
  async fn load_client(
    provider: ExternalLoginProvider,
  ) -> mogh_error::Result<Arc<BuiltProvider>> {
    let ExternalLoginProviderConfig::Oidc(config) = &provider.config
    else {
      unreachable!()
    };
    let client = OidcProvider::from_metadata(
      "test",
      "https://app.example.com/auth/oidc/callback".to_string(),
      config,
      metadata(),
    )?;
    Ok(Arc::new(BuiltProvider::Oidc(client)))
  }

  async fn run(
    auth: &TestAuth,
    token: String,
  ) -> mogh_error::Result<TokenExchangeResponse> {
    exchange(
      auth,
      IP,
      TokenExchangeRequest::id_token(token),
      load_client,
    )
    .await
  }

  fn code(e: &mogh_error::Error) -> &'static str {
    e.error
      .downcast_ref::<OauthError>()
      .map(|e| e.code)
      .unwrap_or("")
  }

  #[tokio::test]
  async fn test_exchange_issues_app_token_for_linked_user() {
    let auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    let response = run(&auth, token().mint()).await.unwrap();

    assert_eq!(response.token_type, "Bearer");
    assert_eq!(response.issued_token_type, TOKEN_TYPE_ACCESS_TOKEN);
    assert_eq!(response.expires_in, 3600);
    // The app token belongs to the linked user
    assert_eq!(
      auth.jwt.decode_sub(&response.access_token).unwrap(),
      "user-id"
    );
    let synced = auth.synced.lock().unwrap();
    assert_eq!(synced.len(), 1);
    assert_eq!(synced[0].provider_id, "oidc");
    assert_eq!(synced[0].external_id, "subject-123");
  }

  #[tokio::test]
  async fn test_exchange_never_signs_up_users() {
    let auth = TestAuth::with_user(None);
    let err = run(&auth, token().mint()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
    assert!(auth.synced.lock().unwrap().is_empty());
  }

  #[tokio::test]
  async fn test_exchange_rejects_invalid_token() {
    let auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    let other_app = TestToken {
      audiences: vec!["another-app".to_string()],
      ..token()
    };
    let err = run(&auth, other_app.mint()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");

    let err = run(&auth, "not-a-jwt".to_string()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
  }

  #[tokio::test]
  async fn test_exchange_requires_provider_opt_in() {
    let mut auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    auth.providers = vec![oidc_provider("oidc", false)];
    let err = run(&auth, token().mint()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
  }

  #[tokio::test]
  async fn test_exchange_unknown_issuer() {
    let auth = TestAuth::with_user(Some(TestUser::default()));
    let foreign = TestToken {
      issuer: "https://evil.example.com".to_string(),
      ..token()
    };
    let err = run(&auth, foreign.mint()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
  }

  /// Token exchange must not be a way around a second factor.
  #[tokio::test]
  async fn test_exchange_rejects_users_requiring_two_factor() {
    let auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: false,
      totp: true,
      ..Default::default()
    }));
    let err = run(&auth, token().mint()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
    assert!(auth.synced.lock().unwrap().is_empty());

    // Enrolled, but skipped for external logins
    let auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      totp: true,
      ..Default::default()
    }));
    assert!(run(&auth, token().mint()).await.is_ok());

    // Not enrolled
    let auth = TestAuth::with_user(Some(TestUser::default()));
    assert!(run(&auth, token().mint()).await.is_ok());
  }

  #[tokio::test]
  async fn test_exchange_enforces_cidr_whitelist_before_sync() {
    let auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      cidr_whitelist: vec!["192.168.0.0/16".to_string()],
      ..Default::default()
    }));
    let err = run(&auth, token().mint()).await.unwrap_err();
    assert_eq!(err.status, StatusCode::FORBIDDEN);
    assert!(auth.synced.lock().unwrap().is_empty());
  }

  #[tokio::test]
  async fn test_exchange_fails_if_sync_fails() {
    let mut auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    auth.sync_fails = true;
    assert!(run(&auth, token().mint()).await.is_err());
  }

  #[tokio::test]
  async fn test_exchange_second_provider_of_same_issuer_accepts() {
    let mut auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    // The first provider is another client at the same issuer
    let mut other_client = oidc_provider("other", true);
    let ExternalLoginProviderConfig::Oidc(config) =
      &mut other_client.config
    else {
      unreachable!()
    };
    config.client_id = "other-client-id".to_string();
    auth.providers = vec![other_client, oidc_provider("oidc", true)];

    let response = run(&auth, token().mint()).await.unwrap();
    assert!(!response.access_token.is_empty());
    assert_eq!(auth.synced.lock().unwrap()[0].provider_id, "oidc");
  }

  /// Accepting the token isn't enough to decide, the
  /// next provider may be the one the user is linked to.
  #[tokio::test]
  async fn test_exchange_falls_through_to_provider_with_the_user() {
    let mut auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    // Another client at the same issuer, which also
    // accepts tokens issued to the 'oidc' provider.
    let mut other_client = oidc_provider("other", true);
    other_client.token_exchange.audiences =
      vec![CLIENT_ID.to_string()];
    let ExternalLoginProviderConfig::Oidc(config) =
      &mut other_client.config
    else {
      unreachable!()
    };
    config.client_id = "other-client-id".to_string();
    auth.providers =
      vec![other_client.clone(), oidc_provider("oidc", true)];

    // 'other' accepts the token, but only 'oidc' has the user linked
    let response = run(&auth, token().mint()).await.unwrap();
    assert_eq!(
      auth.jwt.decode_sub(&response.access_token).unwrap(),
      "user-id"
    );
    assert_eq!(auth.synced.lock().unwrap()[0].provider_id, "oidc");

    // Nobody has the user: reported as such, not as a rejected token
    auth.providers = vec![other_client];
    let err = run(&auth, token().mint()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
    assert!(err.error.to_string().contains("No user is linked"));
  }

  #[tokio::test]
  async fn test_exchange_enforces_max_token_age() {
    let mut auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    auth.providers[0].token_exchange.max_token_age_secs = 300;

    let old_token = TestToken {
      issued_ago: chrono::Duration::minutes(30),
      expires_in: chrono::Duration::hours(8),
      ..token()
    };
    let err = run(&auth, old_token.mint()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
    assert!(err.error.to_string().contains("seconds ago"));

    assert!(run(&auth, token().mint()).await.is_ok());
  }

  #[test]
  fn test_validate_request() {
    let valid = TokenExchangeRequest::id_token("a.b.c");
    assert_eq!(
      validate_request(&valid).unwrap(),
      TOKEN_TYPE_ACCESS_TOKEN
    );

    let jwt = TokenExchangeRequest {
      subject_token_type: TOKEN_TYPE_JWT.to_string(),
      requested_token_type: Some(TOKEN_TYPE_JWT.to_string()),
      ..valid.clone()
    };
    assert_eq!(validate_request(&jwt).unwrap(), TOKEN_TYPE_JWT);

    let wrong_grant = TokenExchangeRequest {
      grant_type: "authorization_code".to_string(),
      ..valid.clone()
    };
    assert_eq!(
      code(&validate_request(&wrong_grant).unwrap_err()),
      "unsupported_grant_type"
    );

    for invalid in [
      // Opaque access tokens have no verifiable audience
      TokenExchangeRequest {
        subject_token_type: TOKEN_TYPE_ACCESS_TOKEN.to_string(),
        ..valid.clone()
      },
      TokenExchangeRequest {
        actor_token: Some("a.b.c".to_string()),
        ..valid.clone()
      },
      TokenExchangeRequest {
        requested_token_type: Some(
          "urn:ietf:params:oauth:token-type:refresh_token"
            .to_string(),
        ),
        ..valid.clone()
      },
      TokenExchangeRequest {
        subject_token: String::new(),
        ..valid.clone()
      },
      TokenExchangeRequest {
        subject_token: "a".repeat(MAX_SUBJECT_TOKEN_LENGTH + 1),
        ..valid.clone()
      },
    ] {
      let err = validate_request(&invalid).unwrap_err();
      assert_eq!(code(&err), "invalid_request", "{invalid:?}");
    }
  }

  #[test]
  fn test_exchange_candidates() {
    let mut disabled = oidc_provider("disabled", true);
    let ExternalLoginProviderConfig::Oidc(config) =
      &mut disabled.config
    else {
      unreachable!()
    };
    config.enabled = false;

    let providers = vec![
      oidc_provider("no-exchange", false),
      disabled,
      oidc_provider("oidc", true),
      named_provider("github", true),
      named_provider("google", false),
    ];

    let ids = |issuer: &str| {
      exchange_candidates(providers.clone(), issuer)
        .into_iter()
        .map(|provider| provider.id)
        .collect::<Vec<_>>()
    };
    // Trailing slash tolerant
    assert_eq!(ids(&format!("{ISSUER}/")), ["oidc"]);
    assert_eq!(ids("https://accounts.google.com"), ["google"]);
    assert_eq!(ids("accounts.google.com"), ["google"]);
    // Github never takes part
    assert!(ids("https://github.com").is_empty());
    assert!(ids("https://evil.example.com").is_empty());
    assert!(ids("").is_empty());
  }

  async fn error_body(
    e: mogh_error::Error,
  ) -> (StatusCode, String, String) {
    let response = error_response(e);
    let status = response.status();
    let cache = response.headers()[header::CACHE_CONTROL]
      .to_str()
      .unwrap()
      .to_string();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
      .await
      .unwrap();
    (status, cache, String::from_utf8(body.to_vec()).unwrap())
  }

  #[tokio::test]
  async fn test_error_response_format() {
    let (status, cache, body) =
      error_body(invalid_grant("Token was rejected")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(cache, "no-store");
    assert_eq!(
      serde_json::from_str::<TokenExchangeError>(&body).unwrap(),
      TokenExchangeError {
        error: "invalid_grant".to_string(),
        error_description: Some("Token was rejected".to_string()),
      }
    );

    // Login rule rejections
    let (status, _, body) = error_body(
      anyhow!("User is not a member of any allowed group")
        .status_code(StatusCode::UNAUTHORIZED),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("invalid_grant"));
    assert!(body.contains("allowed group"));

    // Rate limited
    let (status, _, body) = error_body(
      anyhow!("Too many attempts")
        .status_code(StatusCode::TOO_MANY_REQUESTS),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(body.contains("temporarily_unavailable"));
  }

  #[tokio::test]
  async fn test_error_response_hides_internal_errors() {
    let (status, _, body) = error_body(
      anyhow!("connection refused: http://10.0.0.5:9000/db").into(),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, r#"{"error":"server_error"}"#);
  }

  // =====================
  // = OVER REAL HTTP    =
  // =====================

  /// No providers configured, which is
  /// enough to exercise the http layer.
  struct HttpTestAuth;

  impl AuthImpl for HttpTestAuth {
    fn new() -> Self {
      HttpTestAuth
    }

    fn get_user(
      &self,
      _user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<BoxAuthUser>> {
      Box::pin(async { Err(anyhow!("not implemented").into()) })
    }

    fn handle_request_authentication(
      &self,
      _auth: crate::RequestAuthentication,
      _ip: IpAddr,
      _require_user_enabled: bool,
      _req: axum::extract::Request,
    ) -> crate::DynFuture<mogh_error::Result<axum::extract::Request>>
    {
      Box::pin(async { Err(anyhow!("not implemented").into()) })
    }

    fn jwt_provider(&self) -> &JwtProvider {
      panic!("not needed for these tests")
    }
  }

  /// Serves the token endpoint on a free local port.
  async fn serve() -> String {
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address =
      format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
      axum::serve(
        listener,
        router::<HttpTestAuth>()
          .into_make_service_with_connect_info::<std::net::SocketAddr>(),
      )
      .await
      .unwrap();
    });
    address
  }

  async fn post_form(
    address: &str,
    form: &[(&str, &str)],
  ) -> (StatusCode, TokenExchangeError, String) {
    let response = reqwest::Client::new()
      .post(format!("{address}/token"))
      .form(form)
      .send()
      .await
      .unwrap();
    let status = response.status();
    let cache = response.headers()["cache-control"]
      .to_str()
      .unwrap()
      .to_string();
    (status, response.json().await.unwrap(), cache)
  }

  #[tokio::test]
  async fn test_http_unaccepted_token_gets_oauth_error() {
    let address = serve().await;
    // A well formed request, as sent by
    // `mogh_auth_client::request::token_exchange`,
    // for a token nobody accepts.
    let token = token().mint();
    let (status, error, cache) = post_form(
      &address,
      &[
        ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE),
        ("subject_token", token.as_str()),
        ("subject_token_type", TOKEN_TYPE_ID_TOKEN),
      ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error.error, "invalid_grant");
    assert!(error.error_description.is_some());
    assert_eq!(cache, "no-store");
  }

  #[tokio::test]
  async fn test_http_malformed_requests() {
    let address = serve().await;

    // Required parameters missing
    let (status, error, cache) = post_form(
      &address,
      &[("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error.error, "invalid_request");
    assert_eq!(cache, "no-store");

    let (status, error, _) = post_form(
      &address,
      &[
        ("grant_type", "client_credentials"),
        ("subject_token", "a.b.c"),
        ("subject_token_type", TOKEN_TYPE_ID_TOKEN),
      ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error.error, "unsupported_grant_type");

    // `resource`, `audience` and `scope` may repeat and are ignored
    let (_, error, _) = post_form(
      &address,
      &[
        ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE),
        ("subject_token", "a.b.c"),
        ("subject_token_type", TOKEN_TYPE_ID_TOKEN),
        ("resource", "https://a.example.com"),
        ("resource", "https://b.example.com"),
        ("scope", "read write"),
      ],
    )
    .await;
    assert_eq!(error.error, "invalid_grant");

    // The RFC requires a form, not json
    let response = reqwest::Client::new()
      .post(format!("{address}/token"))
      .json(&TokenExchangeRequest::id_token("a.b.c"))
      .send()
      .await
      .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error: TokenExchangeError = response.json().await.unwrap();
    assert_eq!(error.error, "invalid_request");

    // Only POST
    let response =
      reqwest::get(format!("{address}/token")).await.unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
  }
}
