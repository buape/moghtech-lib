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
//!
//! Apps serving the exchange on another surface (a Vault compatible
//! `auth/jwt/login`) use [exchange_token] and [token_exchange_error].

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
  config::{
    ExternalLoginProvider, ExternalLoginProviderConfig,
    TrustedIssuer, WorkloadRule,
  },
};
use mogh_error::AddStatusCodeError as _;
use mogh_rate_limit::{FailedAttempt, WithFailureRateLimit as _};
use mogh_request_ip::RequestIp;
use tracing::{error, info, instrument};

use crate::{
  AuthImpl, Login, LoginKind,
  api::{
    external::load_provider_client,
    external_login_requires_two_factor,
  },
  middleware::check_user_cidr_whitelist,
  provider::{
    external::{
      BuiltProvider, ExternalLoginInfo, list_external_providers,
      validate_provider_id,
    },
    load_cache::LoadFailedRecently,
    token_exchange::{
      MAX_SUBJECT_TOKEN_LENGTH, TokenVerificationKeys, issuers_match,
      unverified_issuer,
    },
    workload::{
      Claims, WorkloadIdentity, list_trusted_issuers,
      load_verification_keys, lookup_claim, match_rule,
    },
  },
  user::BoxAuthUser,
};

const GOOGLE_ISSUERS: [&str; 2] =
  ["https://accounts.google.com", "accounts.google.com"];

pub fn router<I: AuthImpl>() -> Router {
  Router::new().route("/token", post(token::<I>))
}

/// What the exchange should accept, beyond a valid token.
#[derive(Debug, Clone, Default)]
pub struct TokenExchangeOptions {
  /// Only log in through the login provider or workload rule with
  /// this id or name (Vault's `role`): a workload token is matched
  /// against that rule alone, rather than the first matching rule
  /// of its issuer, and a user token only by that provider. A role
  /// nothing accepting the token's issuer has is refused up front
  /// ([RoleNotFound]), before the exchange has any effect.
  pub role: Option<String>,
}

/// What [exchange_token] logged a token in as.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ExchangedToken {
  /// The issued app token, as the endpoint answers.
  pub response: TokenExchangeResponse,
  /// The id of the user the token belongs to.
  pub user_id: String,
  /// What the token logged in through.
  pub login: ExchangedLogin,
}

/// What a token was exchanged through.
#[derive(Debug, Clone)]
pub enum ExchangedLogin {
  /// A user's token, verified by a login provider.
  Provider {
    provider_id: String,
    provider_name: String,
  },
  /// A workload's token, verified by a trusted issuer and matched
  /// to one of its rules.
  Workload {
    issuer_id: String,
    issuer_name: String,
    rule_id: String,
    rule_name: String,
  },
}

/// The `role` of [TokenExchangeOptions] names no login provider
/// and no workload rule accepting tokens of the token's issuer.
/// Reported as `invalid_grant`; apps can tell it apart with
/// `error.downcast_ref::<RoleNotFound>()`.
#[derive(Debug)]
pub struct RoleNotFound {
  pub role: String,
}

impl std::fmt::Display for RoleNotFound {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "No login provider or workload rule '{}' accepts tokens of this issuer",
      self.role
    )
  }
}

impl std::error::Error for RoleNotFound {}

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
  let (status, error) = token_exchange_error(&e);
  no_store((status, Json(error)).into_response())
}

/// The status and OAuth error (RFC 6749 section 5.2) a failed
/// [exchange_token] is answered with, as the endpoint answers it.
/// Everything but the token's own rejection (`invalid_*`, the rate
/// limit, an unavailable provider) is logged here and reported as
/// a bare `server_error`: the reasons may include internal details.
/// The descriptions of failures counted against the rate limit note
/// the attempts left (`... | You have 2 attempts remaining`).
pub fn token_exchange_error(
  e: &mogh_error::Error,
) -> (StatusCode, TokenExchangeError) {
  let (status, error) =
    if let Some(oauth) = e.error.downcast_ref::<OauthError>() {
      (
        StatusCode::BAD_REQUEST,
        TokenExchangeError {
          error: oauth.code.to_string(),
          error_description: Some(oauth_description(e, oauth)),
        },
      )
    } else if [
      StatusCode::TOO_MANY_REQUESTS,
      // A provider / issuer which can't be reached. The reason
      // was logged where it happened, and isn't part of the error.
      StatusCode::SERVICE_UNAVAILABLE,
    ]
    .contains(&e.status)
    {
      (
        e.status,
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
  (status, error)
}

/// The description of the OAuth error `e` was found to be. A failed
/// exchange counts against the rate limit, which notes how many
/// attempts are left, as it does on the other errors' descriptions.
fn oauth_description(
  e: &mogh_error::Error,
  oauth: &OauthError,
) -> String {
  match e.error.downcast_ref::<FailedAttempt>() {
    Some(attempt) => attempt.annotate(&oauth.description),
    None => oauth.description.clone(),
  }
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
    exchange_token(&auth, ip, request, Default::default()).await
  }
  .await;
  match res {
    Ok(exchanged) => {
      no_store(Json(exchanged.response).into_response())
    }
    Err(e) => error_response(e),
  }
}

/// The RFC 8693 exchange of the `/token` endpoint as a function,
/// for apps serving it on another surface, eg. a Vault compatible
/// `auth/jwt/login`. Exactly what the endpoint does, the failure
/// rate limit by client `ip` included (the surface is
/// unauthenticated wherever it is served): the token is verified
/// by the login providers and trusted issuers, the user's login
/// rules apply, and the app is told about the login through its
/// hooks. Errors map with [token_exchange_error].
pub async fn exchange_token<I: AuthImpl>(
  auth: &I,
  ip: IpAddr,
  request: TokenExchangeRequest,
  options: TokenExchangeOptions,
) -> mogh_error::Result<ExchangedToken> {
  exchange(
    auth,
    ip,
    request,
    |provider| async move { load_provider_client(auth, &provider).await },
    load_issuer_keys,
    options.role.as_deref(),
  )
  .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), &ip)
  .await
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

/// Whether `role` names the provider / rule: by id, slug or name.
fn is_role(role: Option<&str>, names: &[&str]) -> bool {
  role.is_none_or(|role| names.contains(&role))
}

/// The providers which may verify a token claiming to be from `issuer`:
/// enabled, opted in to token exchange, of that issuer, and the
/// `role` if one is named.
///
/// The issuer is not verified at this point, it only selects who
/// verifies the token. Trusted issuers which aren't login providers
/// (workload identity) would be further candidates here.
fn exchange_candidates(
  providers: impl IntoIterator<Item = ExternalLoginProvider>,
  issuer: &str,
  role: Option<&str>,
) -> Vec<ExternalLoginProvider> {
  providers
    .into_iter()
    .filter(|provider| {
      provider.enabled()
        && provider.token_exchange.enabled
        && is_role(
          role,
          &[&provider.id, provider.slug(), &provider.name],
        )
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

/// The RFC 8693 exchange of the `/token` endpoint. The token is either
/// of a user of an external login provider, or of a workload of a
/// trusted issuer.
///
/// `load_client` loads the client which verifies tokens of a provider,
/// `load_keys` the keys which verify tokens of a trusted issuer.
/// `role` restricts both, see [TokenExchangeOptions].
#[instrument("TokenExchange", skip_all, fields(ip = ip.to_string()))]
async fn exchange<I, L, F, K, G>(
  auth: &I,
  ip: IpAddr,
  request: TokenExchangeRequest,
  load_client: L,
  load_keys: K,
  role: Option<&str>,
) -> mogh_error::Result<ExchangedToken>
where
  I: AuthImpl + ?Sized,
  L: Fn(ExternalLoginProvider) -> F,
  F: Future<Output = mogh_error::Result<Arc<BuiltProvider>>>,
  K: Fn(TrustedIssuer) -> G,
  G: Future<Output = mogh_error::Result<Arc<TokenVerificationKeys>>>,
{
  let issued_token_type = validate_request(&request)?;
  let token = request.subject_token.as_str();

  let user_rejection =
    match verify_exchange(auth, token, load_client, role).await {
      Ok(Some(verified)) => {
        return complete_exchange(
          auth,
          ip,
          verified,
          issued_token_type,
        )
        .await;
      }
      Ok(None) => None,
      Err(e) => Some(e),
    };

  let workload_rejection =
    match verify_workload(auth, token, load_keys, role).await {
      Ok(Some(verified)) => {
        return complete_workload(
          auth,
          ip,
          verified,
          issued_token_type,
        )
        .await;
      }
      Ok(None) => None,
      Err(e) => Some(e),
    };

  Err(user_rejection.or(workload_rejection).unwrap_or_else(|| {
    match role {
      // Nothing of that name takes the token's issuer, told
      // apart from a rejected token for Vault's "role not found".
      Some(role) => anyhow::Error::new(RoleNotFound {
        role: role.to_string(),
      })
      .context(OauthError {
        code: "invalid_grant",
        description: format!(
          "No login provider or workload rule '{role}' accepts tokens of this issuer"
        ),
      })
      .status_code(StatusCode::BAD_REQUEST),
      None => invalid_grant(
        "No login provider or trusted issuer accepts tokens of this issuer",
      ),
    }
  }))
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
///
/// `None` if no login provider (named `role`, if one is) takes
/// tokens of the issuer.
pub(crate) async fn verify_exchange<I, L, F>(
  auth: &I,
  token: &str,
  load_client: L,
  role: Option<&str>,
) -> mogh_error::Result<Option<VerifiedExchange>>
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
    role,
  );

  if candidates.is_empty() {
    return Ok(None);
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
    return Ok(Some(VerifiedExchange {
      provider,
      user,
      info,
    }));
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

/// Loads the keys of a trusted issuer. The reason a load fails may
/// include internal addresses, so it is only logged.
async fn load_issuer_keys(
  issuer: TrustedIssuer,
) -> mogh_error::Result<Arc<TokenVerificationKeys>> {
  load_verification_keys(&issuer).await.map_err(|e| {
    // Logged once per attempt, not by every request while it is down.
    if !LoadFailedRecently::is(&e) {
      error!(
        issuer_id = issuer.id,
        issuer = issuer.name,
        "Failed to load keys of trusted issuer | {e:#}"
      );
    }
    anyhow::anyhow!(
      "Trusted issuer '{}' is not available",
      issuer.name
    )
    .status_code(StatusCode::SERVICE_UNAVAILABLE)
  })
}

/// A verified workload token, and the rule it matched.
struct VerifiedWorkload {
  issuer: TrustedIssuer,
  rule: WorkloadRule,
  claims: Claims,
}

/// Finds the trusted issuer which accepts the token, and the rule
/// the token matches: the first matching one, or with a `role` the
/// rule of that id / name. `None` if no trusted issuer has that
/// issuer (and, with a role, a rule of that name).
async fn verify_workload<I, K, G>(
  auth: &I,
  token: &str,
  load_keys: K,
  role: Option<&str>,
) -> mogh_error::Result<Option<VerifiedWorkload>>
where
  I: AuthImpl + ?Sized,
  K: Fn(TrustedIssuer) -> G,
  G: Future<Output = mogh_error::Result<Arc<TokenVerificationKeys>>>,
{
  let issuer = unverified_issuer(token).ok_or_else(|| {
    invalid_grant("The token is not a JWT with an issuer")
  })?;

  // Issuers aren't always unique. Kubernetes clusters share a default
  // issuer and only differ by their keys, so each candidate gets to
  // verify the token with its own.
  let candidates = list_trusted_issuers(auth)
    .await?
    .into_iter()
    .map(|resolved| resolved.issuer)
    .filter(|trusted| {
      trusted.enabled
        && issuers_match(&trusted.issuer, &issuer)
        && trusted
          .rules
          .iter()
          .any(|rule| is_role(role, &[&rule.id, &rule.name]))
    })
    .collect::<Vec<_>>();

  if candidates.is_empty() {
    return Ok(None);
  }

  let mut unavailable = None;
  let mut rejected = None;
  let mut unmatched = None;
  for trusted in candidates {
    let keys = match load_keys(trusted.clone()).await {
      Ok(keys) => keys,
      // Already logged
      Err(e) => {
        unavailable.get_or_insert(e);
        continue;
      }
    };
    let claims = match keys.verify_payload(
      token,
      &trusted.audiences,
      trusted.max_token_age_secs,
    ) {
      Ok(claims) => claims,
      Err(e) => {
        // Only describes the token the caller presented
        rejected = Some(invalid_grant(format!("{e:#}")));
        continue;
      }
    };
    // With a role, only the rule(s) of that name are evaluated,
    // like Vault evaluates the named role.
    let rules = match role {
      Some(_) => trusted
        .rules
        .iter()
        .filter(|rule| is_role(role, &[&rule.id, &rule.name]))
        .cloned()
        .collect::<Vec<_>>(),
      None => trusted.rules.clone(),
    };
    let Some(rule) = match_rule(&rules, &claims).cloned() else {
      unmatched.get_or_insert(invalid_grant(match role {
        Some(role) => format!(
          "The token is valid, but does not match rule '{role}' of '{}'",
          trusted.name
        ),
        None => format!(
          "The token is valid, but matches no rule of '{}'",
          trusted.name
        ),
      }));
      continue;
    };
    check_rule_id(&trusted, &rule)?;
    return Ok(Some(VerifiedWorkload {
      issuer: trusted,
      rule,
      claims,
    }));
  }

  // Report the furthest any issuer got.
  Err(
    unmatched
      .or(rejected)
      .or(unavailable)
      .unwrap_or_else(|| invalid_grant("Token was rejected")),
  )
}

/// The rule id identifies the user of the rule. Ids of stored issuers
/// are generated, but static issuers come from the app configuration,
/// where a missing or repeated id would make rules share one user,
/// and with it each others groups.
fn check_rule_id(
  issuer: &TrustedIssuer,
  rule: &WorkloadRule,
) -> mogh_error::Result<()> {
  let unique = issuer
    .rules
    .iter()
    .filter(|other| other.id == rule.id)
    .count()
    == 1;
  if unique && validate_provider_id(&rule.id).is_ok() {
    return Ok(());
  }
  error!(
    issuer_id = issuer.id,
    issuer = issuer.name,
    rule = rule.name,
    rule_id = rule.id,
    "Rules of a trusted issuer need a unique id (a-z A-Z 0-9 - _)"
  );
  Err(
    anyhow::anyhow!(
      "Trusted issuer '{}' is misconfigured",
      issuer.name
    )
    .into(),
  )
}

/// Claim values end up in the logs, and are as long as the issuer likes.
fn truncate_for_log(value: &str) -> String {
  const MAX: usize = 200;
  match value.char_indices().nth(MAX) {
    Some((index, _)) => format!("{}...", &value[..index]),
    None => value.to_string(),
  }
}

/// Gets the user of the matched rule from the app,
/// applies the login rules and issues a short lived app token.
async fn complete_workload<I: AuthImpl + ?Sized>(
  auth: &I,
  ip: IpAddr,
  VerifiedWorkload {
    issuer,
    rule,
    claims,
  }: VerifiedWorkload,
  issued_token_type: &str,
) -> mogh_error::Result<ExchangedToken> {
  // What identifies the workload, for the audit log below.
  let subject = truncate_for_log(
    claims
      .get("sub")
      .and_then(|sub| sub.as_str())
      .unwrap_or_default(),
  );
  let matched = rule
    .claims
    .iter()
    .filter_map(|condition| {
      let value = lookup_claim(&claims, &condition.claim)?;
      Some(format!(
        "{}={}",
        condition.claim,
        truncate_for_log(&value.to_string())
      ))
    })
    .collect::<Vec<_>>()
    .join(" ");

  let user_id = auth
    .get_or_create_workload_user(WorkloadIdentity {
      issuer_id: issuer.id.clone(),
      rule_id: rule.id.clone(),
      rule_name: rule.name.clone(),
      groups: rule.groups.clone(),
      admin: rule.admin,
      claims,
    })
    .await?;
  let user = auth.get_user(user_id).await?;

  // Without the flag the management API wouldn't
  // stop the workload from creating credentials.
  if !user.is_workload() {
    return Err(
      anyhow::anyhow!(
        "The user returned by 'AuthImpl::get_or_create_workload_user' must report 'AuthUserImpl::is_workload'"
      )
      .into(),
    );
  }

  // Being an admin has to be a decision made on the rule.
  if user.is_admin() && !rule.admin {
    return Err(invalid_grant(format!(
      "The user of rule '{}' is an admin, which the rule doesn't allow",
      rule.name
    )));
  }

  check_user_cidr_whitelist(user.as_ref(), ip)?;

  if external_login_requires_two_factor(user.as_ref()) {
    return Err(invalid_grant(
      "The user of the workload requires a second factor, which a workload can't provide",
    ));
  }

  let login = ExchangedLogin::Workload {
    issuer_id: issuer.id.clone(),
    issuer_name: issuer.name.clone(),
    rule_id: rule.id.clone(),
    rule_name: rule.name.clone(),
  };
  auth
    .record_login(Login::of(
      user.as_ref(),
      ip,
      LoginKind::from(login.clone()),
      None,
    ))
    .await?;

  let default_ttl_ms = auth.jwt_provider().ttl_ms();
  let ttl_ms = match u128::from(rule.token_ttl_secs) * 1000 {
    0 => default_ttl_ms,
    ttl_ms => ttl_ms.min(default_ttl_ms),
  };
  let jwt =
    auth.jwt_provider().encode_sub_with_ttl(user.id(), ttl_ms)?;

  info!(
    user_id = user.id(),
    username = user.username(),
    issuer_id = issuer.id,
    issuer = issuer.name,
    rule_id = rule.id,
    rule = rule.name,
    subject,
    matched,
    "Workload logged in (token exchange)"
  );

  Ok(ExchangedToken {
    response: TokenExchangeResponse {
      access_token: jwt.jwt,
      issued_token_type: issued_token_type.to_string(),
      token_type: "Bearer".to_string(),
      expires_in: u64::try_from(ttl_ms / 1000).unwrap_or(u64::MAX),
    },
    user_id: user.id().to_string(),
    login,
  })
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
) -> mogh_error::Result<ExchangedToken> {
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

  let login = ExchangedLogin::Provider {
    provider_id: provider.id.clone(),
    provider_name: provider.name.clone(),
  };
  auth
    .record_login(Login::of(
      user.as_ref(),
      ip,
      LoginKind::from(login.clone()),
      None,
    ))
    .await?;

  let jwt = auth.jwt_provider().encode_sub(user.id())?;

  info!(
    user_id = user.id(),
    username = user.username(),
    provider_id = provider.id,
    provider = provider.name,
    "User logged in (token exchange)"
  );

  Ok(ExchangedToken {
    response: TokenExchangeResponse {
      access_token: jwt.jwt,
      issued_token_type: issued_token_type.to_string(),
      token_type: "Bearer".to_string(),
      expires_in: u64::try_from(auth.jwt_provider().ttl_ms() / 1000)
        .unwrap_or(u64::MAX),
    },
    user_id: user.id().to_string(),
    login,
  })
}

#[cfg(test)]
mod tests {
  use std::sync::Mutex;

  use anyhow::anyhow;

  use mogh_auth_client::{
    config::{
      NamedOauthConfig, OidcConfig, TokenExchangeConfig,
      TrustedIssuerKeys, WorkloadClaim,
    },
    passkey::Passkey,
  };
  use mogh_rate_limit::RateLimiter;

  use super::*;
  use crate::{
    provider::{
      jwt::JwtProvider,
      oidc::{OidcProvider, UsernameAdditionalClaims},
      token_exchange::test_tokens::{
        CLIENT_ID, ISSUER, Signer, TestToken, jwks_json, metadata,
        other_jwks_json,
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
    workload: bool,
    admin: bool,
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
    fn is_workload(&self) -> bool {
      self.workload
    }
    fn is_admin(&self) -> bool {
      self.admin
    }
  }

  struct TestAuth {
    providers: Vec<ExternalLoginProvider>,
    issuers: Vec<TrustedIssuer>,
    /// The user the app returns for workloads
    workload_user: TestUser,
    workloads: Arc<Mutex<Vec<WorkloadIdentity>>>,
    /// The user linked to ("oidc", "subject-123"), if any
    user: Option<TestUser>,
    sync_fails: bool,
    synced: Arc<Mutex<Vec<ExternalLoginInfo>>>,
    logins: Arc<Mutex<Vec<Login>>>,
    jwt: JwtProvider,
    /// Disabled, unless a test enables it.
    rate_limiter: Arc<RateLimiter>,
  }

  impl TestAuth {
    fn with_user(user: Option<TestUser>) -> TestAuth {
      TestAuth {
        providers: vec![oidc_provider("oidc", true)],
        issuers: Vec::new(),
        workload_user: TestUser {
          workload: true,
          ..Default::default()
        },
        workloads: Default::default(),
        user,
        sync_fails: false,
        synced: Default::default(),
        logins: Default::default(),
        jwt: JwtProvider::new(b"test-jwt-secret", JWT_TTL_MS),
        rate_limiter: RateLimiter::new(true, 0, Default::default()),
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

    fn static_trusted_issuers(&self) -> Vec<TrustedIssuer> {
      self.issuers.clone()
    }

    fn record_login(
      &self,
      login: Login,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      self.logins.lock().unwrap().push(login);
      Box::pin(async { Ok(()) })
    }

    fn get_or_create_workload_user(
      &self,
      identity: WorkloadIdentity,
    ) -> crate::DynFuture<mogh_error::Result<String>> {
      self.workloads.lock().unwrap().push(identity);
      Box::pin(async { Ok("workload-user".to_string()) })
    }

    fn get_user(
      &self,
      user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<BoxAuthUser>> {
      let user = (user_id == "workload-user")
        .then(|| Box::new(self.workload_user.clone()) as BoxAuthUser);
      Box::pin(async move {
        user.ok_or_else(|| anyhow!("no user").into())
      })
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

    fn general_rate_limiter(&self) -> &RateLimiter {
      &self.rate_limiter
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
      slug: String::new(),
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
      slug: String::new(),
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
    run_as(auth, token, None)
      .await
      .map(|exchanged| exchanged.response)
  }

  async fn run_as(
    auth: &TestAuth,
    token: String,
    role: Option<&str>,
  ) -> mogh_error::Result<ExchangedToken> {
    exchange(
      auth,
      IP,
      TokenExchangeRequest::id_token(token),
      load_client,
      load_issuer_keys,
      role,
    )
    .await
  }

  // =====================
  // = WORKLOAD IDENTITY =
  // =====================

  const WORKLOAD_AUDIENCE: &str = "https://app.example.com";

  /// A Github Actions like token of the test issuer.
  fn workload_token(
    repository_id: u64,
    git_ref: &str,
  ) -> TestToken<UsernameAdditionalClaims> {
    TestToken {
      subject: format!("repo:org/app:ref:{git_ref}"),
      audiences: vec![WORKLOAD_AUDIENCE.to_string()],
      ..TestToken::new(UsernameAdditionalClaims {
        username: None,
        extra: [
          (
            "repository_id".to_string(),
            serde_json::json!(repository_id),
          ),
          ("ref".to_string(), serde_json::json!(git_ref)),
        ]
        .into(),
      })
    }
  }

  fn deploy_rule() -> WorkloadRule {
    WorkloadRule {
      id: "deploy".to_string(),
      name: "Deploy".to_string(),
      enabled: true,
      claims: vec![
        WorkloadClaim {
          claim: "repository_id".to_string(),
          pattern: "12345".to_string(),
        },
        WorkloadClaim {
          claim: "ref".to_string(),
          pattern: "refs/heads/release/*".to_string(),
        },
      ],
      groups: vec!["deployers".to_string()],
      admin: false,
      token_ttl_secs: 900,
    }
  }

  /// Static keys, so nothing is fetched.
  fn trusted_issuer(rules: Vec<WorkloadRule>) -> TrustedIssuer {
    TrustedIssuer {
      id: "ci".to_string(),
      name: "CI".to_string(),
      enabled: true,
      issuer: ISSUER.to_string(),
      keys: TrustedIssuerKeys::Static(jwks_json()),
      audiences: vec![WORKLOAD_AUDIENCE.to_string()],
      max_token_age_secs: 0,
      rules,
    }
  }

  fn workload_auth(rules: Vec<WorkloadRule>) -> TestAuth {
    let mut auth = TestAuth::with_user(None);
    auth.providers = Vec::new();
    auth.issuers = vec![trusted_issuer(rules)];
    auth
  }

  #[tokio::test]
  async fn test_workload_gets_short_lived_token_for_rule_user() {
    let auth = workload_auth(vec![deploy_rule()]);
    let token =
      workload_token(12345, "refs/heads/release/1.2").mint();
    let response = run(&auth, token).await.unwrap();

    assert_eq!(
      auth.jwt.decode_sub(&response.access_token).unwrap(),
      "user-id"
    );
    // The rule's lifetime, not the (longer) app default
    assert_eq!(response.expires_in, 900);

    // The app is asked for the user of the rule, with its definition
    let workloads = auth.workloads.lock().unwrap();
    assert_eq!(workloads.len(), 1);
    assert_eq!(workloads[0].issuer_id, "ci");
    assert_eq!(workloads[0].rule_id, "deploy");
    assert_eq!(workloads[0].groups, ["deployers"]);
    assert!(!workloads[0].admin);
    assert_eq!(workloads[0].claims["repository_id"], 12345);
    // Login provider hooks are not involved
    assert!(auth.synced.lock().unwrap().is_empty());
    // The exchange is the rule user's login
    let logins = auth.logins.lock().unwrap();
    assert_eq!(logins.len(), 1);
    assert_eq!(logins[0].user_id, "user-id");
    assert_eq!(
      logins[0].kind,
      LoginKind::Workload {
        issuer_id: "ci".into(),
        issuer_name: "CI".into(),
        rule_id: "deploy".into(),
        rule_name: "Deploy".into(),
      }
    );
  }

  #[tokio::test]
  async fn test_workload_token_ttl_is_capped_at_app_default() {
    let mut rule = deploy_rule();
    rule.token_ttl_secs = 365 * 24 * 60 * 60;
    let auth = workload_auth(vec![rule]);
    let token = workload_token(12345, "refs/heads/release/1").mint();
    assert_eq!(run(&auth, token).await.unwrap().expires_in, 3600);

    let mut rule = deploy_rule();
    rule.token_ttl_secs = 0;
    let auth = workload_auth(vec![rule]);
    let token = workload_token(12345, "refs/heads/release/1").mint();
    assert_eq!(run(&auth, token).await.unwrap().expires_in, 3600);
  }

  #[tokio::test]
  async fn test_workload_token_must_match_a_rule() {
    let auth = workload_auth(vec![deploy_rule()]);
    for token in [
      // Another repository, and another branch
      workload_token(99999, "refs/heads/release/1"),
      workload_token(12345, "refs/heads/main"),
    ] {
      let err = run(&auth, token.mint()).await.unwrap_err();
      assert_eq!(code(&err), "invalid_grant");
      assert!(err.error.to_string().contains("matches no rule"));
    }
    assert!(auth.workloads.lock().unwrap().is_empty());

    // No rules, a disabled rule, or a disabled issuer accept nothing
    let mut disabled_rule = deploy_rule();
    disabled_rule.enabled = false;
    let mut disabled_issuer = workload_auth(vec![deploy_rule()]);
    disabled_issuer.issuers[0].enabled = false;
    for auth in [
      workload_auth(Vec::new()),
      workload_auth(vec![disabled_rule]),
      disabled_issuer,
    ] {
      let token =
        workload_token(12345, "refs/heads/release/1").mint();
      assert!(run(&auth, token).await.is_err());
      assert!(auth.workloads.lock().unwrap().is_empty());
    }
  }

  #[tokio::test]
  async fn test_workload_token_is_verified_like_any_other() {
    let auth = workload_auth(vec![deploy_rule()]);
    let valid = || workload_token(12345, "refs/heads/release/1");
    for token in [
      // The platform default audience, shared with other services
      TestToken {
        audiences: vec!["https://github.com/org".to_string()],
        ..valid()
      },
      TestToken {
        signer: Signer::Other,
        ..valid()
      },
      TestToken {
        expires_in: chrono::Duration::minutes(-1),
        ..valid()
      },
    ] {
      let err = run(&auth, token.mint()).await.unwrap_err();
      assert_eq!(code(&err), "invalid_grant");
    }
    assert!(auth.workloads.lock().unwrap().is_empty());

    // No accepted audience configured accepts nothing
    let mut auth = workload_auth(vec![deploy_rule()]);
    auth.issuers[0].audiences = Vec::new();
    assert!(run(&auth, valid().mint()).await.is_err());
  }

  /// Issuers aren't unique (Kubernetes clusters share a default),
  /// the one whose keys verify the token decides.
  #[tokio::test]
  async fn test_workload_issuers_sharing_an_issuer_url() {
    let mut other_cluster = trusted_issuer(vec![deploy_rule()]);
    other_cluster.id = "other-cluster".to_string();
    // Publishes other keys
    other_cluster.keys = TrustedIssuerKeys::Static(other_jwks_json());
    let mut auth = workload_auth(vec![deploy_rule()]);
    auth.issuers.insert(0, other_cluster);

    let token = workload_token(12345, "refs/heads/release/1").mint();
    assert!(run(&auth, token).await.is_ok());
    assert_eq!(auth.workloads.lock().unwrap()[0].issuer_id, "ci");
  }

  /// Static issuers come from the app configuration. Rules without
  /// (or sharing) an id would share a user, and each others groups.
  #[tokio::test]
  async fn test_workload_rules_need_unique_ids() {
    let token =
      || workload_token(12345, "refs/heads/release/1").mint();
    let mut admin_rule = deploy_rule();
    admin_rule.name = "Admin".to_string();
    admin_rule.admin = true;
    admin_rule.claims[0].pattern = "99999".to_string();

    for id in ["", "deploy", "not valid"] {
      let mut rules = vec![deploy_rule(), admin_rule.clone()];
      rules[0].id = id.to_string();
      rules[1].id = id.to_string();
      let auth = workload_auth(rules);
      let err = run(&auth, token()).await.unwrap_err();
      assert_eq!(
        err.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{id}"
      );
      assert!(auth.workloads.lock().unwrap().is_empty());
    }
  }

  #[test]
  fn test_truncate_for_log() {
    assert_eq!(truncate_for_log("short"), "short");
    let long = "ü".repeat(500);
    let truncated = truncate_for_log(&long);
    assert_eq!(truncated.chars().count(), 203);
    assert!(truncated.ends_with("..."));
  }

  /// An issuer which can't be reached is a temporary
  /// condition for the caller, not a server error.
  #[tokio::test]
  async fn test_workload_unavailable_issuer() {
    let mut auth = workload_auth(vec![deploy_rule()]);
    auth.issuers[0].id = "unavailable-issuer".to_string();
    auth.issuers[0].keys = TrustedIssuerKeys::Static("broken".into());
    let token =
      || workload_token(12345, "refs/heads/release/1").mint();

    // The attempt, and a request during the retry delay
    for _ in 0..2 {
      let err = run(&auth, token()).await.unwrap_err();
      assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
      // Without the reason
      let message = format!("{:#}", err.error);
      assert_eq!(message, "Trusted issuer 'CI' is not available");

      let (status, _, body) = error_body(err).await;
      assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
      assert!(body.contains("temporarily_unavailable"));
    }
    assert!(auth.workloads.lock().unwrap().is_empty());
  }

  #[tokio::test]
  async fn test_workload_user_must_be_flagged_as_workload() {
    let mut auth = workload_auth(vec![deploy_rule()]);
    auth.workload_user.workload = false;
    let token = workload_token(12345, "refs/heads/release/1").mint();
    let err = run(&auth, token).await.unwrap_err();
    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
  }

  #[tokio::test]
  async fn test_workload_admin_has_to_be_allowed_by_the_rule() {
    // Made an admin some other way
    let mut auth = workload_auth(vec![deploy_rule()]);
    auth.workload_user.admin = true;
    let token =
      || workload_token(12345, "refs/heads/release/1").mint();
    let err = run(&auth, token()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");

    let mut rule = deploy_rule();
    rule.admin = true;
    let mut auth = workload_auth(vec![rule]);
    auth.workload_user.admin = true;
    assert!(run(&auth, token()).await.is_ok());
    assert!(auth.workloads.lock().unwrap()[0].admin);
  }

  #[tokio::test]
  async fn test_workload_user_login_rules() {
    let token =
      || workload_token(12345, "refs/heads/release/1").mint();

    let mut auth = workload_auth(vec![deploy_rule()]);
    auth.workload_user.cidr_whitelist =
      vec!["192.168.0.0/16".to_string()];
    let err = run(&auth, token()).await.unwrap_err();
    assert_eq!(err.status, StatusCode::FORBIDDEN);

    let mut auth = workload_auth(vec![deploy_rule()]);
    auth.workload_user.totp = true;
    let err = run(&auth, token()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
  }

  /// A login provider and a trusted issuer are independent: tokens of
  /// an issuer only known as a trusted issuer never reach user logins.
  #[tokio::test]
  async fn test_user_and_workload_paths_are_separate() {
    let mut auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    auth.issuers = vec![trusted_issuer(vec![deploy_rule()])];

    // A user token (audience of the login provider) logs in the user
    let response = run(&auth, token().mint()).await.unwrap();
    assert_eq!(response.expires_in, 3600);
    assert!(auth.workloads.lock().unwrap().is_empty());

    // A workload token is rejected by the login provider
    // (audience), and accepted by the trusted issuer.
    let workload =
      workload_token(12345, "refs/heads/release/1").mint();
    let response = run(&auth, workload).await.unwrap();
    assert_eq!(response.expires_in, 900);
    assert_eq!(auth.workloads.lock().unwrap().len(), 1);
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
    // The exchange is a login through the provider
    let logins = auth.logins.lock().unwrap();
    assert_eq!(logins.len(), 1);
    assert_eq!(logins[0].user_id, "user-id");
    assert!(logins[0].second_factor.is_none());
    assert!(matches!(
      &logins[0].kind,
      LoginKind::Provider { provider_id, .. } if provider_id == "oidc"
    ));
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
      exchange_candidates(providers.clone(), issuer, None)
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

    // A role names a provider by id or name, nothing else qualifies
    let named = |issuer: &str, role: &str| {
      exchange_candidates(providers.clone(), issuer, Some(role))
        .into_iter()
        .map(|provider| provider.id)
        .collect::<Vec<_>>()
    };
    assert_eq!(named(ISSUER, "oidc"), ["oidc"]);
    assert_eq!(named(ISSUER, "OIDC"), ["oidc"]);
    assert!(named(ISSUER, "github").is_empty());
    assert!(named("https://accounts.google.com", "oidc").is_empty());
  }

  // ========
  // = ROLE =
  // ========

  /// The broad rule comes first: without a role it takes every
  /// release token, with the role the narrower rule named is the
  /// one evaluated and logged in as.
  fn broad_then_narrow() -> Vec<WorkloadRule> {
    let mut broad = deploy_rule();
    broad.id = "release".to_string();
    broad.name = "Release".to_string();
    broad.claims.truncate(1);
    broad.groups = vec!["releasers".to_string()];
    vec![broad, deploy_rule()]
  }

  #[tokio::test]
  async fn test_role_selects_the_named_rule() {
    let auth = workload_auth(broad_then_narrow());
    let token =
      || workload_token(12345, "refs/heads/release/1").mint();

    let first = run_as(&auth, token(), None).await.unwrap();
    assert!(matches!(
      &first.login,
      ExchangedLogin::Workload { rule_id, .. } if rule_id == "release"
    ));
    assert_eq!(first.user_id, "user-id");

    // By name, and by id
    for role in ["Deploy", "deploy"] {
      let named = run_as(&auth, token(), Some(role)).await.unwrap();
      let ExchangedLogin::Workload {
        issuer_id,
        issuer_name,
        rule_id,
        rule_name,
      } = &named.login
      else {
        panic!("a workload login")
      };
      assert_eq!(
        (issuer_id.as_str(), issuer_name.as_str()),
        ("ci", "CI")
      );
      assert_eq!(
        (rule_id.as_str(), rule_name.as_str()),
        ("deploy", "Deploy")
      );
      assert_eq!(named.response.expires_in, 900);
    }
    let workloads = auth.workloads.lock().unwrap();
    assert_eq!(workloads.len(), 3);
    assert_eq!(workloads[0].groups, ["releasers"]);
    assert_eq!(workloads[1].groups, ["deployers"]);
  }

  #[tokio::test]
  async fn test_role_refuses_before_any_effect() {
    let auth = workload_auth(broad_then_narrow());

    // The named rule exists but the token doesn't match it: no
    // falling back to the rule which would.
    let token = workload_token(12345, "refs/heads/main").mint();
    let err = run_as(&auth, token, Some("Deploy")).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
    assert!(
      err
        .error
        .to_string()
        .contains("does not match rule 'Deploy'")
    );
    assert!(err.error.downcast_ref::<RoleNotFound>().is_none());

    // No rule (and no provider) of that name takes the issuer:
    // Vault's "role not found", told apart for the app.
    let token = workload_token(12345, "refs/heads/release/1").mint();
    let err = run_as(&auth, token, Some("nope")).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    let not_found = err.error.downcast_ref::<RoleNotFound>().unwrap();
    assert_eq!(not_found.role, "nope");
    let (status, body) = token_exchange_error(&err);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body.error, "invalid_grant");
    assert!(body.error_description.unwrap().contains("'nope'"));

    // Neither refusal reached the app
    assert!(auth.workloads.lock().unwrap().is_empty());
  }

  #[tokio::test]
  async fn test_role_names_a_login_provider() {
    let auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    let exchanged =
      run_as(&auth, token().mint(), Some("OIDC")).await.unwrap();
    assert!(matches!(
      &exchanged.login,
      ExchangedLogin::Provider { provider_id, provider_name }
        if provider_id == "oidc" && provider_name == "OIDC"
    ));
    assert_eq!(exchanged.user_id, "user-id");

    let err = run_as(&auth, token().mint(), Some("other"))
      .await
      .unwrap_err();
    assert!(err.error.downcast_ref::<RoleNotFound>().is_some());
    // Only the successful exchange synced the user
    assert_eq!(auth.synced.lock().unwrap().len(), 1);
  }

  /// [exchange_token] is [exchange] behind the app's failure rate
  /// limit, which must keep the errors' types: the OAuth codes of
  /// the endpoint and the [RoleNotFound] apps tell apart.
  #[tokio::test]
  async fn test_exchange_token_errors_keep_their_type() {
    let mut auth = TestAuth::with_user(None);
    auth.rate_limiter =
      RateLimiter::new(false, 3, std::time::Duration::from_secs(60));
    let exchange_token = |request, role: Option<&str>| {
      exchange_token(
        &auth,
        IP,
        request,
        TokenExchangeOptions {
          role: role.map(String::from),
        },
      )
    };

    let mut request = TokenExchangeRequest::id_token(token().mint());
    request.grant_type = String::from("client_credentials");
    let err = exchange_token(request, None).await.unwrap_err();
    assert_eq!(code(&err), "unsupported_grant_type");
    let (status, body) = token_exchange_error(&err);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
      body,
      TokenExchangeError {
        error: String::from("unsupported_grant_type"),
        // The caller is still told how many attempts are left.
        error_description: Some(format!(
          "Only '{GRANT_TYPE_TOKEN_EXCHANGE}' is supported | You have 2 attempts remaining"
        )),
      }
    );

    let err =
      exchange_token(TokenExchangeRequest::id_token(""), None)
        .await
        .unwrap_err();
    let (status, body) = token_exchange_error(&err);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
      body,
      TokenExchangeError {
        error: String::from("invalid_request"),
        error_description: Some(String::from(
          "'subject_token' is empty | You have 1 attempts remaining"
        )),
      }
    );

    let err = exchange_token(
      TokenExchangeRequest::id_token(token().mint()),
      Some("nope"),
    )
    .await
    .unwrap_err();
    let not_found = err.error.downcast_ref::<RoleNotFound>().unwrap();
    assert_eq!(not_found.role, "nope");
    let (status, body) = token_exchange_error(&err);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
      body,
      TokenExchangeError {
        error: String::from("invalid_grant"),
        error_description: Some(String::from(
          "No login provider or workload rule 'nope' accepts tokens of this issuer | You have 0 attempts remaining"
        )),
      }
    );

    // Out of attempts
    let err = exchange_token(
      TokenExchangeRequest::id_token(token().mint()),
      None,
    )
    .await
    .unwrap_err();
    let (status, body) = token_exchange_error(&err);
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body.error, "temporarily_unavailable");
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

    // A provider or issuer which can't be reached
    let (status, _, body) = error_body(
      anyhow!("Trusted issuer 'CI' is not available")
        .status_code(StatusCode::SERVICE_UNAVAILABLE),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("temporarily_unavailable"));
    assert!(body.contains("not available"));
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
