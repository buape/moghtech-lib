//! Workload identity: tokens of a [TrustedIssuer] are matched against
//! its [WorkloadRule]s, and the matching rule decides who the workload
//! acts as. See [crate::api::token] for the exchange itself.

use std::{
  collections::HashMap,
  hash::{DefaultHasher, Hash as _, Hasher as _},
  sync::{Arc, Mutex, OnceLock},
  time::Duration,
};

use anyhow::{Context as _, anyhow};
use mogh_auth_client::config::{
  TrustedIssuer, TrustedIssuerKeys, WorkloadClaim, WorkloadRule,
};
use openidconnect::{IssuerUrl, core::CoreJsonWebKeySet};
use serde_json::{Map, Value};
use tracing::warn;

use crate::{
  AuthImpl,
  provider::{
    external::validate_provider_id,
    load_cache::LoadCache,
    token_exchange::{TokenVerificationKeys, issuers_match},
  },
  validations::redact_url_credentials,
};

/// Fetched keys are reused for 5min, so a rotation at the issuer is picked up.
const FETCHED_KEYS_VALID_FOR: Duration = Duration::from_secs(5 * 60);
/// Nested claims deeper than this are not looked up.
const MAX_CLAIM_PATH_PARTS: usize = 16;
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Far larger than any real key set.
pub const MAX_JWKS_LENGTH: usize = 256 * 1024;

pub type Claims = Map<String, Value>;

/// The workload a verified token belongs to, passed to
/// [AuthImpl::get_or_create_workload_user].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WorkloadIdentity {
  /// The id of the [TrustedIssuer] which issued the token.
  pub issuer_id: String,
  /// The id of the matched [WorkloadRule]. Together with
  /// `issuer_id` this identifies the user of the workload:
  /// every token matching the rule acts as the same user.
  pub rule_id: String,
  /// The name of the rule, to name the user after.
  pub rule_name: String,
  /// The app groups the user must have. This is the full
  /// list: groups not on it should be removed from the user.
  pub groups: Vec<String>,
  /// Whether the user must be an admin.
  pub admin: bool,
  /// The verified claims of the token, eg. to record which
  /// repository / run / service account the user was last used by.
  pub claims: Claims,
}

// ============
// = MATCHING =
// ============

/// `*` matches any run of characters (including none),
/// everything else is literal and case sensitive.
pub fn glob_match(pattern: &str, value: &str) -> bool {
  let mut parts = pattern.split('*');
  // Without any '*' the first part is the whole pattern.
  let first = parts.next().unwrap_or_default();
  let Some(mut rest) = value.strip_prefix(first) else {
    return false;
  };
  let mut parts = parts.peekable();
  if parts.peek().is_none() {
    return rest.is_empty();
  }
  while let Some(part) = parts.next() {
    if parts.peek().is_none() {
      // The last part has to end the value.
      return rest.ends_with(part);
    }
    match rest.find(part) {
      Some(index) => rest = &rest[index + part.len()..],
      None => return false,
    }
  }
  true
}

/// Finds the claim at a dotted path. Claim names can contain dots
/// themselves (`kubernetes.io`), so every split of the path is tried,
/// longest names first.
pub fn lookup_claim<'a>(
  claims: &'a Claims,
  path: &str,
) -> Option<&'a Value> {
  fn lookup<'a>(
    claims: &'a Claims,
    parts: &[&str],
  ) -> Option<&'a Value> {
    for split in (1..=parts.len()).rev() {
      let Some(value) = claims.get(&parts[..split].join(".")) else {
        continue;
      };
      if split == parts.len() {
        return Some(value);
      }
      if let Some(found) = value
        .as_object()
        .and_then(|nested| lookup(nested, &parts[split..]))
      {
        return Some(found);
      }
    }
    None
  }
  let parts = path.split('.').collect::<Vec<_>>();
  // Every split is tried at every level, which gets expensive fast.
  if path.is_empty() || parts.len() > MAX_CLAIM_PATH_PARTS {
    return None;
  }
  lookup(claims, &parts)
}

fn claim_matches(claims: &Claims, condition: &WorkloadClaim) -> bool {
  let matches = |value: &Value| match value {
    Value::String(value) => glob_match(&condition.pattern, value),
    Value::Bool(value) => {
      glob_match(&condition.pattern, &value.to_string())
    }
    Value::Number(value) => {
      glob_match(&condition.pattern, &value.to_string())
    }
    _ => false,
  };
  match lookup_claim(claims, &condition.claim) {
    // One of the values of a list, eg. `aud`
    Some(Value::Array(values)) => values.iter().any(matches),
    Some(value) => matches(value),
    // A missing claim never matches, whatever the pattern.
    None => false,
  }
}

/// The first enabled rule the claims meet all conditions of.
/// A rule without conditions never matches.
pub fn match_rule<'a>(
  rules: &'a [WorkloadRule],
  claims: &Claims,
) -> Option<&'a WorkloadRule> {
  rules.iter().find(|rule| {
    rule.enabled
      && !rule.claims.is_empty()
      && rule
        .claims
        .iter()
        .all(|condition| claim_matches(claims, condition))
  })
}

// ========
// = KEYS =
// ========

pub fn parse_jwks(jwks: &str) -> anyhow::Result<CoreJsonWebKeySet> {
  if jwks.len() > MAX_JWKS_LENGTH {
    return Err(anyhow!("Key set is too large"));
  }
  let jwks: CoreJsonWebKeySet = serde_json::from_str(jwks)
    .context("Invalid key set (JWKS) json")?;
  if jwks.keys().is_empty() {
    return Err(anyhow!("Key set (JWKS) has no usable keys"));
  }
  Ok(jwks)
}

fn http_client() -> &'static reqwest::Client {
  static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
  CLIENT.get_or_init(|| {
    reqwest::Client::builder()
      .redirect(reqwest::redirect::Policy::none())
      .timeout(FETCH_TIMEOUT)
      .user_agent(concat!(
        env!("CARGO_PKG_NAME"),
        "/",
        env!("CARGO_PKG_VERSION")
      ))
      .build()
      .expect("Invalid workload identity reqwest client")
  })
}

/// Reads at most [MAX_JWKS_LENGTH], whatever the server sends.
///
/// The management api refuses urls with credentials, but issuers
/// configured elsewhere (static ones, rows stored before) may still
/// carry them: errors name the url without them.
async fn fetch_text(url: &str) -> anyhow::Result<String> {
  let shown = redact_url_credentials(url);
  let mut response = http_client()
    .get(url)
    .send()
    .await
    .with_context(|| format!("Failed to reach {shown}"))?
    .error_for_status()
    .with_context(|| format!("Request to {shown} failed"))?;
  let too_large = || anyhow!("Response of {shown} is too large");
  if response
    .content_length()
    .is_some_and(|length| length > MAX_JWKS_LENGTH as u64)
  {
    return Err(too_large());
  }
  let mut body = Vec::<u8>::new();
  while let Some(chunk) = response
    .chunk()
    .await
    .with_context(|| format!("Failed to read response of {shown}"))?
  {
    if body.len() + chunk.len() > MAX_JWKS_LENGTH {
      return Err(too_large());
    }
    body.extend_from_slice(&chunk);
  }
  String::from_utf8(body).with_context(|| {
    format!("Response of {shown} is not valid UTF-8")
  })
}

/// The part of OpenID discovery workload issuers publish. They have
/// no login endpoints, so they are not valid OIDC provider metadata.
#[derive(serde::Deserialize)]
struct IssuerDiscovery {
  issuer: String,
  jwks_uri: String,
}

async fn load_jwks(
  issuer: &TrustedIssuer,
) -> anyhow::Result<CoreJsonWebKeySet> {
  let jwks_uri = match &issuer.keys {
    TrustedIssuerKeys::Static(jwks) => return parse_jwks(jwks),
    TrustedIssuerKeys::JwksUri(url) => url.clone(),
    TrustedIssuerKeys::Discovery {} => {
      let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.issuer.trim_end_matches('/')
      );
      let discovery: IssuerDiscovery =
        serde_json::from_str(&fetch_text(&url).await?)
          .context("Invalid OpenID discovery document")?;
      if !issuers_match(&discovery.issuer, &issuer.issuer) {
        return Err(anyhow!(
          "Discovery document is for another issuer: {}",
          discovery.issuer
        ));
      }
      discovery.jwks_uri
    }
  };
  parse_jwks(&fetch_text(&jwks_uri).await?)
}

/// See [LoadCache] for how concurrent
/// exchanges and outages of the issuer are handled.
fn keys_cache() -> &'static LoadCache<TokenVerificationKeys> {
  static CACHE: OnceLock<LoadCache<TokenVerificationKeys>> =
    OnceLock::new();
  CACHE.get_or_init(Default::default)
}

/// Only what the keys depend on, rule changes don't reload them.
fn keys_fingerprint(issuer: &TrustedIssuer) -> u64 {
  let mut hasher = DefaultHasher::new();
  issuer.issuer.hash(&mut hasher);
  issuer.keys.hash(&mut hasher);
  hasher.finish()
}

/// The keys to verify tokens of the issuer with, cached
/// until its key configuration changes or they are outdated.
pub async fn load_verification_keys(
  issuer: &TrustedIssuer,
) -> anyhow::Result<Arc<TokenVerificationKeys>> {
  // Static keys only change with the configuration
  let valid_for = match issuer.keys {
    TrustedIssuerKeys::Static(_) => None,
    _ => Some(FETCHED_KEYS_VALID_FOR),
  };
  keys_cache()
    .load(&issuer.id, keys_fingerprint(issuer), valid_for, || async {
      Ok(TokenVerificationKeys::new(
        IssuerUrl::new(issuer.issuer.clone())
          .context("Issuer is not a valid url")?,
        load_jwks(issuer).await?,
      ))
    })
    .await
}

pub fn evict_verification_keys(issuer_id: &str) {
  keys_cache().evict(issuer_id);
}

// ==============
// = USER LOCKS =
// ==============

type UserLocks =
  Mutex<HashMap<(String, String), Arc<tokio::sync::Mutex<()>>>>;

/// One lock per (issuer id, rule id) with a caller.
fn user_locks() -> &'static UserLocks {
  static LOCKS: OnceLock<UserLocks> = OnceLock::new();
  LOCKS.get_or_init(Default::default)
}

/// Held while the app gets or creates the user of a rule, see
/// [lock_workload_user]. Releases the lock when dropped.
pub struct WorkloadUserLock {
  key: (String, String),
  guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for WorkloadUserLock {
  fn drop(&mut self) {
    let mut locks =
      user_locks().lock().unwrap_or_else(|e| e.into_inner());
    drop(self.guard.take());
    // Waiting callers hold a clone, which is only taken with the
    // map locked: nobody but the map holding it means nobody waits.
    if locks
      .get(&self.key)
      .is_some_and(|lock| Arc::strong_count(lock) == 1)
    {
      locks.remove(&self.key);
    }
  }
}

/// Serializes the exchanges of one rule (`issuer_id`, `rule_id`)
/// around [AuthImpl::get_or_create_workload_user]. A CI matrix starts
/// many jobs at once, and without this all their first exchanges ask
/// the app for a user which doesn't exist yet at the same moment,
/// racing to create it. Exchanges of other rules don't wait.
///
/// This only covers one instance of the app: apps running several
/// still need a get or create which is safe under concurrency.
pub async fn lock_workload_user(
  issuer_id: &str,
  rule_id: &str,
) -> WorkloadUserLock {
  let key = (issuer_id.to_string(), rule_id.to_string());
  let lock = user_locks()
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .entry(key.clone())
    .or_default()
    .clone();
  let guard = lock.lock_owned().await;
  WorkloadUserLock {
    key,
    guard: Some(guard),
  }
}

// ==============
// = RESOLUTION =
// ==============

/// A [TrustedIssuer] and where it comes from.
pub struct ResolvedIssuer {
  pub issuer: TrustedIssuer,
  /// Whether the issuer comes from [AuthImpl::static_trusted_issuers],
  /// and can't be managed over the API.
  pub is_static: bool,
}

/// Lists all the trusted issuers, static ones first.
/// Issuers with invalid or duplicate ids are skipped.
pub async fn list_trusted_issuers<I: AuthImpl + ?Sized>(
  auth: &I,
) -> mogh_error::Result<Vec<ResolvedIssuer>> {
  let stored = auth.list_trusted_issuers().await?;
  let mut issuers = Vec::<ResolvedIssuer>::new();
  let all = auth
    .static_trusted_issuers()
    .into_iter()
    .map(|issuer| (issuer, true))
    .chain(stored.into_iter().map(|issuer| (issuer, false)));
  for (issuer, is_static) in all {
    if let Err(e) = validate_provider_id(&issuer.id) {
      warn!(
        "Skipping trusted issuer '{}' with invalid id '{}' | {e:#}",
        issuer.name, issuer.id
      );
      continue;
    }
    if issuers
      .iter()
      .any(|existing| existing.issuer.id == issuer.id)
    {
      warn!(
        "Skipping trusted issuer '{}' with duplicate id '{}'",
        issuer.name, issuer.id
      );
      continue;
    }
    issuers.push(ResolvedIssuer { issuer, is_static });
  }
  Ok(issuers)
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  use super::*;
  use crate::provider::token_exchange::test_tokens::jwks_json;

  fn claims(value: Value) -> Claims {
    value.as_object().unwrap().clone()
  }

  fn condition(claim: &str, pattern: &str) -> WorkloadClaim {
    WorkloadClaim {
      claim: claim.to_string(),
      pattern: pattern.to_string(),
    }
  }

  fn rule(id: &str, conditions: &[(&str, &str)]) -> WorkloadRule {
    WorkloadRule {
      id: id.to_string(),
      name: id.to_string(),
      enabled: true,
      claims: conditions
        .iter()
        .map(|(claim, pattern)| condition(claim, pattern))
        .collect(),
      ..Default::default()
    }
  }

  #[test]
  fn test_glob_match() {
    for (pattern, value, expected) in [
      ("main", "main", true),
      ("main", "main2", false),
      ("main", "amain", false),
      ("", "", true),
      ("", "a", false),
      ("*", "", true),
      ("*", "anything/at all", true),
      ("refs/heads/*", "refs/heads/release/1", true),
      ("refs/heads/*", "refs/tags/v1", false),
      ("refs/heads/*", "refs/heads/", true),
      ("*/main", "refs/heads/main", true),
      ("*/main", "refs/heads/main2", false),
      (
        "repo:org/*:ref:refs/heads/main",
        "repo:org/app:ref:refs/heads/main",
        true,
      ),
      (
        "repo:org/*:ref:refs/heads/main",
        "repo:evil/app:ref:refs/heads/main",
        false,
      ),
      ("a*b*c", "aXbXc", true),
      ("a*b*c", "abc", true),
      ("a*b*c", "acb", false),
      // The parts can't overlap
      ("ab*ba", "aba", false),
      ("ab*ba", "abba", true),
      // Literal, not a regex or a character class
      ("a.c", "abc", false),
      ("a?c", "abc", false),
      ("Main", "main", false),
      // Multibyte values
      ("*ü*", "grüße", true),
      ("grü*e", "grüße", true),
    ] {
      assert_eq!(
        glob_match(pattern, value),
        expected,
        "{pattern} / {value}"
      );
    }
  }

  #[test]
  fn test_lookup_claim_with_dotted_names() {
    let claims = claims(json!({
      "sub": "system:serviceaccount:prod:deployer",
      "kubernetes.io": {
        "namespace": "prod",
        "serviceaccount": { "name": "deployer" },
      },
      "realm_access": { "roles": ["a"] },
      "a.b": "flat",
      "a": { "b": "nested" },
    }));
    assert_eq!(
      lookup_claim(&claims, "kubernetes.io.namespace"),
      Some(&json!("prod"))
    );
    assert_eq!(
      lookup_claim(&claims, "kubernetes.io.serviceaccount.name"),
      Some(&json!("deployer"))
    );
    assert_eq!(
      lookup_claim(&claims, "realm_access.roles"),
      Some(&json!(["a"]))
    );
    // The exact name wins over a nested path
    assert_eq!(lookup_claim(&claims, "a.b"), Some(&json!("flat")));
    for missing in
      ["", "missing", "sub.nested", "kubernetes.io.missing", "."]
    {
      assert_eq!(lookup_claim(&claims, missing), None, "{missing}");
    }
  }

  #[test]
  fn test_match_rule() {
    let claims = claims(json!({
      "sub": "repo:org/app:ref:refs/heads/main",
      "repository_id": 12345,
      "repository_owner_id": "99",
      "ref": "refs/heads/main",
      "aud": ["https://app.example.com", "other"],
      "protected": true,
      "nested": { "object": {} },
    }));
    let matched = |rules: &[WorkloadRule]| {
      match_rule(rules, &claims).map(|rule| rule.id.clone())
    };

    // All conditions have to match
    assert_eq!(
      matched(&[rule(
        "a",
        &[("repository_id", "12345"), ("ref", "refs/heads/*")]
      )]),
      Some("a".to_string())
    );
    assert_eq!(
      matched(&[rule(
        "a",
        &[("repository_id", "12345"), ("ref", "refs/tags/*")]
      )]),
      None
    );
    // Numbers, booleans, and one value of a list
    assert!(
      matched(&[rule("a", &[("protected", "true")])]).is_some()
    );
    assert!(
      matched(&[rule("a", &[("aud", "https://app.example.com")])])
        .is_some()
    );
    // Missing claims and objects never match, not even a wildcard
    assert!(matched(&[rule("a", &[("missing", "*")])]).is_none());
    assert!(matched(&[rule("a", &[("nested", "*")])]).is_none());
    // A rule without conditions would match every token
    assert!(matched(&[rule("a", &[])]).is_none());

    // The first enabled matching rule decides
    let mut disabled = rule("disabled", &[("ref", "*")]);
    disabled.enabled = false;
    assert_eq!(
      matched(&[
        disabled,
        rule("no-match", &[("ref", "refs/tags/*")]),
        rule("first", &[("ref", "refs/heads/main")]),
        rule("second", &[("ref", "*")]),
      ]),
      Some("first".to_string())
    );
  }

  #[test]
  fn test_parse_jwks() {
    assert!(parse_jwks(&jwks_json()).is_ok());
    for invalid in ["", "not json", "{}", r#"{"keys":[]}"#] {
      assert!(parse_jwks(invalid).is_err(), "{invalid}");
    }
    // Keys of unknown types are skipped, leaving none
    assert!(parse_jwks(r#"{"keys":[{"kty":"unknown"}]}"#).is_err());
    assert!(parse_jwks(&" ".repeat(MAX_JWKS_LENGTH + 1)).is_err());
  }

  #[tokio::test]
  async fn test_static_keys_are_cached_until_changed() {
    let mut issuer = TrustedIssuer {
      id: "keys-cache-test".to_string(),
      name: "Test".to_string(),
      enabled: true,
      issuer: "https://issuer.example.com".to_string(),
      keys: TrustedIssuerKeys::Static(jwks_json()),
      audiences: vec!["app".to_string()],
      max_token_age_secs: 0,
      rules: Vec::new(),
    };
    let first = load_verification_keys(&issuer).await.unwrap();
    // Rule changes don't reload the keys
    issuer.rules.push(rule("a", &[("sub", "a")]));
    let second = load_verification_keys(&issuer).await.unwrap();
    assert!(Arc::ptr_eq(&first, &second));

    issuer.issuer = "https://other.example.com".to_string();
    let third = load_verification_keys(&issuer).await.unwrap();
    assert!(!Arc::ptr_eq(&first, &third));

    evict_verification_keys(&issuer.id);
    let fourth = load_verification_keys(&issuer).await.unwrap();
    assert!(!Arc::ptr_eq(&third, &fourth));

    issuer.keys = TrustedIssuerKeys::Static("broken".to_string());
    assert!(load_verification_keys(&issuer).await.is_err());
  }

  /// Serves a discovery document and key set like a workload issuer.
  /// `discovery_issuer` overrides the issuer the document claims to be for.
  async fn serve_issuer(
    discovery_issuer: Option<&'static str>,
  ) -> String {
    use axum::{Json, Router, routing::get};
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address =
      format!("http://{}", listener.local_addr().unwrap());
    let issuer = discovery_issuer
      .map(str::to_string)
      .unwrap_or_else(|| address.clone());
    let jwks_uri = format!("{address}/keys");
    let router = Router::new()
      .route(
        "/.well-known/openid-configuration",
        get(move || async move {
          // No login endpoints, like Github Actions or Kubernetes
          Json(json!({ "issuer": issuer, "jwks_uri": jwks_uri }))
        }),
      )
      .route(
        "/keys",
        get(|| async {
          ([("content-type", "application/json")], jwks_json())
        }),
      )
      .route(
        "/redirect",
        get(|| async { axum::response::Redirect::to("/keys") }),
      );
    tokio::spawn(async move {
      axum::serve(listener, router).await.unwrap();
    });
    address
  }

  fn fetched_issuer(
    id: &str,
    issuer: &str,
    keys: TrustedIssuerKeys,
  ) -> TrustedIssuer {
    TrustedIssuer {
      id: id.to_string(),
      name: "Test".to_string(),
      enabled: true,
      issuer: issuer.to_string(),
      keys,
      audiences: vec!["app".to_string()],
      max_token_age_secs: 0,
      rules: Vec::new(),
    }
  }

  #[tokio::test]
  async fn test_keys_from_discovery_and_url() {
    let address = serve_issuer(None).await;
    let discovery = fetched_issuer(
      "fetch-discovery",
      // Trailing slash tolerant
      &format!("{address}/"),
      TrustedIssuerKeys::Discovery {},
    );
    assert!(load_verification_keys(&discovery).await.is_ok());

    let url = fetched_issuer(
      "fetch-url",
      "https://unreachable.example.com",
      TrustedIssuerKeys::JwksUri(format!("{address}/keys")),
    );
    assert!(load_verification_keys(&url).await.is_ok());
  }

  /// The token endpoint is unauthenticated, requests naming an
  /// unreachable issuer must not each cause another fetch.
  #[tokio::test]
  async fn test_failed_load_is_not_retried_right_away() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static FETCHES: AtomicUsize = AtomicUsize::new(0);

    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address =
      format!("http://{}", listener.local_addr().unwrap());
    let router = axum::Router::new().route(
      "/keys",
      axum::routing::get(|| async {
        FETCHES.fetch_add(1, Ordering::SeqCst);
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
      }),
    );
    tokio::spawn(async move {
      axum::serve(listener, router).await.unwrap();
    });

    let issuer = fetched_issuer(
      "fetch-negative-cache",
      &address,
      TrustedIssuerKeys::JwksUri(format!("{address}/keys")),
    );
    for _ in 0..5 {
      assert!(load_verification_keys(&issuer).await.is_err());
    }
    assert_eq!(FETCHES.load(Ordering::SeqCst), 1);

    // A changed configuration is tried right away
    let mut changed = issuer.clone();
    changed.keys =
      TrustedIssuerKeys::JwksUri(format!("{address}/keys?v=2"));
    assert!(load_verification_keys(&changed).await.is_err());
    assert_eq!(FETCHES.load(Ordering::SeqCst), 2);
  }

  #[tokio::test]
  async fn test_oversized_response_is_not_read() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    // A content length over the limit is refused before reading
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let declared =
      format!("http://{}", listener.local_addr().unwrap());
    let router = axum::Router::new().route(
      "/keys",
      axum::routing::get(|| async {
        " ".repeat(MAX_JWKS_LENGTH + 1)
      }),
    );
    tokio::spawn(async move {
      axum::serve(listener, router).await.unwrap();
    });

    // A server which doesn't say how much it
    // sends, and keeps sending until the client hangs up.
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endless =
      format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
      let (mut socket, _) = listener.accept().await.unwrap();
      let mut request = [0u8; 1024];
      let _ = socket.read(&mut request).await;
      let _ = socket
        .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
        .await;
      let chunk = vec![b' '; 64 * 1024];
      while socket.write_all(&chunk).await.is_ok() {}
    });

    for address in [declared, endless] {
      let err = tokio::time::timeout(
        Duration::from_secs(5),
        fetch_text(&format!("{address}/keys")),
      )
      .await
      .expect("the read must stop at the limit")
      .unwrap_err();
      assert!(format!("{err:#}").contains("too large"), "{err:#}");
    }
  }

  /// Issuers configured outside the management api may still have
  /// credentials in their urls, errors (which get logged) never show them.
  #[tokio::test]
  async fn test_fetch_errors_hide_url_credentials() {
    let address = serve_issuer(None).await;
    let with_credentials =
      address.replace("http://", "http://user:hunter2@");
    // Nothing listens there anymore
    let closed = {
      let listener =
        tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
      format!(
        "http://user:hunter2@{}",
        listener.local_addr().unwrap()
      )
    };
    for (id, issuer, keys) in [
      (
        "fetch-credentials-unreachable",
        closed.clone(),
        TrustedIssuerKeys::JwksUri(format!("{closed}/keys")),
      ),
      (
        "fetch-credentials-missing",
        address.clone(),
        TrustedIssuerKeys::JwksUri(format!(
          "{with_credentials}/missing"
        )),
      ),
      (
        "fetch-credentials-not-keys",
        address.clone(),
        TrustedIssuerKeys::JwksUri(format!(
          "{with_credentials}/.well-known/openid-configuration"
        )),
      ),
      (
        "fetch-credentials-discovery",
        closed.clone(),
        TrustedIssuerKeys::Discovery {},
      ),
    ] {
      let issuer = fetched_issuer(id, &issuer, keys);
      let err = load_verification_keys(&issuer).await.err().unwrap();
      for shown in [format!("{err:#}"), format!("{err:?}")] {
        assert!(!shown.contains("hunter2"), "{id}: {shown}");
      }
    }
    let err =
      fetch_text(&format!("{closed}/keys")).await.unwrap_err();
    assert!(
      format!("{err:#}").contains("Failed to reach http://***@"),
      "{err:#}"
    );
  }

  /// Exchanges of one rule get the user one after another, those of
  /// other rules don't wait, and nothing is left behind in the map.
  #[tokio::test]
  async fn test_workload_user_lock() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let holders = Arc::new(AtomicUsize::new(0));
    let max_holders = Arc::new(AtomicUsize::new(0));
    let callers = (0..20)
      .map(|_| {
        let (holders, max_holders) =
          (holders.clone(), max_holders.clone());
        tokio::spawn(async move {
          let _lock =
            lock_workload_user("lock-test", "same-rule").await;
          let now = holders.fetch_add(1, Ordering::SeqCst) + 1;
          max_holders.fetch_max(now, Ordering::SeqCst);
          tokio::time::sleep(Duration::from_millis(5)).await;
          holders.fetch_sub(1, Ordering::SeqCst);
        })
      })
      .collect::<Vec<_>>();
    // Another rule, while the first one is held.
    let other = lock_workload_user("lock-test", "other-rule").await;
    for caller in callers {
      caller.await.unwrap();
    }
    assert_eq!(max_holders.load(Ordering::SeqCst), 1);

    let held = |rule: &str| {
      user_locks()
        .lock()
        .unwrap()
        .contains_key(&("lock-test".to_string(), rule.to_string()))
    };
    assert!(!held("same-rule"));
    assert!(held("other-rule"));
    drop(other);
    assert!(!held("other-rule"));

    // A caller giving up while waiting doesn't block the next one.
    let first = lock_workload_user("lock-test", "cancelled").await;
    let waiting = tokio::time::timeout(
      Duration::from_millis(20),
      lock_workload_user("lock-test", "cancelled"),
    )
    .await;
    assert!(waiting.is_err());
    drop(first);
    let next = tokio::time::timeout(
      Duration::from_secs(5),
      lock_workload_user("lock-test", "cancelled"),
    )
    .await;
    assert!(next.is_ok());
    drop(next);
    assert!(!held("cancelled"));
  }

  #[test]
  fn test_lookup_claim_path_depth_is_bounded() {
    let claims = claims(json!({ "a": "value" }));
    let deep = vec!["a"; MAX_CLAIM_PATH_PARTS + 1].join(".");
    assert_eq!(lookup_claim(&claims, &deep), None);
  }

  #[tokio::test]
  async fn test_keys_fetch_failures() {
    // The document must be for the configured issuer, otherwise any
    // server could vouch for the keys of another issuer.
    let address =
      serve_issuer(Some("https://other.example.com")).await;
    let wrong_issuer = fetched_issuer(
      "fetch-wrong-issuer",
      &address,
      TrustedIssuerKeys::Discovery {},
    );
    let err =
      load_verification_keys(&wrong_issuer).await.err().unwrap();
    assert!(format!("{err:#}").contains("another issuer"), "{err:#}");

    for (id, url) in [
      // Redirects are not followed
      ("fetch-redirect", format!("{address}/redirect")),
      ("fetch-missing", format!("{address}/missing")),
      // Not a key set
      (
        "fetch-not-keys",
        format!("{address}/.well-known/openid-configuration"),
      ),
    ] {
      let issuer = fetched_issuer(
        id,
        &address,
        TrustedIssuerKeys::JwksUri(url.clone()),
      );
      assert!(
        load_verification_keys(&issuer).await.is_err(),
        "{url}"
      );
    }
  }
}
