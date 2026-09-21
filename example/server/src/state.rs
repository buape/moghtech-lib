use std::{
  sync::{Arc, LazyLock, OnceLock},
  time::Duration,
};

use example_client::api::read::GetStatsResponse;
use mogh_auth_client::config::{
  ExternalLoginProvider, TrustedIssuer,
};
use mogh_auth_server::{
  provider::{jwt::JwtProvider, passkey::PasskeyProvider},
  rand::random_string,
};
use mogh_cache::{CloneCache, TimeoutCache};
use mogh_rate_limit::RateLimiter;
use tracing::warn;

use crate::config::core_config;

pub const APP_NAME: &str = "MoghExample";

pub fn jwt_provider() -> &'static JwtProvider {
  static JWT_PROVIDER: OnceLock<JwtProvider> = OnceLock::new();
  JWT_PROVIDER.get_or_init(|| {
    let config = core_config();
    let secret = if config.jwt_secret.is_empty() {
      warn!(
        "No 'jwt_secret' configured, users are logged out on restart"
      );
      random_string(40)
    } else {
      config.jwt_secret.clone()
    };
    JwtProvider::new(
      secret.as_bytes(),
      config.jwt_ttl_seconds as u128 * 1000,
    )
    // Tokens of another app sharing the secret are not accepted.
    .with_iss(config.host.clone())
    .with_aud(APP_NAME)
  })
}

pub fn passkey_provider() -> Option<&'static PasskeyProvider> {
  static PASSKEY_PROVIDER: LazyLock<Option<PasskeyProvider>> =
    LazyLock::new(|| {
      PasskeyProvider::new(&core_config().host)
        .inspect_err(|e| {
          warn!("Invalid 'host' for passkey provider | {e:#}")
        })
        .ok()
    });
  PASSKEY_PROVIDER.as_ref()
}

fn rate_limiter() -> Arc<RateLimiter> {
  let config = core_config();
  RateLimiter::new(
    config.auth_rate_limit_disabled,
    config.auth_rate_limit_max_attempts,
    Duration::from_secs(config.auth_rate_limit_window_seconds),
  )
}

/// Failed authentication of any kind, by ip.
pub fn general_rate_limiter() -> &'static RateLimiter {
  static LIMITER: OnceLock<Arc<RateLimiter>> = OnceLock::new();
  LIMITER.get_or_init(rate_limiter)
}

/// Failed password logins have their own budget, so the
/// remaining attempts shown to the user are accurate.
pub fn local_login_rate_limiter() -> &'static RateLimiter {
  static LIMITER: OnceLock<Arc<RateLimiter>> = OnceLock::new();
  LIMITER.get_or_init(rate_limiter)
}

/// The stored login providers / trusted issuers are read by
/// unauthenticated requests (the login options, every token exchange),
/// so they are served from memory and only reloaded after a change.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AuthCacheKey {
  LoginProviders,
  TrustedIssuers,
}

#[derive(Clone, Debug)]
pub enum AuthCacheEntry {
  LoginProviders(Arc<Vec<ExternalLoginProvider>>),
  TrustedIssuers(Arc<Vec<TrustedIssuer>>),
}

pub fn auth_cache()
-> &'static CloneCache<AuthCacheKey, AuthCacheEntry> {
  static CACHE: OnceLock<CloneCache<AuthCacheKey, AuthCacheEntry>> =
    OnceLock::new();
  CACHE.get_or_init(Default::default)
}

/// How long [GetStatsResponse] is reused for.
pub const STATS_VALID_FOR_MS: i64 = 2_000;

pub fn stats_cache() -> &'static TimeoutCache<(), GetStatsResponse> {
  static CACHE: OnceLock<TimeoutCache<(), GetStatsResponse>> =
    OnceLock::new();
  CACHE.get_or_init(Default::default)
}
