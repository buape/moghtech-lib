#[macro_use]
extern crate tracing;

use anyhow::Context as _;

use crate::config::{core_config, core_keys};

mod api;
mod auth;
mod config;
mod crypto;
mod db;
mod state;

async fn app() -> anyhow::Result<()> {
  let config = core_config();
  info!("Example Server version: v{}", env!("CARGO_PKG_VERSION"));

  // Zero max attempts would refuse every authentication attempt.
  if config.auth_rate_limit_max_attempts < 1 {
    return Err(anyhow::anyhow!(
      "Invalid 'auth_rate_limit_max_attempts' config: must be at least 1 (use 'auth_rate_limit_disabled' to turn the limiter off)"
    ));
  }

  // The client ip drives the auth rate limiter and the cidr whitelists,
  // so an invalid list is a startup error rather than a silent fallback.
  let trusted_proxies =
    mogh_server::TrustedProxies::from_config(&config.trusted_proxies)
      .context("Invalid 'trusted_proxies' config")?;
  info!("Trusted Proxies: {trusted_proxies:?}");

  // Fails here if the private key is invalid.
  info!("Public Key: {}", core_keys().load().public());

  db::init().await?;
  // Fails here if the encryption key is invalid.
  crypto::encryption_key();

  mogh_server::serve_app(api::app(), config, None).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let config = core_config();
  mogh_logger::init(&config.logging)?;

  let mut term_signal = tokio::signal::unix::signal(
    tokio::signal::unix::SignalKind::terminate(),
  )?;

  tokio::select! {
    res = tokio::spawn(app()) => res?,
    _ = term_signal.recv() => Ok(()),
  }
}

// Dev dependencies used by the integration tests only.
#[cfg(test)]
use {
  example_mock_idp as _, reqwest as _, tempfile as _, totp_rs as _,
};
