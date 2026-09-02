use std::{
  collections::HashMap,
  sync::{LazyLock, Mutex},
};

use anyhow::{Context as _, anyhow};
use axum::http::StatusCode;
use data_encoding::BASE32_NOPAD;
use mogh_auth_client::api::login::{
  CompleteTotpLogin, CompleteTotpRecoveryLogin,
};
use mogh_error::{AddStatusCode as _, AddStatusCodeError as _};
use mogh_rate_limit::WithFailureRateLimit;
use mogh_resolver::Resolve;
use tracing::{info, instrument};

use crate::api::login::LoginArgs;

/// Tracks the latest accepted TOTP step per user, to reject reuse
/// of an already accepted code within its valid window ([RFC 6238 §5.2]).
/// In-memory, so this is best-effort protection scoped to this process.
///
/// [RFC 6238 §5.2]: https://datatracker.ietf.org/doc/html/rfc6238#section-5.2
static ACCEPTED_TOTP_STEPS: LazyLock<Mutex<HashMap<String, u64>>> =
  LazyLock::new(Default::default);

/// Returns whether `step` is fresh for this user (strictly newer than
/// the last accepted step), marking it as used if so.
///
/// This is the default implementation of
/// [AuthImpl::consume_totp_step][crate::AuthImpl::consume_totp_step];
/// see that method to enforce this with app-level storage instead.
pub fn consume_totp_step_in_process(
  user_id: &str,
  step: u64,
) -> bool {
  let mut accepted = ACCEPTED_TOTP_STEPS
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner());
  match accepted.get(user_id) {
    Some(last) if step <= *last => false,
    _ => {
      accepted.insert(user_id.to_string(), step);
      true
    }
  }
}

impl Resolve<LoginArgs> for CompleteTotpLogin {
  #[instrument(
    "CompleteTotpLogin",
    skip_all,
    fields(
      ip = ip.to_string(),
    )
  )]
  async fn resolve(
    self,
    LoginArgs { auth, session, ip }: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    async {
      let user_id = session.retrieve_totp_login_user_id().await?;

      let user = auth.get_user(user_id.clone()).await?;
      let totp_secret = user
        .totp_secret()
        .context("User is not enrolled in TOTP 2FA")?;
      let secret_bytes = BASE32_NOPAD
        .decode(totp_secret.as_bytes())
        .context("Failed to decode TOTP secret to bytes")?;

      let totp = auth.make_totp(secret_bytes, None)?;

      // The step is the 30s window since epoch
      // which the TOTP is valid for.
      let step = totp
        .check_current(&self.code)
        .context("Invalid TOTP code")
        .status_code(StatusCode::UNAUTHORIZED)?;

      // A code must only be accepted once (RFC 6238).
      if !auth.consume_totp_step(user_id.clone(), step).await? {
        return Err(
          anyhow!("TOTP code already used. Wait for the next code.")
            .status_code(StatusCode::UNAUTHORIZED),
        );
      }

      let res = auth.jwt_provider().encode_sub(&user_id)?;

      info!(
        user_id = user.id(),
        username = user.username(),
        "TOTP 2FA flow complete, user logged in"
      );

      Ok(res)
    }
    .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), ip)
    .await
  }
}

impl Resolve<LoginArgs> for CompleteTotpRecoveryLogin {
  #[instrument(
    "CompleteTotpRecoveryLogin",
    skip_all,
    fields(
      ip = ip.to_string(),
    )
  )]
  async fn resolve(
    self,
    LoginArgs { auth, session, ip }: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    async {
      let user_id = session.retrieve_totp_login_user_id().await?;

      let user = auth.get_user(user_id.clone()).await?;
      if user.totp_secret().is_none() {
        return Err(
          anyhow!("User is not enrolled in TOTP 2FA")
            .status_code(StatusCode::UNAUTHORIZED),
        );
      }

      // Recovery codes are bcrypt hashed, so each unused code
      // must be verified against the provided one.
      let hashed_code = user
        .hashed_totp_recovery_codes()
        .iter()
        .find(|hash| {
          bcrypt::verify(&self.code, hash).unwrap_or(false)
        })
        .cloned()
        .context("Invalid recovery code")
        .status_code(StatusCode::UNAUTHORIZED)?;

      // Each recovery code can only be used once.
      auth
        .remove_totp_recovery_code(user_id.clone(), hashed_code)
        .await?;

      let res = auth.jwt_provider().encode_sub(&user_id)?;

      info!(
        user_id = user.id(),
        username = user.username(),
        "TOTP recovery code flow complete, user logged in"
      );

      Ok(res)
    }
    .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), ip)
    .await
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_consume_totp_step_rejects_replay() {
    // First use of a step is accepted, replay is rejected.
    assert!(consume_totp_step_in_process("replay-user", 100));
    assert!(!consume_totp_step_in_process("replay-user", 100));
  }

  #[test]
  fn test_consume_totp_step_rejects_older_step() {
    // A code from an older window than the last accepted one
    // is rejected, even within skew.
    assert!(consume_totp_step_in_process("older-step-user", 100));
    assert!(!consume_totp_step_in_process("older-step-user", 99));
  }

  #[test]
  fn test_consume_totp_step_accepts_newer_step() {
    assert!(consume_totp_step_in_process("newer-step-user", 100));
    assert!(consume_totp_step_in_process("newer-step-user", 101));
    assert!(!consume_totp_step_in_process("newer-step-user", 101));
  }

  #[test]
  fn test_consume_totp_step_isolated_per_user() {
    assert!(consume_totp_step_in_process("user-a", 100));
    // Same step for a different user is still accepted.
    assert!(consume_totp_step_in_process("user-b", 100));
  }

  #[test]
  fn test_recovery_code_matches_bcrypt_hash() {
    // The lookup used by CompleteTotpRecoveryLogin: find the
    // stored hash matching the provided code.
    let hashes = [
      bcrypt::hash("code-one", 4).unwrap(),
      bcrypt::hash("code-two", 4).unwrap(),
    ];
    let found = hashes
      .iter()
      .find(|hash| bcrypt::verify("code-two", hash).unwrap_or(false));
    assert_eq!(found, Some(&hashes[1]));
    let missing = hashes.iter().find(|hash| {
      bcrypt::verify("code-three", hash).unwrap_or(false)
    });
    assert!(missing.is_none());
  }
}
