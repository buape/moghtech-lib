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

use crate::{
  Login, SecondFactor, api::login::LoginArgs,
  middleware::check_user_cidr_whitelist,
};

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
      let user_id = session.begin_totp_login_attempt().await?;

      let user = auth.get_user(user_id.clone()).await?;
      let totp_secret = user
        .totp_secret()
        .context("User is not enrolled in TOTP 2FA")?;

      check_user_cidr_whitelist(user.as_ref(), *ip)?;

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

      let kind = session.complete_totp_login().await?;
      auth
        .record_login(Login::of(
          user.as_ref(),
          *ip,
          kind,
          Some(SecondFactor::Totp),
        ))
        .await?;

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
      let user_id = session.begin_totp_login_attempt().await?;

      let user = auth.get_user(user_id.clone()).await?;
      if user.totp_secret().is_none() {
        return Err(
          anyhow!("User is not enrolled in TOTP 2FA")
            .status_code(StatusCode::UNAUTHORIZED),
        );
      }

      check_user_cidr_whitelist(user.as_ref(), *ip)?;

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

      let kind = session.complete_totp_login().await?;
      auth
        .record_login(Login::of(
          user.as_ref(),
          *ip,
          kind,
          Some(SecondFactor::TotpRecovery),
        ))
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
  use std::sync::{Arc, Mutex};

  use std::net::IpAddr;

  use crate::{
    AuthImpl, Login, LoginKind, SecondFactor,
    provider::jwt::JwtProvider,
    session::Session,
    user::{AuthUserImpl, BoxAuthUser},
  };

  use super::*;

  const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 2, 3));
  const SECRET: &[u8] = b"12345678901234567890";

  struct TestUser;

  impl AuthUserImpl for TestUser {
    fn id(&self) -> &str {
      "totp-hook-user"
    }
    fn username(&self) -> &str {
      "totp"
    }
    fn totp_secret(&self) -> Option<&str> {
      static ENCODED: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| BASE32_NOPAD.encode(SECRET));
      Some(&ENCODED)
    }
  }

  #[derive(Default)]
  struct TestAuth {
    logins: Arc<Mutex<Vec<Login>>>,
  }

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      Self::default()
    }
    fn app_name(&self) -> &'static str {
      "test"
    }
    fn get_user(
      &self,
      _user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<BoxAuthUser>> {
      Box::pin(async { Ok(Box::new(TestUser) as BoxAuthUser) })
    }
    fn handle_request_authentication(
      &self,
      _auth: crate::RequestAuthentication,
      _ip: IpAddr,
      _require_user_enabled: bool,
      req: axum::extract::Request,
    ) -> crate::DynFuture<mogh_error::Result<axum::extract::Request>>
    {
      Box::pin(async { Ok(req) })
    }
    fn jwt_provider(&self) -> &JwtProvider {
      static PROVIDER: std::sync::LazyLock<JwtProvider> =
        std::sync::LazyLock::new(|| {
          JwtProvider::new(b"secret", 60_000)
        });
      &PROVIDER
    }
    fn record_login(
      &self,
      login: Login,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      self.logins.lock().unwrap().push(login);
      Box::pin(async { Ok(()) })
    }
  }

  fn session() -> Session {
    Session(tower_sessions::Session::new(
      None,
      Arc::new(tower_sessions::MemoryStore::default()),
      None,
    ))
  }

  /// A TOTP completion records the login with the kind its first
  /// factor left on the session, and takes both off the session.
  #[tokio::test]
  async fn test_completion_records_the_first_factors_login() {
    let auth = TestAuth::default();
    let logins = auth.logins.clone();
    let code = auth
      .make_totp(SECRET.to_vec(), None)
      .unwrap()
      .generate_current()
      .to_string();
    let session = session();
    session
      .insert_totp_login_user_id("totp-hook-user")
      .await
      .unwrap();
    let provider = LoginKind::Provider {
      provider_id: "oidc".into(),
      provider_name: "OIDC".into(),
    };
    session.insert_login_kind(&provider).await.unwrap();
    let args = LoginArgs {
      auth: Box::new(auth),
      session,
      ip: IP,
    };
    let jwt =
      CompleteTotpLogin { code }.resolve(&args).await.unwrap();
    assert_eq!(
      args.auth.jwt_provider().decode_sub(&jwt.jwt).unwrap(),
      "totp-hook-user"
    );
    {
      let logins = logins.lock().unwrap();
      assert_eq!(logins.len(), 1);
      assert_eq!(logins[0].kind, provider);
      assert_eq!(logins[0].second_factor, Some(SecondFactor::Totp));
      assert_eq!(logins[0].ip, IP);
      assert_eq!(logins[0].username, "totp");
    }
    // Nothing is left on the session
    assert!(args.session.begin_totp_login_attempt().await.is_err());
    assert_eq!(
      args.session.take_login_kind().await,
      LoginKind::Local
    );
  }

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
