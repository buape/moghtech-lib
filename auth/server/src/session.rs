use anyhow::Context;
use axum::extract::FromRequestParts;
use mogh_error::{AddStatusCode, AddStatusCodeError as _};
use reqwest::StatusCode;
use webauthn_rs::prelude::{
  PasskeyAuthentication, PasskeyRegistration,
};

use crate::provider::external::SessionExternalLogin;

#[derive(Clone)]
pub struct Session(pub tower_sessions::Session);

impl<S: Send + Sync> FromRequestParts<S> for Session {
  type Rejection = mogh_error::Error;

  async fn from_request_parts(
    parts: &mut axum::http::request::Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    let session = parts
      .extensions
      .get::<tower_sessions::Session>()
      .cloned()
      .context("Request context missing Session extension")?;
    Ok(Session(session))
  }
}

impl Session {
  // =========
  // = LOGIN =
  // =========

  const AUTHENTICATED_USER_ID: &str = "authenticated-user-id";

  pub fn id(&self) -> Option<tower_sessions::session::Id> {
    self.0.id()
  }

  pub async fn insert_authenticated_user_id(
    &self,
    user_id: &str,
  ) -> mogh_error::Result<()> {
    // Cycle the session id on privilege elevation to
    // prevent session fixation attacks. All session data
    // is retained under the new id.
    self
      .0
      .cycle_id()
      .await
      .context("Failed to cycle session id")?;
    self
      .0
      .insert(Self::AUTHENTICATED_USER_ID, user_id)
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  pub async fn retrieve_authenticated_user_id(
    &self,
  ) -> mogh_error::Result<String> {
    self
      .0
      .remove(Self::AUTHENTICATED_USER_ID)
      .await
      .context("Internal session type error")?
      .context("Authentication steps must be completed before JWT can be retrieved")
      .status_code(StatusCode::UNAUTHORIZED)
  }

  const EXTERNAL_LOGIN: &str = "external-login";

  /// Store the in flight external login or link.
  /// Only one can be in flight per session, starting
  /// another replaces the previous one.
  pub async fn insert_external_login(
    &self,
    login: &SessionExternalLogin,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::EXTERNAL_LOGIN, login)
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  /// Takes the in flight external login or link,
  /// it can only be completed once.
  pub async fn retrieve_external_login(
    &self,
  ) -> mogh_error::Result<SessionExternalLogin> {
    self
      .0
      .remove(Self::EXTERNAL_LOGIN)
      .await
      .context("Internal session type error")?
      .context(
        "External login has not been initiated for this session",
      )
      .status_code(StatusCode::UNAUTHORIZED)
  }

  // =============
  // = 2FA LOGIN =
  // =============

  const PASSKEY_LOGIN: &str = "passkey-login";

  pub async fn insert_passkey_login(
    &self,
    user_id: &str,
    state: &PasskeyAuthentication,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::PASSKEY_LOGIN, (user_id, state))
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  pub async fn retrieve_passkey_login(
    &self,
  ) -> mogh_error::Result<(String, PasskeyAuthentication)> {
    self
      .0
      .remove(Self::PASSKEY_LOGIN)
      .await
      .context("Internal session type error")?
      .context(
        "Passkey login has not been initiated for this session",
      )
      .status_code(StatusCode::UNAUTHORIZED)
  }

  const TOTP_LOGIN: &str = "totp-login";
  const TOTP_LOGIN_ATTEMPTS: &str = "totp-login-attempts";

  /// How many codes (TOTP or recovery) can be tried for one
  /// first factor login, before it has to be started again.
  pub const MAX_TOTP_LOGIN_ATTEMPTS: u32 = 5;

  /// Insert the user id which began totp login
  pub async fn insert_totp_login_user_id(
    &self,
    user_id: &str,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::TOTP_LOGIN_ATTEMPTS, 0u32)
      .await
      .context("Failed to serialize session data")?;
    self
      .0
      .insert(Self::TOTP_LOGIN, user_id)
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  /// Returns the user id which began totp login, and counts an attempt
  /// at the second factor. The login stays on the session, so a
  /// mistyped code can be tried again without logging in from the
  /// start, up to [Self::MAX_TOTP_LOGIN_ATTEMPTS] times. Finish it
  /// with [Self::complete_totp_login] once the code is accepted.
  pub async fn begin_totp_login_attempt(
    &self,
  ) -> mogh_error::Result<String> {
    let user_id = self
      .0
      .get::<String>(Self::TOTP_LOGIN)
      .await
      .context("Internal session type error")?
      .context("TOTP login has not been initiated for this session")
      .status_code(StatusCode::UNAUTHORIZED)?;
    let attempts = self
      .0
      .get::<u32>(Self::TOTP_LOGIN_ATTEMPTS)
      .await
      .context("Internal session type error")?
      .unwrap_or_default();
    if attempts >= Self::MAX_TOTP_LOGIN_ATTEMPTS {
      self.complete_totp_login().await?;
      return Err(
        anyhow::anyhow!("Too many invalid codes. Log in again.")
          .status_code(StatusCode::UNAUTHORIZED),
      );
    }
    self
      .0
      .insert(Self::TOTP_LOGIN_ATTEMPTS, attempts + 1)
      .await
      .context("Failed to serialize session data")?;
    Ok(user_id)
  }

  /// Removes the totp login from the session, it can only be completed once.
  pub async fn complete_totp_login(&self) -> mogh_error::Result<()> {
    self
      .0
      .remove::<String>(Self::TOTP_LOGIN)
      .await
      .context("Internal session type error")?;
    self
      .0
      .remove::<u32>(Self::TOTP_LOGIN_ATTEMPTS)
      .await
      .context("Internal session type error")?;
    Ok(())
  }

  // ==================
  // = 2FA ENROLLMENT =
  // ==================

  const PASSKEY_ENROLLMENT: &str = "passkey-enrollment";

  pub async fn insert_passkey_enrollment(
    &self,
    state: &PasskeyRegistration,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::PASSKEY_ENROLLMENT, state)
      .await
      .context("Session: Failed to insert passkey enrollment state")
      .map_err(Into::into)
  }

  pub async fn retrieve_passkey_enrollment(
    &self,
  ) -> mogh_error::Result<PasskeyRegistration> {
    self
      .0
      .remove(Self::PASSKEY_ENROLLMENT)
      .await
      .context("Internal session type error")?
      .context(
        "Passkey enrollment has not been initiated for this session",
      )
      .status_code(StatusCode::UNAUTHORIZED)
  }

  const TOTP_ENROLLMENT: &str = "totp-enrollment";

  /// Insert the totp which began totp enrollment
  pub async fn insert_totp_enrollment(
    &self,
    totp: &totp_rs::Totp,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::TOTP_ENROLLMENT, totp)
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  /// Returns the user id which began totp enrollment
  pub async fn retrieve_totp_enrollment(
    &self,
  ) -> mogh_error::Result<totp_rs::Totp> {
    self
      .0
      .remove(Self::TOTP_ENROLLMENT)
      .await
      .context("Internal session type error")?
      .context(
        "TOTP enrollment has not been initiated for this session",
      )
      .status_code(StatusCode::UNAUTHORIZED)
  }

  // ========
  // = LINK =
  // ========

  const EXTERNAL_LINK: &str = "external-link";

  /// Insert the user id which began external login linking
  pub async fn insert_external_link_user_id(
    &self,
    user_id: &str,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::EXTERNAL_LINK, user_id)
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  /// Returns the user id which began external login linking
  pub async fn retrieve_external_link_user_id(
    &self,
  ) -> mogh_error::Result<String> {
    self
      .0
      .remove(Self::EXTERNAL_LINK)
      .await
      .context("Internal session type error")?
      .context(
        "External link has not been initiated for this session",
      )
      .status_code(StatusCode::UNAUTHORIZED)
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::*;

  fn session() -> Session {
    Session(tower_sessions::Session::new(
      None,
      Arc::new(tower_sessions::MemoryStore::default()),
      None,
    ))
  }

  #[tokio::test]
  async fn test_totp_login_requires_first_factor() {
    let session = session();
    let err = session.begin_totp_login_attempt().await.unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn test_totp_login_can_be_retried_up_to_the_limit() {
    let session = session();
    session.insert_totp_login_user_id("user-1").await.unwrap();
    // A mistyped code doesn't end the login.
    for _ in 0..Session::MAX_TOTP_LOGIN_ATTEMPTS {
      assert_eq!(
        session.begin_totp_login_attempt().await.unwrap(),
        "user-1"
      );
    }
    // Out of attempts, and the login is gone.
    let err = session.begin_totp_login_attempt().await.unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(format!("{:#}", err.error).contains("Too many"));
    let err = session.begin_totp_login_attempt().await.unwrap_err();
    assert!(
      format!("{:#}", err.error).contains("not been initiated")
    );
  }

  #[tokio::test]
  async fn test_totp_login_attempts_reset_by_new_first_factor() {
    let session = session();
    session.insert_totp_login_user_id("user-1").await.unwrap();
    for _ in 0..Session::MAX_TOTP_LOGIN_ATTEMPTS {
      session.begin_totp_login_attempt().await.unwrap();
    }
    session.insert_totp_login_user_id("user-1").await.unwrap();
    assert_eq!(
      session.begin_totp_login_attempt().await.unwrap(),
      "user-1"
    );
  }

  #[tokio::test]
  async fn test_totp_login_completes_once() {
    let session = session();
    session.insert_totp_login_user_id("user-1").await.unwrap();
    session.begin_totp_login_attempt().await.unwrap();
    session.complete_totp_login().await.unwrap();
    // An accepted code ends the login, it can't be completed again.
    let err = session.begin_totp_login_attempt().await.unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }
}
