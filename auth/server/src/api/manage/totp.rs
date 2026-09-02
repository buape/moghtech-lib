use anyhow::Context as _;
use axum::http::StatusCode;
use data_encoding::BASE32_NOPAD;
use mogh_auth_client::api::manage::{
  BeginTotpEnrollment, BeginTotpEnrollmentResponse,
  ConfirmTotpEnrollment, ConfirmTotpEnrollmentResponse, UnenrollTotp,
  UnenrollTotpResponse,
};
use mogh_error::AddStatusCode as _;
use mogh_resolver::Resolve;
use tracing::{info, instrument};

use crate::{
  AuthImpl,
  api::manage::ManageArgs,
  rand::{random_bytes, random_string},
};

/// 160 bits
const TOTP_ENROLLMENT_SECRET_LENGTH: usize = 40;

//

impl Resolve<ManageArgs> for BeginTotpEnrollment {
  #[instrument(
    "BeginTotpEnrollment",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
    )
  )]
  async fn resolve(
    self,
    ManageArgs {
      auth,
      user,
      session,
    }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    auth.check_username_locked(user.username())?;

    let totp = auth.make_totp(
      random_bytes(TOTP_ENROLLMENT_SECRET_LENGTH),
      Some(user.id().to_string()),
    )?;

    let png = totp
      .to_qr_base64()
      .map_err(anyhow::Error::msg)
      .context("Failed to generate QR code png")?;
    let uri =
      totp.to_url().context("Failed to generate QR code uri")?;

    session.insert_totp_enrollment(&totp).await?;

    info!("Totp 2FA enrollment flow initiated");

    Ok(BeginTotpEnrollmentResponse { uri, png })
  }
}

//

impl Resolve<ManageArgs> for ConfirmTotpEnrollment {
  #[instrument(
    "ConfirmTotpEnrollment",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
    )
  )]
  async fn resolve(
    self,
    ManageArgs {
      auth,
      user,
      session,
    }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    let totp = session.retrieve_totp_enrollment().await?;

    // The step is the 30s window since epoch
    // which the TOTP is valid for.
    let _step = totp
      .check_current(&self.code)
      .context("The provided code was not valid. Please try BeginTotpEnrollment flow again.")
      .status_code(StatusCode::BAD_REQUEST)?;

    let recovery_codes =
      (0..10).map(|_| random_string(20)).collect::<Vec<_>>();
    let hashed_recovery_codes = recovery_codes
      .iter()
      .map(|code| {
        bcrypt::hash(code, auth.local_auth_bcrypt_cost())
          .context("Failed to hash a recovery code.")
      })
      .collect::<anyhow::Result<Vec<_>>>()
      .context("Failed to generate valid recovery codes")?;

    auth
      .update_user_stored_totp(
        user.id().to_string(),
        BASE32_NOPAD.encode(totp.secret()),
        hashed_recovery_codes,
      )
      .await?;

    info!("TOTP 2FA enrollment complete");

    Ok(ConfirmTotpEnrollmentResponse { recovery_codes })
  }
}

//

pub async fn unenroll_totp<I: AuthImpl + ?Sized>(
  auth: &I,
  username: &str,
  user_id: String,
) -> mogh_error::Result<()> {
  auth.check_username_locked(username)?;
  auth.remove_user_stored_totp(user_id).await?;
  Ok(())
}

impl Resolve<ManageArgs> for UnenrollTotp {
  #[instrument(
    "UnenrollTotp",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
    )
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    unenroll_totp(
      auth.as_ref(),
      user.username(),
      user.id().to_string(),
    )
    .await?;

    info!("User unenrolled TOTP 2FA");

    Ok(UnenrollTotpResponse {})
  }
}

#[cfg(test)]
mod tests {
  use axum::extract::Request;
  use data_encoding::BASE32_NOPAD;

  use super::*;
  use crate::{
    DynFuture, RequestAuthentication, rand::random_bytes,
    user::BoxAuthUser,
  };

  struct TestAuth;

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      TestAuth
    }

    fn app_name(&self) -> &'static str {
      "TestApp"
    }

    fn get_user(
      &self,
      _user_id: String,
    ) -> DynFuture<mogh_error::Result<BoxAuthUser>> {
      Box::pin(async {
        Err(anyhow::anyhow!("not implemented").into())
      })
    }

    fn handle_request_authentication(
      &self,
      _auth: RequestAuthentication,
      _require_user_enabled: bool,
      _req: Request,
    ) -> DynFuture<mogh_error::Result<Request>> {
      Box::pin(async {
        Err(anyhow::anyhow!("not implemented").into())
      })
    }

    fn jwt_provider(&self) -> &crate::provider::jwt::JwtProvider {
      panic!("not needed for these tests")
    }

    fn get_api_key_hashed_secret(
      &self,
      _key: String,
    ) -> DynFuture<mogh_error::Result<Option<String>>> {
      Box::pin(async { Ok(None) })
    }
  }

  #[test]
  fn test_totp_current_code_round_trip() {
    let auth = TestAuth;
    let totp = auth
      .make_totp(random_bytes(TOTP_ENROLLMENT_SECRET_LENGTH), None)
      .unwrap();
    let code = totp.generate_current().to_string();
    assert_eq!(code.len(), 6);
    assert!(totp.check_current(&code).is_some());
  }

  #[test]
  fn test_totp_rejects_wrong_code() {
    let auth = TestAuth;
    let totp = auth
      .make_totp(random_bytes(TOTP_ENROLLMENT_SECRET_LENGTH), None)
      .unwrap();
    let code = totp.generate_current().to_string();
    // Flip the first digit
    let first = code.chars().next().unwrap();
    let flipped = if first == '9' { '0' } else { '9' };
    let wrong = format!("{flipped}{}", &code[1..]);
    assert!(totp.check_current(&wrong).is_none());
  }

  #[test]
  fn test_totp_rejects_malformed_code() {
    let auth = TestAuth;
    let totp = auth
      .make_totp(random_bytes(TOTP_ENROLLMENT_SECRET_LENGTH), None)
      .unwrap();
    assert!(totp.check_current("").is_none());
    assert!(totp.check_current("not-a-code").is_none());
    assert!(totp.check_current("12345").is_none());
  }

  #[test]
  fn test_totp_secret_base32_storage_round_trip() {
    // Enrollment stores BASE32_NOPAD(secret) (ConfirmTotpEnrollment),
    // login decodes it back (CompleteTotpLogin). A code generated by
    // the enrollment Totp must validate on the login Totp.
    let auth = TestAuth;
    let enrollment_totp = auth
      .make_totp(
        random_bytes(TOTP_ENROLLMENT_SECRET_LENGTH),
        Some("user-id".to_string()),
      )
      .unwrap();

    let stored = BASE32_NOPAD.encode(enrollment_totp.secret());
    let secret_bytes =
      BASE32_NOPAD.decode(stored.as_bytes()).unwrap();
    let login_totp = auth.make_totp(secret_bytes, None).unwrap();

    let code = enrollment_totp.generate_current().to_string();
    assert!(login_totp.check_current(&code).is_some());
  }
}
