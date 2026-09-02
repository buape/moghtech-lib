use mogh_auth_client::passkey::Passkey;

/// Implemented for app specific User struct.
pub trait AuthUserImpl: Send + Sync + 'static {
  fn id(&self) -> &str;

  fn username(&self) -> &str;

  fn hashed_password(&self) -> Option<&str> {
    None
  }

  fn passkey(&self) -> Option<Passkey> {
    None
  }

  fn totp_secret(&self) -> Option<&str> {
    None
  }

  /// The bcrypt-hashed TOTP recovery codes which have not been used,
  /// as stored by AuthImpl::update_user_stored_totp at enrollment.
  /// Required for recovery code login to work.
  fn hashed_totp_recovery_codes(&self) -> &[String] {
    &[]
  }

  fn external_skip_2fa(&self) -> bool {
    true
  }
}

pub type BoxAuthUser = Box<dyn AuthUserImpl>;
