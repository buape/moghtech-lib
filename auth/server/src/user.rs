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

  /// Whitelist of CIDR ranges (eg `10.0.0.0/8`) or ip addresses
  /// from which user logins / api calls are accepted.
  /// Empty means all ips allowed.
  ///
  /// Enforced by the auth server on all login flows
  /// (local, 2FA completion, OIDC / social callbacks)
  /// and on authenticated auth management API calls.
  /// Apps must enforce this on their own APIs in
  /// [AuthImpl::handle_request_authentication][crate::AuthImpl::handle_request_authentication],
  /// see [middleware::check_user_cidr_whitelist][crate::middleware::check_user_cidr_whitelist].
  fn cidr_whitelist(&self) -> &[String] {
    &[]
  }
}

pub type BoxAuthUser = Box<dyn AuthUserImpl>;
