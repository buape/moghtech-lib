//! App-level key representation used by the auth server to
//! authenticate the requests of api keys (key + secret) and signing
//! keys (signed with a private key) alike.

/// Implemented for the app specific api key struct, returned from
/// [AuthImpl::get_api_key][crate::AuthImpl::get_api_key] for an api
/// key and [AuthImpl::get_signing_key][crate::AuthImpl::get_signing_key]
/// for a signing key.
///
/// [AuthApiKey] is a ready made implementation
/// for apps which do not need their own struct.
pub trait AuthApiKeyImpl: Send + Sync + 'static {
  /// The id of the user which owns the key.
  fn user_id(&self) -> &str;

  /// Whitelist of CIDR ranges / ip addresses from which
  /// requests using this key are accepted.
  /// Empty means all ips allowed.
  ///
  /// This is enforced by the auth server in
  /// [AuthImpl::get_user_id_from_request_authentication][crate::AuthImpl::get_user_id_from_request_authentication],
  /// on top of the owning user's
  /// [AuthUserImpl::cidr_whitelist][crate::user::AuthUserImpl::cidr_whitelist].
  fn cidr_whitelist(&self) -> &[String] {
    &[]
  }
}

/// An api key or signing key, see [AuthApiKeyImpl].
pub type BoxAuthApiKey = Box<dyn AuthApiKeyImpl>;

/// Ready made [AuthApiKeyImpl] for apps which do not need their own
/// struct, for api keys and signing keys alike.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthApiKey {
  /// The id of the user which owns the key.
  pub user_id: String,
  /// Whitelist of CIDR ranges / ip addresses from which
  /// requests using this key are accepted.
  /// Empty means all ips allowed.
  pub cidr_whitelist: Vec<String>,
}

impl AuthApiKeyImpl for AuthApiKey {
  fn user_id(&self) -> &str {
    &self.user_id
  }
  fn cidr_whitelist(&self) -> &[String] {
    &self.cidr_whitelist
  }
}

impl From<AuthApiKey> for BoxAuthApiKey {
  fn from(api_key: AuthApiKey) -> Self {
    Box::new(api_key)
  }
}
