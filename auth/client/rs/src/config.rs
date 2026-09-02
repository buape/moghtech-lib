use serde::{Deserialize, Serialize};

pub fn empty_or_redacted(src: &str) -> String {
  if src.is_empty() {
    String::new()
  } else {
    String::from("##############")
  }
}

/// Configuration for OIDC provider
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OidcConfig {
  /// Enable login with configured OIDC provider.
  #[serde(default)]
  pub enabled: bool,
  /// Configure OIDC provider address for
  /// communcation directly with the app server.
  ///
  /// Note. Needs to be reachable from the app server.
  ///
  /// `https://accounts.example.internal/application/o/appname`
  #[serde(default)]
  pub provider: String,
  /// Configure OIDC user redirect host.
  ///
  /// This is the host address users are redirected to in their browser,
  /// and may be different from the `provider` host.
  /// DO NOT include the `path` part, this must be inferred from the above provider path.
  /// If not provided, the host will be the same as `oidc_provider`.
  /// Eg. `https://accounts.example.external`
  #[serde(default)]
  pub redirect_host: String,
  /// Set OIDC client id
  ///
  /// Alias: 'id'
  #[serde(default)]
  #[serde(alias = "id")]
  pub client_id: String,
  /// Set OIDC client secret
  ///
  /// Alias: 'secret'
  #[serde(default)]
  #[serde(alias = "secret")]
  pub client_secret: String,
  /// Use the full email for usernames.
  /// Otherwise, the @address will be stripped,
  /// making usernames more concise.
  #[serde(default)]
  pub use_full_email: bool,
  /// Your OIDC provider may set additional audiences other than `client_id`,
  /// they must be added here to make claims verification work.
  #[serde(default)]
  pub additional_audiences: Vec<String>,
  /// Automatically redirect unauthenticated users to the OIDC provider
  /// instead of showing the login page.
  #[serde(default)]
  pub auto_redirect: bool,
}

impl OidcConfig {
  pub fn enabled(&self) -> bool {
    self.enabled
      && !self.provider.is_empty()
      && !self.client_id.is_empty()
  }

  pub fn sanitize(&mut self) {
    self.client_id = empty_or_redacted(&self.client_id);
    self.client_secret = empty_or_redacted(&self.client_secret);
  }
}

/// Configuration for a named Oauth2 provider,
/// like Github or Google.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NamedOauthConfig {
  /// Whether this login provider is enabled.
  #[serde(default)]
  pub enabled: bool,
  /// The Oauth client id.
  ///
  /// Alias: 'id'
  #[serde(default)]
  #[serde(alias = "id")]
  pub client_id: String,
  /// The Oauth client secret.
  ///
  /// Alias: 'secret'
  #[serde(default)]
  #[serde(alias = "secret")]
  pub client_secret: String,
}

impl NamedOauthConfig {
  pub fn enabled(&self) -> bool {
    self.enabled && !self.client_id.is_empty()
  }

  pub fn sanitize(&mut self) {
    self.client_id = empty_or_redacted(&self.client_id);
    self.client_secret = empty_or_redacted(&self.client_secret);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_empty_or_redacted() {
    assert_eq!(empty_or_redacted(""), "");
    let redacted = empty_or_redacted("super-secret");
    assert!(!redacted.is_empty());
    assert!(!redacted.contains("super-secret"));
  }

  #[test]
  fn test_oidc_config_defaults_from_empty_json() {
    let config: OidcConfig = serde_json::from_str("{}").unwrap();
    assert!(!config.enabled);
    assert!(config.provider.is_empty());
    assert!(config.redirect_host.is_empty());
    assert!(config.client_id.is_empty());
    assert!(config.client_secret.is_empty());
    assert!(!config.use_full_email);
    assert!(config.additional_audiences.is_empty());
    assert!(!config.auto_redirect);
    assert!(!config.enabled());
  }

  #[test]
  fn test_oidc_config_default_auto_redirect_false() {
    let config = OidcConfig::default();
    assert!(!config.auto_redirect);
  }

  #[test]
  fn test_oidc_config_serde_roundtrip_with_auto_redirect() {
    let config = OidcConfig {
      enabled: true,
      provider: "https://idp.example.com".into(),
      client_id: "test-id".into(),
      client_secret: "test-secret".into(),
      auto_redirect: true,
      ..Default::default()
    };
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: OidcConfig =
      serde_json::from_str(&json).unwrap();
    assert!(deserialized.auto_redirect);
    assert!(deserialized.enabled());
  }

  #[test]
  fn test_oidc_config_deserialize_without_auto_redirect() {
    // Backwards compatibility: old configs without auto_redirect
    let json = r#"{"enabled":true,"provider":"https://idp.example.com","client_id":"test-id","client_secret":"s","use_full_email":false,"additional_audiences":[]}"#;
    let config: OidcConfig = serde_json::from_str(json).unwrap();
    assert!(!config.auto_redirect);
  }

  #[test]
  fn test_oidc_config_id_and_secret_aliases() {
    let json = r#"{"enabled":true,"provider":"https://idp.example.com","id":"aliased-id","secret":"aliased-secret"}"#;
    let config: OidcConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.client_id, "aliased-id");
    assert_eq!(config.client_secret, "aliased-secret");
  }

  #[test]
  fn test_oidc_config_enabled_requires_provider_and_client_id() {
    let mut config = OidcConfig {
      enabled: true,
      provider: "https://idp.example.com".into(),
      client_id: "id".into(),
      ..Default::default()
    };
    assert!(config.enabled());
    config.provider = String::new();
    assert!(!config.enabled());
    config.provider = "https://idp.example.com".into();
    config.client_id = String::new();
    assert!(!config.enabled());
    config.client_id = "id".into();
    config.enabled = false;
    assert!(!config.enabled());
  }

  #[test]
  fn test_oidc_config_sanitize_redacts_credentials() {
    let mut config = OidcConfig {
      client_id: "id".into(),
      client_secret: "secret".into(),
      ..Default::default()
    };
    config.sanitize();
    assert!(!config.client_id.contains("id"));
    assert!(!config.client_secret.contains("secret"));
    // Empty fields stay empty after sanitize.
    let mut config = OidcConfig::default();
    config.sanitize();
    assert!(config.client_id.is_empty());
    assert!(config.client_secret.is_empty());
  }

  #[test]
  fn test_named_oauth_config_defaults_and_aliases() {
    let config: NamedOauthConfig =
      serde_json::from_str("{}").unwrap();
    assert!(!config.enabled);
    assert!(!config.enabled());
    let json =
      r#"{"enabled":true,"id":"gh-id","secret":"gh-secret"}"#;
    let config: NamedOauthConfig =
      serde_json::from_str(json).unwrap();
    assert_eq!(config.client_id, "gh-id");
    assert_eq!(config.client_secret, "gh-secret");
    assert!(config.enabled());
  }

  #[test]
  fn test_named_oauth_config_serde_field_names_stable() {
    let config = NamedOauthConfig {
      enabled: true,
      client_id: "id".into(),
      client_secret: "secret".into(),
    };
    let value = serde_json::to_value(&config).unwrap();
    assert_eq!(
      value,
      serde_json::json!({
        "enabled": true,
        "client_id": "id",
        "client_secret": "secret",
      })
    );
  }
}
