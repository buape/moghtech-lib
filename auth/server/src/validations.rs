//! Default username / password validations.
//! These can be overridden on AuthImpl.

use anyhow::Context as _;
use mogh_validations::{StringValidator, StringValidatorMatches};

/// Minimum length for usernames
pub const MIN_USERNAME_LENGTH: usize = 1;
/// Maximum length for usernames
pub const MAX_USERNAME_LENGTH: usize = 100;

/// Validate usernames
///
/// - Between [MIN_USERNAME_LENGTH] and [MAX_USERNAME_LENGTH] characters
/// - Matches `^[a-zA-Z0-9._@-]+$`
pub fn validate_username(username: &str) -> anyhow::Result<()> {
  StringValidator::default()
    .min_length(MIN_USERNAME_LENGTH)
    .max_length(MAX_USERNAME_LENGTH)
    .matches(StringValidatorMatches::Username)
    .validate(username)
    .context("Failed to validate username")
}

/// Minimum length for passwords
pub const MIN_PASSWORD_LENGTH: usize = 8;
/// Maximum length for passwords
pub const MAX_PASSWORD_LENGTH: usize = 1000;

/// Validate passwords
///
/// - Between [MIN_PASSWORD_LENGTH] and [MAX_PASSWORD_LENGTH] characters
pub fn validate_password(password: &str) -> anyhow::Result<()> {
  StringValidator::default()
    .min_length(MIN_PASSWORD_LENGTH)
    .max_length(MAX_PASSWORD_LENGTH)
    .validate(password)
    .context("Failed to validate password")
}

/// Maximum length for API key names
pub const MAX_API_KEY_NAME_LENGTH: usize = 200;

/// Validate api key names
///
/// - Greater than [MAX_API_KEY_NAME_LENGTH] characters
pub fn validate_api_key_name(name: &str) -> anyhow::Result<()> {
  StringValidator::default()
    .max_length(MAX_API_KEY_NAME_LENGTH)
    .validate(name)
    .context("Failed to validate api key name")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_validate_username_bounds() {
    assert!(validate_username("").is_err());
    assert!(validate_username("a").is_ok());
    assert!(
      validate_username(&"a".repeat(MAX_USERNAME_LENGTH)).is_ok()
    );
    assert!(
      validate_username(&"a".repeat(MAX_USERNAME_LENGTH + 1))
        .is_err()
    );
  }

  #[test]
  fn test_validate_username_charset() {
    assert!(validate_username("user.name_1@example-com").is_ok());
    assert!(validate_username("user name").is_err());
    assert!(validate_username("user<script>").is_err());
  }

  #[test]
  fn test_validate_password_bounds() {
    assert!(
      validate_password(&"a".repeat(MIN_PASSWORD_LENGTH - 1))
        .is_err()
    );
    assert!(
      validate_password(&"a".repeat(MIN_PASSWORD_LENGTH)).is_ok()
    );
    assert!(
      validate_password(&"a".repeat(MAX_PASSWORD_LENGTH)).is_ok()
    );
    assert!(
      validate_password(&"a".repeat(MAX_PASSWORD_LENGTH + 1))
        .is_err()
    );
  }

  #[test]
  fn test_validate_api_key_name_bounds() {
    assert!(validate_api_key_name("my key").is_ok());
    assert!(
      validate_api_key_name(&"a".repeat(MAX_API_KEY_NAME_LENGTH))
        .is_ok()
    );
    assert!(
      validate_api_key_name(&"a".repeat(MAX_API_KEY_NAME_LENGTH + 1))
        .is_err()
    );
  }
}
