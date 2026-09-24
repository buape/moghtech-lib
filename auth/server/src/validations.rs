//! Default username / password / api key validations.
//! These can be overridden on AuthImpl.

use anyhow::{Context as _, anyhow};
use mogh_validations::{StringValidator, StringValidatorMatches};
use subtle::ConstantTimeEq as _;

pub use mogh_request_ip::cidr::validate_cidr_whitelist;

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
/// Maximum length for passwords, in characters. A password can't be
/// more than [MAX_PASSWORD_BYTES] long either, which is the tighter
/// bound for characters outside of ASCII.
pub const MAX_PASSWORD_LENGTH: usize = MAX_PASSWORD_BYTES;
/// Maximum length for passwords, in bytes of their UTF-8 encoding.
///
/// Passwords are hashed with bcrypt, which only uses the first 72
/// bytes: a longer password would log in with anything sharing its
/// first 72 bytes (24 characters of CJK text, say), so it is refused
/// instead. Passwords stored before this limit still log in.
pub const MAX_PASSWORD_BYTES: usize = 72;

/// Validate passwords
///
/// - Between [MIN_PASSWORD_LENGTH] and [MAX_PASSWORD_LENGTH] characters
/// - At most [MAX_PASSWORD_BYTES] bytes (UTF-8), bcrypt ignores the rest
pub fn validate_password(password: &str) -> anyhow::Result<()> {
  StringValidator::default()
    .min_length(MIN_PASSWORD_LENGTH)
    .max_length(MAX_PASSWORD_LENGTH)
    .validate(password)
    .context("Failed to validate password")?;
  if password.len() > MAX_PASSWORD_BYTES {
    return Err(
      anyhow!(
        "Input too long. Must be at most {MAX_PASSWORD_BYTES} bytes, \
        characters outside of ASCII take 2 to 4 bytes each."
      )
      .context("Failed to validate password"),
    );
  }
  Ok(())
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

/// Compare two secrets (eg oauth `state` / csrf tokens)
/// in constant time with respect to their contents.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
  a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Whether the url carries credentials in its authority
/// (`scheme://user:password@host`): a username, or any password.
pub fn url_has_credentials(url: &reqwest::Url) -> bool {
  !url.username().is_empty() || url.password().is_some()
}

/// Validate a url the app uses without authentication, such as
/// an OIDC issuer / discovery endpoint, a JWKS url or a redirect host.
///
/// - Parses as a url
/// - Has the `http` or `https` scheme
/// - Carries no credentials ([url_has_credentials]): these would be
///   stored and shown in plain text with the url, sent along with
///   every request to it, and end up in error messages and logs.
///
/// `field` names the url in the error, and nothing of the url
/// itself is in it.
pub fn validate_public_http_url(
  field: &str,
  url: &str,
) -> anyhow::Result<()> {
  let parsed = reqwest::Url::parse(url)
    .with_context(|| format!("'{field}' is not a valid URL"))?;
  if !matches!(parsed.scheme(), "http" | "https") {
    return Err(anyhow!("'{field}' must be an http(s) URL"));
  }
  if url_has_credentials(&parsed) {
    return Err(anyhow!(
      "'{field}' must not carry credentials (scheme://user:password@host): \
      it is used without authentication, and credentials in a url \
      would be stored and logged in plain text"
    ));
  }
  Ok(())
}

/// The url with any credentials in its authority replaced by `***`,
/// for error messages and logs. Urls without credentials are returned
/// unchanged. Works on urls which don't parse too, by removing
/// everything up to the last `@` of the authority.
pub fn redact_url_credentials(url: &str) -> String {
  if let Ok(mut parsed) = reqwest::Url::parse(url) {
    if !url_has_credentials(&parsed) {
      return url.to_string();
    }
    if parsed.set_username("***").is_ok()
      && parsed.set_password(None).is_ok()
    {
      return parsed.into();
    }
  }
  let Some(start) = url.find("://").map(|index| index + 3) else {
    return url.to_string();
  };
  let rest = &url[start..];
  let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
  match rest[..end].rfind('@') {
    Some(at) => format!("{}***@{}", &url[..start], &rest[at + 1..]),
    None => url.to_string(),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_validate_public_http_url() {
    for url in [
      "https://issuer.example.com",
      "http://localhost:8080/keys?v=2",
      // An '@' outside of the authority is not a credential
      "https://example.com/users/@me",
      "https://example.com/keys?owner=a@b",
    ] {
      assert!(validate_public_http_url("url", url).is_ok(), "{url}");
    }
    for url in [
      "not a url",
      "ftp://issuer.example.com",
      "javascript:alert(1)",
      "https://user:password@issuer.example.com",
      "https://user@issuer.example.com",
      "https://:password@issuer.example.com",
      "https://user:@issuer.example.com/keys",
      "http:user:password@issuer.example.com",
    ] {
      assert!(validate_public_http_url("url", url).is_err(), "{url}");
    }
    let err = validate_public_http_url(
      "keys url",
      "https://user:hunter2@issuer.example.com/keys",
    )
    .unwrap_err();
    let err = format!("{err:#}");
    assert!(err.contains("'keys url' must not carry credentials"));
    assert!(!err.contains("hunter2"), "{err}");
  }

  #[test]
  fn test_redact_url_credentials() {
    for (url, redacted) in [
      (
        "https://user:hunter2@issuer.example.com/keys",
        "https://***@issuer.example.com/keys",
      ),
      (
        "http://user@localhost:8080/.well-known/openid-configuration",
        "http://***@localhost:8080/.well-known/openid-configuration",
      ),
      (
        "https://:hunter2@issuer.example.com",
        "https://***@issuer.example.com/",
      ),
      // Unchanged without credentials, even when not normalized
      ("https://issuer.example.com", "https://issuer.example.com"),
      (
        "https://example.com/users/@me",
        "https://example.com/users/@me",
      ),
      // Not parseable (space in the host), stripped all the same
      (
        "https://user:hunter2@bad host/keys",
        "https://***@bad host/keys",
      ),
      ("https://a@b:hunter2@bad host", "https://***@bad host"),
      ("not a url", "not a url"),
    ] {
      assert_eq!(redact_url_credentials(url), redacted, "{url}");
    }
  }

  #[test]
  fn test_constant_time_eq() {
    assert!(constant_time_eq("abc", "abc"));
    assert!(!constant_time_eq("abc", "abd"));
    assert!(!constant_time_eq("abc", "abcd"));
    assert!(constant_time_eq("", ""));
  }

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
  fn test_validate_password_bytes() {
    // bcrypt uses all of a 72 byte password...
    let longest = "a".repeat(MAX_PASSWORD_BYTES);
    validate_password(&longest).unwrap();
    let hash = bcrypt::hash(&longest, 4).unwrap();
    assert!(!bcrypt::verify("a".repeat(71), &hash).unwrap());
    // ...but ignores anything after, so longer ones are refused.
    assert!(validate_password(&format!("{longest}b")).is_err());
    assert!(bcrypt::verify(format!("{longest}b"), &hash).unwrap());
    // Counted in bytes: 24 CJK characters are 72 bytes, 25 too many.
    validate_password(&"密".repeat(24)).unwrap();
    let err = validate_password(&"密".repeat(25)).unwrap_err();
    assert!(
      format!("{err:#}").contains("at most 72 bytes"),
      "{err:#}"
    );
    // A multibyte character straddling the limit.
    assert!(
      validate_password(&format!("{}é", "a".repeat(71))).is_err()
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
