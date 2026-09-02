use std::{
  sync::LazyLock,
  time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, anyhow};
use jsonwebtoken::{
  DecodingKey, EncodingKey, Header, Validation, decode, encode,
};
use mogh_auth_client::api::login::JwtResponse;
use serde::{Deserialize, Serialize};

static DEFAULT_HEADER: LazyLock<Header> =
  LazyLock::new(Default::default);

/// The default `iss` / `aud` claim value.
pub const DEFAULT_ISS_AUD: &str = "mogh_auth";

/// JWT Clock skew tolerance in milliseconds (10 seconds for JWTs)
const JWT_CLOCK_SKEW_TOLERANCE_MS: u128 = 10 * 1000;

#[derive(Clone, Serialize, Deserialize)]
pub struct JwtClaims {
  /// Client identifier, eg user id
  pub sub: String,
  /// Issuer, eg the app name
  pub iss: String,
  /// Audience, eg the app name
  pub aud: String,
  /// Issued at time
  pub iat: u128,
  /// Expiry time
  pub exp: u128,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BorrowedJwtClaims<'a> {
  /// Client identifier, eg user id
  pub sub: &'a str,
  /// Issuer, eg the app name
  pub iss: &'a str,
  /// Audience, eg the app name
  pub aud: &'a str,
  /// Issued at time
  pub iat: u128,
  /// Expiry time
  pub exp: u128,
}

pub struct JwtProvider {
  header: Option<Header>,
  validation: Option<Validation>,
  /// Built from iss / aud, used unless
  /// overridden with [Self::with_validation].
  default_validation: Validation,
  encoding_key: EncodingKey,
  decoding_key: DecodingKey,
  ttl_ms: u128,
  iss: String,
  aud: String,
}

fn build_validation(iss: &str, aud: &str) -> Validation {
  let mut validation = Validation::default();
  validation.set_issuer(&[iss]);
  validation.set_audience(&[aud]);
  validation
}

impl JwtProvider {
  /// Uses [DEFAULT_ISS_AUD] for the iss / aud claims,
  /// override with [Self::with_iss] / [Self::with_aud]
  /// (usually the app name).
  pub fn new(secret: &[u8], ttl_ms: u128) -> Self {
    Self {
      header: None,
      validation: None,
      default_validation: build_validation(
        DEFAULT_ISS_AUD,
        DEFAULT_ISS_AUD,
      ),
      encoding_key: EncodingKey::from_secret(secret),
      decoding_key: DecodingKey::from_secret(secret),
      ttl_ms,
      iss: DEFAULT_ISS_AUD.to_string(),
      aud: DEFAULT_ISS_AUD.to_string(),
    }
  }

  pub fn with_header(mut self, header: Header) -> Self {
    self.header = Some(header);
    self
  }

  pub fn with_validation(mut self, validation: Validation) -> Self {
    self.validation = Some(validation);
    self
  }

  /// Set the `iss` claim issued and required on JWTs.
  pub fn with_iss(mut self, iss: impl Into<String>) -> Self {
    self.iss = iss.into();
    self.default_validation = build_validation(&self.iss, &self.aud);
    self
  }

  /// Set the `aud` claim issued and required on JWTs.
  pub fn with_aud(mut self, aud: impl Into<String>) -> Self {
    self.aud = aud.into();
    self.default_validation = build_validation(&self.iss, &self.aud);
    self
  }

  pub fn header(&self) -> &Header {
    self.header.as_ref().unwrap_or(&DEFAULT_HEADER)
  }

  pub fn validation(&self) -> &Validation {
    self.validation.as_ref().unwrap_or(&self.default_validation)
  }

  pub fn encode_sub(&self, sub: &str) -> anyhow::Result<JwtResponse> {
    let iat =
      SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let exp = iat + self.ttl_ms;
    let claims = BorrowedJwtClaims {
      sub,
      iss: &self.iss,
      aud: &self.aud,
      iat,
      exp,
    };
    let jwt = encode(self.header(), &claims, &self.encoding_key)
      .context("Failed at signing claim")?;
    Ok(JwtResponse { jwt })
  }

  /// Decodes JWT, checks not expired, returns the claims 'sub', ie the User ID
  pub fn decode_sub(&self, jwt: &str) -> anyhow::Result<String> {
    let claims =
      decode::<JwtClaims>(jwt, &self.decoding_key, self.validation())
        .map(|res| res.claims)
        .map_err(|_| anyhow!("Invalid user credentials"))?;

    let now =
      SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

    if claims.exp > now.saturating_sub(JWT_CLOCK_SKEW_TOLERANCE_MS) {
      Ok(claims.sub)
    } else {
      Err(anyhow!("Invalid user credentials"))
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const SECRET: &[u8] = b"test-jwt-secret";

  fn now_ms() -> u128 {
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap()
      .as_millis()
  }

  /// Encode claims directly, bypassing the provider,
  /// to craft tokens with arbitrary iat / exp.
  fn encode_claims(
    secret: &[u8],
    sub: &str,
    iat: u128,
    exp: u128,
  ) -> String {
    encode_claims_iss_aud(
      secret,
      sub,
      DEFAULT_ISS_AUD,
      DEFAULT_ISS_AUD,
      iat,
      exp,
    )
  }

  fn encode_claims_iss_aud(
    secret: &[u8],
    sub: &str,
    iss: &str,
    aud: &str,
    iat: u128,
    exp: u128,
  ) -> String {
    encode(
      &Header::default(),
      &BorrowedJwtClaims {
        sub,
        iss,
        aud,
        iat,
        exp,
      },
      &EncodingKey::from_secret(secret),
    )
    .unwrap()
  }

  #[test]
  fn test_encode_decode_round_trip() {
    let provider = JwtProvider::new(SECRET, 60_000);
    let jwt = provider.encode_sub("user-123").unwrap().jwt;
    assert_eq!(provider.decode_sub(&jwt).unwrap(), "user-123");
  }

  #[test]
  fn test_encode_sub_sets_exp_from_ttl() {
    let provider = JwtProvider::new(SECRET, 60_000);
    let jwt = provider.encode_sub("user-123").unwrap().jwt;
    let claims = decode::<JwtClaims>(
      &jwt,
      &DecodingKey::from_secret(SECRET),
      provider.validation(),
    )
    .unwrap()
    .claims;
    assert_eq!(claims.exp, claims.iat + 60_000);
    assert_eq!(claims.iss, DEFAULT_ISS_AUD);
    assert_eq!(claims.aud, DEFAULT_ISS_AUD);
    let now = now_ms();
    assert!(claims.iat <= now && now <= claims.iat + 5_000);
  }

  #[test]
  fn test_decode_rejects_wrong_secret() {
    let provider = JwtProvider::new(SECRET, 60_000);
    let now = now_ms();
    let forged =
      encode_claims(b"other-secret", "user-123", now, now + 60_000);
    let err = provider.decode_sub(&forged).unwrap_err();
    // Error must not leak internals.
    assert_eq!(err.to_string(), "Invalid user credentials");
  }

  #[test]
  fn test_decode_rejects_expired() {
    let provider = JwtProvider::new(SECRET, 60_000);
    let now = now_ms();
    // Expired beyond the 10s clock skew tolerance.
    let expired =
      encode_claims(SECRET, "user-123", now - 120_000, now - 20_000);
    assert!(provider.decode_sub(&expired).is_err());
  }

  #[test]
  fn test_decode_accepts_within_clock_skew_tolerance() {
    let provider = JwtProvider::new(SECRET, 60_000);
    let now = now_ms();
    // Expired, but within the 10s tolerance.
    let jwt =
      encode_claims(SECRET, "user-123", now - 60_000, now - 5_000);
    assert_eq!(provider.decode_sub(&jwt).unwrap(), "user-123");
  }

  #[test]
  fn test_decode_rejects_tampered_payload() {
    let provider = JwtProvider::new(SECRET, 60_000);
    let jwt = provider.encode_sub("user-123").unwrap().jwt;
    // Swap the payload segment for one from another token.
    let other = provider.encode_sub("user-456").unwrap().jwt;
    let mut parts =
      jwt.split('.').map(String::from).collect::<Vec<_>>();
    parts[1] = other.split('.').nth(1).unwrap().to_string();
    let tampered = parts.join(".");
    assert!(provider.decode_sub(&tampered).is_err());
  }

  #[test]
  fn test_decode_rejects_wrong_algorithm() {
    let provider = JwtProvider::new(SECRET, 60_000);
    let now = now_ms();
    let header = Header::new(jsonwebtoken::Algorithm::HS384);
    let jwt = encode(
      &header,
      &BorrowedJwtClaims {
        sub: "user-123",
        iss: DEFAULT_ISS_AUD,
        aud: DEFAULT_ISS_AUD,
        iat: now,
        exp: now + 60_000,
      },
      &EncodingKey::from_secret(SECRET),
    )
    .unwrap();
    // Default validation only allows HS256.
    assert!(provider.decode_sub(&jwt).is_err());
  }

  #[test]
  fn test_decode_rejects_wrong_iss() {
    let provider = JwtProvider::new(SECRET, 60_000);
    let now = now_ms();
    let jwt = encode_claims_iss_aud(
      SECRET,
      "user-123",
      "other-issuer",
      DEFAULT_ISS_AUD,
      now,
      now + 60_000,
    );
    assert!(provider.decode_sub(&jwt).is_err());
  }

  #[test]
  fn test_decode_rejects_wrong_aud() {
    let provider = JwtProvider::new(SECRET, 60_000);
    let now = now_ms();
    let jwt = encode_claims_iss_aud(
      SECRET,
      "user-123",
      DEFAULT_ISS_AUD,
      "other-audience",
      now,
      now + 60_000,
    );
    assert!(provider.decode_sub(&jwt).is_err());
  }

  #[test]
  fn test_decode_rejects_missing_iss_aud() {
    // Tokens without iss / aud claims (eg issued before
    // these claims existed) must be rejected.
    #[derive(Serialize)]
    struct LegacyClaims<'a> {
      sub: &'a str,
      iat: u128,
      exp: u128,
    }
    let provider = JwtProvider::new(SECRET, 60_000);
    let now = now_ms();
    let jwt = encode(
      &Header::default(),
      &LegacyClaims {
        sub: "user-123",
        iat: now,
        exp: now + 60_000,
      },
      &EncodingKey::from_secret(SECRET),
    )
    .unwrap();
    assert!(provider.decode_sub(&jwt).is_err());
  }

  #[test]
  fn test_custom_iss_aud_round_trip() {
    let provider = JwtProvider::new(SECRET, 60_000)
      .with_iss("my-app")
      .with_aud("my-app-users");
    let jwt = provider.encode_sub("user-123").unwrap().jwt;
    assert_eq!(provider.decode_sub(&jwt).unwrap(), "user-123");
    // A token with the default iss / aud is rejected.
    let now = now_ms();
    let default_jwt =
      encode_claims(SECRET, "user-123", now, now + 60_000);
    assert!(provider.decode_sub(&default_jwt).is_err());
  }

  #[test]
  fn test_decode_rejects_garbage() {
    let provider = JwtProvider::new(SECRET, 60_000);
    assert!(provider.decode_sub("not-a-jwt").is_err());
    assert!(provider.decode_sub("").is_err());
  }
}
