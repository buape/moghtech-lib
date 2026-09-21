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

/// JWT clock skew tolerance, in seconds.
const JWT_CLOCK_SKEW_TOLERANCE_SECS: u64 = 10;

/// The claims of an app token.
///
/// `iat` / `exp` are unix timestamps in **seconds**, as RFC 7519
/// defines them. Tokens issued before 4.0 carried milliseconds, and
/// are rejected (they would read as issued in the far future).
#[derive(Clone, Serialize, Deserialize)]
pub struct JwtClaims {
  /// Client identifier, eg user id
  pub sub: String,
  /// Issuer, eg the app name
  pub iss: String,
  /// Audience, eg the app name
  pub aud: String,
  /// Issued at time, unix timestamp in seconds.
  pub iat: u64,
  /// Expiry time, unix timestamp in seconds.
  pub exp: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BorrowedJwtClaims<'a> {
  /// Client identifier, eg user id
  pub sub: &'a str,
  /// Issuer, eg the app name
  pub iss: &'a str,
  /// Audience, eg the app name
  pub aud: &'a str,
  /// Issued at time, unix timestamp in seconds.
  pub iat: u64,
  /// Expiry time, unix timestamp in seconds.
  pub exp: u64,
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
  validation.leeway = JWT_CLOCK_SKEW_TOLERANCE_SECS;
  validation
}

fn unix_timestamp_secs() -> anyhow::Result<u64> {
  Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

/// Tokens carry whole seconds. Rounded up, so a token
/// is never valid for less than the ttl, or for no time at all.
fn ttl_secs(ttl_ms: u128) -> u64 {
  u64::try_from(ttl_ms.div_ceil(1000))
    .unwrap_or(u64::MAX)
    .max(1)
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

  /// How long encoded tokens are valid for, in milliseconds.
  /// Tokens carry whole seconds, the ttl is rounded up to the next one.
  pub fn ttl_ms(&self) -> u128 {
    self.ttl_ms
  }

  pub fn header(&self) -> &Header {
    self.header.as_ref().unwrap_or(&DEFAULT_HEADER)
  }

  pub fn validation(&self) -> &Validation {
    self.validation.as_ref().unwrap_or(&self.default_validation)
  }

  pub fn encode_sub(&self, sub: &str) -> anyhow::Result<JwtResponse> {
    self.encode_sub_with_ttl(sub, self.ttl_ms)
  }

  /// Encodes a token which is valid for a shorter time than
  /// the default. `ttl_ms` is capped at [Self::ttl_ms].
  pub fn encode_sub_with_ttl(
    &self,
    sub: &str,
    ttl_ms: u128,
  ) -> anyhow::Result<JwtResponse> {
    let iat = unix_timestamp_secs()?;
    let exp = iat.saturating_add(ttl_secs(ttl_ms.min(self.ttl_ms)));
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
    self.decode_claims(jwt).map(|claims| claims.sub)
  }

  /// Decodes the JWT and validates its signature, `iss` / `aud`, and
  /// that it is not expired (with [JWT_CLOCK_SKEW_TOLERANCE_SECS]).
  /// The error never says which of these failed.
  pub fn decode_claims(
    &self,
    jwt: &str,
  ) -> anyhow::Result<JwtClaims> {
    let claims =
      decode::<JwtClaims>(jwt, &self.decoding_key, self.validation())
        .map(|res| res.claims)
        .map_err(|_| anyhow!("Invalid user credentials"))?;

    // Nothing legitimate is issued in the future. Most of all this
    // refuses tokens from before 4.0: their millisecond timestamps
    // read as seconds tens of thousands of years from now, which
    // would pass the expiry check above forever.
    let now = unix_timestamp_secs()?;
    if claims.iat > now.saturating_add(self.validation().leeway) {
      return Err(anyhow!("Invalid user credentials"));
    }

    Ok(claims)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const SECRET: &[u8] = b"test-jwt-secret";

  fn now() -> u64 {
    unix_timestamp_secs().unwrap()
  }

  /// Encode claims directly, bypassing the provider,
  /// to craft tokens with arbitrary iat / exp.
  fn encode_claims(
    secret: &[u8],
    sub: &str,
    iat: u64,
    exp: u64,
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
    iat: u64,
    exp: u64,
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
  fn test_encode_sub_with_ttl_is_capped_at_default() {
    let provider = JwtProvider::new(b"secret", 60_000);
    let claims = |jwt: &str| {
      decode::<JwtClaims>(
        jwt,
        &provider.decoding_key,
        provider.validation(),
      )
      .unwrap()
      .claims
    };
    let short = provider.encode_sub_with_ttl("user", 1_000).unwrap();
    let short = claims(&short.jwt);
    assert_eq!(short.exp, short.iat + 1);
    let long =
      provider.encode_sub_with_ttl("user", u128::MAX).unwrap();
    let long = claims(&long.jwt);
    assert_eq!(long.exp, long.iat + 60);
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
    assert_eq!(claims.exp, claims.iat + 60);
    assert_eq!(claims.iss, DEFAULT_ISS_AUD);
    assert_eq!(claims.aud, DEFAULT_ISS_AUD);
    // Seconds, as RFC 7519 defines the claims.
    let now = now();
    assert!(claims.iat <= now && now <= claims.iat + 5);
  }

  #[test]
  fn test_decode_rejects_wrong_secret() {
    let provider = JwtProvider::new(SECRET, 60_000);
    let now = now();
    let forged =
      encode_claims(b"other-secret", "user-123", now, now + 60);
    let err = provider.decode_sub(&forged).unwrap_err();
    // Error must not leak internals.
    assert_eq!(err.to_string(), "Invalid user credentials");
  }

  #[test]
  fn test_decode_rejects_expired() {
    let provider = JwtProvider::new(SECRET, 60_000);
    let now = now();
    // Expired beyond the 10s clock skew tolerance.
    let expired =
      encode_claims(SECRET, "user-123", now - 120, now - 20);
    assert!(provider.decode_sub(&expired).is_err());
  }

  #[test]
  fn test_decode_accepts_within_clock_skew_tolerance() {
    let provider = JwtProvider::new(SECRET, 60_000);
    let now = now();
    // Expired, but within the 10s tolerance.
    let jwt = encode_claims(SECRET, "user-123", now - 60, now - 5);
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
    let now = now();
    let header = Header::new(jsonwebtoken::Algorithm::HS384);
    let jwt = encode(
      &header,
      &BorrowedJwtClaims {
        sub: "user-123",
        iss: DEFAULT_ISS_AUD,
        aud: DEFAULT_ISS_AUD,
        iat: now,
        exp: now + 60,
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
    let now = now();
    let jwt = encode_claims_iss_aud(
      SECRET,
      "user-123",
      "other-issuer",
      DEFAULT_ISS_AUD,
      now,
      now + 60,
    );
    assert!(provider.decode_sub(&jwt).is_err());
  }

  #[test]
  fn test_decode_rejects_wrong_aud() {
    let provider = JwtProvider::new(SECRET, 60_000);
    let now = now();
    let jwt = encode_claims_iss_aud(
      SECRET,
      "user-123",
      DEFAULT_ISS_AUD,
      "other-audience",
      now,
      now + 60,
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
      iat: u64,
      exp: u64,
    }
    let provider = JwtProvider::new(SECRET, 60_000);
    let now = now();
    let jwt = encode(
      &Header::default(),
      &LegacyClaims {
        sub: "user-123",
        iat: now,
        exp: now + 60,
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
    let now = now();
    let default_jwt =
      encode_claims(SECRET, "user-123", now, now + 60);
    assert!(provider.decode_sub(&default_jwt).is_err());
  }

  #[test]
  fn test_ttl_is_rounded_up_to_whole_seconds() {
    assert_eq!(ttl_secs(0), 1);
    assert_eq!(ttl_secs(1), 1);
    assert_eq!(ttl_secs(1_000), 1);
    assert_eq!(ttl_secs(1_001), 2);
    assert_eq!(ttl_secs(u128::MAX), u64::MAX);
    // A huge ttl must not overflow the expiry.
    let provider = JwtProvider::new(SECRET, u128::MAX);
    let jwt = provider.encode_sub("user-123").unwrap().jwt;
    assert_eq!(provider.decode_sub(&jwt).unwrap(), "user-123");
  }

  #[test]
  fn test_decode_rejects_legacy_millisecond_tokens() {
    // Correctly signed tokens from before 4.0 carry milliseconds. Read
    // as seconds they never expire, so they have to be refused.
    let provider = JwtProvider::new(SECRET, 60_000);
    let now_ms = now() * 1000;
    let legacy =
      encode_claims(SECRET, "user-123", now_ms, now_ms + 60_000);
    let err = provider.decode_sub(&legacy).unwrap_err();
    assert_eq!(err.to_string(), "Invalid user credentials");
    // Also one which expired long ago in milliseconds.
    let legacy = encode_claims(
      SECRET,
      "user-123",
      now_ms - 600_000,
      now_ms - 540_000,
    );
    assert!(provider.decode_sub(&legacy).is_err());
  }

  #[test]
  fn test_decode_rejects_tokens_issued_in_the_future() {
    let provider = JwtProvider::new(SECRET, 60_000);
    let now = now();
    let future =
      encode_claims(SECRET, "user-123", now + 3_600, now + 7_200);
    assert!(provider.decode_sub(&future).is_err());
    // Within the clock skew tolerance it is accepted.
    let skewed = encode_claims(SECRET, "user-123", now + 5, now + 65);
    assert_eq!(provider.decode_sub(&skewed).unwrap(), "user-123");
  }

  #[test]
  fn test_decode_claims_returns_issued_at() {
    let provider = JwtProvider::new(SECRET, 60_000);
    let jwt = provider.encode_sub("user-123").unwrap().jwt;
    let claims = provider.decode_claims(&jwt).unwrap();
    assert_eq!(claims.sub, "user-123");
    assert!(claims.iat <= now() && now() <= claims.iat + 5);
  }

  #[test]
  fn test_decode_rejects_garbage() {
    let provider = JwtProvider::new(SECRET, 60_000);
    assert!(provider.decode_sub("not-a-jwt").is_err());
    assert!(provider.decode_sub("").is_err());
  }
}
