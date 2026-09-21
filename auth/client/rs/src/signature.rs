//! Authenticating requests with an api key v2: instead of sending a
//! secret, the client signs every request with its private key, and
//! the server recognizes it by the public key stored with the api key.
//!
//! The signature is sent in [API_SIGNATURE_HEADER] with the time it
//! was made at in [API_TIMESTAMP_HEADER]. It covers the request method,
//! uri and timestamp ([pki_auth_prologue]), and can only be verified by
//! the server it was made for (the server public key).
//!
//! ```ignore
//! let uri = "/read";
//! let mut request = reqwest.post(format!("{address}{uri}")).json(&body);
//! for (header, value) in signed_request_headers(
//!   &private_key, &server_public_key, "POST", uri,
//! )? {
//!   request = request.header(header, value);
//! }
//! ```

pub const API_SIGNATURE_HEADER: &str = "x-api-signature";
pub const API_TIMESTAMP_HEADER: &str = "x-api-timestamp";

/// What a request signature covers. `uri` is the path and query the
/// server receives (eg. `/read?x=1`), `timestamp` is in milliseconds.
pub fn pki_auth_prologue(
  method: &str,
  uri: &str,
  timestamp: i64,
) -> String {
  format!("{method}|{uri}|{timestamp}")
}

/// The signature for a request made at `timestamp` (unix milliseconds).
///
/// - `private_key`: the private key of the api key (pkcs8 base64 or pem).
/// - `server_public_key`: the public key of the server (spki base64 or
///   pem), which apps make available without authentication.
#[cfg(feature = "pki")]
pub fn sign_request(
  private_key: &str,
  server_public_key: &str,
  method: &str,
  uri: &str,
  timestamp: i64,
) -> anyhow::Result<String> {
  use anyhow::Context as _;
  use mogh_pki::{
    Pkcs8PrivateKey, SpkiPublicKey, one_way::OneWayNoiseHandshake,
  };

  OneWayNoiseHandshake::new_initiator(
    &Pkcs8PrivateKey::maybe_raw_bytes(private_key)?,
    &SpkiPublicKey::maybe_pem_to_raw_bytes(server_public_key)?,
    pki_auth_prologue(method, uri, timestamp).as_bytes(),
  )
  .context("Failed to create request handshake")?
  .generate_signature()
  .context("Failed to generate request signature")
}

/// The headers authenticating a request made right now.
///
/// The server only accepts the signature for about a second by default
/// (`AuthImpl::api_key_v2_timestamp_tolerance_ms`), so create them right
/// before sending, and keep the clock of the client synchronized.
#[cfg(feature = "pki")]
pub fn signed_request_headers(
  private_key: &str,
  server_public_key: &str,
  method: &str,
  uri: &str,
) -> anyhow::Result<[(&'static str, String); 2]> {
  use anyhow::Context as _;

  let timestamp = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .context("Failed to get system timestamp")?
    .as_millis() as i64;
  let signature = sign_request(
    private_key,
    server_public_key,
    method,
    uri,
    timestamp,
  )?;
  Ok([
    (API_SIGNATURE_HEADER, signature),
    (API_TIMESTAMP_HEADER, timestamp.to_string()),
  ])
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_prologue_format_is_stable() {
    // The server builds the same string to verify the signature.
    assert_eq!(
      pki_auth_prologue("POST", "/auth/manage?x=1", 1234),
      "POST|/auth/manage?x=1|1234"
    );
  }

  #[cfg(feature = "pki")]
  #[test]
  fn test_signature_is_verified_by_the_server_key_only() {
    use mogh_pki::{
      EncodedKeyPair, Pkcs8PrivateKey, PkiKind,
      one_way::OneWayNoiseHandshake,
    };

    let server = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
    let client = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
    let signature = sign_request(
      client.private(),
      server.public(),
      "POST",
      "/read",
      1234,
    )
    .unwrap();

    let verify = |private_key: &str, prologue: String| {
      OneWayNoiseHandshake::new_responder(
        &Pkcs8PrivateKey::maybe_raw_bytes(private_key).unwrap(),
        prologue.as_bytes(),
      )
      .unwrap()
      .validate_signature(&signature)
      .map(|public_key| public_key.into_inner())
    };

    // The server learns which client signed it.
    assert_eq!(
      verify(
        server.private(),
        pki_auth_prologue("POST", "/read", 1234)
      )
      .unwrap(),
      client.public()
    );
    // Not valid for another request, or for another server.
    assert!(
      verify(
        server.private(),
        pki_auth_prologue("POST", "/write", 1234)
      )
      .is_err()
    );
    let other = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
    assert!(
      verify(
        other.private(),
        pki_auth_prologue("POST", "/read", 1234)
      )
      .is_err()
    );
  }

  #[cfg(feature = "pki")]
  #[test]
  fn test_signed_request_headers() {
    use mogh_pki::{EncodedKeyPair, PkiKind};

    let server = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
    let client = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
    let [
      (signature_header, signature),
      (timestamp_header, timestamp),
    ] = signed_request_headers(
      client.private(),
      server.public(),
      "POST",
      "/read",
    )
    .unwrap();
    assert_eq!(signature_header, "x-api-signature");
    assert_eq!(timestamp_header, "x-api-timestamp");
    assert!(!signature.is_empty());
    assert!(timestamp.parse::<i64>().unwrap() > 1_700_000_000_000);
    // Invalid keys are an error, not a panic.
    assert!(
      signed_request_headers("not a key !!", "nope", "POST", "/read")
        .is_err()
    );
  }
}
