//! Authenticating requests with a signing key: instead of sending a
//! secret, the client signs every request with its private key, and
//! the server recognizes it by the public key stored with the signing
//! key (`CreateSigningKey`).
//!
//! The signature is sent in [API_SIGNATURE_HEADER] with the time it
//! was made at in [API_TIMESTAMP_HEADER]. It covers the request
//! method, path and query, timestamp and body ([pki_auth_prologue]),
//! and can only be verified by the server it was made for (the server
//! public key). Within the timestamp tolerance of the server (1 second
//! by default) the headers only authenticate this exact request again,
//! never one with another method, path, query or body.
//!
//! Sign the body exactly as it is sent, and the path and query as the
//! server receives them (percent encoded, without the scheme and host,
//! including any prefix a proxy in front of the server doesn't strip).
//!
//! So the headers are generated per request, right before it is sent,
//! over its exact path, query and body: unlike a jwt or an api key,
//! they can't be set once as default headers of a client.
//!
//! ```ignore
//! let path = "/read/GetVersion";
//! let body = serde_json::to_vec(&GetVersion {})?;
//! let mut request = reqwest
//!   .post(format!("{address}{path}"))
//!   .header("content-type", "application/json")
//!   .body(body.clone());
//! for (header, value) in signed_request_headers(
//!   &private_key, &server_public_key, "POST", path, &body,
//! )? {
//!   request = request.header(header, value);
//! }
//! ```

use sha2::Digest as _;

pub const API_SIGNATURE_HEADER: &str = "x-api-signature";
pub const API_TIMESTAMP_HEADER: &str = "x-api-timestamp";

/// The sha256 of a request body as the signature covers it: lowercase
/// hex. An empty body is the sha256 of empty input.
pub fn body_sha256(body: &[u8]) -> String {
  use std::fmt::Write as _;
  let digest = sha2::Sha256::digest(body);
  let mut hex = String::with_capacity(digest.len() * 2);
  for byte in digest.iter() {
    // Writing to a String can't fail.
    let _ = write!(hex, "{byte:02x}");
  }
  hex
}

/// What a request signature covers:
/// `{METHOD}|{path_and_query}|{timestamp}|{sha256(body)}`.
///
/// - `method`: the request method, uppercased here (`POST`).
/// - `path_and_query`: the path and query the server receives
///   (eg. `/read?x=1`), never the scheme and host.
/// - `timestamp`: unix milliseconds, sent in [API_TIMESTAMP_HEADER].
/// - `body`: the request body exactly as sent, empty for none
///   ([body_sha256]), and for a CONNECT request (eg. a websocket over
///   HTTP/2), whose body is the tunnel.
pub fn pki_auth_prologue(
  method: &str,
  path_and_query: &str,
  timestamp: i64,
  body: &[u8],
) -> String {
  format!(
    "{}|{path_and_query}|{timestamp}|{}",
    method.to_ascii_uppercase(),
    body_sha256(body)
  )
}

/// The signature for a request made at `timestamp` (unix
/// milliseconds), see [pki_auth_prologue] for the other arguments.
///
/// - `private_key`: the private key of the signing key (pkcs8 base64
///   or pem).
/// - `server_public_key`: the public key of the server (spki base64 or
///   pem), which apps make available without authentication.
#[cfg(feature = "pki")]
pub fn sign_request(
  private_key: &str,
  server_public_key: &str,
  method: &str,
  path_and_query: &str,
  timestamp: i64,
  body: &[u8],
) -> anyhow::Result<String> {
  use anyhow::Context as _;
  use mogh_pki::{
    Pkcs8PrivateKey, SpkiPublicKey, one_way::OneWayNoiseHandshake,
  };

  OneWayNoiseHandshake::new_initiator(
    &Pkcs8PrivateKey::maybe_raw_bytes(private_key)?,
    &SpkiPublicKey::maybe_pem_to_raw_bytes(server_public_key)?,
    pki_auth_prologue(method, path_and_query, timestamp, body)
      .as_bytes(),
  )
  .context("Failed to create request handshake")?
  .generate_signature()
  .context("Failed to generate request signature")
}

/// The headers authenticating a request made right now, see
/// [sign_request].
///
/// The server only accepts the signature for about a second by default
/// (`AuthImpl::signing_key_timestamp_tolerance_ms`), so create them right
/// before sending, and keep the clock of the client synchronized.
#[cfg(feature = "pki")]
pub fn signed_request_headers(
  private_key: &str,
  server_public_key: &str,
  method: &str,
  path_and_query: &str,
  body: &[u8],
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
    path_and_query,
    timestamp,
    body,
  )?;
  Ok([
    (API_SIGNATURE_HEADER, signature),
    (API_TIMESTAMP_HEADER, timestamp.to_string()),
  ])
}

#[cfg(test)]
mod tests {
  use super::*;

  /// sha256 of empty input.
  const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  #[test]
  fn test_prologue_format_is_stable() {
    // The server builds the same string to verify the signature.
    assert_eq!(
      pki_auth_prologue("POST", "/auth/manage?x=1", 1234, b""),
      format!("POST|/auth/manage?x=1|1234|{EMPTY_SHA256}")
    );
    assert_eq!(
      pki_auth_prologue("POST", "/read", 1234, b"{}"),
      "POST|/read|1234|44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    );
    // The method is uppercased.
    assert_eq!(
      pki_auth_prologue("post", "/read", 1234, b"{}"),
      pki_auth_prologue("POST", "/read", 1234, b"{}"),
    );
  }

  #[test]
  fn test_body_sha256() {
    assert_eq!(body_sha256(b""), EMPTY_SHA256);
    assert_eq!(
      body_sha256(br#"{"type":"GetUserId","params":{}}"#),
      "1063e6f54ccbb0c3e238533021c0952c1cd6c646f177a3bd44b396d640d8a0d8"
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
    let body = br#"{"type":"ListTrustedIssuers","params":{}}"#;
    let signature = sign_request(
      client.private(),
      server.public(),
      "POST",
      "/read",
      1234,
      body,
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
        pki_auth_prologue("POST", "/read", 1234, body)
      )
      .unwrap(),
      client.public()
    );
    // Not valid for another request, or for another server.
    for prologue in [
      pki_auth_prologue("POST", "/write", 1234, body),
      pki_auth_prologue("GET", "/read", 1234, body),
      pki_auth_prologue("POST", "/read", 1235, body),
      // Another body on the same method and path.
      pki_auth_prologue(
        "POST",
        "/read",
        1234,
        br#"{"type":"CreateTrustedIssuer","params":{}}"#,
      ),
      pki_auth_prologue("POST", "/read", 1234, b""),
    ] {
      assert!(verify(server.private(), prologue).is_err());
    }
    let other = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
    assert!(
      verify(
        other.private(),
        pki_auth_prologue("POST", "/read", 1234, body)
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
      b"{}",
    )
    .unwrap();
    assert_eq!(signature_header, "x-api-signature");
    assert_eq!(timestamp_header, "x-api-timestamp");
    assert!(!signature.is_empty());
    assert!(timestamp.parse::<i64>().unwrap() > 1_700_000_000_000);
  }

  /// Invalid keys are an error, not a panic.
  #[cfg(feature = "pki")]
  #[test]
  fn test_signed_request_headers_invalid_keys() {
    use mogh_pki::{EncodedKeyPair, PkiKind};

    let server = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
    let client = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
    let headers = |private_key: &str, server_public_key: &str| {
      signed_request_headers(
        private_key,
        server_public_key,
        "POST",
        "/read",
        b"",
      )
    };

    // A bad private key, with the valid server public key. Note that
    // up to 32 bytes are taken as a raw key, so these are longer.
    let invalid_base64 = "!".repeat(64);
    for private_key in [
      "",
      invalid_base64.as_str(),
      "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
      // A public key given as the private key.
      client.public(),
    ] {
      assert!(
        headers(private_key, server.public()).is_err(),
        "{private_key:?}"
      );
    }

    // A bad server public key, with a valid private key.
    for server_public_key in ["", "nope", invalid_base64.as_str()] {
      assert!(
        headers(client.private(), server_public_key).is_err(),
        "{server_public_key:?}"
      );
    }
  }
}
