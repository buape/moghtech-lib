use anyhow::Context;
use data_encoding::BASE64;

use crate::{
  PkiKind,
  key::{SpkiPublicKey, check_raw_private_key, check_raw_public_key},
};

/// Wrapper around [snow::HandshakeState] to streamline this implementation.
///
/// One message of a Noise IK handshake ([PkiKind::OneWay]): the
/// initiator, which has the responder's static public key pinned,
/// sends its own static public key (encrypted) in a message that
/// authenticates the `prologue`. What it gives, and what it does
/// not:
/// - The prologue is authenticated, not encrypted: both sides must
///   already know it (the request being signed).
/// - Only the holder of the responder's private key can validate a
///   message, and that holder can also forge one for any client
///   public key (key compromise impersonation). This is no publicly
///   verifiable signature: the responder's private key is as
///   sensitive as every client key together.
/// - A message validates again whenever it is replayed with the
///   same prologue. Bind a freshness value into the prologue (a
///   timestamp, a nonce) and have the responder enforce a window,
///   as mogh_auth signed requests do (the prologue covers the
///   method, path, a timestamp and the body hash).
pub struct OneWayNoiseHandshake(snow::HandshakeState);

impl OneWayNoiseHandshake {
  /// `private_key` and `remote_public_key` are the raw 32 byte
  /// X25519 keys (see [crate::Pkcs8PrivateKey::maybe_raw_bytes] and
  /// [SpkiPublicKey::maybe_pem_to_raw_bytes]), not the base64 text
  /// or der. Anything else is an error.
  pub fn new_initiator(
    private_key: &[u8],
    remote_public_key: &[u8],
    prologue: &[u8],
  ) -> anyhow::Result<OneWayNoiseHandshake> {
    check_raw_private_key(private_key)?;
    check_raw_public_key(remote_public_key)
      .context("Invalid remote public key")?;
    Ok(OneWayNoiseHandshake(
      snow::Builder::new(PkiKind::ONE_WAY.parse()?)
        .local_private_key(private_key)
        .context("Invalid private key")?
        .remote_public_key(remote_public_key)
        .context("Invalid remote public key")?
        .prologue(prologue)
        .context("Invalid prologue")?
        .build_initiator()
        .context("Failed to build initiator")?,
    ))
  }

  /// `private_key` is the raw 32 byte X25519 key (see
  /// [crate::Pkcs8PrivateKey::maybe_raw_bytes]), not the base64 text.
  /// Anything else is an error.
  pub fn new_responder(
    private_key: &[u8],
    prologue: &[u8],
  ) -> anyhow::Result<OneWayNoiseHandshake> {
    check_raw_private_key(private_key)?;
    Ok(OneWayNoiseHandshake(
      snow::Builder::new(PkiKind::ONE_WAY.parse()?)
        .local_private_key(private_key)
        .context("Invalid private key")?
        .prologue(prologue)
        .context("Invalid prologue")?
        .build_responder()
        .context("Failed to build responder")?,
    ))
  }

  /// Produces next message to be read on other side of handshake,
  /// base64 encoded for transport.
  pub fn generate_signature(
    &mut self,
  ) -> Result<String, snow::Error> {
    let mut buf = [0u8; 1024];
    let written = self.0.write_message(&[], &mut buf)?;
    Ok(BASE64.encode(&buf[..written]))
  }

  /// Reads base64 encoded signature from other side of handshake,
  /// and produces the client public key. Low order and non
  /// canonical client keys are refused (see
  /// [SpkiPublicKey::from_raw_bytes]).
  ///
  /// It does not prevent replay, see [OneWayNoiseHandshake].
  pub fn validate_signature(
    &mut self,
    signature: &str,
  ) -> anyhow::Result<SpkiPublicKey> {
    let decoded = BASE64
      .decode(signature.as_bytes())
      .context("Failed to base64 decode message")?;
    self.0.read_message(&decoded, &mut []).map(|_| ())?;
    let raw = self
      .0
      .get_remote_static()
      .context("Failed to get remote public key")?;
    SpkiPublicKey::from_raw_bytes(raw)
  }
}
