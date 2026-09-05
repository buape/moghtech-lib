//! Symmetric encryption utilities: AEAD data and envelope
//! encryption ([aead]) under a 32 byte [Key] that is wiped from
//! memory when dropped, with decrypted outputs wiped the same
//! way ([Zeroizing]). Two ciphers ([Cipher]) share one stored
//! format, told apart by a format marker on the ciphertext.

use std::fmt;

use anyhow::{Context as _, anyhow};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroize;

pub mod aead;

pub use data_encoding::BASE64URL;
pub use zeroize::{ZeroizeOnDrop, Zeroizing};

/// A 32 byte symmetric key.
///
/// The material is zeroized when the key is dropped, `Debug`
/// prints none of it, and the comparison is constant time. Keys
/// are not `Clone`: pass them by reference (or share an `Arc`),
/// so the process holds one buffer to wipe per key. A plain
/// `[u8; 32]` copied out of one is never wiped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; 32]);

impl Key {
  pub const LEN: usize = 32;

  /// Copy the material out of `bytes` and wipe `bytes` in place,
  /// so the key holds the only copy. (Taking the array by value
  /// would leave the caller's variable holding a second copy: a
  /// move of a `Copy` array is a copy.)
  pub fn from_bytes(bytes: &mut [u8; Key::LEN]) -> Key {
    let key = Key(*bytes);
    bytes.zeroize();
    key
  }

  /// A key from a byte slice of exactly [Key::LEN] bytes. The
  /// slice is the caller's to wipe (hand it over in a
  /// [Zeroizing] buffer).
  pub fn from_slice(bytes: &[u8]) -> Option<Key> {
    let mut key = Key([0; Key::LEN]);
    if bytes.len() != Key::LEN {
      return None;
    }
    key.0.copy_from_slice(bytes);
    Some(key)
  }

  /// Fresh random key material from the thread rng.
  pub fn generate() -> Key {
    use rand::RngExt as _;
    let mut bytes: [u8; Key::LEN] = rand::rng().random();
    Key::from_bytes(&mut bytes)
  }

  /// Decode base64url encoded key material (the encoding key
  /// files, backups and the Database kind store).
  pub fn from_base64url(encoded: &[u8]) -> anyhow::Result<Key> {
    let decoded = Zeroizing::new(
      BASE64URL
        .decode(encoded)
        .context("Invalid base64url encoding")?,
    );
    Key::from_slice(&decoded).ok_or_else(|| {
      anyhow!("Invalid decoded base64url bytes length")
    })
  }

  /// The base64url encoding of the material, wiped on drop.
  pub fn to_base64url(&self) -> Zeroizing<String> {
    Zeroizing::new(BASE64URL.encode(&self.0))
  }

  pub fn as_bytes(&self) -> &[u8; Key::LEN] {
    &self.0
  }
}

impl PartialEq for Key {
  fn eq(&self, other: &Key) -> bool {
    self.0.ct_eq(&other.0).into()
  }
}

impl Eq for Key {}

impl fmt::Debug for Key {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("Key([REDACTED])")
  }
}

/// The AEAD cipher a ciphertext was produced with. Both take a 32
/// byte [Key] and a random nonce per encryption; they differ in
/// nonce size and hardware acceleration.
///
/// XChaCha20-Poly1305's 192 bit nonce makes random nonces safe at
/// any volume. AES-256-GCM's 96 bit nonce is not: keep one key
/// under roughly 2^32 encryptions (NIST SP 800-38D's bound for
/// random IVs) — under envelope encryption every data key seals
/// one message, so the bound applies to the master key's wraps.
/// AES-GCM is the faster of the two where AES-NI is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Cipher {
  #[default]
  XChaCha20Poly1305,
  Aes256Gcm,
}

impl Cipher {
  pub const ALL: [Cipher; 2] =
    [Cipher::XChaCha20Poly1305, Cipher::Aes256Gcm];

  /// The name in the format marker.
  pub fn marker(self) -> &'static str {
    match self {
      Cipher::XChaCha20Poly1305 => "xchacha20poly1305",
      Cipher::Aes256Gcm => "aes256gcm",
    }
  }

  pub fn from_marker(marker: &str) -> Option<Cipher> {
    Cipher::ALL
      .into_iter()
      .find(|cipher| cipher.marker() == marker)
  }

  /// The nonce size the cipher needs, in bytes.
  pub fn nonce_len(self) -> usize {
    match self {
      Cipher::XChaCha20Poly1305 => 24,
      Cipher::Aes256Gcm => 12,
    }
  }

  /// Prefix a base64url payload with the cipher's format marker:
  /// `$<marker>$<payload>`. `$` is outside the base64url alphabet,
  /// so the marker never collides with an unmarked payload.
  pub fn mark(self, payload: &str) -> String {
    format!("${}${payload}", self.marker())
  }

  /// Split a stored ciphertext into its cipher and base64url
  /// payload. Ciphertexts written before the marker existed carry
  /// none and are XChaCha20-Poly1305, the only cipher then.
  pub fn parse(data: &str) -> anyhow::Result<(Cipher, &str)> {
    let Some(rest) = data.strip_prefix('$') else {
      return Ok((Cipher::XChaCha20Poly1305, data));
    };
    let (marker, payload) = rest
      .split_once('$')
      .context("Invalid ciphertext format marker")?;
    let cipher = Cipher::from_marker(marker)
      .with_context(|| format!("Unknown cipher '{marker}'"))?;
    Ok((cipher, payload))
  }
}

impl fmt::Display for Cipher {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(self.marker())
  }
}

pub struct EncryptedData {
  /// ## data
  /// - encrypted using given key plus the below nonce
  /// - base64url encoded, prefixed with the cipher's format
  ///   marker (`$aes256gcm$...`); no marker means
  ///   XChaCha20-Poly1305, the format before markers existed
  pub data: String,
  /// ## nonce
  /// - the random nonce used to encrypt the data
  /// - base64url encoded
  pub nonce: String,
}

pub struct EnvelopeEncryptedData {
  /// Encrypted using master key
  pub key: EncryptedData,
  /// Encrypted using above key, decrypted.
  pub data: EncryptedData,
}

//

pub trait AssociatedData {
  fn as_bytes(&self) -> &[u8];
}

impl AssociatedData for () {
  fn as_bytes(&self) -> &[u8] {
    &[]
  }
}

impl AssociatedData for &[u8] {
  fn as_bytes(&self) -> &[u8] {
    self
  }
}

impl AssociatedData for Vec<u8> {
  fn as_bytes(&self) -> &[u8] {
    Vec::as_slice(self)
  }
}

impl AssociatedData for &str {
  fn as_bytes(&self) -> &[u8] {
    str::as_bytes(self)
  }
}

impl AssociatedData for String {
  fn as_bytes(&self) -> &[u8] {
    String::as_bytes(self)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn key_round_trips_through_base64url_and_compares() {
    let key = Key::from_bytes(&mut [7u8; 32]);
    let encoded = key.to_base64url();
    assert_eq!(Key::from_base64url(encoded.as_bytes()).unwrap(), key);
    assert_ne!(Key::from_bytes(&mut [8u8; 32]), key);
    assert!(Key::from_slice(&[1u8; 31]).is_none());
    assert!(Key::from_base64url(b"!!").is_err());
    assert_eq!(format!("{key:?}"), "Key([REDACTED])");
  }

  #[test]
  fn from_bytes_wipes_the_source() {
    let mut bytes = [9u8; 32];
    let key = Key::from_bytes(&mut bytes);
    assert_eq!(key.as_bytes(), &[9u8; 32]);
    assert_eq!(bytes, [0u8; 32]);
  }

  #[test]
  fn generated_keys_differ() {
    assert_ne!(Key::generate(), Key::generate());
  }

  #[test]
  fn format_markers_round_trip_and_default_to_legacy() {
    for cipher in Cipher::ALL {
      let marked = cipher.mark("cGF5bG9hZA");
      assert_eq!(
        Cipher::parse(&marked).unwrap(),
        (cipher, "cGF5bG9hZA")
      );
      assert_eq!(Cipher::from_marker(cipher.marker()), Some(cipher));
    }
    // Unmarked: the format before markers, XChaCha20-Poly1305.
    assert_eq!(
      Cipher::parse("cGF5bG9hZA").unwrap(),
      (Cipher::XChaCha20Poly1305, "cGF5bG9hZA")
    );
    assert!(Cipher::parse("$nope$cGF5bG9hZA").is_err());
    assert!(Cipher::parse("$aes256gcm").is_err());
  }
}
