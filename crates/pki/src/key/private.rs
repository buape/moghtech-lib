use std::path::Path;

use anyhow::{Context, anyhow};
use data_encoding::BASE64;
use der::{Decode as _, Encode as _, asn1::OctetStringRef};

use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize as _, Zeroizing};

use crate::PkiKind;

/// The error for input that is neither raw key bytes nor pkcs8.
const NOT_A_PRIVATE_KEY: &str =
  "Private key must be 32 characters or less, or pkcs8 encoded.";

/// An X25519 private key, stored as base64 pkcs8 (v1) der.
///
/// Secret material: the string is wiped from memory on drop, and
/// the [Debug] output is redacted. There is no
/// [Display][std::fmt::Display], so the key can't be formatted into
/// logs or errors by accident: take its text explicitly with
/// [Self::as_str] or [Self::into_inner] (or [Self::as_pem]). The
/// raw `[u8; 32]` copies returned by [Self::as_raw_bytes] and
/// [Self::maybe_raw_bytes] are the caller's to wipe. Wiping is best
/// effort: the Noise handshake keeps its own copy of the key, which
/// it does not wipe.
///
/// ```compile_fail,E0277
/// let key =
///   mogh_pki::EncodedKeyPair::generate(mogh_pki::PkiKind::OneWay)
///     .unwrap()
///     .private;
/// let _ = format!("{key}");
/// ```
#[derive(Clone)]
pub struct Pkcs8PrivateKey(String);

/// Constant-time comparison to avoid leaking
/// secret key material through timing side channels.
impl PartialEq for Pkcs8PrivateKey {
  fn eq(&self, other: &Self) -> bool {
    self.as_bytes().ct_eq(other.as_bytes()).into()
  }
}

impl Eq for Pkcs8PrivateKey {}

impl Drop for Pkcs8PrivateKey {
  fn drop(&mut self) {
    self.0.zeroize();
  }
}

impl From<String> for Pkcs8PrivateKey {
  fn from(value: String) -> Self {
    Self(value)
  }
}

/// Redacted: the key is secret material.
impl std::fmt::Debug for Pkcs8PrivateKey {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("Pkcs8PrivateKey(<redacted>)")
  }
}

impl Pkcs8PrivateKey {
  /// The full private key (base64 pkcs8 der). Secret: never format
  /// it into logs or errors.
  pub fn as_str(&self) -> &str {
    &self.0
  }

  pub fn as_bytes(&self) -> &[u8] {
    self.0.as_bytes()
  }

  /// The full private key (base64 pkcs8 der), moved out. The
  /// returned string is not wiped on drop.
  pub fn into_inner(mut self) -> String {
    // Taken, as the Drop impl wipes what is left.
    std::mem::take(&mut self.0)
  }

  pub fn as_pem(&self) -> String {
    super::encode_pem("PRIVATE KEY", &self.0)
  }

  pub fn write_pem_sync(
    &self,
    path: impl AsRef<Path>,
  ) -> anyhow::Result<()> {
    let path = path.as_ref();
    // Ensure the parent directory exists
    tracing::info!("Writing private key to {path:?}");
    let pem = Zeroizing::new(self.as_pem());
    mogh_secret_file::write(path, pem.as_bytes()).with_context(|| {
      format!("Failed to write private key pem to {path:?}")
    })
  }

  pub async fn write_pem_async(
    &self,
    path: impl AsRef<Path>,
  ) -> anyhow::Result<()> {
    let path = path.as_ref();
    // Ensure the parent directory exists
    tracing::info!("Writing private key to {path:?}");
    let pem = Zeroizing::new(self.as_pem());
    mogh_secret_file::write_async(path, pem.as_bytes())
      .await
      .with_context(|| {
        format!("Failed to write private key pem to {path:?}")
      })
  }

  /// Reads a private key file in any of the forms
  /// [Self::from_maybe_raw_bytes] accepts. An empty (or whitespace
  /// only) file is an error, not a key.
  pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
    let path = path.as_ref();
    let contents =
      Zeroizing::new(std::fs::read_to_string(path).with_context(
        || format!("Failed to read private key at {path:?}"),
      )?);
    Self::from_maybe_raw_bytes(&contents).with_context(|| {
      format!("Invalid private key file at {path:?}")
    })
  }

  /// Parses a private key in any of these forms, see
  /// [Self::maybe_raw_bytes]:
  /// - pkcs8 base64 pem (rfc7468, openssl)
  /// - pkcs8 base64 der (the pem body)
  /// - raw key bytes (32 or fewer), zero padded to 32
  ///
  /// The key is stored in the canonical form: base64 pkcs8 v1 der
  /// (a v2 key's embedded public key is dropped).
  pub fn from_maybe_raw_bytes(
    maybe_pkcs8_private_key: &str,
  ) -> anyhow::Result<Self> {
    let raw =
      Zeroizing::new(Self::maybe_raw_bytes(maybe_pkcs8_private_key)?);
    Self::from_raw_bytes(&*raw)
  }

  /// Encodes raw X25519 private key bytes (32 or fewer, zero padded
  /// to 32) as base64 pkcs8 v1 der. Empty input, and the all zero
  /// key, are refused: every deployment would share that key.
  pub fn from_raw_bytes(private_key: &[u8]) -> anyhow::Result<Self> {
    if private_key.len() > 32 {
      return Err(anyhow!(
        "Private key bytes too long, expected 32 bytes or less."
      ));
    }
    if private_key.is_empty() {
      return Err(anyhow!("Private key is empty"));
    }

    let mut raw = Zeroizing::new([0u8; 32]);
    raw[..private_key.len()].copy_from_slice(private_key);
    check_scalar(&raw)?;

    let octet = OctetStringRef::new(&raw[..])
      .map_err(anyhow::Error::msg)
      .context("Failed to parse private key bytes into octet")?;

    let mut octet_buf = Zeroizing::new([0u8; 128]);
    let octet_der = octet
      .encode_to_slice(&mut *octet_buf)
      .map_err(anyhow::Error::msg)
      .context("Failed to write private key octet into der")?;

    let pki = pkcs8::PrivateKeyInfo {
      algorithm: super::algorithm(),
      private_key: octet_der,
      public_key: None,
    };

    let mut der_buf = Zeroizing::new([0u8; 128]);
    let private_key = pki
      .encode_to_slice(&mut *der_buf)
      .map_err(anyhow::Error::msg)
      .context("Failed to write private key info into der")?;

    Ok(Self(BASE64.encode(private_key)))
  }

  pub fn as_raw_bytes(&self) -> anyhow::Result<[u8; 32]> {
    Self::raw_bytes(self.0.as_bytes())
  }

  /// Converts pkcs8 base64 bytes
  /// to raw private key
  pub fn raw_bytes(
    pkcs8_private_key: &[u8],
  ) -> anyhow::Result<[u8; 32]> {
    let decoded = Zeroizing::new(
      BASE64
        .decode(pkcs8_private_key)
        .context("Private key is not valid base64 encoding")?,
    );
    Self::raw_bytes_after_decode(&decoded)
  }

  /// The raw X25519 private key, from any of:
  /// - pkcs8 base64 pem (rfc7468, openssl)
  /// - pkcs8 base64 der (the pem body), v1 or v2
  /// - raw key bytes: input of 32 characters or fewer is used as the
  ///   key itself, zero padded to 32.
  ///
  /// Surrounding whitespace (a key file's trailing newline) is
  /// ignored for the pem and base64 forms. Raw input is used exactly
  /// as given, so a key keeps deriving the same public key however
  /// it is passed.
  ///
  /// Empty or whitespace only input, and the all zero key, are
  /// refused: every deployment given them would share the same,
  /// publicly known key.
  ///
  /// A raw key is the X25519 scalar itself, with no key derivation,
  /// so a short or guessable value can be brute forced from the
  /// public key. Prefer a generated key (`EncodedKeyPair::generate`).
  pub fn maybe_raw_bytes(
    maybe_pkcs8_private_key: &str,
  ) -> anyhow::Result<[u8; 32]> {
    let trimmed = maybe_pkcs8_private_key.trim();
    if trimmed.is_empty() {
      return Err(anyhow!("Private key is empty"));
    }
    // check pem rfc7468 (openssl)
    if trimmed.starts_with("-----BEGIN") {
      let (_label, private_key_der) =
        pem_rfc7468::decode_vec(trimmed.as_bytes())
          .map_err(anyhow::Error::msg)
          .context("Failed to get der from pem")?;
      let private_key_der = Zeroizing::new(private_key_der);
      return Self::raw_bytes_after_decode(&private_key_der);
    }
    let len = maybe_pkcs8_private_key.len();
    if len <= 32 {
      let mut res = [0u8; 32];
      res[..len].copy_from_slice(maybe_pkcs8_private_key.as_bytes());
      check_scalar(&res)?;
      return Ok(res);
    }
    // base64 der
    Self::raw_bytes(trimmed.as_bytes()).context(NOT_A_PRIVATE_KEY)
  }

  fn raw_bytes_after_decode(
    decoded: &[u8],
  ) -> anyhow::Result<[u8; 32]> {
    let pki = pkcs8::PrivateKeyInfo::from_der(decoded)
      .map_err(anyhow::Error::msg)
      .context("Failed to parse pki from der")?;
    if pki.algorithm.oid != super::OID_X25519 {
      return Err(anyhow!("Private key is not X25519"));
    }
    let octet = OctetStringRef::from_der(pki.private_key)
      .map_err(anyhow::Error::msg)
      .context("Failed to get octet string ref from private key")?
      .as_bytes();

    if octet.len() != 32 {
      return Err(anyhow!(
        "Raw private key length should be 32, got {}",
        octet.len()
      ));
    }

    let mut res = [0u8; 32];
    res.copy_from_slice(octet);
    check_scalar(&res)?;
    Ok(res)
  }

  pub fn compute_public_key_using_dh(
    &self,
    pki_kind: PkiKind,
  ) -> anyhow::Result<super::public::SpkiPublicKey> {
    super::public::SpkiPublicKey::from_private_key_using_dh(
      pki_kind, &self.0,
    )
  }
}

/// Checks raw private key bytes handed straight to a handshake:
/// exactly 32 bytes (not the base64 text), and not the all zero
/// key.
pub(crate) fn check_raw_private_key(
  private_key: &[u8],
) -> anyhow::Result<()> {
  let raw: &[u8; 32] = private_key.try_into().map_err(|_| {
    anyhow!(
      "Private key must be 32 raw bytes, got {} (see Pkcs8PrivateKey::maybe_raw_bytes)",
      private_key.len()
    )
  })?;
  check_scalar(raw)
}

/// Refuses the all zero key, which empty or zero input produces.
/// X25519 clamps the scalar (clears the low 3 bits and the top bit,
/// sets bit 254), so every input which clamps to the zero key's
/// scalar is refused too (`"\x01"`, ...). Branch free over the key
/// bytes.
fn check_scalar(raw: &[u8; 32]) -> anyhow::Result<()> {
  let mut bits = (raw[0] & 0xf8) | (raw[31] & 0x3f);
  for byte in &raw[1..31] {
    bits |= byte;
  }
  if bool::from(bits.ct_eq(&0)) {
    return Err(anyhow!(
      "Private key is all zero, a publicly known key"
    ));
  }
  Ok(())
}
