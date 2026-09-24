use std::path::Path;

use anyhow::{Context, anyhow};
use data_encoding::BASE64;
use der::{Decode as _, Encode as _, asn1::BitStringRef};
use snow::{
  params::NoiseParams,
  resolvers::{CryptoResolver, DefaultResolver},
};
use zeroize::Zeroizing;

use crate::PkiKind;

/// An X25519 public key, stored as base64 spki der.
///
/// Every constructor that parses key bytes refuses non canonical
/// encodings and low order points (see
/// [SpkiPublicKey::from_raw_bytes]), so a key has one string form.
/// `From<String>` wraps the string as given, unchecked.
#[derive(Debug, PartialEq, Clone)]
pub struct SpkiPublicKey(String);

impl From<String> for SpkiPublicKey {
  fn from(value: String) -> Self {
    Self(value)
  }
}

impl std::fmt::Display for SpkiPublicKey {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.0)
  }
}

impl SpkiPublicKey {
  pub fn as_str(&self) -> &str {
    &self.0
  }

  pub fn as_bytes(&self) -> &[u8] {
    self.0.as_bytes()
  }

  pub fn into_inner(self) -> String {
    self.0
  }

  pub fn as_pem(&self) -> String {
    super::encode_pem("PUBLIC KEY", &self.0)
  }

  pub fn write_pem_sync(
    &self,
    path: impl AsRef<Path>,
  ) -> anyhow::Result<()> {
    let path = path.as_ref();
    tracing::info!("Writing public key to {path:?}");
    mogh_secret_file::write(path, self.as_pem()).with_context(|| {
      format!("Failed to write public key pem to {path:?}")
    })
  }

  pub async fn write_pem_async(
    &self,
    path: impl AsRef<Path>,
  ) -> anyhow::Result<()> {
    let path = path.as_ref();
    tracing::info!("Writing public key to {path:?}");
    mogh_secret_file::write_async(path, self.as_pem())
      .await
      .with_context(|| {
        format!("Failed to write public key pem to {path:?}")
      })
  }

  /// Supports file or hardcoded spec.
  ///
  /// - Direct pass: `public_key = "MCow..."`
  /// - File path: `public_key = "file:/path/to/key.pub"`
  pub fn from_spec(spec: &str) -> anyhow::Result<Self> {
    if let Some(path) = spec.strip_prefix("file:") {
      SpkiPublicKey::from_file(path)
    } else {
      SpkiPublicKey::from_maybe_pem(spec)
    }
  }

  pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
    let path = path.as_ref();
    let contents =
      std::fs::read_to_string(path).with_context(|| {
        format!("Failed to read public key at {path:?}")
      })?;
    Self::from_maybe_pem(&contents)
  }

  /// Accepts pem rfc7468 (openssl) or base64 der (second line of
  /// rfc7468 pem). Surrounding whitespace is ignored.
  pub fn from_maybe_pem(
    public_key_maybe_pem: &str,
  ) -> anyhow::Result<Self> {
    let public_key_der =
      Self::maybe_pem_to_der(public_key_maybe_pem)?;
    Self::from_der(&public_key_der)
  }

  /// Accepts der (not base64)
  pub fn from_der(public_key_der: &[u8]) -> anyhow::Result<Self> {
    let raw = Self::der_to_raw_bytes(public_key_der)?;
    Self::from_raw_bytes(&raw)
  }

  /// Encodes raw X25519 public key bytes as base64 spki der.
  /// Refuses anything but 32 bytes, non canonical encodings (the
  /// unused top bit set, or u >= 2^255 - 19: aliases of another
  /// key), and the low order points, with which a handshake can be
  /// completed without the private key.
  pub fn from_raw_bytes(public_key: &[u8]) -> anyhow::Result<Self> {
    check_raw_public_key(public_key)?;

    let bs = BitStringRef::new(0, public_key)
      .map_err(anyhow::Error::msg)
      .context("Failed to parse public key bytes into bit string")?;

    let spki = spki::SubjectPublicKeyInfo {
      algorithm: super::algorithm(),
      subject_public_key: bs,
    };

    let mut buf = [0u8; 128];
    let public_key = spki
      .encode_to_slice(&mut buf)
      .map_err(anyhow::Error::msg)
      .context("Failed to write subject public key info into der")?;

    Ok(Self(BASE64.encode(public_key)))
  }

  pub fn maybe_pem_to_raw_bytes(
    public_key_maybe_pem: &str,
  ) -> anyhow::Result<[u8; 32]> {
    let der = Self::maybe_pem_to_der(public_key_maybe_pem)?;
    Self::der_to_raw_bytes(&der)
  }

  /// The spki der of a pem or base64 der public key. Surrounding
  /// whitespace is ignored. The der is not validated, see
  /// [Self::der_to_raw_bytes].
  pub fn maybe_pem_to_der(
    public_key_maybe_pem: &str,
  ) -> anyhow::Result<Vec<u8>> {
    let public_key_maybe_pem = public_key_maybe_pem.trim();
    if public_key_maybe_pem.starts_with("-----BEGIN") {
      let (_label, public_key_der) =
        pem_rfc7468::decode_vec(public_key_maybe_pem.as_bytes())
          .map_err(anyhow::Error::msg)
          .context("Failed to get der from pem")?;
      Ok(public_key_der)
    } else {
      BASE64
        .decode(public_key_maybe_pem.as_bytes())
        .context("Public key is not base64")
    }
  }

  /// The raw X25519 public key in spki der, checked like
  /// [Self::from_raw_bytes].
  pub fn der_to_raw_bytes(
    spki_der: &[u8],
  ) -> anyhow::Result<[u8; 32]> {
    let spki = spki::SubjectPublicKeyInfo::<
      der::AnyRef<'_>,
      BitStringRef<'_>,
    >::from_der(spki_der)
    .map_err(anyhow::Error::msg)
    .context("Invalid public key der")?;

    if spki.algorithm.oid != super::OID_X25519 {
      return Err(anyhow!("Public key is not X25519"));
    }

    let bs = spki.subject_public_key;

    // Check byte aligned
    if bs.unused_bits() != 0 {
      return Err(anyhow!("Public key spki der is not byte-aligned"));
    }

    let raw = bs.as_bytes().context("Bitstring has no bytes")?;
    check_raw_public_key(raw)?;

    let mut res = [0u8; 32];
    res.copy_from_slice(raw);
    Ok(res)
  }

  pub fn from_private_key_using_dh(
    pki_kind: PkiKind,
    maybe_pkcs8_private_key: &str,
  ) -> anyhow::Result<Self> {
    let params: NoiseParams = pki_kind.noise_params().parse()?;
    let mut dh = DefaultResolver.resolve_dh(&params.dh).context(
      "No DH implementation available with these noise params",
    )?;
    let private_key =
      Zeroizing::new(crate::key::Pkcs8PrivateKey::maybe_raw_bytes(
        maybe_pkcs8_private_key,
      )?);
    dh.set(&*private_key);
    Self::from_raw_bytes(dh.pubkey())
  }
}

/// X25519 public keys of low order, in canonical encoding (u, little
/// endian): the DH output with any of them is all zero, whatever the
/// private key, so anyone could complete a handshake as "them"
/// without a private key. The libsodium blocklist; its other entries
/// (p, p + 1) are not canonical and refused as such.
const LOW_ORDER_POINTS: [[u8; 32]; 5] = [
  // 0 (order 4)
  [0; 32],
  // 1 (order 1)
  [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ],
  // order 8
  [
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
    0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
    0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
  ],
  // order 8
  [
    0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1,
    0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c,
    0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
  ],
  // p - 1 (order 2)
  [
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
  ],
];

/// Checks raw X25519 public key bytes, as parsed from an encoding or
/// received in a handshake:
/// - exactly 32 bytes (not the base64 text or the spki der),
/// - canonical: the unused top bit clear, and u < p = 2^255 - 19.
///   X25519 ignores the top bit and reduces u mod p, so otherwise
///   the same key would have several string forms.
/// - not a low order point (see [LOW_ORDER_POINTS]).
///
/// Every key generated or derived here passes.
pub(crate) fn check_raw_public_key(
  public_key: &[u8],
) -> anyhow::Result<()> {
  let raw: &[u8; 32] = public_key.try_into().map_err(|_| {
    anyhow!(
      "Raw public key length should be 32, got {}",
      public_key.len()
    )
  })?;
  let at_least_p = raw[31] == 0x7f
    && raw[1..31].iter().all(|byte| *byte == 0xff)
    && raw[0] >= 0xed;
  if raw[31] & 0x80 != 0 || at_least_p {
    return Err(anyhow!(
      "Public key is not a canonical X25519 encoding"
    ));
  }
  if LOW_ORDER_POINTS.contains(raw) {
    return Err(anyhow!("Public key is a low order X25519 point"));
  }
  Ok(())
}
