use data_encoding::BASE64;
use der::Encode as _;

use super::{EncodedKeyPair, Pkcs8PrivateKey, SpkiPublicKey};
use crate::PkiKind;

fn encode_pkcs8_b64(oid: &str, raw_private_key: &[u8]) -> String {
  let octet =
    der::asn1::OctetStringRef::new(raw_private_key).unwrap();
  let mut buf = [0u8; 128];
  let octet_der = octet.encode_to_slice(&mut buf).unwrap();
  let pki = pkcs8::PrivateKeyInfo {
    algorithm: spki::AlgorithmIdentifier {
      oid: spki::ObjectIdentifier::new_unwrap(oid),
      parameters: None,
    },
    private_key: octet_der,
    public_key: None,
  };
  let mut buf = [0u8; 128];
  BASE64.encode(pki.encode_to_slice(&mut buf).unwrap())
}

fn encode_spki_der(
  oid: &str,
  raw_public_key: &[u8],
  unused_bits: u8,
) -> Vec<u8> {
  let spki = spki::SubjectPublicKeyInfo {
    algorithm: spki::AlgorithmIdentifier::<der::AnyRef<'_>> {
      oid: spki::ObjectIdentifier::new_unwrap(oid),
      parameters: None,
    },
    subject_public_key: der::asn1::BitStringRef::new(
      unused_bits,
      raw_public_key,
    )
    .unwrap(),
  };
  let mut buf = [0u8; 128];
  spki.encode_to_slice(&mut buf).unwrap().to_vec()
}

#[test]
fn generate_private_key_raw_bytes_round_trip() {
  let keys = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  let raw = keys.private.as_raw_bytes().unwrap();
  let restored = Pkcs8PrivateKey::from_raw_bytes(&raw).unwrap();
  assert_eq!(keys.private.as_str(), restored.as_str());
}

#[test]
fn generate_private_key_pem_round_trip() {
  let keys = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();
  let pem = keys.private.as_pem();
  let restored = Pkcs8PrivateKey::from_maybe_raw_bytes(&pem).unwrap();
  assert_eq!(keys.private.as_str(), restored.as_str());
  assert_eq!(
    Pkcs8PrivateKey::maybe_raw_bytes(&pem).unwrap(),
    keys.private.as_raw_bytes().unwrap()
  );
}

#[test]
fn generate_private_key_base64_round_trip() {
  let keys = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  // Stored format is 64 character base64 der
  assert_eq!(keys.private.as_str().len(), 64);
  let restored =
    Pkcs8PrivateKey::from_maybe_raw_bytes(keys.private.as_str())
      .unwrap();
  assert_eq!(keys.private.as_str(), restored.as_str());
}

#[test]
fn private_key_constant_time_eq_matches_expected() {
  let keys = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  let same = Pkcs8PrivateKey::from(keys.private.as_str().to_string());
  // Pkcs8PrivateKey has no Debug impl (it is secret
  // material), so use plain boolean assertions.
  assert!(keys.private == same);
  assert!(keys.private == keys.private.clone());

  let other = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  assert!(keys.private != other.private);

  // Differing lengths must compare unequal
  let truncated =
    Pkcs8PrivateKey::from(keys.private.as_str()[..32].to_string());
  assert!(keys.private != truncated);
}

#[test]
fn generate_public_key_pem_round_trip() {
  let keys = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  let pem = keys.public.as_pem();
  let restored = SpkiPublicKey::from_maybe_pem(&pem).unwrap();
  assert_eq!(keys.public, restored);
}

#[test]
fn generate_public_key_der_and_raw_bytes_round_trip() {
  let keys = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();
  let der =
    SpkiPublicKey::maybe_pem_to_der(keys.public.as_str()).unwrap();
  assert_eq!(SpkiPublicKey::from_der(&der).unwrap(), keys.public);
  let raw = SpkiPublicKey::der_to_raw_bytes(&der).unwrap();
  assert_eq!(
    SpkiPublicKey::from_raw_bytes(&raw).unwrap(),
    keys.public
  );
  assert_eq!(
    SpkiPublicKey::maybe_pem_to_raw_bytes(keys.public.as_str())
      .unwrap(),
    raw
  );
}

#[test]
fn public_key_derivation_is_consistent() {
  let keys = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  let computed = keys
    .private
    .compute_public_key_using_dh(PkiKind::OneWay)
    .unwrap();
  assert_eq!(keys.public, computed);
  // Both kinds use the same 25519 DH, so derivation must agree
  let computed = keys
    .private
    .compute_public_key_using_dh(PkiKind::Mutual)
    .unwrap();
  assert_eq!(keys.public, computed);
}

#[test]
fn from_private_key_derives_matching_public_key() {
  let keys = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();
  let restored = EncodedKeyPair::from_private_key(
    PkiKind::Mutual,
    keys.private.as_str(),
  )
  .unwrap();
  assert_eq!(keys.private.as_str(), restored.private.as_str());
  assert_eq!(keys.public, restored.public);
}

#[test]
fn short_raw_private_key_is_zero_padded() {
  let key = Pkcs8PrivateKey::from_maybe_raw_bytes("hello").unwrap();
  let mut expected = [0u8; 32];
  expected[..5].copy_from_slice(b"hello");
  assert_eq!(key.as_raw_bytes().unwrap(), expected);
  assert_eq!(
    Pkcs8PrivateKey::maybe_raw_bytes("hello").unwrap(),
    expected
  );
  // Derivation must agree between the raw and pkcs8 forms
  let from_raw = SpkiPublicKey::from_private_key_using_dh(
    PkiKind::OneWay,
    "hello",
  )
  .unwrap();
  let from_pkcs8 =
    key.compute_public_key_using_dh(PkiKind::OneWay).unwrap();
  assert_eq!(from_raw, from_pkcs8);
}

#[test]
fn private_key_rejects_oversized_input() {
  let too_long = "a".repeat(65);
  assert!(Pkcs8PrivateKey::from_maybe_raw_bytes(&too_long).is_err());
  assert!(Pkcs8PrivateKey::maybe_raw_bytes(&too_long).is_err());
  assert!(Pkcs8PrivateKey::from_raw_bytes(&[0u8; 33]).is_err());
}

#[test]
fn private_key_rejects_invalid_base64() {
  let invalid = "!".repeat(64);
  assert!(Pkcs8PrivateKey::from_maybe_raw_bytes(&invalid).is_err());
  assert!(Pkcs8PrivateKey::maybe_raw_bytes(&invalid).is_err());
}

#[test]
fn private_key_rejects_garbage_pem() {
  let pem =
    "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
  assert!(Pkcs8PrivateKey::from_maybe_raw_bytes(pem).is_err());
  assert!(Pkcs8PrivateKey::maybe_raw_bytes(pem).is_err());
}

#[test]
fn private_key_rejects_truncated_der() {
  let keys = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  let mut der = BASE64.decode(keys.private.as_bytes()).unwrap();
  der.truncate(der.len() - 4);
  let truncated = BASE64.encode(&der);
  assert!(Pkcs8PrivateKey::raw_bytes(truncated.as_bytes()).is_err());
}

#[test]
fn private_key_rejects_wrong_algorithm() {
  // Ed25519 OID instead of X25519
  let b64 = encode_pkcs8_b64("1.3.101.112", &[7u8; 32]);
  assert!(Pkcs8PrivateKey::raw_bytes(b64.as_bytes()).is_err());
}

#[test]
fn private_key_rejects_oversized_inner_octet_without_panic() {
  // Well formed pkcs8 with a 48 byte inner key must
  // error (not panic) on conversion to raw bytes.
  let b64 = encode_pkcs8_b64("1.3.101.110", &[7u8; 48]);
  assert!(Pkcs8PrivateKey::raw_bytes(b64.as_bytes()).is_err());
  assert!(Pkcs8PrivateKey::from_maybe_raw_bytes(&b64).is_err());
}

#[test]
fn public_key_rejects_invalid_input() {
  assert!(SpkiPublicKey::from_maybe_pem("not-base-64!").is_err());
  assert!(
    SpkiPublicKey::from_maybe_pem(
      "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
    )
    .is_err()
  );
  assert!(SpkiPublicKey::from_raw_bytes(&[0u8; 16]).is_err());
  assert!(SpkiPublicKey::from_raw_bytes(&[0u8; 33]).is_err());
}

#[test]
fn public_key_rejects_truncated_der() {
  let keys = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  let mut der =
    SpkiPublicKey::maybe_pem_to_der(keys.public.as_str()).unwrap();
  der.truncate(der.len() - 4);
  assert!(SpkiPublicKey::from_der(&der).is_err());
  assert!(SpkiPublicKey::der_to_raw_bytes(&der).is_err());
}

#[test]
fn public_key_rejects_wrong_algorithm() {
  // Ed25519 OID instead of X25519
  let der = encode_spki_der("1.3.101.112", &[7u8; 32], 0);
  assert!(SpkiPublicKey::from_der(&der).is_err());
  assert!(SpkiPublicKey::der_to_raw_bytes(&der).is_err());
}

#[test]
fn public_key_rejects_wrong_length_bit_string() {
  let der = encode_spki_der("1.3.101.110", &[7u8; 16], 0);
  assert!(SpkiPublicKey::from_der(&der).is_err());
  assert!(SpkiPublicKey::der_to_raw_bytes(&der).is_err());
}

#[test]
fn public_key_rejects_unaligned_bit_string() {
  let der = encode_spki_der("1.3.101.110", &[7u8; 32], 3);
  assert!(SpkiPublicKey::from_der(&der).is_err());
  assert!(SpkiPublicKey::der_to_raw_bytes(&der).is_err());
}

#[test]
fn pem_wrapping_matches_rfc7468() {
  // A 96 character base64 body must wrap at 64 characters,
  // or pem_rfc7468 will reject it on re-parse.
  let long = SpkiPublicKey::from("A".repeat(96));
  let pem = long.as_pem();
  for line in pem.lines() {
    assert!(line.len() <= 64);
  }
  assert!(pem_rfc7468::decode_vec(pem.as_bytes()).is_ok());
}

#[test]
fn generate_write_and_load_round_trip() {
  let dir = std::env::temp_dir().join(format!(
    "mogh_pki_test_{}_{}",
    std::process::id(),
    std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_nanos()
  ));
  let path = dir.join("test.key");

  let keys =
    EncodedKeyPair::generate_write_sync(PkiKind::OneWay, &path)
      .unwrap();

  let private = Pkcs8PrivateKey::from_file(&path).unwrap();
  assert_eq!(keys.private.as_str(), private.as_str());

  let public =
    SpkiPublicKey::from_file(path.with_extension("pub")).unwrap();
  assert_eq!(keys.public, public);

  // Loading with existing file must return the same pair
  let loaded =
    EncodedKeyPair::load_maybe_generate(PkiKind::OneWay, &path)
      .unwrap();
  assert_eq!(keys.private.as_str(), loaded.private.as_str());
  assert_eq!(keys.public, loaded.public);

  let spec = format!("file:{}", path.with_extension("pub").display());
  assert_eq!(SpkiPublicKey::from_spec(&spec).unwrap(), keys.public);

  std::fs::remove_dir_all(&dir).ok();
}
