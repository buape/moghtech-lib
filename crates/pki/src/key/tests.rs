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

/// A fresh scratch directory per test (no tempfile dependency).
fn scratch_dir(name: &str) -> std::path::PathBuf {
  let dir = std::env::temp_dir().join(format!(
    "mogh_pki_{name}_{}_{}",
    std::process::id(),
    std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_nanos()
  ));
  std::fs::create_dir_all(&dir).unwrap();
  dir
}

#[test]
fn rotation_commit_swaps_the_live_key_and_keeps_the_old_one() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_commit");
  let path = dir.join("test.key");
  let spec = format!("file:{}", path.display());
  let pair =
    RotatableKeyPair::from_private_key_spec(PkiKind::OneWay, &spec)
      .unwrap();
  let original = pair.load().clone();
  assert!(pair.retired(PkiKind::OneWay).unwrap().is_none());

  assert!(!pair.rotation_pending());
  let rotation = pair.begin_rotation(PkiKind::OneWay).unwrap();
  assert!(pair.rotation_pending());
  let candidate = rotation.candidate().clone();
  assert_ne!(candidate.public, original.public);
  // Nothing live changed before commit.
  assert_eq!(pair.load().public, original.public);
  assert!(dir.join("test.key.next").exists());
  assert!(
    Pkcs8PrivateKey::from_file(&path).unwrap() == original.private
  );

  rotation.commit().unwrap();
  // The candidate is live, on disk and in memory; the previous
  // key waits for revocation.
  assert_eq!(pair.load().public, candidate.public);
  assert!(
    Pkcs8PrivateKey::from_file(&path).unwrap() == candidate.private
  );
  assert_eq!(
    SpkiPublicKey::from_file(dir.join("test.pub")).unwrap(),
    candidate.public
  );
  assert!(!dir.join("test.key.next").exists());
  let retired = pair.retired(PkiKind::OneWay).unwrap().unwrap();
  assert_eq!(retired.public, original.public);
  // Until finished, no new rotation may start.
  assert!(pair.begin_rotation(PkiKind::OneWay).is_err());

  pair.finish_rotation().unwrap();
  assert!(pair.retired(PkiKind::OneWay).unwrap().is_none());
  assert!(!pair.rotation_pending());
  // Idempotent.
  pair.finish_rotation().unwrap();

  // A restart loads the committed key.
  let reloaded =
    RotatableKeyPair::from_private_key_spec(PkiKind::OneWay, &spec)
      .unwrap();
  assert_eq!(reloaded.load().public, candidate.public);

  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rotation_resumes_and_aborts_a_candidate() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_resume");
  let path = dir.join("test.key");
  let spec = format!("file:{}", path.display());
  let pair =
    RotatableKeyPair::from_private_key_spec(PkiKind::OneWay, &spec)
      .unwrap();
  let original = pair.load().clone();

  // A candidate left behind (crash before commit) is resumed, not
  // replaced: the caller may already have registered it.
  let first = pair.begin_rotation(PkiKind::OneWay).unwrap();
  let candidate = first.candidate().clone();
  drop(first);
  let resumed = pair.begin_rotation(PkiKind::OneWay).unwrap();
  assert_eq!(resumed.candidate().public, candidate.public);
  assert_eq!(resumed.previous().public, original.public);

  // Abort leaves the live key alone and drops the candidate.
  resumed.abort().unwrap();
  assert!(!dir.join("test.key.next").exists());
  assert_eq!(pair.load().public, original.public);
  assert!(
    Pkcs8PrivateKey::from_file(&path).unwrap() == original.private
  );

  // An unreadable leftover is replaced.
  std::fs::write(dir.join("test.key.next"), "garbage").unwrap();
  let fresh = pair.begin_rotation(PkiKind::OneWay).unwrap();
  assert_ne!(fresh.candidate().public, candidate.public);
  fresh.abort().unwrap();

  // Not file backed: no rotation.
  let inline = RotatableKeyPair::from_private_key_spec(
    PkiKind::OneWay,
    original.private.as_str(),
  )
  .unwrap();
  assert!(!inline.rotatable());
  assert!(inline.begin_rotation(PkiKind::OneWay).is_err());
  assert!(inline.retired(PkiKind::OneWay).unwrap().is_none());
  inline.finish_rotation().unwrap();

  std::fs::remove_dir_all(dir).unwrap();
}

// ---- Empty and well known private keys ----

#[test]
fn empty_private_key_is_refused_everywhere() {
  use super::RotatableKeyPair;
  use crate::mutual::MutualNoiseHandshake;

  for empty in ["", " ", "\n", "\t\r\n"] {
    assert!(Pkcs8PrivateKey::from_maybe_raw_bytes(empty).is_err());
    assert!(Pkcs8PrivateKey::maybe_raw_bytes(empty).is_err());
    assert!(
      EncodedKeyPair::from_private_key(PkiKind::OneWay, empty)
        .is_err()
    );
    assert!(
      RotatableKeyPair::from_private_key_spec(PkiKind::OneWay, empty)
        .is_err()
    );
    assert!(
      SpkiPublicKey::from_private_key_using_dh(
        PkiKind::Mutual,
        empty
      )
      .is_err()
    );
    assert!(
      Pkcs8PrivateKey::from(empty.to_string())
        .compute_public_key_using_dh(PkiKind::OneWay)
        .is_err()
    );
    assert!(
      MutualNoiseHandshake::new_initiator(empty, b"p").is_err()
    );
    assert!(
      MutualNoiseHandshake::new_responder(empty, b"p").is_err()
    );
  }
  assert!(Pkcs8PrivateKey::from_raw_bytes(&[]).is_err());
}

#[test]
fn all_zero_private_key_is_refused() {
  // The all zero scalar, and inputs X25519 clamps to it.
  assert!(Pkcs8PrivateKey::from_raw_bytes(&[0; 32]).is_err());
  assert!(Pkcs8PrivateKey::from_raw_bytes(&[7]).is_err());
  let mut clamped_away = [0u8; 32];
  clamped_away[0] = 0x07;
  clamped_away[31] = 0xc0;
  assert!(Pkcs8PrivateKey::from_raw_bytes(&clamped_away).is_err());
  for raw in ["\u{1}", "\u{7}", "\0\0\0"] {
    assert!(Pkcs8PrivateKey::from_maybe_raw_bytes(raw).is_err());
    assert!(Pkcs8PrivateKey::maybe_raw_bytes(raw).is_err());
  }
  // Also when pkcs8 wraps it.
  let zero = encode_pkcs8_b64("1.3.101.110", &[0; 32]);
  assert!(Pkcs8PrivateKey::raw_bytes(zero.as_bytes()).is_err());
  assert!(Pkcs8PrivateKey::from_maybe_raw_bytes(&zero).is_err());
  let pem = super::encode_pem("PRIVATE KEY", &zero);
  assert!(Pkcs8PrivateKey::maybe_raw_bytes(&pem).is_err());
  // A key one bit away is fine.
  let mut one_bit = [0u8; 32];
  one_bit[0] = 0x08;
  assert!(Pkcs8PrivateKey::from_raw_bytes(&one_bit).is_ok());
}

#[test]
fn empty_private_key_file_is_refused_not_replaced() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("empty_key_file");
  for (name, contents) in [("empty.key", ""), ("newline.key", "\n")] {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    let spec = format!("file:{}", path.display());
    let err =
      RotatableKeyPair::from_private_key_spec(PkiKind::OneWay, &spec)
        .err()
        .expect("an empty key file must be refused");
    let err = format!("{err:#}");
    assert!(err.contains("empty"), "{err}");
    assert!(err.contains(name), "{err}");
    assert!(Pkcs8PrivateKey::from_file(&path).is_err());
    assert!(
      EncodedKeyPair::from_file(PkiKind::OneWay, &path).is_err()
    );
    // Left as it is for the operator, not replaced by a new key.
    assert_eq!(std::fs::read_to_string(&path).unwrap(), contents);
  }
  std::fs::remove_dir_all(dir).unwrap();
}

// ---- Encodings ----

#[test]
fn private_key_encodings_tolerate_surrounding_whitespace() {
  let keys = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  let raw = keys.private.as_raw_bytes().unwrap();
  let pem = keys.private.as_pem();
  for input in [
    format!("{}\n", keys.private.as_str()),
    format!("  {}\r\n", keys.private.as_str()),
    format!("\n{pem}"),
    format!("{pem}\n\n"),
  ] {
    let parsed =
      Pkcs8PrivateKey::from_maybe_raw_bytes(&input).unwrap();
    assert_eq!(parsed.as_str(), keys.private.as_str());
    assert_eq!(
      Pkcs8PrivateKey::maybe_raw_bytes(&input).unwrap(),
      raw
    );
  }

  // A key file written by hand (`echo`) ends in a newline.
  let dir = scratch_dir("key_newline");
  let path = dir.join("hand.key");
  std::fs::write(&path, format!("{}\n", keys.private.as_str()))
    .unwrap();
  let loaded =
    EncodedKeyPair::from_file(PkiKind::OneWay, &path).unwrap();
  assert_eq!(loaded.private.as_str(), keys.private.as_str());
  assert_eq!(loaded.public, keys.public);
  let pub_path = dir.join("hand.pub");
  std::fs::write(&pub_path, format!("{}\n", keys.public.as_str()))
    .unwrap();
  let spec = format!("file:{}", pub_path.display());
  assert_eq!(SpkiPublicKey::from_spec(&spec).unwrap(), keys.public);
  assert_eq!(
    SpkiPublicKey::from_maybe_pem(&format!(" {}\n", keys.public))
      .unwrap(),
    keys.public
  );
  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn raw_private_keys_are_used_exactly_as_given() {
  // Raw input is not trimmed, so a raw key keeps deriving the same
  // public key it always did.
  let mut expected = [0u8; 32];
  expected[..6].copy_from_slice(b"hello\n");
  assert_eq!(
    Pkcs8PrivateKey::maybe_raw_bytes("hello\n").unwrap(),
    expected
  );
  assert_ne!(
    Pkcs8PrivateKey::maybe_raw_bytes("hello\n").unwrap(),
    Pkcs8PrivateKey::maybe_raw_bytes("hello").unwrap()
  );
}

#[test]
fn pkcs8_v2_private_key_is_normalized_to_v1() {
  let keys = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();
  let raw = keys.private.as_raw_bytes().unwrap();
  let public_raw =
    SpkiPublicKey::maybe_pem_to_raw_bytes(keys.public.as_str())
      .unwrap();
  // OneAsymmetricKey (pkcs8 v2), carrying the public key.
  let octet = der::asn1::OctetStringRef::new(&raw).unwrap();
  let mut buf = [0u8; 128];
  let octet_der = octet.encode_to_slice(&mut buf).unwrap();
  let v2 = pkcs8::PrivateKeyInfo {
    algorithm: super::algorithm(),
    private_key: octet_der,
    public_key: Some(&public_raw),
  };
  assert_eq!(v2.version(), pkcs8::Version::V2);
  let mut buf = [0u8; 128];
  let v2 = BASE64.encode(v2.encode_to_slice(&mut buf).unwrap());
  assert_ne!(v2.len(), 64);
  let v2_pem = super::encode_pem("PRIVATE KEY", &v2);

  for input in [&v2, &v2_pem] {
    let parsed =
      Pkcs8PrivateKey::from_maybe_raw_bytes(input).unwrap();
    // Stored in the canonical v1 form, which every consumer reads.
    assert_eq!(parsed.as_str(), keys.private.as_str());
    assert_eq!(Pkcs8PrivateKey::maybe_raw_bytes(input).unwrap(), raw);
    let pair =
      EncodedKeyPair::from_private_key(PkiKind::Mutual, input)
        .unwrap();
    assert_eq!(pair.public, keys.public);
    assert_eq!(pair.private.as_str(), keys.private.as_str());
  }
}

#[test]
fn private_key_debug_is_redacted() {
  let keys = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  let debug = format!("{:?}", keys.private);
  assert!(!debug.contains(keys.private.as_str()), "{debug}");
  assert!(debug.contains("redacted"), "{debug}");
  // into_inner hands the key out (the Drop impl must not wipe it).
  let expected = keys.private.as_str().to_string();
  assert_eq!(keys.private.clone().into_inner(), expected);
}

// ---- Public key validation ----

/// Canonical low order X25519 points (see public::LOW_ORDER_POINTS).
fn low_order_points() -> Vec<[u8; 32]> {
  let hex = |s: &str| -> [u8; 32] {
    data_encoding::HEXLOWER
      .decode(s.as_bytes())
      .unwrap()
      .try_into()
      .unwrap()
  };
  vec![
    [0; 32],
    hex(
      "0100000000000000000000000000000000000000000000000000000000000000",
    ),
    hex(
      "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    ),
    hex(
      "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    ),
    hex(
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ),
  ]
}

#[test]
fn low_order_points_give_an_all_zero_shared_secret() {
  use snow::resolvers::{CryptoResolver as _, DefaultResolver};
  // The blocklist is right: with any private key, the DH output is
  // all zero, so no private key is needed to complete a handshake.
  let params: snow::params::NoiseParams =
    PkiKind::OneWay.noise_params().parse().unwrap();
  let keys = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  let mut dh = DefaultResolver.resolve_dh(&params.dh).unwrap();
  dh.set(&keys.private.as_raw_bytes().unwrap());
  for point in low_order_points() {
    let mut out = [0xffu8; 32];
    dh.dh(&point, &mut out).unwrap();
    assert_eq!(out, [0; 32], "{point:?}");
  }
}

#[test]
fn low_order_and_non_canonical_public_keys_are_refused() {
  for point in low_order_points() {
    assert!(SpkiPublicKey::from_raw_bytes(&point).is_err());
    let der = encode_spki_der("1.3.101.110", &point, 0);
    assert!(SpkiPublicKey::from_der(&der).is_err());
    assert!(SpkiPublicKey::der_to_raw_bytes(&der).is_err());
    let b64 = BASE64.encode(&der);
    assert!(SpkiPublicKey::from_maybe_pem(&b64).is_err());
    assert!(SpkiPublicKey::maybe_pem_to_raw_bytes(&b64).is_err());
  }
  // The all zero key, as a client would register it.
  assert!(
    SpkiPublicKey::from_maybe_pem(
      "MCowBQYDK2VuAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    .is_err()
  );

  let keys = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  let raw =
    SpkiPublicKey::maybe_pem_to_raw_bytes(keys.public.as_str())
      .unwrap();
  // The same key with the ignored top bit set: another string for
  // the same key.
  let mut high_bit = raw;
  high_bit[31] |= 0x80;
  assert!(SpkiPublicKey::from_raw_bytes(&high_bit).is_err());
  let der = encode_spki_der("1.3.101.110", &high_bit, 0);
  assert!(SpkiPublicKey::from_der(&der).is_err());
  // u >= p: p itself (= 0), p + 1 (= 1) and 2^255 - 1.
  for first in [0xed, 0xee, 0xff] {
    let mut at_least_p = [0xffu8; 32];
    at_least_p[0] = first;
    at_least_p[31] = 0x7f;
    assert!(SpkiPublicKey::from_raw_bytes(&at_least_p).is_err());
  }
  // The largest canonical u (p - 2) is fine.
  let mut largest = [0xffu8; 32];
  largest[0] = 0xeb;
  largest[31] = 0x7f;
  assert!(SpkiPublicKey::from_raw_bytes(&largest).is_ok());
  // Generated keys always pass.
  for _ in 0..32 {
    let keys = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
    assert!(
      SpkiPublicKey::from_maybe_pem(keys.public.as_str()).is_ok()
    );
  }
}

// ---- Rotation ----

#[test]
fn a_failed_commit_leaves_no_retired_key() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_failed_commit");
  let path = dir.join("test.key");
  let spec = format!("file:{}", path.display());
  let pair =
    RotatableKeyPair::from_private_key_spec(PkiKind::OneWay, &spec)
      .unwrap();
  let original = pair.load().clone();
  let original_file = std::fs::read(&path).unwrap();

  let rotation = pair.begin_rotation(PkiKind::OneWay).unwrap();
  let candidate = rotation.candidate().clone();
  // The rename onto the live path fails (as onto a mount point):
  // make the live path a non empty directory.
  std::fs::remove_file(&path).unwrap();
  std::fs::create_dir(&path).unwrap();
  std::fs::write(path.join("occupied"), "").unwrap();
  assert!(rotation.commit().is_err());

  // Nothing switched, and nothing offers the live key for
  // revocation.
  assert_eq!(pair.load().public, original.public);
  assert!(!dir.join("test.key.old").exists());
  assert!(pair.retired(PkiKind::OneWay).unwrap().is_none());

  // Once the live file is back, the candidate resumes.
  std::fs::remove_dir_all(&path).unwrap();
  std::fs::write(&path, &original_file).unwrap();
  let resumed = pair.begin_rotation(PkiKind::OneWay).unwrap();
  assert_eq!(resumed.candidate().public, candidate.public);
  resumed.commit().unwrap();
  assert_eq!(pair.load().public, candidate.public);
  let retired = pair.retired(PkiKind::OneWay).unwrap().unwrap();
  assert_eq!(retired.public, original.public);
  pair.finish_rotation().unwrap();

  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn an_old_key_equal_to_the_live_one_is_not_retired() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_interrupted_commit");
  let path = dir.join("test.key");
  let old = dir.join("test.key.old");
  let spec = format!("file:{}", path.display());
  let pair =
    RotatableKeyPair::from_private_key_spec(PkiKind::OneWay, &spec)
      .unwrap();
  let live = pair.load().clone();

  // A crash between keeping the previous key and the switch.
  let rotation = pair.begin_rotation(PkiKind::OneWay).unwrap();
  let candidate = rotation.candidate().clone();
  drop(rotation);
  live.private.write_pem_sync(&old).unwrap();
  assert!(pair.rotation_pending());
  // Never handed out for revocation: it is the key in use. Only
  // read, so it stays until begin_rotation.
  assert!(pair.retired(PkiKind::OneWay).unwrap().is_none());
  assert!(old.exists());
  assert!(pair.rotation_pending());

  // begin_rotation settles it, and resumes the candidate.
  let resumed = pair.begin_rotation(PkiKind::OneWay).unwrap();
  assert!(!old.exists());
  assert_eq!(resumed.candidate().public, candidate.public);
  resumed.abort().unwrap();

  // A real retired key (another key) still blocks a new rotation.
  EncodedKeyPair::generate(PkiKind::OneWay)
    .unwrap()
    .private
    .write_pem_sync(&old)
    .unwrap();
  assert!(pair.retired(PkiKind::OneWay).unwrap().is_some());
  assert!(pair.begin_rotation(PkiKind::OneWay).is_err());
  pair.finish_rotation().unwrap();

  std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn one_rotation_at_a_time() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_exclusive");
  let path = dir.join("test.key");
  let spec = format!("file:{}", path.display());
  let pair =
    RotatableKeyPair::from_private_key_spec(PkiKind::OneWay, &spec)
      .unwrap();
  let original = pair.load().clone();

  let rotation = pair.begin_rotation(PkiKind::OneWay).unwrap();
  let err = pair.begin_rotation(PkiKind::OneWay).err().unwrap();
  assert!(err.to_string().contains("in progress"), "{err:#}");
  assert!(pair.rotate(PkiKind::OneWay).await.is_err());
  assert!(pair.finish_rotation().is_err());
  // Nothing changed meanwhile.
  assert_eq!(pair.load().public, original.public);

  // Dropping ends it.
  drop(rotation);
  let rotation = pair.begin_rotation(PkiKind::OneWay).unwrap();
  rotation.abort().unwrap();
  let rotated = pair.rotate(PkiKind::OneWay).await.unwrap();
  assert_eq!(pair.load().public, rotated);
  let rotation = pair.begin_rotation(PkiKind::OneWay).unwrap();
  rotation.commit().unwrap();
  pair.finish_rotation().unwrap();

  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn commit_refuses_a_replaced_candidate() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_replaced_candidate");
  let path = dir.join("test.key");
  let next = dir.join("test.key.next");
  let spec = format!("file:{}", path.display());
  let pair =
    RotatableKeyPair::from_private_key_spec(PkiKind::OneWay, &spec)
      .unwrap();
  let original = pair.load().clone();

  let rotation = pair.begin_rotation(PkiKind::OneWay).unwrap();
  // Another writer replaced the candidate file meanwhile.
  let other = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  other.private.write_pem_sync(&next).unwrap();
  let err = rotation.commit().err().unwrap();
  assert!(err.to_string().contains("changed"), "{err:#}");

  // Nothing changed: memory and disk agree on the previous key.
  assert_eq!(pair.load().public, original.public);
  assert!(
    Pkcs8PrivateKey::from_file(&path).unwrap() == original.private
  );
  assert!(!dir.join("test.key.old").exists());
  assert!(pair.retired(PkiKind::OneWay).unwrap().is_none());

  std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn rotate_switches_memory_with_the_key_file() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_pub_fails");
  let path = dir.join("test.key");
  let spec = format!("file:{}", path.display());
  let pair =
    RotatableKeyPair::from_private_key_spec(PkiKind::OneWay, &spec)
      .unwrap();
  let original = pair.load().clone();

  // The `.pub` sidecar can't be written (a directory in its place).
  let pub_path = dir.join("test.pub");
  std::fs::remove_file(&pub_path).unwrap();
  std::fs::create_dir(&pub_path).unwrap();
  std::fs::write(pub_path.join("occupied"), "").unwrap();

  // The private key file switched, so memory must switch with it.
  let public = pair.rotate(PkiKind::OneWay).await.unwrap();
  assert_ne!(public, original.public);
  assert_eq!(pair.load().public, public);
  let on_disk =
    EncodedKeyPair::from_file(PkiKind::OneWay, &path).unwrap();
  assert_eq!(on_disk.public, public);

  // Not file backed: nothing to rotate.
  let inline = RotatableKeyPair::from_private_key_spec(
    PkiKind::OneWay,
    original.private.as_str(),
  )
  .unwrap();
  assert_eq!(
    inline.rotate(PkiKind::OneWay).await.unwrap(),
    original.public
  );

  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rotate_follows_the_key_file_when_the_write_errors() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_write_errors");
  let path = dir.join("test.key");
  let spec = format!("file:{}", path.display());
  let pair =
    RotatableKeyPair::from_private_key_spec(PkiKind::OneWay, &spec)
      .unwrap();
  let original = pair.load().clone();

  // Fails before touching the file: nothing switched.
  let err = pair
    .rotate_with(PkiKind::OneWay, |_, _| {
      Err(anyhow::anyhow!("create failed"))
    })
    .err()
    .unwrap();
  assert!(err.to_string().contains("create failed"), "{err:#}");
  assert_eq!(pair.load().public, original.public);
  assert!(
    Pkcs8PrivateKey::from_file(&path).unwrap() == original.private
  );

  // Fails midway through an in place write: the file holds no key
  // memory could switch to, so the error stands.
  let err = pair
    .rotate_with(PkiKind::OneWay, |_, path| {
      std::fs::write(path, "-----BEGIN PRIVATE KEY-----\nMC4C")
        .unwrap();
      Err(anyhow::anyhow!("write failed"))
    })
    .err()
    .unwrap();
  assert!(err.to_string().contains("write failed"), "{err:#}");
  assert_eq!(pair.load().public, original.public);
  original.private.write_pem_sync(&path).unwrap();

  // Fails after the new key is in place (syncing the directory):
  // the file switched, so memory switches with it.
  let public = pair
    .rotate_with(PkiKind::OneWay, |private, path| {
      private.write_pem_sync(path)?;
      Err(anyhow::anyhow!("directory sync failed"))
    })
    .unwrap();
  assert_ne!(public, original.public);
  assert_eq!(pair.load().public, public);
  let on_disk =
    EncodedKeyPair::from_file(PkiKind::OneWay, &path).unwrap();
  assert_eq!(on_disk.public, public);
  assert_eq!(
    SpkiPublicKey::from_file(dir.join("test.pub")).unwrap(),
    public
  );

  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn reading_the_retired_key_never_blocks_a_rotation() {
  use super::{RotatableKeyPair, RotationGuard};

  let dir = scratch_dir("retired_unguarded");
  let path = dir.join("test.key");
  let old = dir.join("test.key.old");
  let spec = format!("file:{}", path.display());
  let pair =
    RotatableKeyPair::from_private_key_spec(PkiKind::OneWay, &spec)
      .unwrap();
  // While one thread keeps reading `.old`, a rotation starting on
  // another is never refused as already in progress: the number of
  // refusals.
  let race = |expected: Option<&SpkiPublicKey>| {
    std::thread::scope(|scope| {
      let reader = scope.spawn(|| {
        for _ in 0..500 {
          let loaded = pair.retired(PkiKind::OneWay).unwrap();
          assert_eq!(loaded.map(|k| k.public).as_ref(), expected);
        }
      });
      let mut refused = 0;
      while !reader.is_finished() {
        if RotationGuard::acquire(&pair.rotating).is_err() {
          refused += 1;
        }
      }
      refused
    })
  };

  // A retired key.
  let retired = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  retired.private.write_pem_sync(&old).unwrap();
  assert_eq!(race(Some(&retired.public)), 0);
  pair.finish_rotation().unwrap();

  // An `.old` holding the live key (a commit that did not switch):
  // not retired, and never removed by a read, which would need the
  // guard.
  let live = pair.load().clone();
  live.private.write_pem_sync(&old).unwrap();
  assert_eq!(race(None), 0);
  assert!(old.exists());
  // Nor while a rotation is in flight (a commit writes it before
  // its switch).
  let rotation = pair.begin_rotation(PkiKind::OneWay).unwrap();
  // begin_rotation removed it, under the guard.
  assert!(!old.exists());
  live.private.write_pem_sync(&old).unwrap();
  assert!(pair.retired(PkiKind::OneWay).unwrap().is_none());
  assert!(old.exists());
  rotation.abort().unwrap();
  assert!(pair.retired(PkiKind::OneWay).unwrap().is_none());
  assert!(old.exists());
  let rotation = pair.begin_rotation(PkiKind::OneWay).unwrap();
  assert!(!old.exists());
  rotation.abort().unwrap();

  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn only_an_empty_key_file_suggests_deleting_it() {
  let dir = scratch_dir("load_hint");

  let empty = dir.join("empty.key");
  std::fs::write(&empty, " \n").unwrap();
  let err =
    EncodedKeyPair::load_maybe_generate(PkiKind::OneWay, &empty)
      .err()
      .unwrap();
  assert!(
    format!("{err:#}")
      .contains("delete it to have a new key generated"),
    "{err:#}"
  );

  // A real key in a form this can't load (Ed25519), garbage, and
  // an unreadable file (a directory) are refused without the hint:
  // deleting would throw away a registered identity.
  let ed25519 = dir.join("ed25519.key");
  std::fs::write(
    &ed25519,
    encode_pkcs8_b64("1.3.101.112", &[7u8; 32]) + "\n",
  )
  .unwrap();
  let garbage = dir.join("garbage.key");
  std::fs::write(&garbage, "this is not a private key, not at all\n")
    .unwrap();
  let unreadable = dir.join("unreadable.key");
  std::fs::create_dir(&unreadable).unwrap();
  for path in [&ed25519, &garbage, &unreadable] {
    let before = std::fs::symlink_metadata(path).unwrap();
    let err =
      EncodedKeyPair::load_maybe_generate(PkiKind::OneWay, path)
        .err()
        .unwrap();
    let err = format!("{err:#}");
    assert!(err.contains("Failed to load the private key"), "{err}");
    assert!(!err.contains("new key generated"), "{err}");
    // Left as it is.
    let after = std::fs::symlink_metadata(path).unwrap();
    assert_eq!(before.len(), after.len());
    assert_eq!(before.is_dir(), after.is_dir());
  }

  std::fs::remove_dir_all(dir).unwrap();
}
