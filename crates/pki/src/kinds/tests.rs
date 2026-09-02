use crate::{
  EncodedKeyPair, PkiKind, mutual::MutualNoiseHandshake,
  one_way::OneWayNoiseHandshake,
};

#[test]
fn one_way_handshake_produces_client_public_key() {
  let client = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  let server = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();

  let client_private = client.private.as_raw_bytes().unwrap();
  let server_private = server.private.as_raw_bytes().unwrap();
  let server_public = crate::SpkiPublicKey::maybe_pem_to_raw_bytes(
    server.public.as_str(),
  )
  .unwrap();

  let prologue = b"request body";

  let mut initiator = OneWayNoiseHandshake::new_initiator(
    &client_private,
    &server_public,
    prologue,
  )
  .unwrap();
  let mut responder =
    OneWayNoiseHandshake::new_responder(&server_private, prologue)
      .unwrap();

  let signature = initiator.generate_signature().unwrap();
  let client_public =
    responder.validate_signature(&signature).unwrap();
  assert_eq!(client.public, client_public);
}

#[test]
fn one_way_handshake_rejects_tampered_signature() {
  let client = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  let server = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();

  let client_private = client.private.as_raw_bytes().unwrap();
  let server_private = server.private.as_raw_bytes().unwrap();
  let server_public = crate::SpkiPublicKey::maybe_pem_to_raw_bytes(
    server.public.as_str(),
  )
  .unwrap();

  let mut initiator = OneWayNoiseHandshake::new_initiator(
    &client_private,
    &server_public,
    b"prologue",
  )
  .unwrap();
  let mut responder =
    OneWayNoiseHandshake::new_responder(&server_private, b"prologue")
      .unwrap();

  let signature = initiator.generate_signature().unwrap();
  let decoded =
    data_encoding::BASE64.decode(signature.as_bytes()).unwrap();
  let mut tampered = decoded;
  tampered[0] ^= 0xff;
  let tampered = data_encoding::BASE64.encode(&tampered);
  assert!(responder.validate_signature(&tampered).is_err());
  assert!(responder.validate_signature("not base64!").is_err());
}

#[test]
fn one_way_handshake_rejects_mismatched_prologue() {
  let client = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  let server = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();

  let client_private = client.private.as_raw_bytes().unwrap();
  let server_private = server.private.as_raw_bytes().unwrap();
  let server_public = crate::SpkiPublicKey::maybe_pem_to_raw_bytes(
    server.public.as_str(),
  )
  .unwrap();

  let mut initiator = OneWayNoiseHandshake::new_initiator(
    &client_private,
    &server_public,
    b"request body",
  )
  .unwrap();
  let mut responder = OneWayNoiseHandshake::new_responder(
    &server_private,
    b"tampered body",
  )
  .unwrap();

  let signature = initiator.generate_signature().unwrap();
  assert!(responder.validate_signature(&signature).is_err());
}

#[test]
fn mutual_handshake_exchanges_public_keys() {
  let client = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();
  let server = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();

  let prologue = b"prologue";

  let mut initiator = MutualNoiseHandshake::new_initiator(
    client.private.as_str(),
    prologue,
  )
  .unwrap();
  let mut responder = MutualNoiseHandshake::new_responder(
    server.private.as_str(),
    prologue,
  )
  .unwrap();

  let m1 = initiator.next_message().unwrap();
  responder.read_message(&m1).unwrap();

  let m2 = responder.next_message().unwrap();
  initiator.read_message(&m2).unwrap();

  // Initiator has the responder public key after m2
  let server_public = crate::SpkiPublicKey::from_raw_bytes(
    initiator.remote_public_key().unwrap(),
  )
  .unwrap();
  assert_eq!(server.public, server_public);

  let m3 = initiator.next_message().unwrap();
  responder.read_message(&m3).unwrap();

  // Responder has the initiator public key after m3
  let client_public = crate::SpkiPublicKey::from_raw_bytes(
    responder.remote_public_key().unwrap(),
  )
  .unwrap();
  assert_eq!(client.public, client_public);
}

#[test]
fn mutual_handshake_rejects_tampered_message() {
  let client = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();
  let server = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();

  let mut initiator = MutualNoiseHandshake::new_initiator(
    client.private.as_str(),
    b"prologue",
  )
  .unwrap();
  let mut responder = MutualNoiseHandshake::new_responder(
    server.private.as_str(),
    b"prologue",
  )
  .unwrap();

  let m1 = initiator.next_message().unwrap();
  responder.read_message(&m1).unwrap();

  let mut m2 = responder.next_message().unwrap();
  let last = m2.len() - 1;
  m2[last] ^= 0xff;
  assert!(initiator.read_message(&m2).is_err());
}
