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

#[test]
fn one_way_constructors_refuse_wrong_key_lengths() {
  let client = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  let server = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  let client_private = client.private.as_raw_bytes().unwrap();
  let server_public = crate::SpkiPublicKey::maybe_pem_to_raw_bytes(
    server.public.as_str(),
  )
  .unwrap();
  let server_der =
    crate::SpkiPublicKey::maybe_pem_to_der(server.public.as_str())
      .unwrap();

  // The base64 text (64 / 60 bytes), the der (44 bytes), or any
  // other length is an error, not a panic or a zero padded key.
  let wrong_private: [&[u8]; 4] =
    [client.private.as_bytes(), &[7; 33], &[7; 31], &[]];
  for private in wrong_private {
    assert!(
      OneWayNoiseHandshake::new_responder(private, b"p").is_err(),
      "{}",
      private.len()
    );
    assert!(
      OneWayNoiseHandshake::new_initiator(
        private,
        &server_public,
        b"p"
      )
      .is_err(),
      "{}",
      private.len()
    );
  }
  let wrong_public: [&[u8]; 5] = [
    server.public.as_bytes(),
    &server_der,
    &[7; 33],
    &[7; 31],
    &[],
  ];
  for public in wrong_public {
    assert!(
      OneWayNoiseHandshake::new_initiator(
        &client_private,
        public,
        b"p"
      )
      .is_err(),
      "{}",
      public.len()
    );
  }
  // The all zero private key, and a low order server key.
  assert!(
    OneWayNoiseHandshake::new_responder(&[0; 32], b"p").is_err()
  );
  assert!(
    OneWayNoiseHandshake::new_initiator(
      &client_private,
      &[0; 32],
      b"p"
    )
    .is_err()
  );
}

/// A DH which, once set to [FORGED], claims the all zero (low order)
/// public key and outputs the all zero shared secret, as the
/// honest side computes with that key. This is how a handshake is
/// completed "as" a low order key with no private key at all.
/// Keys generated or set otherwise behave normally.
struct ForgingDh {
  inner: Box<dyn snow::types::Dh>,
  forged: bool,
}

const FORGED: [u8; 32] = [0xaa; 32];

impl snow::types::Dh for ForgingDh {
  fn name(&self) -> &'static str {
    self.inner.name()
  }
  fn pub_len(&self) -> usize {
    self.inner.pub_len()
  }
  fn priv_len(&self) -> usize {
    self.inner.priv_len()
  }
  fn set(&mut self, privkey: &[u8]) {
    self.forged = privkey == FORGED;
    self.inner.set(privkey);
  }
  fn generate(
    &mut self,
    rng: &mut dyn snow::types::Random,
  ) -> Result<(), snow::Error> {
    self.forged = false;
    self.inner.generate(rng)
  }
  fn pubkey(&self) -> &[u8] {
    if self.forged {
      &[0; 32]
    } else {
      self.inner.pubkey()
    }
  }
  fn privkey(&self) -> &[u8] {
    self.inner.privkey()
  }
  fn dh(
    &self,
    pubkey: &[u8],
    out: &mut [u8],
  ) -> Result<(), snow::Error> {
    if self.forged {
      out[..32].fill(0);
      Ok(())
    } else {
      self.inner.dh(pubkey, out)
    }
  }
}

struct ForgingResolver;

impl snow::resolvers::CryptoResolver for ForgingResolver {
  fn resolve_rng(&self) -> Option<Box<dyn snow::types::Random>> {
    snow::resolvers::DefaultResolver.resolve_rng()
  }
  fn resolve_dh(
    &self,
    choice: &snow::params::DHChoice,
  ) -> Option<Box<dyn snow::types::Dh>> {
    let inner =
      snow::resolvers::DefaultResolver.resolve_dh(choice)?;
    Some(Box::new(ForgingDh {
      inner,
      forged: false,
    }))
  }
  fn resolve_hash(
    &self,
    choice: &snow::params::HashChoice,
  ) -> Option<Box<dyn snow::types::Hash>> {
    snow::resolvers::DefaultResolver.resolve_hash(choice)
  }
  fn resolve_cipher(
    &self,
    choice: &snow::params::CipherChoice,
  ) -> Option<Box<dyn snow::types::Cipher>> {
    snow::resolvers::DefaultResolver.resolve_cipher(choice)
  }
}

fn forging_builder(pki_kind: PkiKind) -> snow::Builder<'static> {
  snow::Builder::with_resolver(
    pki_kind.noise_params().parse().unwrap(),
    Box::new(ForgingResolver),
  )
}

#[test]
fn one_way_refuses_a_low_order_client_key() {
  let server = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  let server_private = server.private.as_raw_bytes().unwrap();
  let server_public = crate::SpkiPublicKey::maybe_pem_to_raw_bytes(
    server.public.as_str(),
  )
  .unwrap();

  // An attacker with no private key at all, claiming the all zero
  // client key: the server's DH with it is all zero too, so the
  // message is valid Noise.
  let mut forged = forging_builder(PkiKind::OneWay)
    .local_private_key(&FORGED)
    .unwrap()
    .remote_public_key(&server_public)
    .unwrap()
    .prologue(b"request")
    .unwrap()
    .build_initiator()
    .unwrap();
  let mut buf = [0u8; 1024];
  let written = forged.write_message(&[], &mut buf).unwrap();
  let signature = data_encoding::BASE64.encode(&buf[..written]);

  let mut responder =
    OneWayNoiseHandshake::new_responder(&server_private, b"request")
      .unwrap();
  let err = responder.validate_signature(&signature).err().unwrap();
  assert!(format!("{err:#}").contains("low order"), "{err:#}");

  // The forging resolver itself is sound: an honest key signed
  // through it still validates.
  let client = EncodedKeyPair::generate(PkiKind::OneWay).unwrap();
  let client_private = client.private.as_raw_bytes().unwrap();
  let mut honest = forging_builder(PkiKind::OneWay)
    .local_private_key(&client_private)
    .unwrap()
    .remote_public_key(&server_public)
    .unwrap()
    .prologue(b"request")
    .unwrap()
    .build_initiator()
    .unwrap();
  let written = honest.write_message(&[], &mut buf).unwrap();
  let signature = data_encoding::BASE64.encode(&buf[..written]);
  let mut responder =
    OneWayNoiseHandshake::new_responder(&server_private, b"request")
      .unwrap();
  assert_eq!(
    responder.validate_signature(&signature).unwrap(),
    client.public
  );
}

#[test]
fn mutual_refuses_a_low_order_initiator_key() {
  let server = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();

  let mut forged = forging_builder(PkiKind::Mutual)
    .local_private_key(&FORGED)
    .unwrap()
    .prologue(b"prologue")
    .unwrap()
    .build_initiator()
    .unwrap();
  let mut responder = MutualNoiseHandshake::new_responder(
    server.private.as_str(),
    b"prologue",
  )
  .unwrap();

  let mut buf = [0u8; 1024];
  let written = forged.write_message(&[], &mut buf).unwrap();
  responder.read_message(&buf[..written]).unwrap();
  let m2 = responder.next_message().unwrap();
  forged.read_message(&m2, &mut buf).unwrap();
  let written = forged.write_message(&[], &mut buf).unwrap();
  // The forged handshake completes as far as Noise goes...
  responder.read_message(&buf[..written]).unwrap();
  // ...but the claimed key is refused.
  let err = responder.remote_public_key().err().unwrap();
  assert!(format!("{err:#}").contains("low order"), "{err:#}");
}
