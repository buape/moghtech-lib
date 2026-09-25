# Mogh PKI

Public key identification using [Noise](https://noiseprotocol.org)
handshakes over X25519 keys.

```rust
fn main() -> anyhow::Result<()> {
  let mogh_pki::EncodedKeyPair { private, public } =
    mogh_pki::EncodedKeyPair::generate(mogh_pki::PkiKind::Mutual)?;
  // The private key is secret: it has no `Display` and its `Debug`
  // is redacted. Take its text explicitly with `as_str`.
  println!("Private: {} | Public: {public}", private.as_str());
  Ok(())
}
```

## Keys

- A private key is stored as base64 pkcs8 der. It is parsed from pem
  (openssl), from base64 pkcs8 der (v1 or v2), or from raw key bytes:
  input of 32 characters or fewer is used as the X25519 key itself,
  with no key derivation, so a short value can be brute forced from
  the public key. Prefer generated keys.
- `Pkcs8PrivateKey` has no `Display` and a redacted `Debug`, so it
  can't be formatted into a log or error by accident. Take the key
  text explicitly: `as_str`, `into_inner` or `as_pem`.
- An empty private key (or an existing empty key file) is an error:
  it would be the same, publicly known key everywhere.
- Public keys are stored as base64 spki der. Low order points and non
  canonical encodings are refused.
- `RotatableKeyPair::from_private_key_spec` takes the key inline, or
  `file:/path/to/key` (generated there when the file does not exist).
  A file backed pair can rotate: in one step (`rotate`), or in two
  phases for a key registered elsewhere (`begin_rotation`, register
  the candidate, `commit`, revoke `retired`, `finish_rotation`). One
  rotation of a pair at a time, and only one process may rotate a
  given key file. Both write the key file with `mogh_secret_file`:
  an atomic replace keeping its owner, group and mode, or an in
  place write (not atomic) where the file can't be replaced, like a
  docker / kubernetes single file mount.

## Handshakes

- `PkiKind::OneWay` (Noise IK): the client has the server public key
  pinned and proves its own key in one message, which authenticates
  (does not encrypt) a prologue both sides know. Only the server can
  validate it, and whoever holds the server private key can forge one
  for any client key. A message can be replayed: bind a timestamp or
  nonce into the prologue and enforce a window.
- `PkiKind::Mutual` (Noise XX): three messages, after which each side
  knows the other's public key.
