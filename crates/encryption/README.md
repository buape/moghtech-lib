# Mogh Encryption

Utilities to encrypt and decrypt data: AEAD data and envelope encryption
(XChaCha20-Poly1305 or AES-256-GCM) under a 32 byte `Key` which is wiped
from memory when dropped. Nonces and keys are read from the OS random source.

```rust
use mogh_encryption::{Cipher, Key, Zeroizing, aead};

let master_key = Key::generate();
let data = b"secret contents";
// Associated data is authenticated but not encrypted,
// eg an id binding the ciphertext to its owner.
let aad = "user-123";

let encrypted = aead::envelope_encrypt(
  data,
  &master_key,
  &aad,
  Cipher::default(),
)?;

// The plaintext is wiped when dropped.
let decrypted: Zeroizing<Vec<u8>> =
  aead::envelope_decrypt(&encrypted, &master_key, &aad)?;
assert_eq!(decrypted.as_slice(), data);
```
