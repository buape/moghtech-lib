//! Authenticated encryption under a [Key], with the cipher chosen
//! per call ([Cipher]) and recorded on the ciphertext through its
//! format marker, so decryption needs no out of band knowledge.

use aes_gcm::Aes256Gcm;
use anyhow::{Context, anyhow};
use chacha20poly1305::{
  KeyInit, XChaCha20Poly1305,
  aead::{Aead, Payload, generic_array::GenericArray},
};
use data_encoding::BASE64URL;
use rand::{RngExt as _, rngs::ThreadRng};
use zeroize::Zeroizing;

use crate::{
  AssociatedData, Cipher, EncryptedData, EnvelopeEncryptedData, Key,
};

#[derive(Default)]
pub struct EncryptionProvider(pub ThreadRng);

impl EncryptionProvider {
  /// Encrypts the given bytes using the given key, a random
  /// nonce, and the given associated data, with `cipher`.
  pub fn encrypt<A: AssociatedData>(
    &mut self,
    data: &[u8],
    key: &Key,
    associated_data: &A,
    cipher: Cipher,
  ) -> anyhow::Result<EncryptedData> {
    let nonce: Vec<u8> = match cipher {
      Cipher::XChaCha20Poly1305 => {
        self.0.random::<[u8; 24]>().to_vec()
      }
      Cipher::Aes256Gcm => self.0.random::<[u8; 12]>().to_vec(),
    };
    let payload = Payload {
      msg: data,
      aad: associated_data.as_bytes(),
    };
    let sealed = match cipher {
      Cipher::XChaCha20Poly1305 => {
        XChaCha20Poly1305::new(key.as_bytes().into())
          .encrypt(GenericArray::from_slice(&nonce), payload)
      }
      Cipher::Aes256Gcm => Aes256Gcm::new(key.as_bytes().into())
        .encrypt(GenericArray::from_slice(&nonce), payload),
    }
    .map_err(|e| anyhow!("Encryption failed | {e:?}"))?;
    Ok(EncryptedData {
      data: cipher.mark(&BASE64URL.encode(&sealed)),
      nonce: BASE64URL.encode(&nonce),
    })
  }

  /// Encrypts the given bytes using a random key, a random nonce,
  /// and the given associated data. Then encrypts the key using
  /// the master key, a random nonce, and the same associated
  /// data. Both layers use `cipher`.
  pub fn envelope_encrypt<A: AssociatedData>(
    &mut self,
    data: &[u8],
    master_key: &Key,
    associated_data: &A,
    cipher: Cipher,
  ) -> anyhow::Result<EnvelopeEncryptedData> {
    let key = Key::generate();
    let data = self.encrypt(data, &key, associated_data, cipher)?;
    let key = self.encrypt(
      key.as_bytes(),
      master_key,
      associated_data,
      cipher,
    )?;
    Ok(EnvelopeEncryptedData { key, data })
  }
}

/// Decrypts the given [EncryptedData] back into bytes using the
/// given key and the given associated data, with the cipher its
/// format marker names. The plaintext is wiped when dropped.
pub fn decrypt<A: AssociatedData>(
  EncryptedData { data, nonce }: &EncryptedData,
  key: &Key,
  associated_data: &A,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
  let (cipher, payload) = Cipher::parse(data)?;
  let data = BASE64URL
    .decode(payload.as_bytes())
    .context("Data is not valid base64url")?;
  let nonce = BASE64URL
    .decode(nonce.as_bytes())
    .context("Nonce is not valid base64url")?;
  if nonce.len() != cipher.nonce_len() {
    return Err(anyhow!("Invalid nonce"));
  }
  let payload = Payload {
    msg: &data,
    aad: associated_data.as_bytes(),
  };
  match cipher {
    Cipher::XChaCha20Poly1305 => {
      XChaCha20Poly1305::new(key.as_bytes().into())
        .decrypt(GenericArray::from_slice(&nonce), payload)
    }
    Cipher::Aes256Gcm => Aes256Gcm::new(key.as_bytes().into())
      .decrypt(GenericArray::from_slice(&nonce), payload),
  }
  .map(Zeroizing::new)
  .map_err(|e| anyhow!("Decryption failed | {e:?}"))
}

/// Decrypts the given [EnvelopeEncryptedData] back into bytes
/// using the given master key and the given associated data; each
/// layer uses the cipher its own marker names. The plaintext (and
/// the unwrapped data key) are wiped when dropped.
pub fn envelope_decrypt<A: AssociatedData>(
  EnvelopeEncryptedData { key, data }: &EnvelopeEncryptedData,
  master_key: &Key,
  associated_data: &A,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
  let key = decrypt(key, master_key, associated_data)?;
  let key = Key::from_slice(&key).ok_or_else(|| {
    anyhow!(
      "The envelope encryption key is not 32 bytes after decryption"
    )
  })?;
  decrypt(data, &key, associated_data)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn key() -> Key {
    Key::from_bytes(&mut [7u8; 32])
  }
  fn other_key() -> Key {
    Key::from_bytes(&mut [8u8; 32])
  }

  #[test]
  fn encrypt_decrypt_round_trip_every_cipher() {
    let mut provider = EncryptionProvider::default();
    for cipher in Cipher::ALL {
      let encrypted = provider
        .encrypt(b"secret payload", &key(), &(), cipher)
        .unwrap();
      assert!(
        encrypted
          .data
          .starts_with(&format!("${}$", cipher.marker()))
      );
      let decrypted = decrypt(&encrypted, &key(), &()).unwrap();
      assert_eq!(decrypted.as_slice(), b"secret payload");
      // Wrong key fails.
      assert!(decrypt(&encrypted, &other_key(), &()).is_err());
      // Nonce sized for the cipher.
      assert_eq!(
        BASE64URL.decode(encrypted.nonce.as_bytes()).unwrap().len(),
        cipher.nonce_len()
      );
    }
  }

  #[test]
  fn unmarked_ciphertext_reads_as_xchacha() {
    let mut provider = EncryptionProvider::default();
    let encrypted = provider
      .encrypt(b"legacy", &key(), &(), Cipher::XChaCha20Poly1305)
      .unwrap();
    let (_, payload) = Cipher::parse(&encrypted.data).unwrap();
    let legacy = EncryptedData {
      data: payload.to_string(),
      nonce: encrypted.nonce.clone(),
    };
    assert_eq!(
      decrypt(&legacy, &key(), &()).unwrap().as_slice(),
      b"legacy"
    );
  }

  #[test]
  fn marker_and_nonce_must_agree() {
    let mut provider = EncryptionProvider::default();
    let encrypted = provider
      .encrypt(b"data", &key(), &(), Cipher::Aes256Gcm)
      .unwrap();
    // Relabelled as XChaCha: the 12 byte nonce is rejected before
    // any decryption is attempted.
    let (_, payload) = Cipher::parse(&encrypted.data).unwrap();
    let relabelled = EncryptedData {
      data: Cipher::XChaCha20Poly1305.mark(payload),
      nonce: encrypted.nonce.clone(),
    };
    let err = decrypt(&relabelled, &key(), &()).unwrap_err();
    assert!(err.to_string().contains("Invalid nonce"));
  }

  #[test]
  fn round_trip_with_associated_data() {
    let mut provider = EncryptionProvider::default();
    let aad = "user-123";
    for cipher in Cipher::ALL {
      let encrypted =
        provider.encrypt(b"data", &key(), &aad, cipher).unwrap();
      assert_eq!(
        decrypt(&encrypted, &key(), &aad).unwrap().as_slice(),
        b"data"
      );
      // Different associated data must fail authentication.
      assert!(decrypt(&encrypted, &key(), &"user-456").is_err());
      // Missing associated data must fail too.
      assert!(decrypt(&encrypted, &key(), &()).is_err());
    }
  }

  #[test]
  fn tampered_ciphertext_fails() {
    let mut provider = EncryptionProvider::default();
    for cipher in Cipher::ALL {
      let encrypted =
        provider.encrypt(b"data", &key(), &(), cipher).unwrap();
      let (_, payload) = Cipher::parse(&encrypted.data).unwrap();
      let mut raw = BASE64URL.decode(payload.as_bytes()).unwrap();
      raw[0] ^= 0xff;
      let tampered = EncryptedData {
        data: cipher.mark(&BASE64URL.encode(&raw)),
        nonce: encrypted.nonce.clone(),
      };
      assert!(decrypt(&tampered, &key(), &()).is_err());
    }
  }

  #[test]
  fn nonces_are_unique_per_encryption() {
    let mut provider = EncryptionProvider::default();
    let a = provider
      .encrypt(b"data", &key(), &(), Cipher::default())
      .unwrap();
    let b = provider
      .encrypt(b"data", &key(), &(), Cipher::default())
      .unwrap();
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.data, b.data);
  }

  #[test]
  fn empty_plaintext_round_trip() {
    let mut provider = EncryptionProvider::default();
    let encrypted = provider
      .encrypt(b"", &key(), &(), Cipher::Aes256Gcm)
      .unwrap();
    assert_eq!(
      decrypt(&encrypted, &key(), &()).unwrap().as_slice(),
      b""
    );
  }

  #[test]
  fn invalid_input_is_error_not_panic() {
    let bad_data = EncryptedData {
      data: "!!not-base64!!".to_string(),
      nonce: BASE64URL.encode(&[0u8; 24]),
    };
    let err = decrypt(&bad_data, &key(), &()).unwrap_err();
    assert!(err.to_string().contains("Data is not valid base64url"));

    let bad_nonce = EncryptedData {
      data: BASE64URL.encode(b"whatever"),
      nonce: "!!not-base64!!".to_string(),
    };
    let err = decrypt(&bad_nonce, &key(), &()).unwrap_err();
    assert!(err.to_string().contains("Nonce is not valid base64url"));

    let short_nonce = EncryptedData {
      data: BASE64URL.encode(b"whatever"),
      nonce: BASE64URL.encode(&[0u8; 12]),
    };
    let err = decrypt(&short_nonce, &key(), &()).unwrap_err();
    assert!(err.to_string().contains("Invalid nonce"));

    let unknown = EncryptedData {
      data: "$rot13$whatever".to_string(),
      nonce: BASE64URL.encode(&[0u8; 12]),
    };
    let err = decrypt(&unknown, &key(), &()).unwrap_err();
    assert!(err.to_string().contains("Unknown cipher"));
  }

  #[test]
  fn envelope_round_trip_and_mixed_layers() {
    let mut provider = EncryptionProvider::default();
    let aad = "tenant-1".to_string();
    for cipher in Cipher::ALL {
      let envelope = provider
        .envelope_encrypt(b"envelope contents", &key(), &aad, cipher)
        .unwrap();
      assert_eq!(
        envelope_decrypt(&envelope, &key(), &aad)
          .unwrap()
          .as_slice(),
        b"envelope contents"
      );
      assert!(
        envelope_decrypt(&envelope, &other_key(), &aad).is_err()
      );
      assert!(
        envelope_decrypt(&envelope, &key(), &"tenant-2").is_err()
      );
      // Data cannot be decrypted directly with the master key.
      assert!(decrypt(&envelope.data, &key(), &aad).is_err());
    }
    // The key layer rewrapped under the other cipher (a master
    // key rotation): each layer decrypts by its own marker.
    let envelope = provider
      .envelope_encrypt(
        b"contents",
        &key(),
        &aad,
        Cipher::XChaCha20Poly1305,
      )
      .unwrap();
    let inner = decrypt(&envelope.key, &key(), &aad).unwrap();
    let rewrapped = EnvelopeEncryptedData {
      key: provider
        .encrypt(&inner, &other_key(), &aad, Cipher::Aes256Gcm)
        .unwrap(),
      data: envelope.data,
    };
    assert_eq!(
      envelope_decrypt(&rewrapped, &other_key(), &aad)
        .unwrap()
        .as_slice(),
      b"contents"
    );
  }
}
