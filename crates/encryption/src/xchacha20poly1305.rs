use anyhow::{Context, anyhow};
use chacha20poly1305::{
  KeyInit, XChaCha20Poly1305, XNonce,
  aead::{Aead, Payload},
};
use data_encoding::BASE64URL;
use rand::{RngExt as _, rngs::ThreadRng};

use crate::{AssociatedData, EncryptedData, EnvelopeEncryptedData};

// The lifetime of provider is basically tied to the nonce provider, so they are coupled here.

#[derive(Default)]
pub struct EncryptionProvider(pub ThreadRng);

impl EncryptionProvider {
  /// Encrypts the given bytes using the given 32 byte key,
  /// a random nonce, and the given associated data.
  pub fn encrypt<A: AssociatedData>(
    &mut self,
    data: &[u8],
    key: [u8; 32],
    associated_data: &A,
  ) -> anyhow::Result<EncryptedData> {
    let nonce: [u8; 24] = self.0.random();
    let key = XChaCha20Poly1305::new((&key).into());
    let data = key
      .encrypt(
        XNonce::from_slice(&nonce),
        Payload {
          msg: data,
          aad: associated_data.as_bytes(),
        },
      )
      .map_err(|e| anyhow!("Encryption failed | {e:?}"))?;
    Ok(EncryptedData {
      data: BASE64URL.encode(&data),
      nonce: BASE64URL.encode(&nonce),
    })
  }

  /// Encrypts the given bytes using a random 32 byte key,
  /// a random nonce, and the given associated data.
  /// Then encrypts the key using the master key, a random nonce,
  /// and the same associated data.
  pub fn envelope_encrypt<A: AssociatedData>(
    &mut self,
    data: &[u8],
    master_key: [u8; 32],
    associated_data: &A,
  ) -> anyhow::Result<EnvelopeEncryptedData> {
    let key: [u8; 32] = self.0.random();
    let data = self.encrypt(data, key, associated_data)?;
    let key = self.encrypt(&key, master_key, associated_data)?;
    Ok(EnvelopeEncryptedData { key, data })
  }
}

/// Decrypts the given [EncryptedData] back into bytes using the given 32 byte key
/// and the given associated data.
pub fn decrypt<A: AssociatedData>(
  EncryptedData { data, nonce }: &EncryptedData,
  key: [u8; 32],
  associated_data: &A,
) -> anyhow::Result<Vec<u8>> {
  let data = BASE64URL
    .decode(data.as_bytes())
    .context("Data is not valid base64url")?;
  let nonce = BASE64URL
    .decode(nonce.as_bytes())
    .context("Nonce is not valid base64url")?;
  if nonce.len() != 24 {
    return Err(anyhow!("Invalid nonce"));
  }
  let key = XChaCha20Poly1305::new((&key).into());
  key
    .decrypt(
      XNonce::from_slice(&nonce),
      Payload {
        msg: &data,
        aad: associated_data.as_bytes(),
      },
    )
    .map_err(|e| anyhow!("Decryption failed | {e:?}"))
}

/// Decrypts the given [EnvelopeEncryptedData] back into bytes using the given 32 byte master key
/// and the given associated data.
pub fn envelope_decrypt<A: AssociatedData>(
  EnvelopeEncryptedData { key, data }: &EnvelopeEncryptedData,
  master_key: [u8; 32],
  associated_data: &A,
) -> anyhow::Result<Vec<u8>> {
  let key: [u8; 32] = decrypt(key, master_key, associated_data)?
    .try_into()
    .map_err(|_| {
      anyhow!(
        "The envelope encryption key is not 32 bytes after decryption"
      )
    })?;
  decrypt(data, key, associated_data)
}

#[cfg(test)]
mod tests {
  use super::*;

  const KEY: [u8; 32] = [7u8; 32];
  const OTHER_KEY: [u8; 32] = [8u8; 32];

  #[test]
  fn encrypt_decrypt_round_trip() {
    let mut provider = EncryptionProvider::default();
    let encrypted =
      provider.encrypt(b"secret payload", KEY, &()).unwrap();
    let decrypted = decrypt(&encrypted, KEY, &()).unwrap();
    assert_eq!(decrypted, b"secret payload");
  }

  #[test]
  fn round_trip_with_associated_data() {
    let mut provider = EncryptionProvider::default();
    let aad = "user-123";
    let encrypted = provider.encrypt(b"data", KEY, &aad).unwrap();
    assert_eq!(decrypt(&encrypted, KEY, &aad).unwrap(), b"data");
    // Different associated data must fail authentication.
    assert!(decrypt(&encrypted, KEY, &"user-456").is_err());
    // Missing associated data must fail too.
    assert!(decrypt(&encrypted, KEY, &()).is_err());
  }

  #[test]
  fn wrong_key_fails() {
    let mut provider = EncryptionProvider::default();
    let encrypted = provider.encrypt(b"data", KEY, &()).unwrap();
    assert!(decrypt(&encrypted, OTHER_KEY, &()).is_err());
  }

  #[test]
  fn tampered_ciphertext_fails() {
    let mut provider = EncryptionProvider::default();
    let encrypted = provider.encrypt(b"data", KEY, &()).unwrap();
    let mut raw =
      BASE64URL.decode(encrypted.data.as_bytes()).unwrap();
    raw[0] ^= 0xff;
    let tampered = EncryptedData {
      data: BASE64URL.encode(&raw),
      nonce: encrypted.nonce.clone(),
    };
    assert!(decrypt(&tampered, KEY, &()).is_err());
  }

  #[test]
  fn nonces_are_unique_per_encryption() {
    let mut provider = EncryptionProvider::default();
    let a = provider.encrypt(b"data", KEY, &()).unwrap();
    let b = provider.encrypt(b"data", KEY, &()).unwrap();
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.data, b.data);
    // Both still decrypt to the same plaintext.
    assert_eq!(decrypt(&a, KEY, &()).unwrap(), b"data");
    assert_eq!(decrypt(&b, KEY, &()).unwrap(), b"data");
  }

  #[test]
  fn empty_plaintext_round_trip() {
    let mut provider = EncryptionProvider::default();
    let encrypted = provider.encrypt(b"", KEY, &()).unwrap();
    assert_eq!(decrypt(&encrypted, KEY, &()).unwrap(), b"");
  }

  #[test]
  fn invalid_base64_is_error_not_panic() {
    let bad_data = EncryptedData {
      data: "!!not-base64!!".to_string(),
      nonce: BASE64URL.encode(&[0u8; 24]),
    };
    let err = decrypt(&bad_data, KEY, &()).unwrap_err();
    assert!(err.to_string().contains("Data is not valid base64url"));

    let bad_nonce = EncryptedData {
      data: BASE64URL.encode(b"whatever"),
      nonce: "!!not-base64!!".to_string(),
    };
    let err = decrypt(&bad_nonce, KEY, &()).unwrap_err();
    assert!(err.to_string().contains("Nonce is not valid base64url"));
  }

  #[test]
  fn wrong_nonce_length_is_error_not_panic() {
    let encrypted = EncryptedData {
      data: BASE64URL.encode(b"whatever"),
      nonce: BASE64URL.encode(&[0u8; 12]),
    };
    let err = decrypt(&encrypted, KEY, &()).unwrap_err();
    assert!(err.to_string().contains("Invalid nonce"));
  }

  #[test]
  fn envelope_round_trip() {
    let mut provider = EncryptionProvider::default();
    let aad = "tenant-1".to_string();
    let envelope = provider
      .envelope_encrypt(b"envelope contents", KEY, &aad)
      .unwrap();
    assert_eq!(
      envelope_decrypt(&envelope, KEY, &aad).unwrap(),
      b"envelope contents"
    );
    // Wrong master key fails
    assert!(envelope_decrypt(&envelope, OTHER_KEY, &aad).is_err());
    // Wrong associated data fails
    assert!(envelope_decrypt(&envelope, KEY, &"tenant-2").is_err());
  }

  #[test]
  fn envelope_data_key_is_not_master_key() {
    let mut provider = EncryptionProvider::default();
    let envelope =
      provider.envelope_encrypt(b"contents", KEY, &()).unwrap();
    // Data cannot be decrypted directly with the master key.
    assert!(decrypt(&envelope.data, KEY, &()).is_err());
    // But can with the decrypted inner key.
    let inner: [u8; 32] = decrypt(&envelope.key, KEY, &())
      .unwrap()
      .try_into()
      .unwrap();
    assert_eq!(
      decrypt(&envelope.data, inner, &()).unwrap(),
      b"contents"
    );
  }
}
