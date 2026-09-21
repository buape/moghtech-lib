//! Encrypts secrets before they are stored in the database.

use std::{path::Path, sync::OnceLock};

use anyhow::Context as _;
use mogh_encryption::{Cipher, EnvelopeEncryptedData, Key, aead};

use crate::config::core_config;

/// The key comes from the config, else it is generated once
/// and kept next to the database with `0600` permissions.
pub fn encryption_key() -> &'static Key {
  static ENCRYPTION_KEY: OnceLock<Key> = OnceLock::new();
  ENCRYPTION_KEY.get_or_init(|| match load_encryption_key() {
    Ok(key) => key,
    Err(e) => panic!("{e:?}"),
  })
}

fn load_encryption_key() -> anyhow::Result<Key> {
  let config = core_config();
  if !config.encryption_key.is_empty() {
    return Key::from_base64url(config.encryption_key.as_bytes())
      .context("Invalid 'encryption_key' config");
  }
  let path = config.database_path.with_extension("encryption.key");
  if path.exists() {
    let encoded = std::fs::read_to_string(&path)
      .with_context(|| format!("Failed to read {path:?}"))?;
    return Key::from_base64url(encoded.trim().as_bytes())
      .with_context(|| {
        format!("Invalid encryption key at {path:?}")
      });
  }
  let key = Key::try_generate()?;
  write_key(&path, &key)?;
  tracing::info!("Generated database encryption key at {path:?}");
  Ok(key)
}

fn write_key(path: &Path, key: &Key) -> anyhow::Result<()> {
  mogh_secret_file::write(path, key.to_base64url().as_bytes())
    .with_context(|| format!("Failed to write {path:?}"))
}

/// Envelope encrypts `data`, bound to `associated_data`
/// (eg. the id of the row), so the ciphertext can't be
/// moved to another row.
pub fn seal(
  data: &str,
  associated_data: &str,
) -> anyhow::Result<String> {
  let sealed = aead::envelope_encrypt(
    data.as_bytes(),
    encryption_key(),
    &associated_data,
    Cipher::default(),
  )?;
  Ok(sealed.to_string())
}

pub fn open(
  sealed: &str,
  associated_data: &str,
) -> anyhow::Result<String> {
  let sealed: EnvelopeEncryptedData = sealed.parse()?;
  let data = aead::envelope_decrypt(
    &sealed,
    encryption_key(),
    &associated_data,
  )?;
  String::from_utf8(data.to_vec()).context("Data is not valid UTF-8")
}
