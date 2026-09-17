use std::{
  path::{Path, PathBuf},
  sync::Arc,
};

use anyhow::Context;
use arc_swap::ArcSwap;
use der::AnyRef;

mod private;
mod public;

#[cfg(test)]
mod tests;

pub use private::Pkcs8PrivateKey;
pub use public::SpkiPublicKey;

use crate::PkiKind;

const OID_X25519: spki::ObjectIdentifier =
  spki::ObjectIdentifier::new_unwrap("1.3.101.110");

fn algorithm() -> spki::AlgorithmIdentifier<AnyRef<'static>> {
  spki::AlgorithmIdentifier {
    oid: OID_X25519,
    parameters: None,
  }
}

/// Wraps a base64 body in pem framing,
/// with lines wrapped at 64 characters per RFC 7468.
fn encode_pem(label: &str, base64_body: &str) -> String {
  let mut pem = format!("-----BEGIN {label}-----\n");
  for line in base64_body.as_bytes().chunks(64) {
    pem.push_str(&String::from_utf8_lossy(line));
    pem.push('\n');
  }
  pem.push_str(&format!("-----END {label}-----\n"));
  pem
}

#[derive(Clone)]
pub struct EncodedKeyPair {
  /// pkcs8 encoded private key
  pub private: Pkcs8PrivateKey,
  /// spki encoded public key
  pub public: SpkiPublicKey,
}

impl EncodedKeyPair {
  pub fn generate(pki_kind: PkiKind) -> anyhow::Result<Self> {
    let builder =
      snow::Builder::new(pki_kind.noise_params().parse()?);
    let keypair = builder
      .generate_keypair()
      .context("Failed to generate keypair")?;
    let private = Pkcs8PrivateKey::from_raw_bytes(&keypair.private)?;
    let public = SpkiPublicKey::from_raw_bytes(&keypair.public)?;
    Ok(Self { private, public })
  }

  pub fn generate_write_sync(
    pki_kind: PkiKind,
    path: impl AsRef<Path>,
  ) -> anyhow::Result<Self> {
    let path = path.as_ref();
    // Generate and write pems to path
    let keys = Self::generate(pki_kind)?;
    keys.private.write_pem_sync(path)?;
    keys.public.write_pem_sync(path.with_extension("pub"))?;
    Ok(keys)
  }

  pub async fn generate_write_async(
    pki_kind: PkiKind,
    path: impl AsRef<Path>,
  ) -> anyhow::Result<Self> {
    let path = path.as_ref();
    // Generate and write pems to path
    let keys = Self::generate(pki_kind)?;
    keys.private.write_pem_async(path).await?;
    keys
      .public
      .write_pem_async(path.with_extension("pub"))
      .await?;
    Ok(keys)
  }

  pub fn load_maybe_generate(
    pki_kind: PkiKind,
    private_key_path: impl AsRef<Path>,
  ) -> anyhow::Result<Self> {
    let path = private_key_path.as_ref();

    let exists = path.try_exists().with_context(|| {
      format!("Invalid private key path: {path:?}")
    })?;

    if !exists {
      return Self::generate_write_sync(pki_kind, path);
    }

    let private = Pkcs8PrivateKey::from_file(private_key_path)?;
    let public = private.compute_public_key_using_dh(pki_kind)?;

    Ok(Self { private, public })
  }

  pub fn from_private_key(
    pki_kind: PkiKind,
    maybe_pkcs8_private_key: &str,
  ) -> anyhow::Result<Self> {
    let private =
      Pkcs8PrivateKey::from_maybe_raw_bytes(maybe_pkcs8_private_key)?;
    let public = private.compute_public_key_using_dh(pki_kind)?;
    Ok(Self { private, public })
  }

  /// Loads the pair from a private key file (raw / der / pem),
  /// deriving the public key.
  pub fn from_file(
    pki_kind: PkiKind,
    private_key_path: impl AsRef<Path>,
  ) -> anyhow::Result<Self> {
    let private = Pkcs8PrivateKey::from_file(private_key_path)?;
    let public = private.compute_public_key_using_dh(pki_kind)?;
    Ok(Self { private, public })
  }

  pub fn private(&self) -> &str {
    self.private.as_str()
  }

  pub fn public(&self) -> &str {
    self.public.as_str()
  }
}

/// `<path><suffix>`: a sibling of the key file, keeping the full
/// file name (`cperiphery.key.next`, not `cperiphery.next`).
fn sibling(path: &Path, suffix: &str) -> PathBuf {
  let mut name = path.as_os_str().to_owned();
  name.push(suffix);
  PathBuf::from(name)
}

/// The candidate of an in-flight [RotatableKeyPair::begin_rotation].
const NEXT_SUFFIX: &str = ".next";
/// The key a committed rotation retired, until
/// [RotatableKeyPair::finish_rotation].
const OLD_SUFFIX: &str = ".old";

pub struct RotatableKeyPair {
  keys: ArcSwap<EncodedKeyPair>,
  path: Option<PathBuf>,
}

impl RotatableKeyPair {
  /// Parses from either direct private key (raw / der / pem),
  /// or from file containing raw / der / pem.
  /// Use `file:/path/to/private.key` to specify file.
  pub fn from_private_key_spec(
    pki_kind: PkiKind,
    private_key_spec: &str,
  ) -> anyhow::Result<Self> {
    let (keys, path) = if let Some(path) =
      private_key_spec.strip_prefix("file:")
    {
      let path = PathBuf::from(path);
      (
        EncodedKeyPair::load_maybe_generate(pki_kind, &path)?,
        Some(path),
      )
    } else {
      (
        EncodedKeyPair::from_private_key(pki_kind, private_key_spec)?,
        None,
      )
    };
    Ok(Self {
      keys: ArcSwap::new(Arc::new(keys)),
      path,
    })
  }

  /// If 'path' is Some, generates, writes, and stores new key pair.
  /// Returns the public key, maybe new if using file.
  pub async fn rotate(
    &self,
    pki_kind: PkiKind,
  ) -> anyhow::Result<SpkiPublicKey> {
    let Some(path) = self.path.as_deref() else {
      return Ok(self.keys.load().public.clone());
    };
    let keys =
      EncodedKeyPair::generate_write_async(pki_kind, path).await?;
    let public_key = keys.public.clone();
    self.keys.store(Arc::new(keys));
    Ok(public_key)
  }

  pub fn load(&self) -> arc_swap::Guard<Arc<EncodedKeyPair>> {
    self.keys.load()
  }

  pub fn rotatable(&self) -> bool {
    self.path.is_some()
  }

  /// The live private key file, when file backed.
  pub fn path(&self) -> Option<&Path> {
    self.path.as_deref()
  }

  /// Starts a two-phase rotation of a file backed pair, for
  /// clients whose public key is registered somewhere (a server
  /// allow list) that must learn the new key before the old one
  /// stops being used: generates a candidate pair written to
  /// `<path>.next`, leaving the live key file untouched, so a crash
  /// at any point before [KeyRotation::commit] still boots with the
  /// registered key. Resumes an existing candidate (a rotation
  /// interrupted before commit; the caller re-registers it, which
  /// must be idempotent). Errors when the pair is not file backed,
  /// and while a [retired][Self::retired] key of an earlier
  /// rotation is still waiting to be finished.
  pub fn begin_rotation(
    &self,
    pki_kind: PkiKind,
  ) -> anyhow::Result<KeyRotation<'_>> {
    let Some(path) = self.path.as_deref() else {
      anyhow::bail!(
        "The private key is not file backed, so it cannot be rotated"
      );
    };
    let old_path = sibling(path, OLD_SUFFIX);
    if old_path.try_exists()? {
      anyhow::bail!(
        "A previous rotation is not finished: the retired key at {old_path:?} must be revoked and cleaned up first"
      );
    }
    let next_path = sibling(path, NEXT_SUFFIX);
    let candidate = match next_path.try_exists()? {
      true => match EncodedKeyPair::from_file(pki_kind, &next_path) {
        Ok(candidate) => {
          tracing::info!(
            "Resuming key rotation with the candidate at {next_path:?}"
          );
          candidate
        }
        // Unreadable leftover: it was never usable, so nothing can
        // have been registered under it. Start over.
        Err(e) => {
          tracing::warn!(
            "Replacing the unreadable rotation candidate at {next_path:?} | {e:#}"
          );
          Self::write_candidate(pki_kind, &next_path)?
        }
      },
      false => Self::write_candidate(pki_kind, &next_path)?,
    };
    Ok(KeyRotation {
      pair: self,
      live_path: path.to_path_buf(),
      next_path,
      old_path,
      candidate,
    })
  }

  fn write_candidate(
    pki_kind: PkiKind,
    next_path: &Path,
  ) -> anyhow::Result<EncodedKeyPair> {
    let candidate = EncodedKeyPair::generate(pki_kind)?;
    candidate.private.write_pem_sync(next_path)?;
    Ok(candidate)
  }

  /// The pair a committed rotation retired (`<path>.old`), until
  /// [Self::finish_rotation] removes it: the caller revokes its
  /// public key wherever it was registered, then finishes. `None`
  /// when no rotation is waiting to be finished.
  pub fn retired(
    &self,
    pki_kind: PkiKind,
  ) -> anyhow::Result<Option<EncodedKeyPair>> {
    let Some(path) = self.path.as_deref() else {
      return Ok(None);
    };
    let old_path = sibling(path, OLD_SUFFIX);
    if !old_path.try_exists()? {
      return Ok(None);
    }
    EncodedKeyPair::from_file(pki_kind, &old_path)
      .with_context(|| {
        format!("Failed to load the retired key at {old_path:?}")
      })
      .map(Some)
  }

  /// Whether a rotation was interrupted: a candidate (`<path>.next`)
  /// or a retired key (`<path>.old`) is waiting, see
  /// [Self::begin_rotation] and [Self::retired].
  pub fn rotation_pending(&self) -> bool {
    self.path.as_deref().is_some_and(|path| {
      sibling(path, NEXT_SUFFIX).exists()
        || sibling(path, OLD_SUFFIX).exists()
    })
  }

  /// Deletes the retired key of a committed rotation. Idempotent.
  pub fn finish_rotation(&self) -> anyhow::Result<()> {
    let Some(path) = self.path.as_deref() else {
      return Ok(());
    };
    let old_path = sibling(path, OLD_SUFFIX);
    match std::fs::remove_file(&old_path) {
      Ok(()) => Ok(()),
      Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
      Err(e) => Err(e).with_context(|| {
        format!("Failed to delete the retired key at {old_path:?}")
      }),
    }
  }
}

/// An in-flight rotation, see [RotatableKeyPair::begin_rotation].
/// Dropping it without [commit][Self::commit] or
/// [abort][Self::abort] leaves the candidate file for the next
/// [begin_rotation][RotatableKeyPair::begin_rotation] to resume.
pub struct KeyRotation<'a> {
  pair: &'a RotatableKeyPair,
  live_path: PathBuf,
  next_path: PathBuf,
  old_path: PathBuf,
  candidate: EncodedKeyPair,
}

impl KeyRotation<'_> {
  /// The new pair, not yet in use.
  pub fn candidate(&self) -> &EncodedKeyPair {
    &self.candidate
  }

  /// The pair in use until commit.
  pub fn previous(&self) -> Arc<EncodedKeyPair> {
    self.pair.load().clone()
  }

  /// Makes the candidate the live pair. The previous private key
  /// is first written to `<path>.old` (to be revoked, see
  /// [RotatableKeyPair::retired]), then the candidate is renamed
  /// over the live path: one atomic rename, so the live file never
  /// goes missing. From here every signature uses the new key.
  /// The `.pub` sidecar is refreshed on a best effort basis.
  pub fn commit(self) -> anyhow::Result<()> {
    let previous = self.pair.load().clone();
    previous
      .private
      .write_pem_sync(&self.old_path)
      .context("Failed to keep the previous key for revocation")?;
    std::fs::rename(&self.next_path, &self.live_path).with_context(
      || {
        format!(
          "Failed to move the new key {:?} into place at {:?}",
          self.next_path, self.live_path
        )
      },
    )?;
    let public = self.candidate.public.clone();
    self.pair.keys.store(Arc::new(self.candidate));
    if let Err(e) =
      public.write_pem_sync(self.live_path.with_extension("pub"))
    {
      tracing::warn!(
        "Rotated the private key, but failed to refresh the public key file | {e:#}"
      );
    }
    Ok(())
  }

  /// Drops the candidate (deletes `<path>.next`). Nothing else
  /// changed.
  pub fn abort(self) -> anyhow::Result<()> {
    match std::fs::remove_file(&self.next_path) {
      Ok(()) => Ok(()),
      Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
      Err(e) => Err(e).with_context(|| {
        format!(
          "Failed to delete the rotation candidate at {:?}",
          self.next_path
        )
      }),
    }
  }
}
