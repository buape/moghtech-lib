use std::{
  path::{Path, PathBuf},
  sync::atomic::{AtomicU64, Ordering},
};

/// Writes data to path, setting permissions to 0600.
/// `std::fs` sync version.
///
/// The contents are written to a temp file beside the path, and renamed
/// onto it, so readers never see a partially written file, and a failed
/// write leaves any existing file untouched.
///
/// Also ensures parent directory exists.
pub fn write(
  path: impl AsRef<Path>,
  contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
  use std::{io::Write, os::unix::fs::OpenOptionsExt};

  let path = path.as_ref();

  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent)?;
  }

  let temp_path = temp_path(path)?;

  let res = (|| {
    let mut file = std::fs::OpenOptions::new()
      .write(true)
      // Never write over an existing temp file.
      .create_new(true)
      // Only ever creates the temp file,
      // so the mode is always applied.
      .mode(0o600)
      .open(&temp_path)?;

    file.write_all(contents.as_ref())?;
    // The contents have to be on disk
    // before the rename makes them visible.
    file.sync_all()?;
    drop(file);

    // This leaves existing permissions intact.
    if let Ok(existing) = std::fs::metadata(path) {
      std::fs::set_permissions(&temp_path, existing.permissions())?;
    }

    std::fs::rename(&temp_path, path)
  })();

  if res.is_err() {
    // Don't leave the temp file behind.
    let _ = std::fs::remove_file(&temp_path);
  }

  res
}

/// Writes data to path, setting permissions to 0600.
/// `tokio::fs` async version.
///
/// The contents are written to a temp file beside the path, and renamed
/// onto it, so readers never see a partially written file, and a failed
/// write leaves any existing file untouched.
///
/// Also ensures parent directory exists.
#[cfg(feature = "tokio")]
pub async fn write_async(
  path: impl AsRef<Path>,
  contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
  use tokio::io::AsyncWriteExt;

  let path = path.as_ref();

  if let Some(parent) = path.parent() {
    tokio::fs::create_dir_all(parent).await?;
  }

  let temp_path = temp_path(path)?;

  let res = async {
    let mut file = tokio::fs::OpenOptions::new()
      .write(true)
      // Never write over an existing temp file.
      .create_new(true)
      // Only ever creates the temp file,
      // so the mode is always applied.
      .mode(0o600)
      .open(&temp_path)
      .await?;

    file.write_all(contents.as_ref()).await?;
    // The contents have to be on disk
    // before the rename makes them visible.
    file.sync_all().await?;
    drop(file);

    // This leaves existing permissions intact.
    if let Ok(existing) = tokio::fs::metadata(path).await {
      tokio::fs::set_permissions(&temp_path, existing.permissions())
        .await?;
    }

    tokio::fs::rename(&temp_path, path).await
  }
  .await;

  if res.is_err() {
    // Don't leave the temp file behind.
    let _ = tokio::fs::remove_file(&temp_path).await;
  }

  res
}

/// A unique path beside `path` to write to before renaming onto it.
/// It has to be in the same directory,
/// as a rename can't cross filesystems.
fn temp_path(path: &Path) -> std::io::Result<PathBuf> {
  static COUNT: AtomicU64 = AtomicU64::new(0);

  let Some(file_name) = path.file_name() else {
    return Err(std::io::Error::new(
      std::io::ErrorKind::InvalidInput,
      format!("Path to write has no file name: {path:?}"),
    ));
  };

  Ok(path.with_file_name(format!(
    ".{}.{}.{}.tmp",
    file_name.to_string_lossy(),
    std::process::id(),
    COUNT.fetch_add(1, Ordering::Relaxed),
  )))
}

#[cfg(test)]
mod tests {
  use std::{os::unix::fs::PermissionsExt, path::PathBuf};

  fn temp_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
      "mogh_secret_file_write_test_{}_{name}",
      std::process::id()
    ))
  }

  #[test]
  fn write_creates_parents_and_sets_mode() {
    let dir = temp_dir("sync");
    let path = dir.join("nested").join("secret");
    super::write(&path, "hunter2").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter2");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    // Overwriting replaces previous contents.
    super::write(&path, "x").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "x");
    // The temp file is not left behind.
    assert_eq!(
      std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
      1
    );
    std::fs::remove_dir_all(dir).unwrap();
  }

  /// An existing file keeps its permissions,
  /// even though it is replaced by the temp file.
  #[test]
  fn write_keeps_existing_permissions() {
    let dir = temp_dir("sync-permissions");
    let path = dir.join("secret");
    super::write(&path, "hunter2").unwrap();
    std::fs::set_permissions(
      &path,
      std::fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    super::write(&path, "hunter3").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter3");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o640);
    std::fs::remove_dir_all(dir).unwrap();
  }

  /// A write which fails leaves the existing contents in place,
  /// rather than truncating them.
  #[test]
  fn failed_write_keeps_existing_contents() {
    let dir = temp_dir("sync-failure");
    let path = dir.join("secret");
    super::write(&path, "hunter2").unwrap();

    // Make the temp file impossible to create.
    std::fs::set_permissions(
      &dir,
      std::fs::Permissions::from_mode(0o555),
    )
    .unwrap();
    let res = super::write(&path, "hunter3");
    std::fs::set_permissions(
      &dir,
      std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    // Root can write to the directory regardless of its mode,
    // in which case there is no failure to assert on.
    if res.is_err() {
      assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter2");
      assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    }

    std::fs::remove_dir_all(dir).unwrap();
  }

  #[cfg(feature = "tokio")]
  #[tokio::test]
  async fn write_async_creates_parents_and_sets_mode() {
    let dir = temp_dir("async");
    let path = dir.join("nested").join("secret");
    super::write_async(&path, "hunter2").await.unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter2");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    // Overwriting replaces previous contents,
    // and leaves no temp file behind.
    super::write_async(&path, "x").await.unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "x");
    assert_eq!(
      std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
      1
    );
    std::fs::remove_dir_all(dir).unwrap();
  }

  #[cfg(feature = "tokio")]
  #[tokio::test]
  async fn failed_write_async_keeps_existing_contents() {
    let dir = temp_dir("async-failure");
    let path = dir.join("secret");
    super::write_async(&path, "hunter2").await.unwrap();

    // Make the temp file impossible to create.
    std::fs::set_permissions(
      &dir,
      std::fs::Permissions::from_mode(0o555),
    )
    .unwrap();
    let res = super::write_async(&path, "hunter3").await;
    std::fs::set_permissions(
      &dir,
      std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    // Root can write to the directory regardless of its mode,
    // in which case there is no failure to assert on.
    if res.is_err() {
      assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter2");
      assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    }

    std::fs::remove_dir_all(dir).unwrap();
  }
}
