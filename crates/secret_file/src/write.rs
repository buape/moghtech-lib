use std::path::Path;

/// Writes data to path, setting permissions to 0600.
/// `std::fs` sync version.
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

  let mut file = std::fs::OpenOptions::new()
    .write(true)
    .create(true)
    .truncate(true)
    // Only sets mode if file is created.
    // This leaves existing permissions intact.
    .mode(0o600)
    .open(path)?;

  file.write_all(contents.as_ref())?;
  file.flush()?;

  Ok(())
}

/// Writes data to path, setting permissions to 0600.
/// `tokio::fs` async version.
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

  let mut file = tokio::fs::OpenOptions::new()
    .write(true)
    .create(true)
    .truncate(true)
    // Only sets mode if file is created.
    // This leaves existing permissions intact.
    .mode(0o600)
    .open(path)
    .await?;

  file.write_all(contents.as_ref()).await?;
  file.flush().await?;

  Ok(())
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
    // Overwriting truncates previous contents.
    super::write(&path, "x").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "x");
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
    std::fs::remove_dir_all(dir).unwrap();
  }
}
