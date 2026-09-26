use std::{
  fs::{File, Metadata, OpenOptions},
  hash::BuildHasher,
  io::{ErrorKind, Write},
  path::{Path, PathBuf},
  sync::atomic::{AtomicU64, Ordering},
};

#[cfg(any(target_os = "linux", target_os = "android"))]
mod xattr;

/// Writes data to path. A new file is created with `0600`
/// permissions (on unix). `std::fs` sync version.
///
/// Also ensures parent directory exists.
///
/// ## Atomic replace
///
/// The contents are written to a temp file beside the path, synced
/// to disk, and renamed onto it, so readers never see a partially
/// written file, and a failed write leaves any existing file
/// untouched. The directory is synced after the rename (and after
/// creating any parent directories), so once this returns `Ok` the
/// new file survives a crash.
///
/// An existing file keeps its permissions, and on unix its owner
/// and group. On Linux it also keeps its access ACL (`setfacl`) and
/// its SELinux / Smack security label, and doesn't take on the
/// directory's default ACL. When these can't be kept (eg. relabeling
/// is not permitted), and the file can't be written in place either
/// (see below), the write fails rather than changing them.
///
/// Other extended attributes (eg. `user.*`, or NFSv4 ACLs), and ACLs
/// on other platforms, are not carried over when the file is
/// replaced.
///
/// ## Symlinks
///
/// A symlink at the path is **not followed**. It is replaced by a
/// new file, and the file it points to is left untouched, so a
/// planted link can't redirect the write to another file. Anything
/// else at the path which is not a regular file (eg. a fifo) is
/// replaced the same way. To write the file a trusted link points
/// to, resolve the link first (eg. with [std::fs::canonicalize]),
/// and write to the resolved path.
///
/// ## In place writes
///
/// Some existing files can't be replaced without changing what they
/// are. These are written in place instead (like 1.0 did), which
/// is **not atomic**: a failure midway can leave the file partially
/// written. This is the case when:
/// - The file is a bind mount (eg. a docker / kubernetes single
///   file mount), which can't be renamed onto.
/// - The directory can't be written to (or is read only),
///   but the file can.
/// - The owner / group, or on Linux the ACL / security label, can't
///   be given to a new file, eg. a non-root process writing a file
///   owned by another user. Except for another user's file in a
///   sticky directory (eg. `/tmp`) this process doesn't own, which
///   fails, like a rename would.
/// - The file has other hard links, which a replace would split
///   off. Only when the directory can be written to by its owner
///   alone, being root or the file's owner, so no one else can have
///   planted the link. Otherwise, or when the file can't be opened
///   for writing (eg. it is read only), the link is split off.
///
/// Don't write to paths in directories which untrusted users can
/// write to, as they can plant the file which is written.
///
/// ## Errors
///
/// In rare cases, an error syncing the directory (eg. an I/O error)
/// is returned after the new contents are already in place.
pub fn write(
  path: impl AsRef<Path>,
  contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
  write_file(path.as_ref(), contents.as_ref())
}

/// Writes data to path. A new file is created with `0600`
/// permissions (on unix). `tokio` async version.
///
/// Runs [write()] on the tokio blocking thread pool,
/// see [write()] for how the file is written.
///
/// If the returned future is dropped once polled, the write still
/// runs to completion in the background. It is never cut off
/// halfway, so it doesn't leave a temp file with the contents
/// behind.
#[cfg(feature = "tokio")]
pub async fn write_async(
  path: impl AsRef<Path>,
  contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
  let path = path.as_ref().to_path_buf();
  let contents = ClearOnDrop(contents.as_ref().to_vec());
  match tokio::task::spawn_blocking(move || {
    write_file(&path, &contents.0)
  })
  .await
  {
    Ok(res) => res,
    Err(_) => Err(std::io::Error::other("background task failed")),
  }
}

/// Clears the copy of the contents handed to
/// the blocking thread pool once it is dropped.
#[cfg(feature = "tokio")]
struct ClearOnDrop(Vec<u8>);

#[cfg(feature = "tokio")]
impl Drop for ClearOnDrop {
  fn drop(&mut self) {
    self.0.fill(0);
    std::hint::black_box(&self.0);
  }
}

fn write_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
  if let Some(parent) = path.parent() {
    create_dir_all(parent)?;
  }

  // The entry at the path itself, not following a symlink.
  let existing = match std::fs::symlink_metadata(path) {
    Ok(existing) => Some(existing),
    Err(e) if e.kind() == ErrorKind::NotFound => None,
    Err(e) => return Err(e),
  };

  // Only a regular file keeps its identity, or is written in place.
  // Anything else, like a symlink, is replaced by a new file,
  // so a link is never followed.
  let Some(existing) = existing.filter(Metadata::is_file) else {
    replace(path, None, false, contents)?;
    return Ok(());
  };

  let mut in_place = true;
  if hard_linked(&existing) {
    in_place = hard_link_trusted(path, &existing)?;
    if in_place {
      // Written in place, so the links keep sharing the contents.
      match write_in_place(path, &existing, contents) {
        // eg. a read only file, which can still be replaced,
        // splitting it off from its other links.
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
          in_place = false;
        }
        res => return res,
      }
    }
  }

  if replace(path, Some(&existing), in_place, contents)? {
    Ok(())
  } else {
    write_in_place(path, &existing, contents)
  }
}

/// Writes the contents to a new temp file beside `path`, and renames
/// it onto `path`, keeping the owner, group, mode and (on Linux)
/// access control extended attributes of the `existing` file. With
/// `in_place`, returns `Ok(false)`, leaving `path` untouched, when
/// the existing file has to be written in place instead.
fn replace(
  path: &Path,
  existing: Option<&Metadata>,
  in_place: bool,
  contents: &[u8],
) -> std::io::Result<bool> {
  let (mut file, temp) = match create_temp(path) {
    Ok(temp) => temp,
    // The directory can't be written to,
    // but the existing file may be.
    Err(e)
      if in_place
        && matches!(
          e.kind(),
          ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
        ) =>
    {
      return Ok(false);
    }
    Err(e) => return Err(e),
  };

  if let Some(existing) = existing {
    // Read before copy_identity may give the temp file away: its
    // owner as created is the writer as the kernel sees it.
    let created = file.metadata()?;
    match copy_identity(path, &file, &created, existing) {
      Ok(()) => {}
      // eg. a non-root process can't give a file to another user,
      // the owner is outside the user namespace, or relabeling
      // the file is not permitted.
      Err(e) if not_permitted(&e) => {
        if in_place
          && sticky_permits_in_place(path, &created, existing)?
        {
          return Ok(false);
        }
        return Err(std::io::Error::new(
          e.kind(),
          format!(
            "Can't keep the owner / group / access control of \
             {path:?}: {e}"
          ),
        ));
      }
      Err(e) => return Err(e),
    }
  }

  file.write_all(contents)?;
  // The contents have to be on disk
  // before the rename makes them visible.
  file.sync_all()?;
  drop(file);

  #[cfg(test)]
  tests::injected_failure(path)?;

  match std::fs::rename(&temp.path, path) {
    Ok(()) => temp.keep(),
    // eg. a bind mounted file, which can only be written in place.
    Err(e)
      if in_place
        && matches!(
          e.kind(),
          ErrorKind::ResourceBusy | ErrorKind::CrossesDevices
        ) =>
    {
      return Ok(false);
    }
    Err(e) => return Err(e),
  }

  // The rename is only durable once its directory is synced.
  sync_dir(parent_dir(path))?;

  Ok(true)
}

/// Writes the contents into the existing regular file, for files
/// which can't be replaced. Not atomic.
fn write_in_place(
  path: &Path,
  existing: &Metadata,
  contents: &[u8],
) -> std::io::Result<()> {
  let mut file = OpenOptions::new().write(true).open(path)?;
  // Opening follows a symlink, so make sure this is still the file
  // checked before, and not eg. a link someone swapped in since.
  if !same_file(&file.metadata()?, existing) {
    return Err(std::io::Error::other(format!(
      "{path:?} was replaced before it could be written"
    )));
  }
  file.write_all(contents)?;
  // Truncated after writing, so the file is never left empty.
  file.set_len(contents.len() as u64)?;
  file.sync_all()
}

#[cfg(unix)]
fn same_file(opened: &Metadata, existing: &Metadata) -> bool {
  use std::os::unix::fs::MetadataExt;
  opened.dev() == existing.dev() && opened.ino() == existing.ino()
}

/// The file id is not available outside of unix,
/// so this only checks it is still a regular file.
#[cfg(not(unix))]
fn same_file(opened: &Metadata, _existing: &Metadata) -> bool {
  opened.is_file()
}

/// Gives the new temp file (`created`: its metadata as created) the
/// owner, group and mode of the `existing` file at `path`, and on
/// Linux its access control extended attributes (ACL and security
/// label).
#[cfg(unix)]
fn copy_identity(
  path: &Path,
  temp: &File,
  created: &Metadata,
  existing: &Metadata,
) -> std::io::Result<()> {
  use std::os::unix::fs::{MetadataExt, fchown};

  let uid =
    (created.uid() != existing.uid()).then_some(existing.uid());
  let gid =
    (created.gid() != existing.gid()).then_some(existing.gid());
  if uid.is_some() || gid.is_some() {
    fchown(temp, uid, gid)?;
  }

  // Set through the handle rather than the path, so it can't be
  // redirected. The ACL before the mode: an ACL's owning group entry
  // may deny what the mode's group bits (its mask) allow, which the
  // mode alone would grant meanwhile. The mode after the chown,
  // which clears setuid / setgid.
  let res = copy_access_control(path, temp)
    .and_then(|()| temp.set_permissions(existing.permissions()));
  if res.is_err() && uid.is_some() {
    // Given away (CAP_CHOWN), but no longer this process's to set
    // the mode / ACL of (no CAP_FOWNER): take it back, or it can't
    // be removed from a sticky directory.
    let _ = fchown(temp, Some(created.uid()), Some(created.gid()));
  }
  res
}

/// Only unix has an owner and mode to carry over. The read only flag
/// is not copied: Windows can't rename onto a read only file anyways.
#[cfg(not(unix))]
fn copy_identity(
  _path: &Path,
  _temp: &File,
  _created: &Metadata,
  _existing: &Metadata,
) -> std::io::Result<()> {
  Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
use xattr::copy_access_control;

/// Extended attributes are only carried over on Linux.
#[cfg(all(
  unix,
  not(any(target_os = "linux", target_os = "android"))
))]
fn copy_access_control(
  _path: &Path,
  _temp: &File,
) -> std::io::Result<()> {
  Ok(())
}

/// Whether setting the owner / group / mode / access control failed
/// because it is not permitted (or supported), rather than eg. an
/// I/O error.
fn not_permitted(e: &std::io::Error) -> bool {
  matches!(
    e.kind(),
    ErrorKind::PermissionDenied
      | ErrorKind::InvalidInput
      | ErrorKind::Unsupported
  )
}

/// Whether the existing file, whose owner / group can't be given to
/// a new file, may be written in place instead. In a sticky
/// directory (eg. `/tmp`) the kernel only lets the owner of the file
/// or of the directory replace it, so another user's file there is
/// not written either: it may have been planted to receive the
/// contents.
///
/// The writer is the owner of the temp file as it was `created`
/// (the process's filesystem uid, which the kernel's check goes
/// by), not its owner now: [copy_identity] may have given it to the
/// existing file's owner before failing to set its mode.
#[cfg(unix)]
fn sticky_permits_in_place(
  path: &Path,
  created: &Metadata,
  existing: &Metadata,
) -> std::io::Result<bool> {
  use std::os::unix::fs::MetadataExt;
  let dir = std::fs::metadata(parent_dir(path))?;
  Ok(sticky_permits(
    dir.mode(),
    dir.uid(),
    existing.uid(),
    created.uid(),
  ))
}

/// There is no owner to keep outside of unix.
#[cfg(not(unix))]
fn sticky_permits_in_place(
  _path: &Path,
  _created: &Metadata,
  _existing: &Metadata,
) -> std::io::Result<bool> {
  Ok(true)
}

/// The kernel's rule for replacing a file in a sticky directory:
/// only the owner of the file or of the directory may.
#[cfg(unix)]
fn sticky_permits(
  dir_mode: u32,
  dir_uid: u32,
  file_uid: u32,
  writer_uid: u32,
) -> bool {
  dir_mode & 0o1000 == 0
    || writer_uid == file_uid
    || writer_uid == dir_uid
}

/// Whether the existing file has other hard links,
/// which replacing it would split off.
#[cfg(unix)]
fn hard_linked(existing: &Metadata) -> bool {
  std::os::unix::fs::MetadataExt::nlink(existing) > 1
}

/// Hard links are not detected outside of unix.
#[cfg(not(unix))]
fn hard_linked(_existing: &Metadata) -> bool {
  false
}

/// Whether the hard link at `path` can be written through. Where
/// `fs.protected_hardlinks` is off, anyone who can write to the
/// directory could have linked another user's file there.
#[cfg(unix)]
fn hard_link_trusted(
  path: &Path,
  existing: &Metadata,
) -> std::io::Result<bool> {
  use std::os::unix::fs::MetadataExt;
  let dir = std::fs::metadata(parent_dir(path))?;
  Ok(owner_only_dir(dir.mode(), dir.uid(), existing.uid()))
}

/// Hard links are not detected outside of unix.
#[cfg(not(unix))]
fn hard_link_trusted(
  _path: &Path,
  _existing: &Metadata,
) -> std::io::Result<bool> {
  Ok(false)
}

/// Whether only the directory's owner can add entries to it (going
/// by its mode, which also reflects the mask of any ACL), and that
/// owner is root or the file's owner.
#[cfg(unix)]
fn owner_only_dir(
  dir_mode: u32,
  dir_uid: u32,
  file_uid: u32,
) -> bool {
  dir_mode & 0o022 == 0 && (dir_uid == 0 || dir_uid == file_uid)
}

/// Creates the directory and its missing parents,
/// syncing the directories which hold the new ones.
fn create_dir_all(dir: &Path) -> std::io::Result<()> {
  // The missing directories, deepest first.
  let mut missing = Vec::new();
  let mut next = Some(dir);
  while let Some(dir) = next
    && !dir.as_os_str().is_empty()
    && std::fs::symlink_metadata(dir)
      .is_err_and(|e| e.kind() == ErrorKind::NotFound)
  {
    missing.push(dir);
    next = dir.parent();
  }

  if missing.is_empty() {
    return Ok(());
  }

  std::fs::create_dir_all(dir)?;

  // A new directory entry is only durable
  // once the directory holding it is synced.
  for dir in missing.into_iter().rev() {
    sync_dir(parent_dir(dir))?;
  }

  Ok(())
}

/// The directory holding `path`, "." for a bare file name.
fn parent_dir(path: &Path) -> &Path {
  match path.parent() {
    Some(dir) if !dir.as_os_str().is_empty() => dir,
    _ => Path::new("."),
  }
}

/// Syncs the directory, making the entries
/// renamed / created in it durable.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
  match File::open(dir).and_then(|dir| dir.sync_all()) {
    Ok(()) => Ok(()),
    // Some filesystems can't sync a directory,
    // and a directory without read permission can't be opened.
    Err(e)
      if matches!(
        e.kind(),
        ErrorKind::InvalidInput
          | ErrorKind::Unsupported
          | ErrorKind::PermissionDenied
      ) =>
    {
      Ok(())
    }
    Err(e) => Err(e),
  }
}

/// Directories can't be opened to sync them outside of unix.
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
  Ok(())
}

/// How many temp file names are tried before giving up.
const TEMP_ATTEMPTS: u32 = 8;

/// Creates a new temp file beside `path` to write to,
/// before renaming it onto `path`.
fn create_temp(path: &Path) -> std::io::Result<(File, TempPath)> {
  let mut attempt = 1;
  loop {
    let temp = temp_path(path)?;
    let mut options = OpenOptions::new();
    // Never opens an existing file (or follows a symlink),
    // so only this call ever writes to the temp file.
    options.write(true).create_new(true);
    // Only ever creates the temp file,
    // so the mode is always applied.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    match options.open(&temp) {
      Ok(file) => {
        return Ok((
          file,
          TempPath {
            path: temp,
            remove: true,
          },
        ));
      }
      // Someone else's file, which is left alone.
      Err(e)
        if e.kind() == ErrorKind::AlreadyExists
          && attempt < TEMP_ATTEMPTS =>
      {
        attempt += 1;
      }
      Err(e) => return Err(e),
    }
  }
}

/// A unique path beside `path` to write to before renaming onto it.
/// It has to be in the same directory,
/// as a rename can't cross filesystems.
fn temp_path(path: &Path) -> std::io::Result<PathBuf> {
  static COUNT: AtomicU64 = AtomicU64::new(0);

  let Some(file_name) = path.file_name() else {
    return Err(std::io::Error::new(
      ErrorKind::InvalidInput,
      format!("Path to write has no file name: {path:?}"),
    ));
  };

  #[cfg(test)]
  if let Some(forced) = tests::forced_temp_path(path) {
    return Ok(forced);
  }

  // Random, so the name can't be predicted, and doesn't collide
  // with a writer in another pid namespace (eg. another container).
  let random = std::collections::hash_map::RandomState::new()
    .hash_one((
      std::process::id(),
      COUNT.fetch_add(1, Ordering::Relaxed),
      std::time::SystemTime::now(),
    ));

  // Keeps the temp name within the usual 255 byte limit.
  let file_name = file_name.to_string_lossy();
  let mut end = file_name.len().min(64);
  while !file_name.is_char_boundary(end) {
    end -= 1;
  }

  Ok(path.with_file_name(format!(
    ".{}.{random:016x}.tmp",
    &file_name[..end]
  )))
}

/// Removes the temp file on drop,
/// unless it was renamed into place.
struct TempPath {
  path: PathBuf,
  remove: bool,
}

impl TempPath {
  fn keep(mut self) {
    self.remove = false;
  }
}

impl Drop for TempPath {
  fn drop(&mut self) {
    if self.remove {
      let _ = std::fs::remove_file(&self.path);
    }
  }
}

#[cfg(test)]
mod tests {
  use std::{
    path::{Path, PathBuf},
    sync::Mutex,
  };

  /// Paths whose writes fail after the temp file is written.
  static FAIL_BEFORE_RENAME: Mutex<Vec<PathBuf>> =
    Mutex::new(Vec::new());

  pub(super) fn injected_failure(path: &Path) -> std::io::Result<()> {
    if FAIL_BEFORE_RENAME.lock().unwrap().iter().any(|p| p == path) {
      Err(std::io::Error::other("injected failure"))
    } else {
      Ok(())
    }
  }

  #[cfg(unix)]
  fn inject_failure(path: &Path) {
    FAIL_BEFORE_RENAME.lock().unwrap().push(path.to_path_buf());
  }

  /// Paths whose writes can't set (or remove) the access control
  /// extended attributes of the temp file, as if not permitted.
  #[cfg(any(target_os = "linux", target_os = "android"))]
  static FAIL_ACCESS_CONTROL: Mutex<Vec<PathBuf>> =
    Mutex::new(Vec::new());

  #[cfg(any(target_os = "linux", target_os = "android"))]
  pub(super) fn injected_access_control_failure(
    path: &Path,
  ) -> std::io::Result<()> {
    if FAIL_ACCESS_CONTROL
      .lock()
      .unwrap()
      .iter()
      .any(|p| p == path)
    {
      Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "injected access control failure",
      ))
    } else {
      Ok(())
    }
  }

  #[cfg(any(target_os = "linux", target_os = "android"))]
  fn inject_access_control_failure(path: &Path) {
    FAIL_ACCESS_CONTROL.lock().unwrap().push(path.to_path_buf());
  }

  /// Temp paths handed out, in order, before random ones, per path
  /// written: `(path, temp path)`.
  static FORCED_TEMP_PATHS: Mutex<Vec<(PathBuf, PathBuf)>> =
    Mutex::new(Vec::new());

  pub(super) fn forced_temp_path(path: &Path) -> Option<PathBuf> {
    let mut forced = FORCED_TEMP_PATHS.lock().unwrap();
    let i = forced.iter().position(|(p, _)| p == path)?;
    Some(forced.remove(i).1)
  }

  /// Makes the next temp paths of writes to `path` the `temps`.
  #[cfg(unix)]
  fn force_temp_paths(path: &Path, temps: &[PathBuf]) {
    FORCED_TEMP_PATHS.lock().unwrap().extend(
      temps.iter().map(|temp| (path.to_path_buf(), temp.clone())),
    );
  }

  /// Whether forced temp paths of writes to `path` are left.
  #[cfg(unix)]
  fn forced_temp_paths_left(path: &Path) -> bool {
    FORCED_TEMP_PATHS
      .lock()
      .unwrap()
      .iter()
      .any(|(p, _)| p == path)
  }

  #[test]
  fn temp_paths_are_unique_and_short() {
    let path = Path::new("dir").join("secret");
    let a = super::temp_path(&path).unwrap();
    let b = super::temp_path(&path).unwrap();
    assert_ne!(a, b);
    assert_eq!(a.parent(), path.parent());
    let name = a.file_name().unwrap().to_str().unwrap();
    assert!(name.starts_with(".secret."), "{name}");
    assert!(name.ends_with(".tmp"), "{name}");

    let long = "é".repeat(127);
    let temp = super::temp_path(Path::new(&long)).unwrap();
    assert!(temp.as_os_str().len() <= 255);
    assert!(super::temp_path(Path::new("/")).is_err());
  }

  #[cfg(unix)]
  #[test]
  fn sync_dir_accepts_bare_file_name() {
    super::sync_dir(super::parent_dir(Path::new("secret"))).unwrap();
  }

  #[cfg(unix)]
  mod unix {
    use std::{
      os::unix::fs::{MetadataExt, PermissionsExt},
      path::{Path, PathBuf},
    };

    fn temp_dir(name: &str) -> PathBuf {
      let dir = std::env::temp_dir().join(format!(
        "mogh_secret_file_write_test_{}_{name}",
        std::process::id()
      ));
      let _ = std::fs::remove_dir_all(&dir);
      dir
    }

    fn mode(path: &Path) -> u32 {
      std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    fn set_mode(path: &Path, mode: u32) {
      std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(mode),
      )
      .unwrap();
    }

    fn entries(dir: &Path) -> Vec<String> {
      let mut entries = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
      entries.sort();
      entries
    }

    /// Whether the process ignores directory permissions (root).
    fn bypasses_permissions(dir: &Path) -> bool {
      let probe = dir.join("probe");
      let res = std::fs::write(&probe, "");
      let _ = std::fs::remove_file(probe);
      res.is_ok()
    }

    #[test]
    fn write_creates_parents_and_sets_mode() {
      let dir = temp_dir("sync");
      let path = dir.join("nested").join("secret");
      super::super::write(&path, "hunter2").unwrap();
      assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter2");
      assert_eq!(mode(&path), 0o600);
      // Overwriting replaces previous contents.
      super::super::write(&path, "x").unwrap();
      assert_eq!(std::fs::read_to_string(&path).unwrap(), "x");
      // The temp file is not left behind.
      assert_eq!(entries(path.parent().unwrap()), ["secret"]);
      std::fs::remove_dir_all(dir).unwrap();
    }

    /// An existing file keeps its permissions,
    /// even though it is replaced by the temp file.
    #[test]
    fn write_keeps_existing_permissions() {
      let dir = temp_dir("sync-permissions");
      let path = dir.join("secret");
      super::super::write(&path, "hunter2").unwrap();
      set_mode(&path, 0o640);
      super::super::write(&path, "hunter3").unwrap();
      assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter3");
      assert_eq!(mode(&path), 0o640);
      std::fs::remove_dir_all(dir).unwrap();
    }

    /// A write which fails after the temp file is written leaves the
    /// existing contents in place, and doesn't leave the temp file.
    #[test]
    fn failed_write_keeps_existing_contents() {
      let dir = temp_dir("sync-failure");
      let path = dir.join("secret");
      super::super::write(&path, "hunter2").unwrap();
      super::inject_failure(&path);
      assert!(super::super::write(&path, "hunter3").is_err());
      assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter2");
      assert_eq!(entries(&dir), ["secret"]);
      std::fs::remove_dir_all(dir).unwrap();
    }

    /// When neither a temp file can be created, nor the file written
    /// in place, the write fails and the file is left untouched.
    #[test]
    fn unwritable_file_keeps_existing_contents() {
      let dir = temp_dir("sync-unwritable");
      let path = dir.join("secret");
      super::super::write(&path, "hunter2").unwrap();

      set_mode(&path, 0o400);
      set_mode(&dir, 0o555);
      let res = super::super::write(&path, "hunter3");
      set_mode(&dir, 0o755);

      // Root can write regardless of the modes,
      // in which case there is no failure to assert on.
      if res.is_err() {
        assert_eq!(
          std::fs::read_to_string(&path).unwrap(),
          "hunter2"
        );
        assert_eq!(entries(&dir), ["secret"]);
      }

      std::fs::remove_dir_all(dir).unwrap();
    }

    /// A writable file in a directory which can't be written to
    /// is written in place, as 1.0 did.
    #[test]
    fn write_in_read_only_dir_writes_in_place() {
      let dir = temp_dir("sync-read-only-dir");
      let path = dir.join("secret");
      super::super::write(&path, "hunter2 is longer").unwrap();
      let ino = std::fs::metadata(&path).unwrap().ino();

      set_mode(&dir, 0o555);
      let in_place = !bypasses_permissions(&dir);
      let res = super::super::write(&path, "hunter3");
      set_mode(&dir, 0o755);

      res.unwrap();
      assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter3");
      assert_eq!(mode(&path), 0o600);
      assert_eq!(entries(&dir), ["secret"]);
      if in_place {
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), ino);
      }
      std::fs::remove_dir_all(dir).unwrap();
    }

    /// A symlink is not followed: it is replaced by a new file,
    /// and the file it points to is left untouched.
    #[test]
    fn write_replaces_symlinks() {
      let dir = temp_dir("sync-symlink");
      let real = dir.join("real").join("secret");
      super::super::write(&real, "hunter2").unwrap();
      set_mode(&real, 0o640);

      let link = dir.join("link");
      std::os::unix::fs::symlink(&real, &link).unwrap();
      super::super::write(&link, "hunter3").unwrap();
      assert!(link.symlink_metadata().unwrap().is_file());
      assert_eq!(std::fs::read_to_string(&link).unwrap(), "hunter3");
      // A new file, which doesn't take the mode of the link target.
      assert_eq!(mode(&link), 0o600);
      assert_eq!(std::fs::read_to_string(&real).unwrap(), "hunter2");
      assert_eq!(mode(&real), 0o640);

      // A dangling link doesn't get its target created.
      let dangling = dir.join("dangling");
      std::os::unix::fs::symlink("real/new", &dangling).unwrap();
      super::super::write(&dangling, "hunter4").unwrap();
      assert!(dangling.symlink_metadata().unwrap().is_file());
      assert_eq!(entries(&dir.join("real")), ["secret"]);

      // A link to a directory, and a link loop.
      let to_dir = dir.join("to_dir");
      std::os::unix::fs::symlink("real", &to_dir).unwrap();
      let a = dir.join("a");
      std::os::unix::fs::symlink("b", &a).unwrap();
      std::os::unix::fs::symlink("a", dir.join("b")).unwrap();
      for path in [&to_dir, &a] {
        super::super::write(path, "hunter5").unwrap();
        assert!(path.symlink_metadata().unwrap().is_file());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "hunter5");
      }

      assert_eq!(entries(&dir.join("real")), ["secret"]);
      assert_eq!(
        entries(&dir),
        ["a", "b", "dangling", "link", "real", "to_dir"]
      );
      std::fs::remove_dir_all(dir).unwrap();
    }

    /// A symlink in a directory which can't be written to is not
    /// written through in place either: the write fails.
    #[test]
    fn write_never_writes_through_symlinks_in_place() {
      let dir = temp_dir("sync-symlink-read-only-dir");
      let real = dir.join("real");
      super::super::write(&real, "hunter2").unwrap();
      let locked = dir.join("locked");
      std::fs::create_dir(&locked).unwrap();
      let link = locked.join("link");
      std::os::unix::fs::symlink(&real, &link).unwrap();

      set_mode(&locked, 0o555);
      let root = bypasses_permissions(&locked);
      let res = super::super::write(&link, "hunter3");
      set_mode(&locked, 0o755);

      // Root can replace the link regardless of the mode.
      if !root {
        assert!(res.is_err());
        assert!(link.symlink_metadata().unwrap().is_symlink());
      }
      assert_eq!(std::fs::read_to_string(&real).unwrap(), "hunter2");
      assert_eq!(entries(&locked), ["link"]);
      std::fs::remove_dir_all(dir).unwrap();
    }

    /// An in place write only writes the file checked before,
    /// not eg. a symlink someone swapped in since.
    #[test]
    fn in_place_write_checks_the_file() {
      let dir = temp_dir("sync-in-place-swap");
      let real = dir.join("real");
      let path = dir.join("secret");
      super::super::write(&real, "hunter2").unwrap();
      super::super::write(&path, "hunter2").unwrap();
      let checked = std::fs::symlink_metadata(&path).unwrap();

      std::fs::remove_file(&path).unwrap();
      std::os::unix::fs::symlink(&real, &path).unwrap();
      assert!(
        super::super::write_in_place(&path, &checked, b"hunter3")
          .is_err()
      );
      assert_eq!(std::fs::read_to_string(&real).unwrap(), "hunter2");
      std::fs::remove_dir_all(dir).unwrap();
    }

    /// A fifo is replaced like a symlink, rather than blocking on
    /// it, or writing the contents to whoever reads it.
    #[test]
    fn write_replaces_fifo() {
      let dir = temp_dir("sync-fifo");
      let path = dir.join("secret");
      std::fs::create_dir_all(&dir).unwrap();
      let created = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .is_ok_and(|status| status.success());
      if !created {
        eprintln!("Can't run mkfifo, skipping");
        std::fs::remove_dir_all(dir).unwrap();
        return;
      }

      let (tx, rx) = std::sync::mpsc::channel();
      let thread_path = path.clone();
      std::thread::spawn(move || {
        let _ = tx.send(super::super::write(&thread_path, "hunter2"));
      });
      let res = rx.recv_timeout(std::time::Duration::from_secs(5));
      if res.is_err() {
        // Unblocks the write by reading the fifo.
        let _ = std::fs::read(&path);
        panic!("write blocked on the fifo");
      }

      res.unwrap().unwrap();
      assert!(path.symlink_metadata().unwrap().is_file());
      assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter2");
      assert_eq!(mode(&path), 0o600);
      std::fs::remove_dir_all(dir).unwrap();
    }

    /// Hard links keep sharing the contents,
    /// when only their owner can write to the directory.
    #[test]
    fn write_keeps_hard_links() {
      let dir = temp_dir("sync-hard-link");
      let a = dir.join("a");
      let b = dir.join("b");
      super::super::write(&a, "hunter2 is longer").unwrap();
      set_mode(&dir, 0o755);
      std::fs::hard_link(&a, &b).unwrap();
      super::super::write(&a, "hunter3").unwrap();
      assert_eq!(std::fs::read_to_string(&a).unwrap(), "hunter3");
      assert_eq!(std::fs::read_to_string(&b).unwrap(), "hunter3");
      assert_eq!(std::fs::metadata(&a).unwrap().nlink(), 2);
      assert_eq!(entries(&dir), ["a", "b"]);
      std::fs::remove_dir_all(dir).unwrap();
    }

    /// In a directory others can write to, someone else could have
    /// planted the hard link, so it is split off like 1.1.0 did,
    /// rather than written through.
    #[test]
    fn write_splits_hard_links_others_could_plant() {
      let dir = temp_dir("sync-hard-link-shared-dir");
      let a = dir.join("a");
      let b = dir.join("b");
      super::super::write(&a, "hunter2").unwrap();
      std::fs::hard_link(&a, &b).unwrap();
      set_mode(&dir, 0o775);
      super::super::write(&a, "hunter3").unwrap();
      assert_eq!(std::fs::read_to_string(&a).unwrap(), "hunter3");
      assert_eq!(std::fs::read_to_string(&b).unwrap(), "hunter2");
      assert_eq!(std::fs::metadata(&a).unwrap().nlink(), 1);
      assert_eq!(mode(&a), 0o600);
      assert_eq!(entries(&dir), ["a", "b"]);
      std::fs::remove_dir_all(dir).unwrap();
    }

    /// A hard linked file which can't be opened for writing
    /// is still replaced, splitting off the link like 1.1.0 did.
    #[test]
    fn write_splits_read_only_hard_links() {
      let dir = temp_dir("sync-hard-link-read-only");
      let a = dir.join("a");
      let b = dir.join("b");
      super::super::write(&a, "hunter2").unwrap();
      set_mode(&dir, 0o755);
      std::fs::hard_link(&a, &b).unwrap();
      set_mode(&a, 0o400);
      let root =
        std::fs::OpenOptions::new().write(true).open(&a).is_ok();

      super::super::write(&a, "hunter3").unwrap();
      assert_eq!(std::fs::read_to_string(&a).unwrap(), "hunter3");
      assert_eq!(mode(&a), 0o400);
      // Root writes it in place.
      if !root {
        assert_eq!(std::fs::read_to_string(&b).unwrap(), "hunter2");
        assert_eq!(std::fs::metadata(&a).unwrap().nlink(), 1);
      }
      assert_eq!(entries(&dir), ["a", "b"]);
      std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn hard_links_are_kept_in_owner_only_dirs() {
      use super::super::owner_only_dir;
      // The file owner's own directory, or root's.
      assert!(owner_only_dir(0o40700, 1000, 1000));
      assert!(owner_only_dir(0o40755, 0, 1000));
      // Others can write to it (or an ACL lets them).
      assert!(!owner_only_dir(0o40775, 1000, 1000));
      assert!(!owner_only_dir(0o40757, 1000, 1000));
      assert!(!owner_only_dir(0o41777, 0, 0));
      // Its owner could have linked another user's file.
      assert!(!owner_only_dir(0o40755, 1000, 0));
    }

    #[test]
    fn sticky_dirs_protect_other_users_files() {
      use super::super::sticky_permits;
      // Not sticky.
      assert!(sticky_permits(0o40777, 0, 1001, 1000));
      // Another user's file in root's /tmp.
      assert!(!sticky_permits(0o41777, 0, 1001, 1000));
      // The writer's own file, or own directory.
      assert!(sticky_permits(0o41777, 0, 1000, 1000));
      assert!(sticky_permits(0o41777, 1000, 1001, 1000));
    }

    /// The writer is the temp file's owner as created, not as it is
    /// after the chown: with CAP_CHOWN but no CAP_FOWNER, the temp
    /// file is given to the planted file's owner before setting its
    /// mode fails, and the check used to take that owner as the
    /// writer, writing another user's file in place.
    #[test]
    fn sticky_dirs_go_by_the_writer_as_created() {
      use super::super::sticky_permits_in_place;
      // A sticky directory owned by root, like /tmp.
      let Some(sticky) = ["/tmp", "/var/tmp", "/dev/shm"]
        .into_iter()
        .map(Path::new)
        .find(|dir| {
          std::fs::metadata(dir).is_ok_and(|dir| {
            dir.mode() & 0o1000 != 0 && dir.uid() == 0
          })
        })
      else {
        eprintln!("No sticky directory owned by root, skipping");
        return;
      };
      let dir = temp_dir("sticky-writer");
      let own = dir.join("own");
      super::super::write(&own, "").unwrap();
      // The temp file as this process creates it.
      let created = std::fs::metadata(&own).unwrap();
      std::fs::remove_dir_all(&dir).unwrap();
      if created.uid() == 0 {
        eprintln!("Root, skipping");
        return;
      }
      // Another user's (root's) file, planted in the directory.
      let planted = std::fs::metadata("/").unwrap();
      let path = sticky.join("planted");
      assert!(
        !sticky_permits_in_place(&path, &created, &planted).unwrap()
      );
      // What the temp file looks like once given to that user.
      assert!(
        sticky_permits_in_place(&path, &planted, &planted).unwrap()
      );
      // The writer's own file.
      assert!(
        sticky_permits_in_place(&path, &created, &created).unwrap()
      );
    }

    /// The existing file's group is carried over to the new file,
    /// rather than becoming the writer's primary group.
    #[test]
    fn write_keeps_existing_group() {
      let dir = temp_dir("sync-group");
      let path = dir.join("secret");
      super::super::write(&path, "hunter2").unwrap();
      set_mode(&path, 0o640);
      let own_gid = std::fs::metadata(&path).unwrap().gid();

      // Another group this process is a member of.
      let status = std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default();
      let Some(gid) = status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .into_iter()
        .flat_map(|groups| groups.split_whitespace())
        .filter_map(|gid| gid.parse::<u32>().ok())
        .find(|gid| *gid != own_gid)
      else {
        eprintln!("No supplementary group, skipping");
        std::fs::remove_dir_all(dir).unwrap();
        return;
      };

      std::os::unix::fs::chown(&path, None, Some(gid)).unwrap();
      super::super::write(&path, "hunter3").unwrap();
      assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter3");
      assert_eq!(std::fs::metadata(&path).unwrap().gid(), gid);
      assert_eq!(mode(&path), 0o640);
      assert_eq!(entries(&dir), ["secret"]);
      std::fs::remove_dir_all(dir).unwrap();
    }

    /// Root keeps the existing file's owner,
    /// rather than giving the file to root.
    #[test]
    fn write_keeps_existing_owner() {
      let dir = temp_dir("sync-owner");
      let path = dir.join("secret");
      super::super::write(&path, "hunter2").unwrap();
      // Only root can give the file away.
      if std::os::unix::fs::chown(&path, Some(12345), Some(12345))
        .is_err()
      {
        eprintln!("Not root, skipping");
        std::fs::remove_dir_all(dir).unwrap();
        return;
      }
      super::super::write(&path, "hunter3").unwrap();
      let metadata = std::fs::metadata(&path).unwrap();
      assert_eq!((metadata.uid(), metadata.gid()), (12345, 12345));
      assert_eq!(mode(&path), 0o600);
      assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter3");
      std::fs::remove_dir_all(dir).unwrap();
    }

    /// Files at the predictable names 1.1.0 picked for its temp
    /// files (pid / counter) are neither written, nor removed, nor
    /// fail the write. An actual collision with a temp name is
    /// covered by [write_skips_taken_temp_names].
    #[test]
    fn write_leaves_other_temp_files_alone() {
      let dir = temp_dir("sync-other-temp");
      let path = dir.join("secret");
      std::fs::create_dir_all(&dir).unwrap();
      // The names 1.1.0 would pick.
      let pid = std::process::id();
      for n in 0..256 {
        std::fs::write(
          dir.join(format!(".secret.{pid}.{n}.tmp")),
          "",
        )
        .unwrap();
      }
      super::super::write(&path, "hunter2").unwrap();
      assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter2");
      assert_eq!(entries(&dir).len(), 257);
      std::fs::remove_dir_all(dir).unwrap();
    }

    /// Plants someone else's entries at the `count` temp names the
    /// next write to `path` tries first: a symlink to `victim`, a
    /// dangling symlink, then files.
    fn plant_taken_temps(
      path: &Path,
      victim: &Path,
      count: u32,
    ) -> Vec<PathBuf> {
      let dir = path.parent().unwrap();
      let taken = (0..count)
        .map(|n| dir.join(format!(".secret.taken{n}.tmp")))
        .collect::<Vec<_>>();
      for (n, temp) in taken.iter().enumerate() {
        match n {
          0 => std::os::unix::fs::symlink(victim, temp).unwrap(),
          1 => std::os::unix::fs::symlink("missing", temp).unwrap(),
          _ => std::fs::write(temp, format!("theirs {n}")).unwrap(),
        }
      }
      super::force_temp_paths(path, &taken);
      taken
    }

    /// The entries [plant_taken_temps] planted are untouched.
    fn assert_taken_temps_untouched(
      taken: &[PathBuf],
      victim: &Path,
    ) {
      for (n, temp) in taken.iter().enumerate() {
        match n {
          0 | 1 => {
            assert!(temp.symlink_metadata().unwrap().is_symlink())
          }
          _ => assert_eq!(
            std::fs::read_to_string(temp).unwrap(),
            format!("theirs {n}")
          ),
        }
      }
      assert_eq!(std::fs::read_to_string(victim).unwrap(), "theirs");
      assert!(!victim.with_file_name("missing").exists());
    }

    /// A temp name someone else's entry already has is skipped:
    /// a file there is neither written nor removed, a symlink there
    /// is not followed, and the write goes on with another name.
    #[test]
    fn write_skips_taken_temp_names() {
      let dir = temp_dir("sync-taken-temp");
      let path = dir.join("secret");
      let victim = dir.join("victim");
      std::fs::create_dir_all(&dir).unwrap();
      std::fs::write(&victim, "theirs").unwrap();

      // All attempts but the last collide.
      let taken = plant_taken_temps(
        &path,
        &victim,
        super::super::TEMP_ATTEMPTS - 1,
      );
      super::super::write(&path, "hunter2").unwrap();
      // Every taken name was tried.
      assert!(!super::forced_temp_paths_left(&path));

      assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter2");
      assert_eq!(mode(&path), 0o600);
      assert_taken_temps_untouched(&taken, &victim);
      // Nothing else is left behind.
      assert_eq!(entries(&dir).len(), taken.len() + 2);
      std::fs::remove_dir_all(dir).unwrap();
    }

    /// When every temp name tried is taken, the write fails,
    /// leaving the existing file and the taken entries untouched.
    #[test]
    fn write_gives_up_when_temp_names_stay_taken() {
      let dir = temp_dir("sync-taken-temp-all");
      let path = dir.join("secret");
      let victim = dir.join("victim");
      super::super::write(&path, "hunter2").unwrap();
      std::fs::write(&victim, "theirs").unwrap();

      let taken = plant_taken_temps(
        &path,
        &victim,
        super::super::TEMP_ATTEMPTS,
      );
      let err = super::super::write(&path, "hunter3").unwrap_err();
      assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
      assert!(!super::forced_temp_paths_left(&path));

      assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter2");
      assert_taken_temps_untouched(&taken, &victim);
      assert_eq!(entries(&dir).len(), taken.len() + 2);
      std::fs::remove_dir_all(dir).unwrap();
    }

    /// File names near the 255 byte limit can still be written,
    /// the temp name doesn't outgrow it.
    #[test]
    fn write_long_file_name() {
      let dir = temp_dir("sync-long-name");
      let path = dir.join("s".repeat(250));
      super::super::write(&path, "hunter2").unwrap();
      super::super::write(&path, "hunter3").unwrap();
      assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter3");
      std::fs::remove_dir_all(dir).unwrap();
    }

    /// Env var marking the process as running in the mount namespace
    /// set up by [write_bind_mounted_file].
    const BIND_MOUNT_TEST_DIR: &str =
      "MOGH_SECRET_FILE_BIND_MOUNT_TEST_DIR";

    /// A single file bind mount (eg. a docker / kubernetes secret)
    /// can't be renamed onto, so it is written in place.
    /// Runs [bind_mounted_file_in_namespace] in a new user and mount
    /// namespace, skipped where these aren't available.
    #[test]
    fn write_bind_mounted_file() {
      let dir = temp_dir("sync-bind-mount");
      std::fs::create_dir_all(&dir).unwrap();
      let output = std::process::Command::new("unshare")
        .args(["--user", "--map-root-user", "--mount", "--"])
        .arg(std::env::current_exe().unwrap())
        .args([
          "--exact",
          "write::tests::unix::bind_mounted_file_in_namespace",
          "--ignored",
          "--nocapture",
          "--test-threads=1",
        ])
        .env(BIND_MOUNT_TEST_DIR, &dir)
        .output();
      let _ = std::fs::remove_dir_all(&dir);
      let output = match output {
        Ok(output) => output,
        Err(e) => {
          eprintln!("Can't run unshare, skipping: {e}");
          return;
        }
      };
      let stdout = String::from_utf8_lossy(&output.stdout);
      let stderr = String::from_utf8_lossy(&output.stderr);
      if !output.status.success() && stdout.is_empty() {
        eprintln!("No user namespaces, skipping: {stderr}");
        return;
      }
      assert!(
        output.status.success()
          && stdout.contains("1 passed")
          && !stdout.contains("skipping"),
        "{stdout}\n{stderr}"
      );
    }

    #[test]
    #[ignore = "run in a mount namespace by write_bind_mounted_file"]
    fn bind_mounted_file_in_namespace() {
      let Some(dir) = std::env::var_os(BIND_MOUNT_TEST_DIR) else {
        eprintln!("Not in a mount namespace, skipping");
        return;
      };
      let dir = PathBuf::from(dir);
      let host = dir.join("host").join("secret");
      let mounted = dir.join("mounted").join("secret");
      super::super::write(&host, "hunter2 is longer").unwrap();
      super::super::write(&mounted, "").unwrap();
      let status = std::process::Command::new("mount")
        .arg("--bind")
        .args([&host, &mounted])
        .status()
        .unwrap();
      assert!(status.success());
      assert_eq!(
        std::fs::read_to_string(&mounted).unwrap(),
        "hunter2 is longer"
      );

      super::super::write(&mounted, "hunter3").unwrap();
      assert_eq!(
        std::fs::read_to_string(&mounted).unwrap(),
        "hunter3"
      );
      assert_eq!(std::fs::read_to_string(&host).unwrap(), "hunter3");
      assert_eq!(entries(mounted.parent().unwrap()), ["secret"]);
    }

    /// The access ACL and security label are carried over on Linux.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    mod linux {
      use std::{
        ffi::{CStr, CString},
        os::unix::{ffi::OsStrExt, fs::MetadataExt},
        path::Path,
      };

      use super::{entries, mode, set_mode, temp_dir};
      use crate::write::write;

      const ACL_ACCESS: &CStr = c"system.posix_acl_access";
      const ACL_DEFAULT: &CStr = c"system.posix_acl_default";

      // POSIX ACL entry tags, and the id of the entries without one.
      const USER_OBJ: u16 = 0x01;
      const USER: u16 = 0x02;
      const GROUP_OBJ: u16 = 0x04;
      const MASK: u16 = 0x10;
      const OTHER: u16 = 0x20;
      const NO_ID: u32 = u32::MAX;

      /// The user granted access in the ACLs, standing in for a
      /// sidecar: the owner of `path`, as the id has to be mapped in
      /// the user namespace the tests run in (`nobody` may not be).
      fn sidecar(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().uid()
      }

      /// A POSIX ACL as the kernel stores it in the xattr (version 2):
      /// `(tag, permissions, id)` entries, sorted by tag.
      fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in entries {
          acl.extend(tag.to_le_bytes());
          acl.extend(perm.to_le_bytes());
          acl.extend(id.to_le_bytes());
        }
        acl
      }

      /// `setfacl -m u:<sidecar>:r` on the `0600` file at `path`: the
      /// sidecar can read it, the owning group can't. The mode shows
      /// the mask, `0640`.
      fn sidecar_acl(path: &Path) -> Vec<u8> {
        acl(&[
          (USER_OBJ, 6, NO_ID),
          (USER, 4, sidecar(path)),
          (GROUP_OBJ, 0, NO_ID),
          (MASK, 4, NO_ID),
          (OTHER, 0, NO_ID),
        ])
      }

      fn c_path(path: &Path) -> CString {
        CString::new(path.as_os_str().as_bytes()).unwrap()
      }

      fn get_xattr(path: &Path, name: &CStr) -> Option<Vec<u8>> {
        let path = c_path(path);
        let mut buf = vec![0u8; 64 * 1024];
        // SAFETY: path and name are nul terminated,
        // buf is valid for writes of buf.len() bytes.
        let len = unsafe {
          libc::lgetxattr(
            path.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
          )
        };
        if len < 0 {
          let e = std::io::Error::last_os_error();
          assert_eq!(e.raw_os_error(), Some(libc::ENODATA), "{e}");
          return None;
        }
        buf.truncate(len as usize);
        Some(buf)
      }

      /// Sets the xattr, `false` when the filesystem doesn't support
      /// it (eg. ACLs), and the test is skipped.
      fn set_xattr(path: &Path, name: &CStr, value: &[u8]) -> bool {
        let path = c_path(path);
        // SAFETY: path and name are nul terminated,
        // value is valid for reads of value.len() bytes.
        let res = unsafe {
          libc::lsetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
          )
        };
        if res == 0 {
          return true;
        }
        let e = std::io::Error::last_os_error();
        assert_eq!(
          e.kind(),
          std::io::ErrorKind::Unsupported,
          "set {name:?}: {e}"
        );
        eprintln!("No {name:?} support, skipping: {e}");
        false
      }

      fn ino(path: &Path) -> u64 {
        std::fs::metadata(path).unwrap().ino()
      }

      /// A file with an ACL (eg. granting a sidecar read) keeps it,
      /// and so the owning group keeps being denied, rather than the
      /// mask (the mode's group bits) becoming the group's access.
      /// The file is still replaced atomically.
      #[test]
      fn write_keeps_the_acl() {
        let dir = temp_dir("sync-acl");
        let path = dir.join("secret");
        write(&path, "hunter2").unwrap();
        let acl = sidecar_acl(&path);
        if !set_xattr(&path, ACL_ACCESS, &acl) {
          std::fs::remove_dir_all(dir).unwrap();
          return;
        }
        assert_eq!(mode(&path), 0o640);
        let replaced = ino(&path);

        write(&path, "hunter3").unwrap();
        assert_eq!(
          std::fs::read_to_string(&path).unwrap(),
          "hunter3"
        );
        assert_eq!(get_xattr(&path, ACL_ACCESS), Some(acl));
        assert_eq!(mode(&path), 0o640);
        assert_ne!(ino(&path), replaced);
        assert_eq!(entries(&dir), ["secret"]);
        std::fs::remove_dir_all(dir).unwrap();
      }

      /// A file without an ACL doesn't take on the directory's default
      /// ACL when it is replaced: its mode keeps meaning what it did.
      #[test]
      fn write_keeps_no_acl_under_a_default_acl() {
        let dir = temp_dir("sync-default-acl");
        let path = dir.join("secret");
        write(&path, "hunter2").unwrap();
        set_mode(&path, 0o640);
        let default = acl(&[
          (USER_OBJ, 7, NO_ID),
          (USER, 4, sidecar(&dir)),
          (GROUP_OBJ, 0, NO_ID),
          (MASK, 4, NO_ID),
          (OTHER, 0, NO_ID),
        ]);
        if !set_xattr(&dir, ACL_DEFAULT, &default) {
          std::fs::remove_dir_all(dir).unwrap();
          return;
        }

        write(&path, "hunter3").unwrap();
        assert_eq!(
          std::fs::read_to_string(&path).unwrap(),
          "hunter3"
        );
        assert_eq!(get_xattr(&path, ACL_ACCESS), None);
        assert_eq!(mode(&path), 0o640);

        // A new file does take it on, masked by its 0600 mode,
        // so only its owner has access.
        let new = dir.join("new");
        write(&new, "hunter2").unwrap();
        assert_eq!(mode(&new), 0o600);
        assert_eq!(entries(&dir), ["new", "secret"]);
        std::fs::remove_dir_all(dir).unwrap();
      }

      /// When the ACL / label can't be given to the new file (eg.
      /// relabeling is not permitted), the file is written in place,
      /// keeping them.
      #[test]
      fn write_in_place_when_the_acl_cant_be_kept() {
        let dir = temp_dir("sync-acl-in-place");
        let path = dir.join("secret");
        write(&path, "hunter2 is longer").unwrap();
        let acl = sidecar_acl(&path);
        if !set_xattr(&path, ACL_ACCESS, &acl) {
          std::fs::remove_dir_all(dir).unwrap();
          return;
        }
        let kept = ino(&path);

        super::super::inject_access_control_failure(&path);
        write(&path, "hunter3").unwrap();
        assert_eq!(
          std::fs::read_to_string(&path).unwrap(),
          "hunter3"
        );
        assert_eq!(ino(&path), kept);
        assert_eq!(get_xattr(&path, ACL_ACCESS), Some(acl));
        assert_eq!(mode(&path), 0o640);
        assert_eq!(entries(&dir), ["secret"]);
        std::fs::remove_dir_all(dir).unwrap();
      }

      /// When the ACL can't be given to the new file, and the file
      /// can't be written in place either (a hard link others could
      /// have planted), the write fails rather than dropping it.
      #[test]
      fn write_fails_when_the_acl_cant_be_kept() {
        let dir = temp_dir("sync-acl-fails");
        let a = dir.join("a");
        let b = dir.join("b");
        write(&a, "hunter2").unwrap();
        std::fs::hard_link(&a, &b).unwrap();
        set_mode(&dir, 0o775);
        let acl = sidecar_acl(&a);
        if !set_xattr(&a, ACL_ACCESS, &acl) {
          std::fs::remove_dir_all(dir).unwrap();
          return;
        }

        super::super::inject_access_control_failure(&a);
        let err = write(&a, "hunter3").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("access control"), "{err}");
        for path in [&a, &b] {
          assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "hunter2"
          );
        }
        assert_eq!(std::fs::metadata(&a).unwrap().nlink(), 2);
        assert_eq!(get_xattr(&a, ACL_ACCESS), Some(acl));
        assert_eq!(entries(&dir), ["a", "b"]);
        std::fs::remove_dir_all(dir).unwrap();
      }
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn write_async_creates_parents_and_sets_mode() {
      let dir = temp_dir("async");
      let path = dir.join("nested").join("secret");
      super::super::write_async(&path, "hunter2").await.unwrap();
      assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter2");
      assert_eq!(mode(&path), 0o600);
      // Overwriting replaces previous contents,
      // and leaves no temp file behind.
      super::super::write_async(&path, "x").await.unwrap();
      assert_eq!(std::fs::read_to_string(&path).unwrap(), "x");
      assert_eq!(entries(path.parent().unwrap()), ["secret"]);
      std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn failed_write_async_keeps_existing_contents() {
      let dir = temp_dir("async-failure");
      let path = dir.join("secret");
      super::super::write_async(&path, "hunter2").await.unwrap();
      super::inject_failure(&path);
      assert!(
        super::super::write_async(&path, "hunter3").await.is_err()
      );
      assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter2");
      assert_eq!(entries(&dir), ["secret"]);
      std::fs::remove_dir_all(dir).unwrap();
    }

    /// Dropping the future doesn't cut the write off halfway, leaving
    /// the temp file with the contents behind. The write completes.
    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn dropped_write_async_completes() {
      let dir = temp_dir("async-dropped");
      let path = dir.join("secret");
      let contents = vec![b'x'; 1 << 20];

      // Polled once, which starts the write, then dropped.
      let mut write =
        Box::pin(super::super::write_async(&path, &contents));
      std::future::poll_fn(|cx| {
        let _ = write.as_mut().poll(cx);
        std::task::Poll::Ready(())
      })
      .await;
      drop(write);

      for _ in 0..500 {
        if std::fs::read(&path).is_ok_and(|c| c == contents)
          && entries(&dir) == ["secret"]
        {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10))
          .await;
      }
      assert!(std::fs::read(&path).unwrap() == contents);
      assert_eq!(entries(&dir), ["secret"]);
      std::fs::remove_dir_all(dir).unwrap();
    }
  }
}
