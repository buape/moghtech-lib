use std::path::{Path, PathBuf};

use indexmap::IndexMap;

/// Collects the paths listed in a directory's include file,
/// in the order they are listed, without duplicates. Local paths
/// are kept as listed (joined to the canonical directory), so a
/// symlink (`app.env` -> `secret`) keeps the name its type is
/// detected from, and deduped by canonical path (a missing one is
/// skipped). `cicada:` paths are kept as written.
pub struct IncludesLoader {
  /// The listed path by its dedupe key (the canonical path, or a
  /// `cicada:` path as written). A path listed again keeps its
  /// first position and spelling.
  includes: IndexMap<PathBuf, PathBuf>,
  include_file_name: &'static str,
}

impl IncludesLoader {
  pub fn new(include_file_name: &'static str) -> Self {
    Self {
      includes: IndexMap::new(),
      include_file_name,
    }
  }

  pub fn init(path: &Path, include_file_name: &'static str) -> Self {
    let mut includes = Self::new(include_file_name);
    includes.load_more(path);
    includes
  }

  /// The included paths, in include order.
  pub fn finish(self) -> Vec<PathBuf> {
    self.includes.into_values().collect()
  }

  pub fn load_more(&mut self, folder: &Path) {
    if !folder.is_dir() {
      return;
    }
    let Ok(folder) = folder.canonicalize() else {
      return;
    };
    // Add any includes in this folder
    let Ok(ignore) =
      std::fs::read_to_string(folder.join(self.include_file_name))
    else {
      return;
    };
    let lines = ignore
      .split('\n')
      .map(|line| line.trim())
      // Ignore empty / commented out lines
      .filter(|line| !line.is_empty() && !line.starts_with('#'))
      // Remove end of line comments: a '#' preceded by
      // whitespace. A '#' inside a path is kept.
      .map(|line| {
        line
          .split_once(" #")
          .or_else(|| line.split_once("\t#"))
          .map(|res| res.0.trim())
          .unwrap_or(line)
      });
    for line in lines {
      // A cicada source is no local path: kept as written, for
      // the loader to load it (or refuse it without the
      // feature) rather than dropped as a missing path.
      if crate::load::is_cicada_path(Path::new(line)) {
        let path = PathBuf::from(line);
        self.includes.entry(path.clone()).or_insert(path);
        continue;
      }
      // Absolute, as the folder is canonical. Not canonicalized
      // itself: a symlink is loaded by its own name.
      let path = folder.join(line);
      let Ok(key) = path.canonicalize() else {
        continue;
      };
      self.includes.entry(key).or_insert(path);
    }
  }
}
