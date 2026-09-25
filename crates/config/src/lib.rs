//! # Mogh Config
//!
//! This library is used to parse Core, Periphery, and CLI config files.
//! It supports interpolating environment variables (`${VAR}`) and
//! command output (`$(command)`, a single command word without
//! arguments) into the values of local toml / yaml / json files, as
//! well as merging together multiple files into a final
//! configuration object.
//!
//! Sources are toml, yaml, json, and env files (`.env`, `*.env`):
//! flat `NAME=value` entries whose names are lowercased to match
//! struct fields, the way `envy` reads the process environment,
//! with dots nesting (`DATABASE.ADDRESS` fills `database.address`;
//! a name with an empty segment, `.dockerconfigjson`, stays one flat
//! key), and whose values are taken verbatim (no interpolation: they are
//! secrets, not templates). The final deserialization coerces
//! string values into the field's type (numbers, booleans, comma
//! separated lists, `Option`, unit enum variants), see [lenient].
//!
//! With the `cicada` feature, `cicada://filesystem/path.yaml?env=a+b`
//! loads a file from Cicada interpolated with the environments, and
//! `cicada://.env?env=a+b` the environments themselves as an env
//! file; the loader is re-exported as `cicada`.

use std::path::{Path, PathBuf};

use colored::Colorize;
use indexmap::IndexMap;
use serde::de::DeserializeOwned;

mod env_file;
mod error;
mod includes;
mod interpolate;
pub mod lenient;
mod load;
mod merge;

pub use env_file::{
  EnvFileError, is_env_file, parse_env_file, parse_env_file_object,
};
pub use error::{
  Error, deserialize_final, redact_serde_error, value_type,
};
pub use interpolate::*;
pub use merge::{merge_config, merge_objects};

/// The Cicada loader behind `cicada:` paths, so an application
/// reaches its background (`cicada::spawn`, `cicada::on_change`,
/// `cicada::subscribe`) and direct loads (`cicada::load_env_as`)
/// without depending on the crate itself.
///
/// Versioning: the loader's API is part of this crate's API. A
/// `cicada_loader` minor (`0.x`) bump ships as a `mogh_config`
/// major release; a loader patch bump stays a patch release.
#[cfg(feature = "cicada")]
pub use cicada_loader as cicada;

pub type Result<T> = ::core::result::Result<T, Error>;

/// Compiles the README's examples, so they keep up with the API.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

/// The key deduping a file reached by several paths (as given,
/// through a directory scan, an include, a symlink): its canonical
/// path. A cicada source is its own key.
fn dedupe_key(path: &Path) -> PathBuf {
  if load::is_cicada_path(path) {
    return path.to_path_buf();
  }
  path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// Set the configuration for loading config files.
pub struct ConfigLoader<'outer, 'inner> {
  /// Paths to either files or directories
  /// to include in the final configuration.
  ///
  /// Path coming later in the array (higher index) will override
  /// configuration in earlier paths.
  pub paths: &'outer [&'inner Path],
  /// Wilcard patterns to match file names in given directories.
  ///
  /// Patterns coming later in the array (higher index) will override
  /// configuration added by earlier patterns, however this is
  /// only relavant within an individual directory. Later `paths`
  /// and later includes will still have higher priority. A file
  /// matching several patterns takes the priority of the last one,
  /// so `["*config.*", "*config.local.*"]` applies
  /// `core.config.local.toml` over `core.config.toml`.
  ///
  /// A pattern which doesn't compile is an error
  /// ([Error::InvalidWildcard]). With no patterns, a directory scan
  /// loads every file in it except env files.
  pub match_wildcards: &'outer [&'inner str],
  /// The file name to search for `.include` file.
  ///
  /// Each line of the include file is a path (file or directory)
  /// to load after the directory's own files. Includes are applied
  /// in the order listed, recursively, and later includes override
  /// earlier ones. Every include overrides the directory's own
  /// files, so a directory can include shared defaults which are
  /// then refined by later includes. A `cicada:` line is a source
  /// like a `cicada:` path (an error without the `cicada` feature).
  pub include_file_name: &'static str,
  /// Whether to merge nested config objects.
  /// Otherwise, the object will be replaced at
  /// the top-level key by the highest priority config file
  /// in which it is specified.
  ///
  /// When merging, a `null` (a yaml section with every line
  /// commented out) keeps the object, and any other value replaces
  /// it (the final deserialization reports one the config type
  /// can't take): a source is never dropped over a type conflict.
  pub merge_nested: bool,
  /// Whether to extend array in configuration files.
  /// Otherwise, the array will be replaced at
  /// the top-level key by the highest priority config file
  /// in which it is specified.
  ///
  /// When extending, a `null` adds nothing, an env file's comma
  /// separated value (`HOSTS=b,c`) adds its entries, and any other
  /// value replaces the array.
  pub extend_array: bool,
  /// Print some extra information on configuation load.
  ///
  /// Note. This is different than application level log level.
  pub debug_print: bool,
}

impl ConfigLoader<'_, '_> {
  pub fn load<T: DeserializeOwned>(self) -> Result<T> {
    let ConfigLoader {
      paths,
      match_wildcards,
      include_file_name,
      merge_nested,
      extend_array,
      debug_print,
    } = self;

    if debug_print {
      println!(
        "{}: {}: {paths:?}",
        "DEBUG".cyan(),
        "Config paths".dimmed()
      );
    }

    // A pattern which doesn't compile is an error: dropping it
    // would widen the filter (to every file, with none left).
    let wildcards = match_wildcards
      .iter()
      .map(|&wc| {
        wildcard::Wildcard::new(wc.as_bytes()).map_err(|e| {
          Error::InvalidWildcard {
            pattern: wc.to_string(),
            message: e.to_string(),
          }
        })
      })
      .collect::<Result<Vec<_>>>()?;

    if debug_print {
      println!(
        "{}: {}: {match_wildcards:?}",
        "DEBUG".cyan(),
        "Config wildcards".dimmed()
      );
    }

    // The files to load in priority order, by the canonical path
    // (so one file reached as given and through a directory scan is
    // loaded once), each loaded from the path it was found at,
    // which names its type (`app.env` may link to a file without
    // the extension).
    let mut all_files = IndexMap::<PathBuf, PathBuf>::new();
    // If the same file comes up again later on, it should be
    // removed and reinserted so it maintains higher priority,
    // keeping a name its type is known by: a scan finding the
    // target of a listed `app.env` link as `secret` must not
    // replace the name the file can be parsed by.
    let mut push = |key: PathBuf, path: PathBuf| {
      let path = match all_files.shift_remove(&key) {
        Some(prev)
          if !load::has_config_type(&path)
            && load::has_config_type(&prev) =>
        {
          prev
        }
        _ => path,
      };
      all_files.insert(key, path);
    };

    for &path in paths {
      // Cicada paths shortcut to all_files.
      #[cfg(feature = "cicada")]
      if load::is_cicada_path(path) {
        push(path.to_path_buf(), path.to_path_buf());
        continue;
      }

      #[cfg(not(feature = "cicada"))]
      if load::is_cicada_path(path) {
        return Err(Error::CicadaFeatureDisabled {
          path: path.to_path_buf(),
        });
      }

      let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(e) => {
          if debug_print {
            println!(
              "{}: {}: {path:?} | {e:?}",
              "DEBUG".cyan(),
              "Skipping Path".dimmed()
            );
          }
          continue;
        }
      };

      if metadata.is_dir() {
        let mut files = Vec::new();
        // Guards against include cycles (A includes B includes A,
        // or a directory including itself).
        let mut visiting = std::collections::HashSet::new();
        // Files come back in priority order (later overrides earlier).
        load::load_config_files(
          &mut files,
          &mut visiting,
          path,
          &wildcards,
          include_file_name,
          debug_print,
        )?;
        for path in files {
          push(dedupe_key(&path), path);
        }
      } else if metadata.is_file() {
        push(dedupe_key(path), path.to_path_buf());
      }
    }
    let all_files = all_files.into_values().collect::<Vec<_>>();
    if debug_print {
      println!(
        "{}: {}: {all_files:?}",
        "DEBUG".cyan(),
        "Found Files".dimmed()
      );
    }
    load::load_parse_config_files(
      &all_files,
      merge_nested,
      extend_array,
    )
  }
}
