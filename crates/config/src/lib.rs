//! # Mogh Config
//!
//! This library is used to parse Core, Periphery, and CLI config files.
//! It supports interpolating in environment variables (only '${VAR}' syntax),
//! as well as merging together multiple files into a final configuration object.
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
//! file; the loader is re-exported as [cicada].

use std::path::Path;

use colored::Colorize;
use indexmap::IndexSet;
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
  /// and later includes will still have higher priority.
  pub match_wildcards: &'outer [&'inner str],
  /// The file name to search for `.include` file.
  ///
  /// Each line of the include file is a path (file or directory)
  /// to load after the directory's own files. Includes are applied
  /// in the order listed, recursively, and later includes override
  /// earlier ones. Every include overrides the directory's own
  /// files, so a directory can include shared defaults which are
  /// then refined by later includes.
  pub include_file_name: &'static str,
  /// Whether to merge nested config objects.
  /// Otherwise, the object will be replaced at
  /// the top-level key by the highest priority config file
  /// in which it is specified.
  pub merge_nested: bool,
  /// Whether to extend array in configuration files.
  /// Otherwise, the array will be replaced at
  /// the top-level key by the highest priority config file
  /// in which it is specified.
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

    let mut wildcards = Vec::with_capacity(match_wildcards.len());

    for &wc in match_wildcards {
      match wildcard::Wildcard::new(wc.as_bytes()) {
        Ok(wc) => wildcards.push(wc),
        Err(e) => {
          println!(
            "{}: Keyword '{}' is invalid wildcard | {e:?}",
            "ERROR".red(),
            wc.bold(),
          );
        }
      }
    }

    if debug_print {
      println!(
        "{}: {}: {match_wildcards:?}",
        "DEBUG".cyan(),
        "Config wildcards".dimmed()
      );
    }

    let mut all_files = IndexSet::new();

    for &path in paths {
      // Cicada paths shortcut to all_files.
      // Note. Must compare against the path as a string,
      // Path::starts_with compares whole components and misses
      // the `cicada:some/path` (no slash) form.
      #[cfg(feature = "cicada")]
      if path.to_string_lossy().starts_with("cicada:") {
        let path = path.to_path_buf();
        // If the same path comes up again later on, it should be removed and
        // reinserted so it maintains higher priority.
        all_files.shift_remove(&path);
        all_files.insert(path);
        continue;
      }

      #[cfg(not(feature = "cicada"))]
      if path.to_string_lossy().starts_with("cicada:") {
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
        );
        for path in files {
          // If the same file comes up again later on, it should be
          // removed and reinserted so it maintains higher priority.
          all_files.shift_remove(&path);
          all_files.insert(path);
        }
      } else if metadata.is_file() {
        let path = path.to_path_buf();
        // If the same path comes up again later on, it should be removed and
        // reinserted so it maintains higher priority.
        all_files.shift_remove(&path);
        all_files.insert(path);
      }
    }
    if debug_print {
      println!(
        "{}: {}: {all_files:?}",
        "DEBUG".cyan(),
        "Found Files".dimmed()
      );
    }
    load::load_parse_config_files(
      &all_files.into_iter().collect::<Vec<_>>(),
      merge_nested,
      extend_array,
    )
  }
}
