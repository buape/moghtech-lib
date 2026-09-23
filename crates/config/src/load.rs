use std::{
  collections::HashSet,
  fs::File,
  io::Read,
  path::{Path, PathBuf},
};

use colored::Colorize;
use serde::de::DeserializeOwned;

use crate::{
  Error, Result,
  env_file::{is_env_file, parse_env_file_object},
  error::{redact_serde_error, redact_toml_error, redact_yaml_error},
  includes::IncludesLoader,
  interpolate_value,
  merge::merge_objects,
};

/// Collects config files under `path` into `files` in priority
/// order (later overrides earlier):
///
/// 1. The directory's own matching files, ordered by the matched
///    wildcard (later wildcards override earlier), then by name.
/// 2. Each path listed in the directory's include file, in the
///    order listed, recursively. Later includes override earlier
///    ones, and every include overrides the directory's own files.
///
/// A path included more than once (eg two includes sharing a
/// common include) is emitted each time, so its last occurrence
/// takes the highest priority. Only true recursion (a directory
/// including itself, directly or indirectly) is cut.
pub fn load_config_files(
  files: &mut Vec<PathBuf>,
  // canonical directories on the current include stack
  visiting: &mut HashSet<PathBuf>,
  path: &Path,
  keywords: &[wildcard::Wildcard],
  include_file_name: &'static str,
  debug_print: bool,
) {
  // File base case.
  if path.is_file() {
    files.push(path.to_path_buf());
    return;
  }

  if !path.is_dir() {
    return;
  }

  let Ok(folder) = path.canonicalize() else {
    return;
  };
  if !visiting.insert(folder.clone()) {
    if debug_print {
      println!(
        "{}: {}: {folder:?}",
        "DEBUG".cyan(),
        "Skipping include cycle".dimmed()
      );
    }
    return;
  }
  let Ok(read_dir) = std::fs::read_dir(&folder) else {
    return;
  };

  // Collect any config files in the current dir,
  // with the index of the matched wildcard.
  let mut dir_files = Vec::new();
  for dir_entry in read_dir.flatten() {
    let path = dir_entry.path();
    // Follows symlinks (eg Kubernetes ConfigMap mounts),
    // unlike DirEntry::metadata.
    let Ok(metadata) = std::fs::metadata(&path) else {
      continue;
    };
    if metadata.is_file() {
      let file_name = dir_entry.file_name();
      let Some(file_name) = file_name.to_str() else {
        continue;
      };
      // The include file is never a config file.
      if file_name == include_file_name {
        continue;
      }
      // An env file next to the config (a compose `.env`) is only
      // a config source when a wildcard asks for it, or when it is
      // listed as a path itself.
      if keywords.is_empty() && is_env_file(&path) {
        if debug_print {
          println!(
            "{}: {}: {path:?} (match it with a wildcard to load it)",
            "DEBUG".cyan(),
            "Skipping env file".dimmed()
          );
        }
        continue;
      }
      // Ensure file name matches a wildcard keyword
      let index = if keywords.is_empty() {
        0
      } else if let Some(index) = keywords
        .iter()
        .position(|wc| wc.is_match(file_name.as_bytes()))
      {
        index
      } else {
        continue;
      };
      let Ok(path) = path.canonicalize() else {
        continue;
      };
      dir_files.push((index, path));
    }
  }
  // Wildcard priority only applies within this directory.
  dir_files.sort();
  files.extend(dir_files.into_iter().map(|(_, path)| path));

  // Collect any paths specified in 'includes'
  let includes =
    IncludesLoader::init(&folder, include_file_name).finish();
  if includes.is_empty() {
    visiting.remove(&folder);
    return;
  }

  if debug_print {
    println!(
      "{}: {}: {includes:?}",
      "DEBUG".cyan(),
      format_args!(
        "{} {path:?} {}",
        "Config Path".dimmed(),
        "Includes".dimmed()
      ),
    );
  }

  // Add these paths as well recursively.
  for path in includes {
    load_config_files(
      files,
      visiting,
      &path,
      keywords,
      include_file_name,
      debug_print,
    );
  }
  visiting.remove(&folder);
}

/// Splits a cicada path (`cicada://...`, `cicada:/...` or `cicada:...`)
/// into the node path and the list of environments.
/// Returns `None` if the path is not a cicada path.
///
/// Environments are given as a query suffix, using `+` as the
/// list separator (comma is reserved for splitting multiple paths):
///
/// - `cicada://filesystem/config.yaml` -> no environments
/// - `cicada://filesystem/config.yaml?env=prod` -> `["prod"]`
/// - `cicada://filesystem/config.yaml?env=prod+us-east` -> `["prod", "us-east"]`
/// - `cicada://filesystem/config.yaml?env=prod&env=us-east` -> `["prod", "us-east"]`
/// - `cicada://.env?env=prod+us-east` -> the environments themselves,
///   as an env file (the loader's reserved `.env` path)
#[cfg(feature = "cicada")]
pub fn parse_cicada_path(
  path: &Path,
) -> Option<(PathBuf, Vec<String>)> {
  let path_str = path.to_string_lossy();
  let path =
    path_str.strip_prefix("cicada:")?.trim_start_matches('/');
  let Some((path, query)) = path.split_once('?') else {
    return Some((PathBuf::from(path), Vec::new()));
  };
  let environments = query
    .split('&')
    .filter_map(|pair| {
      let (key, value) = pair.split_once('=')?;
      matches!(
        key.trim(),
        "env" | "envs" | "environment" | "environments"
      )
      .then_some(value)
    })
    .flat_map(|value| value.split('+'))
    .map(str::trim)
    .filter(|env| !env.is_empty())
    .map(String::from)
    .collect();
  Some((PathBuf::from(path), environments))
}

/// loads multiple config files.
///
/// If cicada feature is enabled, the files
/// can be cicada paths (`cicada://filesystem/config.yaml?env=prod+us-east`),
/// provided user configures `CICADA_...` env vars.
/// See [parse_cicada_path] for the environment syntax.
///
/// A local file which fails to open or parse is reported and
/// skipped. A cicada source which fails to load or parse is an
/// error ([Error::CicadaLoad], or the parse error): skipping it
/// would start the app with defaults where the operator expects
/// their configuration.
///
/// Each local toml / yaml / json source is interpolated (`${VAR}`,
/// `$(cmd)`) as it is parsed. Env file sources and every cicada
/// source are not: their values are secrets taken verbatim, never
/// templates (Core interpolated a cicada file's `[[SECRET]]`
/// placeholders already), and a secret must not be able to run a
/// command in the process reading it.
pub fn load_parse_config_files<T: DeserializeOwned>(
  files: &[PathBuf],
  merge_nested: bool,
  extend_array: bool,
) -> Result<T> {
  let mut target = serde_json::Map::new();

  for file in files {
    #[cfg(feature = "cicada")]
    let (source, interpolate) =
      if let Some((node, environments)) = parse_cicada_path(file) {
        // Never skipped, unlike a local file: eg. Core briefly
        // unreachable at an exit-on-change restart must not start
        // the app with its defaults.
        let contents = cicada_loader::load(&node, environments)
          .map_err(|e| Error::CicadaLoad {
            path: file.clone(),
            message: format!("{e:#}"),
          })?;
        let source = parse_config_contents(&node, &contents)?;
        (Ok(source), false)
      } else {
        (load_parse_config_file(file), !is_env_file(file))
      };

    #[cfg(not(feature = "cicada"))]
    let (source, interpolate) =
      (load_parse_config_file(file), !is_env_file(file));

    let source: serde_json::Map<String, serde_json::Value> =
      match source {
        Ok(source) => source,
        Err(e) => {
          println!("{}: {e}", "WARN".yellow());
          continue;
        }
      };

    // Interpolate each string leaf (and key) individually, rather
    // than the serialized document, so values containing quotes,
    // backslashes or newlines cannot break or inject into the json.
    let source = if !interpolate {
      source
    } else {
      let mut source = serde_json::Value::Object(source);
      interpolate_value(&mut source);
      match source {
        serde_json::Value::Object(source) => source,
        _ => unreachable!("interpolation keeps the value an object"),
      }
    };

    target = match merge_objects(
      target.clone(),
      source,
      merge_nested,
      extend_array,
    ) {
      Ok(target) => target,
      Err(e) => {
        eprintln!("{}: {e}", "WARN".yellow());
        target
      }
    };
  }

  crate::error::deserialize_final(&serde_json::Value::Object(target))
}

/// Loads and parses a single config file
pub fn load_parse_config_file<T: DeserializeOwned>(
  file: &Path,
) -> Result<T> {
  let mut file_handle =
    File::open(file).map_err(|e| Error::FileOpen {
      e,
      path: file.to_path_buf(),
    })?;
  let mut contents = String::new();
  file_handle.read_to_string(&mut contents).map_err(|e| {
    Error::ReadFileContents {
      e,
      path: file.to_path_buf(),
    }
  })?;
  parse_config_contents(file, &contents)
}

/// Parses config contents by the file's name: toml, yaml / yml,
/// json, or an env file (`.env`, `*.env`, see
/// [parse_env_file_object]): a flat set of `NAME=value` entries
/// with names lowercased and dots nesting, so `DB_PASSWORD=x` fills
/// a `db_password` field and `DATABASE.ADDRESS=y` fills
/// `database.address`, the way `envy` would read the process
/// environment. A name with an empty segment (`.dockerconfigjson`)
/// stays one flat key.
pub fn parse_config_contents<T: DeserializeOwned>(
  file: &Path,
  contents: &str,
) -> Result<T> {
  if is_env_file(file) {
    let object = parse_env_file_object(contents).map_err(|e| {
      Error::ParseEnvFile {
        e,
        path: file.to_path_buf(),
      }
    })?;
    return serde_json::from_value(serde_json::Value::Object(object))
      .map_err(|e| Error::ParseJson {
        path: file.to_path_buf(),
        message: redact_serde_error(&e),
      });
  }
  let extension = file
    .extension()
    .and_then(|e| e.to_str())
    .map(str::to_ascii_lowercase);
  let config = match extension.as_deref() {
    Some("toml") => {
      toml::from_str(contents).map_err(|e| Error::ParseToml {
        path: file.to_path_buf(),
        message: redact_toml_error(&e, contents),
      })?
    }
    Some("yaml") | Some("yml") => serde_yaml_ng::from_str(contents)
      .map_err(|e| Error::ParseYaml {
      path: file.to_path_buf(),
      message: redact_yaml_error(&e),
    })?,
    Some("json") => serde_json::from_str(contents).map_err(|e| {
      Error::ParseJson {
        path: file.to_path_buf(),
        message: redact_serde_error(&e),
      }
    })?,
    Some(_) | None => {
      return Err(Error::UnsupportedFileType {
        path: file.to_path_buf(),
      });
    }
  };
  Ok(config)
}

#[cfg(all(test, feature = "cicada"))]
mod tests {
  use super::*;

  #[test]
  fn parses_cicada_paths() {
    for prefix in ["cicada:", "cicada:/", "cicada://"] {
      let full = PathBuf::from(format!(
        "{prefix}filesystem/path/config.yaml?env=prod+us-east"
      ));
      let (path, envs) = parse_cicada_path(&full).unwrap();
      assert_eq!(path, PathBuf::from("filesystem/path/config.yaml"));
      assert_eq!(envs, vec!["prod", "us-east"]);
    }
    let (path, envs) = parse_cicada_path(Path::new(
      "cicada://fs/config.yaml?env=a&env=b",
    ))
    .unwrap();
    assert_eq!(path, PathBuf::from("fs/config.yaml"));
    assert_eq!(envs, vec!["a", "b"]);
    let (path, envs) =
      parse_cicada_path(Path::new("cicada://fs/config.yaml"))
        .unwrap();
    assert_eq!(path, PathBuf::from("fs/config.yaml"));
    assert!(envs.is_empty());
    assert!(
      parse_cicada_path(Path::new("/etc/config.yaml")).is_none()
    );
  }
}
