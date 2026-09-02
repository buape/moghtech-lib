use std::{
  fs::File,
  io::Read,
  path::{Path, PathBuf},
};

use colored::Colorize;
use serde::de::DeserializeOwned;

use crate::{
  Error, Result, includes::IncludesLoader, interpolate_env_and_shell,
  merge::merge_objects,
};

pub fn load_config_files(
  // stores index of matching keyword as well as path
  files: &mut Vec<(usize, PathBuf)>,
  path: &Path,
  keywords: &[wildcard::Wildcard],
  include_file_name: &'static str,
  debug_print: bool,
) {
  // File base case.
  if path.is_file() {
    files.push((0, path.to_path_buf()));
    return;
  }

  if !path.is_dir() {
    return;
  }

  let Ok(folder) = path.canonicalize() else {
    return;
  };
  let Ok(read_dir) = std::fs::read_dir(&folder) else {
    return;
  };

  // Collect any config files in the current dir.
  for dir_entry in read_dir.flatten() {
    let path = dir_entry.path();
    let Ok(metadata) = dir_entry.metadata() else {
      continue;
    };
    if metadata.is_file() {
      let file_name = dir_entry.file_name();
      let Some(file_name) = file_name.to_str() else {
        continue;
      };
      // Ensure file name matches a wildcard keyword
      let index = if keywords.is_empty() {
        0
      } else if let Some(index) = keywords
        .iter()
        .position(|wc| wc.is_match(file_name.as_bytes()))
      {
        // actual config keyword matches will have higher priority than
        // when files are added via the base case.
        index + 1
      } else {
        continue;
      };
      let Ok(path) = path.canonicalize() else {
        continue;
      };
      files.push((index, path));
    }
  }

  // Collect any paths specified in 'includes'
  let includes =
    IncludesLoader::init(&folder, include_file_name).finish();
  if includes.is_empty() {
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
      &path,
      keywords,
      include_file_name,
      debug_print,
    );
  }
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
pub fn load_parse_config_files<T: DeserializeOwned>(
  files: &[PathBuf],
  merge_nested: bool,
  extend_array: bool,
) -> Result<T> {
  let mut target = serde_json::Map::new();

  for file in files {
    #[cfg(feature = "cicada")]
    let source = if let Some((file, environments)) =
      parse_cicada_path(file)
    {
      let contents = match cicada_loader::load(&file, environments) {
        Ok(contents) => contents,
        Err(e) => {
          println!(
            "{}: Cicada configuration at '{}' failed to load | {e:?}",
            "ERROR".red(),
            file.display(),
          );
          continue;
        }
      };
      parse_config_contents(&file, &contents)
    } else {
      load_parse_config_file(file)
    };

    #[cfg(not(feature = "cicada"))]
    let source = load_parse_config_file(file);

    let source = match source {
      Ok(source) => source,
      Err(e) => {
        println!("{}: {e}", "WARN".yellow());
        continue;
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

  let json = serde_json::to_string(&target)
    .map_err(|e| Error::SerializeJson { e })?;
  let interpolated = interpolate_env_and_shell(&json);

  serde_json::from_str(&interpolated)
    .map_err(|e| Error::ParseFinalJson { e })
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

/// Parses config contents
pub fn parse_config_contents<T: DeserializeOwned>(
  file: &Path,
  contents: &str,
) -> Result<T> {
  let extension = file
    .extension()
    .and_then(|e| e.to_str())
    .map(str::to_ascii_lowercase);
  let config = match extension.as_deref() {
    Some("toml") => {
      toml::from_str(contents).map_err(|e| Error::ParseToml {
        e,
        path: file.to_path_buf(),
      })?
    }
    Some("yaml") | Some("yml") => serde_yaml_ng::from_str(contents)
      .map_err(|e| Error::ParseYaml {
      e,
      path: file.to_path_buf(),
    })?,
    Some("json") => serde_json::from_str(contents).map_err(|e| {
      Error::ParseJson {
        e,
        path: file.to_path_buf(),
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
