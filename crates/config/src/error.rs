use std::{path::PathBuf, sync::LazyLock};

use serde::de::DeserializeOwned;

/// The json type name of a value, for error messages
/// which must not include the value itself.
pub fn value_type(value: &serde_json::Value) -> &'static str {
  match value {
    serde_json::Value::Null => "null",
    serde_json::Value::Bool(_) => "boolean",
    serde_json::Value::Number(_) => "number",
    serde_json::Value::String(_) => "string",
    serde_json::Value::Array(_) => "array",
    serde_json::Value::Object(_) => "object",
  }
}

/// Redacts values from a serde error message, since config values
/// may be secrets and errors are logged: double quoted strings
/// (`invalid type: string "hunter2"`) and backticked tokens
/// (`invalid type: integer `4829``, `unknown variant `x``).
pub fn redact_serde_error(e: &serde_json::Error) -> String {
  redact_message(&e.to_string())
}

/// [redact_serde_error] for the message of any parser.
fn redact_message(message: &str) -> String {
  static QUOTED: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#""(?:[^"\\]|\\.)*"|`[^`]*`"#).unwrap()
  });
  QUOTED.replace_all(message, "[redacted]").into_owned()
}

/// The message of a toml error, redacted like [redact_serde_error],
/// with the line and column of its span in `contents`. Not the
/// error's `Display`, which quotes the offending line, nor its
/// `Debug`, which includes all of `contents`.
pub(crate) fn redact_toml_error(
  e: &toml::de::Error,
  contents: &str,
) -> String {
  let message = redact_message(e.message().trim_end());
  let Some((line, column)) =
    e.span().and_then(|span| line_column(contents, span.start))
  else {
    return message;
  };
  format!("{message} at line {line} column {column}")
}

/// The yaml error message (with its line and column), redacted like
/// [redact_serde_error].
pub(crate) fn redact_yaml_error(e: &serde_yaml_ng::Error) -> String {
  redact_message(&e.to_string())
}

/// The 1 based line and column (in chars) of a byte offset.
fn line_column(
  contents: &str,
  offset: usize,
) -> Option<(usize, usize)> {
  let before = contents.get(..offset)?;
  let line = before.matches('\n').count() + 1;
  let column = before
    .rsplit('\n')
    .next()
    .map_or(0, |line| line.chars().count())
    + 1;
  Some((line, column))
}

/// Deserialize the merged config into the final type, mapping
/// failures to [Error::ParseFinalJson] with the path of the
/// offending field and the type found there, never its value.
/// String values coerce into the requested type the way `envy`
/// reads the process environment (numbers, booleans, comma
/// separated lists, `Option`, unit enum variants), see
/// [crate::lenient].
pub fn deserialize_final<T: DeserializeOwned>(
  value: &serde_json::Value,
) -> crate::Result<T> {
  serde_path_to_error::deserialize(crate::lenient::Lenient(
    value.clone(),
  ))
  .map_err(|e| {
    let path = e.path();
    let found = value_at(value, path).map(value_type);
    Error::ParseFinalJson {
      path: path.to_string(),
      found,
      message: redact_serde_error(e.inner()),
    }
  })
}

/// The value at a serde error path, if the path resolves.
fn value_at<'a>(
  mut value: &'a serde_json::Value,
  path: &serde_path_to_error::Path,
) -> Option<&'a serde_json::Value> {
  use serde_path_to_error::Segment;
  for segment in path.iter() {
    value = match segment {
      Segment::Map { key } | Segment::Enum { variant: key } => {
        value.get(key)?
      }
      // A sequence split out of a string (see [crate::lenient]):
      // the string is what was found there.
      Segment::Seq { .. } if value.is_string() => return Some(value),
      Segment::Seq { index } => value.get(index)?,
      Segment::Unknown => return None,
    };
  }
  Some(value)
}

/// Config errors never include config values,
/// which may be secrets, only keys and types.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  #[error(
    "Types on field {key} do not match | got {found}, expected object"
  )]
  ObjectFieldTypeMismatch {
    key: String,
    /// The json type name of the value found.
    found: &'static str,
  },

  #[error(
    "Types on field {key} do not match | got {found}, expected array"
  )]
  ArrayFieldTypeMismatch {
    key: String,
    /// The json type name of the value found.
    found: &'static str,
  },

  #[error("Failed to open file at {path} | {e:?}")]
  FileOpen { e: std::io::Error, path: PathBuf },

  #[error("Failed to read contents of file at {path} | {e:?}")]
  ReadFileContents { e: std::io::Error, path: PathBuf },

  /// The parser's error is not kept: it quotes the file.
  #[error("Failed to parse toml file at {path} | {message}")]
  ParseToml {
    path: PathBuf,
    /// The parser's message with values redacted
    /// ([redact_serde_error]), and the line and column.
    message: String,
  },

  /// The parser's error is not kept, see [Error::ParseToml].
  #[error("Failed to parse yaml file at {path} | {message}")]
  ParseYaml {
    path: PathBuf,
    /// The parser's message with values redacted
    /// ([redact_serde_error]), and the line and column.
    message: String,
  },

  /// The parser's error is not kept, see [Error::ParseToml].
  #[error("Failed to parse json file at {path} | {message}")]
  ParseJson {
    path: PathBuf,
    /// The parser's message with values redacted
    /// ([redact_serde_error]), and the line and column.
    message: String,
  },

  /// See [crate::parse_env_file]; the message names the line and
  /// what was expected, never a value.
  #[error("Failed to parse env file at {path} | {e}")]
  ParseEnvFile {
    e: crate::env_file::EnvFileError,
    path: PathBuf,
  },

  #[error("Unsupported file type at {path}")]
  UnsupportedFileType { path: PathBuf },

  /// See [deserialize_final]. The message has values redacted
  /// ([redact_serde_error]); `found` is the json type at `path`.
  #[error(
    "Failed to parse merged config into final type at '{path}' | found {} | {message}",
    found.unwrap_or("nothing")
  )]
  ParseFinalJson {
    /// Dot separated path to the offending field, `.` for the root.
    path: String,
    /// The json type name found at `path`, if it resolves.
    found: Option<&'static str>,
    message: String,
  },

  #[error("Failed to serialize config to json string | {e:?}")]
  SerializeJson { e: serde_json::Error },

  #[error("Failed to read directory at {path:?}")]
  ReadDir { path: PathBuf, e: std::io::Error },

  #[error("Failed to get file handle for file in directory {path:?}")]
  DirFile { e: std::io::Error, path: PathBuf },

  #[error("Failed to get file name for file at {path:?}")]
  GetFileName { path: PathBuf },

  #[error("Failed to get metadata for path {path:?} | {e:?}")]
  ReadPathMetaData { path: PathBuf, e: std::io::Error },

  #[error("Parsed value is not object")]
  ValueIsNotObject,

  /// A [crate::ConfigLoader::match_wildcards] pattern which doesn't
  /// compile. An error rather than a dropped pattern: dropping it
  /// widens the filter (with none left, a directory scan loads every
  /// file in it).
  #[error("Config wildcard '{pattern}' is invalid | {message}")]
  InvalidWildcard { pattern: String, message: String },

  /// A `cicada:` config path (listed in the paths, or in an include
  /// file), without the `cicada` feature to load it. An error rather
  /// than a skipped path: the app would start with defaults where
  /// the operator expects their configuration.
  #[error(
    "Config path {path:?} is a cicada path, which needs the 'cicada' feature of mogh_config to be enabled"
  )]
  CicadaFeatureDisabled { path: PathBuf },

  /// A `cicada:` config path (listed in the paths, or in an include
  /// file) which failed to load from Cicada (Core unreachable, the
  /// device not onboarded or not granted the environments, the file
  /// missing, ...). An error rather than a skipped path, like
  /// [Error::CicadaFeatureDisabled].
  #[error("Failed to load cicada config at {path:?} | {message}")]
  CicadaLoad {
    /// The path as listed, `cicada://...`.
    path: PathBuf,
    /// The loader's error chain.
    message: String,
  },
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn redacts_quoted_values_from_serde_errors() {
    let err = serde_json::from_value::<u16>(serde_json::json!(
      "hunter2 \"quoted\" secret"
    ))
    .unwrap_err();
    let message = redact_serde_error(&err);
    assert!(!message.contains("hunter2"), "{message}");
    assert!(
      message.contains("invalid type: string [redacted]"),
      "{message}"
    );
    assert!(message.contains("expected u16"));
    // Numbers are formatted in backticks by serde.
    let err =
      serde_json::from_value::<String>(serde_json::json!(482913))
        .unwrap_err();
    let message = redact_serde_error(&err);
    assert!(!message.contains("482913"), "{message}");
  }

  /// Parse errors are returned to the app, which logs them: a
  /// `cicada:` file carries the secrets Core interpolated into it.
  #[test]
  fn parse_errors_redact_values_and_name_the_line() {
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct Typed {
      port: u16,
    }
    let assert_redacted = |err: Error, location: Option<&str>| {
      for message in [err.to_string(), format!("{err:?}")] {
        assert!(!message.contains("hunter2"), "{message}");
        if let Some(location) = location {
          assert!(message.contains(location), "{message}");
        }
      }
    };
    let parse = |file: &str, contents: &str| {
      crate::load::parse_config_contents::<serde_json::Value>(
        std::path::Path::new(file),
        contents,
      )
      .unwrap_err()
    };
    let parse_typed = |file: &str, contents: &str| {
      crate::load::parse_config_contents::<Typed>(
        std::path::Path::new(file),
        contents,
      )
      .unwrap_err()
    };

    let err = parse("a.toml", "secret = \"hunter2\"\n[[broken");
    assert!(matches!(err, Error::ParseToml { .. }), "{err:?}");
    assert_redacted(err, Some("at line 2 column"));
    // The column counts chars, not bytes.
    let err = parse("a.toml", "k = \"é\" hunter2");
    assert_redacted(err, Some("at line 1 column 9"));
    let err = parse_typed("a.toml", "port = \"hunter2\"");
    assert_redacted(err, Some("expected u16"));

    let err = parse("a.yaml", "secret: \"hunter2\"\nbroken: [");
    assert!(matches!(err, Error::ParseYaml { .. }), "{err:?}");
    assert_redacted(err, Some("at line"));
    let err = parse_typed("a.yaml", "port: hunter2");
    assert_redacted(err, Some("expected u16"));

    let err = parse("a.json", "{\"secret\": \"hunter2\",");
    assert!(matches!(err, Error::ParseJson { .. }), "{err:?}");
    assert_redacted(err, Some("at line 1 column"));
    let err = parse_typed("a.json", "{\"port\": \"hunter2\"}");
    assert_redacted(err, Some("expected u16"));

    let err = parse_typed(".env", "PORT=hunter2");
    assert!(matches!(err, Error::ParseJson { .. }), "{err:?}");
    assert_redacted(err, Some("expected u16"));
  }

  #[test]
  fn deserialize_final_reports_path_and_type_not_value() {
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct Server {
      port: u16,
    }
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct Config {
      server: Server,
      pins: Vec<u8>,
    }
    let err = deserialize_final::<Config>(&serde_json::json!({
      "server": { "port": "hunter2secret" },
      "pins": [1, 2],
    }))
    .unwrap_err();
    let message = err.to_string();
    assert!(message.contains("at 'server.port'"), "{message}");
    assert!(message.contains("found string"), "{message}");
    assert!(message.contains("expected u16"), "{message}");
    assert!(!message.contains("hunter2secret"), "{message}");

    let err = deserialize_final::<Config>(&serde_json::json!({
      "server": { "port": 1 },
      "pins": [1, 70000],
    }))
    .unwrap_err();
    let message = err.to_string();
    assert!(message.contains("at 'pins[1]'"), "{message}");
    assert!(message.contains("found number"), "{message}");
    assert!(!message.contains("70000"), "{message}");
  }

  #[test]
  fn mismatch_errors_name_key_and_type_only() {
    let err = Error::ObjectFieldTypeMismatch {
      key: "field".into(),
      found: value_type(&serde_json::json!("secret")),
    };
    assert_eq!(
      err.to_string(),
      "Types on field field do not match | got string, expected object"
    );
    assert_eq!(value_type(&serde_json::json!(null)), "null");
    assert_eq!(value_type(&serde_json::json!([1])), "array");
  }
}
