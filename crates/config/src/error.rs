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
  static QUOTED: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#""(?:[^"\\]|\\.)*"|`[^`]*`"#).unwrap()
  });
  QUOTED
    .replace_all(&e.to_string(), "[redacted]")
    .into_owned()
}

/// Deserialize the merged config into the final type, mapping
/// failures to [Error::ParseFinalJson] with the path of the
/// offending field and the type found there, never its value.
pub fn deserialize_final<T: DeserializeOwned>(
  value: &serde_json::Value,
) -> crate::Result<T> {
  serde_path_to_error::deserialize(value).map_err(|e| {
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

  #[error("Failed to parse toml file at {path} | {e:?}")]
  ParseToml { e: toml::de::Error, path: PathBuf },

  #[error("Failed to parse yaml file at {path} | {e:?}")]
  ParseYaml {
    e: serde_yaml_ng::Error,
    path: PathBuf,
  },

  #[error("Failed to parse json file at {path} | {e:?}")]
  ParseJson { e: serde_json::Error, path: PathBuf },

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
