//! Env file (`.env`) syntax as a configuration source: a flat set
//! of `NAME=value` entries, the format Cicada renders a stack of
//! secret environments in and the one dotenv files use.
//!
//! The grammar is Cicada's (a serialized secret export parses back
//! unchanged): `#` lines are comments, blank lines are skipped, an
//! `export ` prefix is accepted, and a value is unquoted (taken
//! literally to the end of the line, trimmed), single quoted
//! (literal) or double quoted with `\n` / `\r` / `\t` / `\"` / `\\`
//! escapes. Nothing is substituted inside a value: `${VAR}` and
//! `$(cmd)` are kept as written, since env file values are secrets
//! and never templates.
//!
//! As a configuration source ([parse_env_file_object]) names are
//! lowercased to match struct fields, and dots nest:
//! `DATABASE.ADDRESS=x` fills `database.address`, so a flat set of
//! secrets can populate a structured config. A name with an empty
//! segment (`.dockerconfigjson`, `A..B`) stays one flat key.

/// Where an env file failed to parse. The message never carries a
/// value, only what was expected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvFileError {
  /// 1-based line number.
  pub line: usize,
  pub message: String,
}

impl std::fmt::Display for EnvFileError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "line {}: {}", self.line, self.message)
  }
}

impl std::error::Error for EnvFileError {}

fn error(line: usize, message: impl Into<String>) -> EnvFileError {
  EnvFileError {
    line,
    message: message.into(),
  }
}

/// Parses an env file into `(name, value)` pairs in file order,
/// names as written. A name given twice is an error (which of the
/// two the author meant is anyone's guess).
pub fn parse_env_file(
  content: &str,
) -> Result<Vec<(String, String)>, EnvFileError> {
  Ok(
    parse_entries(content)?
      .into_iter()
      .map(|entry| (entry.name, entry.value))
      .collect(),
  )
}

/// Parses an env file into the configuration object it describes:
/// names lowercased (`DB_PASSWORD` is the field `db_password`),
/// dots nesting (`DATABASE.ADDRESS` is `database.address`), values
/// strings (the final deserialization coerces them).
///
/// A name with an empty segment cannot nest (`.dockerconfigjson`,
/// `A..B`, `A.`, `.`), so it is kept whole as one flat key,
/// lowercased (`.dockerconfigjson`, `a..b`): Cicada accepts such
/// secret names, and one of them must not fail the whole source.
///
/// Errors, with the line and both names involved: a name that is
/// both a value and an object (`DATABASE=x` next to
/// `DATABASE.ADDRESS=y`), and two spellings of one name (`Db` and
/// `DB`).
pub fn parse_env_file_object(
  content: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, EnvFileError>
{
  let mut object = serde_json::Map::new();
  // The entry which set each key (a value) or first nested under it
  // (an object), by its dotted path, to name both sides of a
  // conflict. A nested path never has an empty segment and a flat
  // key always does, so the two never share a path.
  let mut origins =
    std::collections::HashMap::<String, (String, usize)>::new();
  for entry in parse_entries(content)? {
    let name = entry.name.to_lowercase();
    let segments = if name.split('.').any(str::is_empty) {
      vec![name.as_str()]
    } else {
      name.split('.').collect::<Vec<_>>()
    };
    let (last, parents) =
      segments.split_last().expect("split yields one segment");
    let mut current = &mut object;
    for (depth, segment) in parents.iter().enumerate() {
      let path = segments[..=depth].join(".");
      let slot =
        current.entry(segment.to_string()).or_insert_with(|| {
          origins
            .insert(path.clone(), (entry.name.clone(), entry.line));
          serde_json::Value::Object(Default::default())
        });
      match slot {
        serde_json::Value::Object(map) => current = map,
        _ => {
          return Err(conflict(
            &entry,
            &origins[&path],
            format!("`{path}` is both a value and an object"),
          ));
        }
      }
    }
    if let Some(existing) = current.get(*last) {
      return Err(conflict(
        &entry,
        &origins[&name],
        if existing.is_object() {
          format!("`{name}` is both a value and an object")
        } else {
          // Exact duplicates were refused while parsing the entries.
          String::from("names are case insensitive")
        },
      ));
    }
    origins.insert(name.clone(), (entry.name.clone(), entry.line));
    current.insert(
      last.to_string(),
      serde_json::Value::String(entry.value),
    );
  }
  Ok(object)
}

/// A conflict between `entry` and the earlier entry `origin` (its
/// name and line), naming both.
fn conflict(
  entry: &Entry,
  (origin, origin_line): &(String, usize),
  message: String,
) -> EnvFileError {
  error(
    entry.line,
    format!(
      "`{}` conflicts with `{origin}` (line {origin_line}): {message}",
      entry.name
    ),
  )
}

struct Entry {
  line: usize,
  name: String,
  value: String,
}

fn parse_entries(content: &str) -> Result<Vec<Entry>, EnvFileError> {
  // A byte order mark (hand written on Windows) is not part of the
  // first name.
  let content = content.strip_prefix('\u{FEFF}').unwrap_or(content);
  let mut entries: Vec<Entry> = Vec::new();
  for (idx, raw) in content.lines().enumerate() {
    let number = idx + 1;
    let line = raw.trim();
    if line.is_empty() || line.starts_with('#') {
      continue;
    }
    // Real env files often carry `export NAME=value`.
    let line = line
      .strip_prefix("export ")
      .map(str::trim_start)
      .unwrap_or(line);
    let Some((name, value)) = line.split_once('=') else {
      return Err(error(
        number,
        "expected `NAME=value`, a `#` comment, or a blank line",
      ));
    };
    let name = name.trim();
    if name.is_empty() {
      return Err(error(number, "missing name before `=`"));
    }
    if entries.iter().any(|existing| existing.name == name) {
      return Err(error(
        number,
        format!("duplicate entry for `{name}`"),
      ));
    }
    entries.push(Entry {
      line: number,
      name: name.to_string(),
      value: parse_value(value.trim(), number)?,
    });
  }
  Ok(entries)
}

/// A value after `=`, already trimmed: unquoted (taken literally to
/// the end of the line), single quoted (literal), or double quoted
/// with escapes.
fn parse_value(
  value: &str,
  line: usize,
) -> Result<String, EnvFileError> {
  let mut chars = value.chars();
  match chars.next() {
    Some('"') => {
      let mut out = String::new();
      loop {
        match chars.next() {
          Some('\\') => match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some(c) => {
              return Err(error(
                line,
                format!("unsupported escape `\\{c}`"),
              ));
            }
            None => {
              return Err(error(
                line,
                "unterminated double quoted value",
              ));
            }
          },
          Some('"') => break,
          Some(c) => out.push(c),
          None => {
            return Err(error(
              line,
              "unterminated double quoted value",
            ));
          }
        }
      }
      if chars.next().is_some() {
        return Err(error(
          line,
          "unexpected content after closing quote",
        ));
      }
      Ok(out)
    }
    Some('\'') => {
      // Like Core: the value runs to the last quote, so `'it's'`
      // is `it's`.
      let rest = &value[1..];
      let Some(end) = rest.rfind('\'') else {
        return Err(error(line, "unterminated single quoted value"));
      };
      if !rest[end + 1..].is_empty() {
        return Err(error(
          line,
          "unexpected content after closing quote",
        ));
      }
      Ok(rest[..end].to_string())
    }
    _ => Ok(value.to_string()),
  }
}

/// Whether a config path is an env file: named `.env`, or with the
/// `env` extension (`app.env`). `Path::extension` is `None` for
/// `.env`, hence the file name check.
pub fn is_env_file(path: &std::path::Path) -> bool {
  let name = path
    .file_name()
    .and_then(|name| name.to_str())
    .unwrap_or_default();
  name == ".env"
    || path
      .extension()
      .and_then(|ext| ext.to_str())
      .is_some_and(|ext| ext.eq_ignore_ascii_case("env"))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_the_cicada_grammar() {
    let file = "\
# A comment
export DB_PASSWORD=hunter2
PORT = 8080

# The description of B
B=\"escaped\\nnewline \\\"quoted\\\" \\\\ #tag\"
SINGLE='it's literal ${NOT_EXPANDED}'
EMPTY=
UNQUOTED=$(not run) ${NOT_EXPANDED} # not a comment
";
    let entries = parse_env_file(file).unwrap();
    assert_eq!(
      entries,
      vec![
        ("DB_PASSWORD".to_string(), "hunter2".to_string()),
        ("PORT".to_string(), "8080".to_string()),
        (
          "B".to_string(),
          "escaped\nnewline \"quoted\" \\ #tag".to_string()
        ),
        (
          "SINGLE".to_string(),
          "it's literal ${NOT_EXPANDED}".to_string()
        ),
        ("EMPTY".to_string(), String::new()),
        (
          "UNQUOTED".to_string(),
          "$(not run) ${NOT_EXPANDED} # not a comment".to_string()
        ),
      ]
    );
  }

  #[test]
  fn errors_name_the_line_and_never_the_value() {
    for (file, expected) in [
      ("A=1\nnot an entry", "line 2: expected `NAME=value`"),
      ("=1", "line 1: missing name"),
      ("A=1\nA=2", "line 2: duplicate entry for `A`"),
      ("A=\"bad \\x escape\"", "line 1: unsupported escape `\\x`"),
      (
        "A=\"unterminated",
        "line 1: unterminated double quoted value",
      ),
      (
        "A='unterminated",
        "line 1: unterminated single quoted value",
      ),
      (
        "A=\"secret\" trailing",
        "line 1: unexpected content after closing quote",
      ),
      (
        "A='secret' trailing",
        "line 1: unexpected content after closing quote",
      ),
    ] {
      let err = parse_env_file(file).unwrap_err().to_string();
      assert!(err.starts_with(expected), "{file:?}: {err}");
      assert!(!err.contains("secret"), "{err}");
    }
  }

  #[test]
  fn a_byte_order_mark_is_not_part_of_the_first_name() {
    assert_eq!(
      parse_env_file("\u{FEFF}A=1\nB=2").unwrap(),
      vec![
        ("A".to_string(), "1".to_string()),
        ("B".to_string(), "2".to_string()),
      ]
    );
  }

  #[test]
  fn objects_lowercase_names_and_nest_on_dots() {
    let object = parse_env_file_object(
      "TITLE=app\nDATABASE.ADDRESS=db:5432\nDATABASE.CREDENTIALS.USERNAME=u\nDatabase.Credentials.Password=\"p\"\nPORT=8080\n",
    )
    .unwrap();
    assert_eq!(
      serde_json::Value::Object(object),
      serde_json::json!({
        "title": "app",
        "port": "8080",
        "database": {
          "address": "db:5432",
          "credentials": { "username": "u", "password": "p" },
        },
      })
    );
    assert_eq!(
      serde_json::Value::Object(parse_env_file_object("").unwrap()),
      serde_json::json!({})
    );
  }

  #[test]
  fn objects_refuse_conflicts_naming_the_line_and_both_names() {
    for (file, expected) in [
      (
        "DATABASE=x\nDATABASE.ADDRESS=y",
        "line 2: `DATABASE.ADDRESS` conflicts with `DATABASE` (line 1): `database` is both a value and an object",
      ),
      (
        "DATABASE.ADDRESS=y\nDATABASE=x",
        "line 2: `DATABASE` conflicts with `DATABASE.ADDRESS` (line 1): `database` is both a value and an object",
      ),
      (
        "A.B=1\nA.B.C=2",
        "line 2: `A.B.C` conflicts with `A.B` (line 1): `a.b` is both a value and an object",
      ),
      (
        "A.B.C=1\nA.X=2\nA.B=3",
        "line 3: `A.B` conflicts with `A.B.C` (line 1): `a.b` is both a value and an object",
      ),
      (
        "Db=1\nDB=2",
        "line 2: `DB` conflicts with `Db` (line 1): names are case insensitive",
      ),
      (
        "Database.Address=1\nDATABASE.ADDRESS=2",
        "line 2: `DATABASE.ADDRESS` conflicts with `Database.Address` (line 1): names are case insensitive",
      ),
      (
        ".DockerConfigJson=1\n.dockerconfigjson=2",
        "line 2: `.dockerconfigjson` conflicts with `.DockerConfigJson` (line 1): names are case insensitive",
      ),
    ] {
      let err = parse_env_file_object(file).unwrap_err().to_string();
      assert_eq!(err, expected, "{file:?}");
    }
    // Values never appear in the messages.
    let err = parse_env_file_object("A=secretvalue\nA.B=1")
      .unwrap_err()
      .to_string();
    assert!(!err.contains("secretvalue"), "{err}");
  }

  /// Cicada accepts secret names which cannot nest: each is one
  /// flat key, and the rest of the file still nests.
  #[test]
  fn names_with_an_empty_segment_stay_flat() {
    let object = parse_env_file_object(
      ".DockerConfigJson={\"auths\":{}}\nA..B=1\nX.=2\n.=3\nA.B=4\nDATABASE.ADDRESS=db:5432\n",
    )
    .unwrap();
    assert_eq!(
      serde_json::Value::Object(object),
      serde_json::json!({
        ".dockerconfigjson": "{\"auths\":{}}",
        "a..b": "1",
        "x.": "2",
        ".": "3",
        "a": { "b": "4" },
        "database": { "address": "db:5432" },
      })
    );
  }

  #[test]
  fn env_files_are_recognized_by_name_or_extension() {
    use std::path::Path;
    assert!(is_env_file(Path::new(".env")));
    assert!(is_env_file(Path::new("/etc/app/.env")));
    assert!(is_env_file(Path::new("app.env")));
    assert!(is_env_file(Path::new("APP.ENV")));
    assert!(!is_env_file(Path::new("config.toml")));
    assert!(!is_env_file(Path::new(".envrc")));
    assert!(!is_env_file(Path::new("env")));
  }
}
