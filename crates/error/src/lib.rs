pub use anyhow;

use anyhow::Context;

mod serror;

pub use serror::Serror;

#[cfg(feature = "axum")]
mod axum;
#[cfg(feature = "axum")]
pub use crate::axum::*;

pub fn serialize_error(e: &anyhow::Error) -> String {
  try_serialize_error(e).unwrap_or_else(|_| format!("{e:#?}"))
}

pub fn try_serialize_error(
  e: &anyhow::Error,
) -> anyhow::Result<String> {
  let serror: Serror = e.into();
  let res = serde_json::to_string(&serror)?;
  anyhow::Ok(res)
}

pub fn serialize_error_pretty(e: &anyhow::Error) -> String {
  try_serialize_error_pretty(e).unwrap_or_else(|_| format!("{e:#?}"))
}

pub fn try_serialize_error_pretty(
  e: &anyhow::Error,
) -> anyhow::Result<String> {
  let serror: Serror = e.into();
  let res = serde_json::to_string_pretty(&serror)?;
  anyhow::Ok(res)
}

pub fn serialize_error_bytes(e: &anyhow::Error) -> Vec<u8> {
  try_serialize_error_bytes(e)
    .unwrap_or_else(|_| format!("{e:#?}").into_bytes())
}

pub fn try_serialize_error_bytes(
  e: &anyhow::Error,
) -> anyhow::Result<Vec<u8>> {
  let serror: Serror = e.into();
  let res = serde_json::to_vec(&serror)?;
  anyhow::Ok(res)
}

pub fn deserialize_error(json: String) -> anyhow::Error {
  serror_into_anyhow_error(deserialize_serror(json))
}

pub fn deserialize_serror(json: String) -> Serror {
  try_deserialize_serror(&json).unwrap_or_else(|_| Serror {
    error: json.clone(),
    trace: Default::default(),
  })
}

pub fn try_deserialize_serror(json: &str) -> anyhow::Result<Serror> {
  serde_json::from_str(json)
    .context("failed to deserialize string into Serror")
}

pub fn deserialize_error_bytes(json: &[u8]) -> anyhow::Error {
  serror_into_anyhow_error(deserialize_serror_bytes(json))
}

pub fn deserialize_serror_bytes(json: &[u8]) -> Serror {
  try_deserialize_serror_bytes(json).unwrap_or_else(|_| Serror {
    error: match String::from_utf8(json.to_vec()) {
      std::result::Result::Ok(res) => res,
      Err(e) => format!("Bytes are not valid utf8 | {e:?}"),
    },
    trace: Default::default(),
  })
}

pub fn try_deserialize_serror_bytes(
  json: &[u8],
) -> anyhow::Result<Serror> {
  serde_json::from_slice(json)
    .context("failed to deserialize string into Serror")
}

pub fn serror_into_anyhow_error(mut serror: Serror) -> anyhow::Error {
  let mut e = match serror.trace.pop() {
    None => return anyhow::Error::msg(serror.error),
    Some(msg) => anyhow::Error::msg(msg),
  };

  while let Some(msg) = serror.trace.pop() {
    e = e.context(msg);
  }

  e = e.context(serror.error);

  e
}

#[cfg(test)]
mod tests {
  use super::*;

  fn chain(e: &anyhow::Error) -> Vec<String> {
    e.chain().map(|e| e.to_string()).collect()
  }

  fn example_error() -> anyhow::Error {
    anyhow::anyhow!("root cause")
      .context("middle context")
      .context("top level")
  }

  #[test]
  fn serror_from_anyhow_error_splits_chain() {
    let serror: Serror = (&example_error()).into();
    assert_eq!(serror.error, "top level");
    assert_eq!(serror.trace, vec!["middle context", "root cause"]);
  }

  #[test]
  fn serror_from_error_without_context() {
    let serror: Serror = anyhow::anyhow!("only error").into();
    assert_eq!(serror.error, "only error");
    assert!(serror.trace.is_empty());
  }

  #[test]
  fn serialize_deserialize_roundtrip_preserves_chain() {
    let e = example_error();
    let serialized = serialize_error(&e);
    // Sanity check the serialized shape
    let value: serde_json::Value =
      serde_json::from_str(&serialized).unwrap();
    assert_eq!(
      value,
      serde_json::json!({
        "error": "top level",
        "trace": ["middle context", "root cause"]
      })
    );
    let deserialized = deserialize_error(serialized);
    assert_eq!(chain(&deserialized), chain(&e));
  }

  #[test]
  fn serialize_error_bytes_matches_string_version() {
    let e = example_error();
    assert_eq!(
      serialize_error(&e).into_bytes(),
      serialize_error_bytes(&e)
    );
    let deserialized =
      deserialize_error_bytes(&serialize_error_bytes(&e));
    assert_eq!(chain(&deserialized), chain(&e));
  }

  #[test]
  fn serialize_error_pretty_parses_to_same_serror() {
    let e = example_error();
    let pretty: Serror =
      serde_json::from_str(&serialize_error_pretty(&e)).unwrap();
    assert_eq!(pretty.error, "top level");
    assert_eq!(pretty.trace, vec!["middle context", "root cause"]);
  }

  #[test]
  fn deserialize_serror_falls_back_to_raw_string() {
    let serror = deserialize_serror(String::from("not json"));
    assert_eq!(serror.error, "not json");
    assert!(serror.trace.is_empty());
  }

  #[test]
  fn deserialize_serror_bytes_falls_back_on_invalid_utf8() {
    let serror = deserialize_serror_bytes(&[0xff, 0xfe]);
    assert!(serror.error.contains("Bytes are not valid utf8"));
    assert!(serror.trace.is_empty());
  }

  #[test]
  fn serror_into_anyhow_error_rebuilds_chain() {
    let serror = Serror {
      error: String::from("top level"),
      trace: vec![
        String::from("middle context"),
        String::from("root cause"),
      ],
    };
    let e = serror_into_anyhow_error(serror);
    assert_eq!(
      chain(&e),
      vec!["top level", "middle context", "root cause"]
    );
  }

  #[test]
  fn serror_into_anyhow_error_without_trace() {
    let e = serror_into_anyhow_error(Serror {
      error: String::from("only error"),
      trace: Vec::new(),
    });
    assert_eq!(chain(&e), vec!["only error"]);
  }
}
