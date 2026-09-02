use serde::{Serialize, de::DeserializeOwned};

use crate::{Error, Result};

/// - Object is serde_json::Map<String, serde_json::Value>.
/// - Source will overide target.
/// - Will recurse when field is object if merge_object = true, otherwise object will be replaced.
/// - Will extend when field is array if extend_array = true, otherwise array will be replaced.
/// - Will return error when types on source and target fields do not match.
pub fn merge_objects(
  mut target: serde_json::Map<String, serde_json::Value>,
  source: serde_json::Map<String, serde_json::Value>,
  merge_nested: bool,
  extend_array: bool,
) -> Result<serde_json::Map<String, serde_json::Value>> {
  for (key, value) in source {
    let Some(curr) = target.remove(&key) else {
      target.insert(key, value);
      continue;
    };
    match curr {
      serde_json::Value::Object(target_obj) => {
        if !merge_nested {
          target.insert(key, value);
          continue;
        }
        match value {
          serde_json::Value::Object(source_obj) => {
            target.insert(
              key,
              serde_json::Value::Object(merge_objects(
                target_obj,
                source_obj,
                merge_nested,
                extend_array,
              )?),
            );
          }
          _ => {
            return Err(Error::ObjectFieldTypeMismatch {
              key,
              value,
            });
          }
        }
      }
      serde_json::Value::Array(mut target_arr) => {
        if !extend_array {
          target.insert(key, value);
          continue;
        }
        match value {
          serde_json::Value::Array(source_arr) => {
            target_arr.extend(source_arr);
            target.insert(key, serde_json::Value::Array(target_arr));
          }
          _ => {
            return Err(Error::ArrayFieldTypeMismatch { key, value });
          }
        }
      }
      _ => {
        target.insert(key, value);
      }
    }
  }
  Ok(target)
}

/// Source will overide target
pub fn merge_config<T: Serialize + DeserializeOwned>(
  target: T,
  source: T,
  merge_nested: bool,
  extend_array: bool,
) -> Result<T> {
  let serde_json::Value::Object(target) =
    serde_json::to_value(target)
      .map_err(|e| Error::SerializeJson { e })?
  else {
    return Err(Error::ValueIsNotObject);
  };
  let serde_json::Value::Object(source) =
    serde_json::to_value(source)
      .map_err(|e| Error::SerializeJson { e })?
  else {
    return Err(Error::ValueIsNotObject);
  };
  let object =
    merge_objects(target, source, merge_nested, extend_array)?;
  serde_json::from_value(serde_json::Value::Object(object))
    .map_err(|e| Error::ParseFinalJson { e })
}

#[cfg(test)]
mod tests {
  use super::*;

  fn object(
    json: serde_json::Value,
  ) -> serde_json::Map<String, serde_json::Value> {
    match json {
      serde_json::Value::Object(object) => object,
      _ => panic!("expected object"),
    }
  }

  #[test]
  fn source_overrides_target_scalars() {
    let target =
      object(serde_json::json!({ "a": 1, "b": "old", "c": true }));
    let source = object(serde_json::json!({ "b": "new", "d": 2 }));
    let merged = merge_objects(target, source, false, false).unwrap();
    assert_eq!(
      serde_json::Value::Object(merged),
      serde_json::json!({ "a": 1, "b": "new", "c": true, "d": 2 })
    );
  }

  #[test]
  fn nested_objects_merge_when_enabled() {
    let target = object(
      serde_json::json!({ "nested": { "keep": 1, "replace": 1 } }),
    );
    let source = object(
      serde_json::json!({ "nested": { "replace": 2, "add": 3 } }),
    );
    let merged = merge_objects(target, source, true, false).unwrap();
    assert_eq!(
      serde_json::Value::Object(merged),
      serde_json::json!({
        "nested": { "keep": 1, "replace": 2, "add": 3 }
      })
    );
  }

  #[test]
  fn nested_objects_replace_when_disabled() {
    let target = object(
      serde_json::json!({ "nested": { "keep": 1, "replace": 1 } }),
    );
    let source =
      object(serde_json::json!({ "nested": { "replace": 2 } }));
    let merged = merge_objects(target, source, false, false).unwrap();
    assert_eq!(
      serde_json::Value::Object(merged),
      serde_json::json!({ "nested": { "replace": 2 } })
    );
  }

  #[test]
  fn arrays_extend_when_enabled() {
    let target = object(serde_json::json!({ "arr": [1, 2] }));
    let source = object(serde_json::json!({ "arr": [3] }));
    let merged = merge_objects(target, source, false, true).unwrap();
    assert_eq!(
      serde_json::Value::Object(merged),
      serde_json::json!({ "arr": [1, 2, 3] })
    );
  }

  #[test]
  fn arrays_replace_when_disabled() {
    let target = object(serde_json::json!({ "arr": [1, 2] }));
    let source = object(serde_json::json!({ "arr": [3] }));
    let merged = merge_objects(target, source, false, false).unwrap();
    assert_eq!(
      serde_json::Value::Object(merged),
      serde_json::json!({ "arr": [3] })
    );
  }

  #[test]
  fn object_type_mismatch_errors_when_merging_nested() {
    let target = object(serde_json::json!({ "field": { "a": 1 } }));
    let source = object(serde_json::json!({ "field": 42 }));
    let err = merge_objects(target, source, true, false).unwrap_err();
    assert!(matches!(
      err,
      Error::ObjectFieldTypeMismatch { key, .. } if key == "field"
    ));
  }

  #[test]
  fn array_type_mismatch_errors_when_extending() {
    let target = object(serde_json::json!({ "field": [1] }));
    let source = object(serde_json::json!({ "field": 42 }));
    let err = merge_objects(target, source, false, true).unwrap_err();
    assert!(matches!(
      err,
      Error::ArrayFieldTypeMismatch { key, .. } if key == "field"
    ));
  }

  #[test]
  fn merge_config_merges_typed_values() {
    #[derive(
      serde::Serialize, serde::Deserialize, Debug, PartialEq,
    )]
    struct Config {
      a: i64,
      b: String,
      arr: Vec<i64>,
    }
    let target = Config {
      a: 1,
      b: String::from("target"),
      arr: vec![1],
    };
    let source = Config {
      a: 2,
      b: String::from("source"),
      arr: vec![2],
    };
    let merged = merge_config(target, source, true, true).unwrap();
    assert_eq!(
      merged,
      Config {
        a: 2,
        b: String::from("source"),
        arr: vec![1, 2],
      }
    );
  }

  #[test]
  fn merge_config_rejects_non_objects() {
    let err = merge_config(1_i64, 2_i64, false, false).unwrap_err();
    assert!(matches!(err, Error::ValueIsNotObject));
  }
}
