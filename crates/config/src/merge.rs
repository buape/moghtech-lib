use serde::{Serialize, de::DeserializeOwned};

use crate::{Error, Result};

/// - Object is serde_json::Map<String, serde_json::Value>.
/// - Source will overide target.
/// - Will recurse when field is object if merge_object = true, otherwise object will be replaced.
/// - Will extend when field is array if extend_array = true, otherwise array will be replaced.
/// - Will return error when types on source and target fields do not match.
///
/// [crate::ConfigLoader] merges its sources with its own, lenient
/// rules instead (a later source never fails to merge, and env file
/// lists extend arrays): see [crate::ConfigLoader::merge_nested]
/// and [crate::ConfigLoader::extend_array].
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
              found: crate::error::value_type(&value),
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
            return Err(Error::ArrayFieldTypeMismatch {
              key,
              found: crate::error::value_type(&value),
            });
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

/// Merges one [crate::ConfigLoader] source over the sources before
/// it, in place. Unlike [merge_objects] it never fails, so a source
/// is never dropped over one key (a cicada source full of secrets
/// included):
///
/// - Source overrides target.
/// - With `merge_nested`, two objects merge key by key. A `null`
///   (a yaml section with every line commented out) has no keys to
///   merge, so it keeps the object.
/// - With `extend_array`, an array extends the array before it, and
///   a `null` adds nothing. With `split_lists` (an env file source,
///   whose lists are comma separated strings: `HOSTS=b,c`), a string
///   extends it with the list's entries.
/// - Any other value replaces the one before it, as it does without
///   `merge_nested` / `extend_array`. A value the config type can't
///   take fails the final deserialization, which names its path and
///   type (never the value), rather than being skipped here.
pub(crate) fn merge_source(
  target: &mut serde_json::Map<String, serde_json::Value>,
  source: serde_json::Map<String, serde_json::Value>,
  merge_nested: bool,
  extend_array: bool,
  split_lists: bool,
) {
  for (key, value) in source {
    let Some(curr) = target.get_mut(&key) else {
      target.insert(key, value);
      continue;
    };
    match (curr, value) {
      (
        serde_json::Value::Object(target_obj),
        serde_json::Value::Object(source_obj),
      ) if merge_nested => {
        merge_source(
          target_obj,
          source_obj,
          merge_nested,
          extend_array,
          split_lists,
        );
      }
      (serde_json::Value::Object(_), serde_json::Value::Null)
        if merge_nested => {}
      (
        serde_json::Value::Array(target_arr),
        serde_json::Value::Array(source_arr),
      ) if extend_array => target_arr.extend(source_arr),
      (serde_json::Value::Array(_), serde_json::Value::Null)
        if extend_array => {}
      (
        serde_json::Value::Array(target_arr),
        serde_json::Value::String(list),
      ) if extend_array && split_lists => {
        // The same syntax the final deserialization splits.
        target_arr.extend(
          list
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
              serde_json::Value::String(entry.to_string())
            }),
        );
      }
      (curr, value) => *curr = value,
    }
  }
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
  crate::error::deserialize_final(&serde_json::Value::Object(object))
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

  /// The public merge keeps its contract for callers merging
  /// something other than config sources (eg. Komodo action args):
  /// a string or `null` is no list, and `null` is no object.
  #[test]
  fn public_merge_does_not_split_strings_onto_arrays() {
    let target = object(serde_json::json!({ "msg": ["default"] }));
    let source = object(serde_json::json!({ "msg": "hello, world" }));
    let err = merge_objects(target, source, true, true).unwrap_err();
    assert!(matches!(
      err,
      Error::ArrayFieldTypeMismatch { key, found: "string" }
        if key == "msg"
    ));
    let target = object(serde_json::json!({ "msg": ["default"] }));
    let source = object(serde_json::json!({ "msg": null }));
    assert!(merge_objects(target, source, true, true).is_err());
    let target = object(serde_json::json!({ "db": { "a": 1 } }));
    let source = object(serde_json::json!({ "db": null }));
    assert!(merge_objects(target, source, true, true).is_err());
  }

  fn merge_source_json(
    target: serde_json::Value,
    source: serde_json::Value,
    merge_nested: bool,
    extend_array: bool,
    split_lists: bool,
  ) -> serde_json::Value {
    let mut target = object(target);
    merge_source(
      &mut target,
      object(source),
      merge_nested,
      extend_array,
      split_lists,
    );
    serde_json::Value::Object(target)
  }

  /// A yaml section with every line commented out is `null`: it
  /// has nothing to merge, and the rest of the source still applies.
  #[test]
  fn source_null_keeps_objects_and_arrays_when_merging() {
    let target = serde_json::json!({
      "port": 1,
      "database": { "address": "localhost" },
      "hosts": ["a"],
    });
    let source = serde_json::json!({
      "port": 9000,
      "database": null,
      "hosts": null,
    });
    assert_eq!(
      merge_source_json(
        target.clone(),
        source.clone(),
        true,
        true,
        false
      ),
      serde_json::json!({
        "port": 9000,
        "database": { "address": "localhost" },
        "hosts": ["a"],
      })
    );
    // Without the flags, null replaces like any other value.
    assert_eq!(
      merge_source_json(target, source, false, false, false),
      serde_json::json!({
        "port": 9000,
        "database": null,
        "hosts": null,
      })
    );
  }

  /// A type conflict never drops the source: the later value
  /// replaces the earlier one (the final deserialization reports it
  /// if the config type can't take it), and every other key applies.
  #[test]
  fn source_type_conflicts_replace_instead_of_dropping_the_source() {
    let merged = merge_source_json(
      serde_json::json!({
        "port": 1,
        "database": { "address": "localhost" },
        "ports": [8120],
      }),
      serde_json::json!({
        "port": 9000,
        "db_password": "secret",
        "database": "postgres://x",
        "ports": 8120,
      }),
      true,
      true,
      true,
    );
    assert_eq!(
      merged,
      serde_json::json!({
        "port": 9000,
        "db_password": "secret",
        "database": "postgres://x",
        "ports": 8120,
      })
    );
  }

  /// Only an env file source's string is a list to extend with.
  #[test]
  fn only_env_file_strings_extend_arrays() {
    let target = serde_json::json!({ "hosts": ["a"] });
    let source = serde_json::json!({ "hosts": "b, c,," });
    assert_eq!(
      merge_source_json(
        target.clone(),
        source.clone(),
        true,
        true,
        true
      ),
      serde_json::json!({ "hosts": ["a", "b", "c"] })
    );
    assert_eq!(
      merge_source_json(
        target.clone(),
        source.clone(),
        true,
        true,
        false
      ),
      serde_json::json!({ "hosts": "b, c,," })
    );
    assert_eq!(
      merge_source_json(target, source, true, false, true),
      serde_json::json!({ "hosts": "b, c,," })
    );
  }

  #[test]
  fn source_objects_merge_nested_and_arrays_extend() {
    assert_eq!(
      merge_source_json(
        serde_json::json!({
          "nested": { "keep": 1, "replace": 1, "list": [1] }
        }),
        serde_json::json!({
          "nested": { "replace": 2, "add": 3, "list": [2] }
        }),
        true,
        true,
        false,
      ),
      serde_json::json!({
        "nested": { "keep": 1, "replace": 2, "add": 3, "list": [1, 2] }
      })
    );
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

  /// merge_config round trips through json, where every map key is
  /// a string: integer, bool and newtype keys come back typed.
  #[test]
  fn merge_config_keeps_typed_map_keys() {
    use std::collections::{BTreeMap, HashMap};

    #[derive(
      serde::Serialize,
      serde::Deserialize,
      Debug,
      PartialEq,
      Eq,
      Hash,
      PartialOrd,
      Ord,
    )]
    struct Id(String);

    #[derive(
      serde::Serialize, serde::Deserialize, Debug, PartialEq,
    )]
    struct Config {
      ports: HashMap<u16, String>,
      limits: BTreeMap<u64, u32>,
      flags: HashMap<bool, String>,
      owners: BTreeMap<Id, String>,
    }
    let target = Config {
      ports: HashMap::from([(8080, "api".into())]),
      limits: BTreeMap::from([(10, 1)]),
      flags: HashMap::from([(true, "on".into())]),
      owners: BTreeMap::from([(Id("a".into()), "x".into())]),
    };
    let source = Config {
      ports: HashMap::from([(9090, "metrics".into())]),
      limits: BTreeMap::from([(10, 2)]),
      flags: HashMap::from([(false, "off".into())]),
      owners: BTreeMap::from([(Id("b".into()), "y".into())]),
    };
    let merged = merge_config(target, source, true, false).unwrap();
    assert_eq!(
      merged,
      Config {
        ports: HashMap::from([
          (8080, "api".into()),
          (9090, "metrics".into())
        ]),
        limits: BTreeMap::from([(10, 2)]),
        flags: HashMap::from([
          (true, "on".into()),
          (false, "off".into())
        ]),
        owners: BTreeMap::from([
          (Id("a".into()), "x".into()),
          (Id("b".into()), "y".into())
        ]),
      }
    );
  }
}
