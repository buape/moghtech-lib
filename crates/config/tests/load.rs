// Integration test binaries only use a subset
// of the library dependencies.
#![allow(unused_crate_dependencies)]

use std::path::{Path, PathBuf};

use mogh_config::ConfigLoader;

/// Creates a unique, empty directory for a test
/// and cleans it up on drop.
struct TestDir(PathBuf);

impl TestDir {
  fn new(name: &str) -> TestDir {
    let path = std::env::temp_dir().join(format!(
      "mogh_config_test_{}_{name}",
      std::process::id()
    ));
    // Ensure a clean folder
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    TestDir(path)
  }

  fn write(&self, file: &str, contents: &str) -> PathBuf {
    let path = self.0.join(file);
    std::fs::write(&path, contents).unwrap();
    path
  }
}

impl Drop for TestDir {
  fn drop(&mut self) {
    let _ = std::fs::remove_dir_all(&self.0);
  }
}

fn load(
  paths: &[&Path],
  match_wildcards: &[&str],
  merge_nested: bool,
  extend_array: bool,
) -> serde_json::Value {
  ConfigLoader {
    paths,
    match_wildcards,
    include_file_name: ".include",
    merge_nested,
    extend_array,
    debug_print: false,
  }
  .load()
  .unwrap()
}

#[test]
fn loads_toml_yaml_and_json_files() {
  let dir = TestDir::new("formats");
  let toml = dir.write("config.toml", "a = 1");
  let yaml = dir.write("config.yaml", "b: 2");
  let yml = dir.write("config.yml", "c: 3");
  let json = dir.write("config.json", r#"{ "d": 4 }"#);

  let config = load(&[&toml, &yaml, &yml, &json], &[], false, false);
  assert_eq!(
    config,
    serde_json::json!({ "a": 1, "b": 2, "c": 3, "d": 4 })
  );
}

#[test]
fn extension_matching_is_case_insensitive() {
  let dir = TestDir::new("upper_ext");
  let toml = dir.write("config.TOML", "a = 1");
  let config = load(&[&toml], &[], false, false);
  assert_eq!(config, serde_json::json!({ "a": 1 }));
}

#[test]
fn unsupported_extension_is_skipped_with_warning() {
  let dir = TestDir::new("unsupported_ext");
  let txt = dir.write("config.txt", "a = 1");
  let toml = dir.write("config.toml", "b = 2");
  // The .txt file fails to parse and is skipped, rest still loads.
  let config = load(&[&txt, &toml], &[], false, false);
  assert_eq!(config, serde_json::json!({ "b": 2 }));
}

#[test]
fn missing_paths_are_skipped() {
  let dir = TestDir::new("missing_path");
  let toml = dir.write("config.toml", "a = 1");
  let missing = dir.0.join("does_not_exist.toml");
  let config = load(&[&missing, &toml], &[], false, false);
  assert_eq!(config, serde_json::json!({ "a": 1 }));
}

#[test]
fn later_paths_override_earlier_paths() {
  let dir = TestDir::new("precedence");
  let base = dir.write(
    "base.toml",
    "a = 1\nb = \"base\"\narr = [1]\n[nested]\nx = 1\ny = 1",
  );
  let override_ = dir.write(
    "override.json",
    r#"{ "b": "override", "arr": [2], "nested": { "y": 2 } }"#,
  );

  // merge_nested + extend_array
  let config = load(&[&base, &override_], &[], true, true);
  assert_eq!(
    config,
    serde_json::json!({
      "a": 1,
      "b": "override",
      "arr": [1, 2],
      "nested": { "x": 1, "y": 2 }
    })
  );

  // replace nested / arrays
  let config = load(&[&base, &override_], &[], false, false);
  assert_eq!(
    config,
    serde_json::json!({
      "a": 1,
      "b": "override",
      "arr": [2],
      "nested": { "y": 2 }
    })
  );
}

#[test]
fn repeated_path_moves_to_highest_priority() {
  let dir = TestDir::new("repeat_path");
  let first = dir.write("first.toml", "a = \"first\"");
  let second = dir.write("second.toml", "a = \"second\"");
  // `first` is repeated after `second`, so it should win.
  let config = load(&[&first, &second, &first], &[], false, false);
  assert_eq!(config, serde_json::json!({ "a": "first" }));
}

#[test]
fn directory_loading_respects_wildcard_order() {
  let dir = TestDir::new("wildcards");
  dir.write("01_a.toml", "key = \"a\"\nonly_a = 1");
  dir.write("02_b.toml", "key = \"b\"\nonly_b = 1");
  dir.write("ignored.toml", "ignored = 1");

  // Later wildcards have higher priority, so 01_a wins.
  let config =
    load(&[&dir.0], &["02_*.toml", "01_*.toml"], false, false);
  assert_eq!(
    config,
    serde_json::json!({ "key": "a", "only_a": 1, "only_b": 1 })
  );

  // With a single wildcard, files apply in path order (02_b last).
  let config = load(&[&dir.0], &["0*.toml"], false, false);
  assert_eq!(
    config,
    serde_json::json!({ "key": "b", "only_a": 1, "only_b": 1 })
  );

  // Files not matching any wildcard are excluded entirely.
  let config = load(&[&dir.0], &["0*.toml"], false, false);
  assert_eq!(config.get("ignored"), None);
}

#[test]
fn file_paths_override_directory_paths() {
  let dir = TestDir::new("file_over_dir");
  dir.write("config.toml", "a = \"dir\"");
  let standalone = TestDir::new("file_over_dir_standalone");
  let file = standalone.write("override.toml", "a = \"file\"");

  let config = load(&[&dir.0, &file], &["*.toml"], false, false);
  assert_eq!(config, serde_json::json!({ "a": "file" }));
}

#[test]
fn include_file_pulls_in_other_directories() {
  let included = TestDir::new("included_dir");
  included.write("extra.toml", "extra = 1\nkey = \"included\"");
  let dir = TestDir::new("includes");
  dir.write("main.toml", "key = \"main\"\nmain = 1");
  dir.write(
    ".include",
    &format!(
      "# comment line\n\n{} # end of line comment\n",
      included.0.display()
    ),
  );

  let config = load(&[&dir.0], &["*.toml"], false, false);
  assert_eq!(config.get("extra"), Some(&serde_json::json!(1)));
  assert_eq!(config.get("main"), Some(&serde_json::json!(1)));
}

#[test]
fn interpolates_env_vars_into_config() {
  let var = "MOGH_CONFIG_TEST_INTERPOLATION_VAR";
  unsafe { std::env::set_var(var, "interpolated") };
  let dir = TestDir::new("interpolation");
  let toml =
    dir.write("config.toml", &format!("value = \"${{{var}}}\""));
  let config = load(&[&toml], &[], false, false);
  assert_eq!(config, serde_json::json!({ "value": "interpolated" }));
}

#[test]
fn interpolates_unset_env_vars_to_empty_string() {
  let dir = TestDir::new("interpolation_unset");
  let toml = dir.write(
    "config.toml",
    "value = \"${MOGH_CONFIG_TEST_DEFINITELY_UNSET_VAR}\"",
  );
  let config = load(&[&toml], &[], false, false);
  assert_eq!(config, serde_json::json!({ "value": "" }));
}
