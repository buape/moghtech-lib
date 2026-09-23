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
  // Includes override the directory's own files.
  assert_eq!(config.get("key"), Some(&serde_json::json!("included")));
}

#[test]
fn includes_apply_in_include_order() {
  // Directory names are chosen so that path order (zz < ...)
  // disagrees with include order, proving include order wins.
  let main = TestDir::new("zz_order_main");
  let first = TestDir::new("yy_order_first");
  let second = TestDir::new("aa_order_second");
  let nested = TestDir::new("bb_order_nested");
  main.write("main.toml", "key = \"main\"\nmain = 1");
  first.write("first.toml", "key = \"first\"\nfirst = 1");
  second.write("second.toml", "key = \"second\"\nsecond = 1");
  nested.write("nested.toml", "key = \"nested\"\nnested = 1");
  // first includes nested, so nested is applied right after
  // first, before second.
  first.write(
    ".include",
    &format!(
      "{}
",
      nested.0.display()
    ),
  );
  main.write(
    ".include",
    &format!(
      "{}
{}
",
      first.0.display(),
      second.0.display()
    ),
  );

  let config = load(&[&main.0], &["*.toml"], false, false);
  assert_eq!(
    config,
    serde_json::json!({
      "key": "second",
      "main": 1,
      "first": 1,
      "nested": 1,
      "second": 1,
    })
  );

  // Reversing the include order reverses the priority.
  main.write(
    ".include",
    &format!(
      "{}
{}
",
      second.0.display(),
      first.0.display()
    ),
  );
  let config = load(&[&main.0], &["*.toml"], false, false);
  assert_eq!(config.get("key"), Some(&serde_json::json!("nested")));
}

#[test]
fn wildcard_priority_is_per_directory() {
  let main = TestDir::new("wc_per_dir_main");
  let included = TestDir::new("wc_per_dir_included");
  main.write("02_high.toml", "key = \"main-high\"");
  included.write("01_low.toml", "key = \"included-low\"");
  main.write(
    ".include",
    &format!(
      "{}
",
      included.0.display()
    ),
  );
  // 02_* is the higher priority wildcard, but only within a
  // directory: the include still overrides the main directory.
  let config =
    load(&[&main.0], &["01_*.toml", "02_*.toml"], false, false);
  assert_eq!(config, serde_json::json!({ "key": "included-low" }));
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

#[test]
fn include_cycles_do_not_recurse_forever() {
  let a = TestDir::new("cycle_a");
  // b is nested in a, so `..` from b is a.
  let b = a.0.join("b");
  std::fs::create_dir(&b).unwrap();
  a.write("a.toml", "a = 1");
  std::fs::write(b.join("b.toml"), "b = 2").unwrap();
  // a includes b and itself, b includes a (absolute and relative).
  a.write(".include", &format!("{}\n.\n", b.display()));
  std::fs::write(
    b.join(".include"),
    format!("{}\n..\n", a.0.display()),
  )
  .unwrap();
  let config = load(&[&a.0], &["*.toml"], false, false);
  assert_eq!(config.get("a"), Some(&serde_json::json!(1)));
  assert_eq!(config.get("b"), Some(&serde_json::json!(2)));
}

#[test]
fn diamond_includes_keep_last_occurrence_priority() {
  // main includes first then second, both include shared.
  // shared is applied under second as well, so it overrides
  // second, as the include order rule promises.
  let main = TestDir::new("diamond_main");
  let first = TestDir::new("diamond_first");
  let second = TestDir::new("diamond_second");
  let shared = TestDir::new("diamond_shared");
  main.write("main.toml", "key = \"main\"");
  first.write("first.toml", "key = \"first\"");
  second.write("second.toml", "key = \"second\"");
  shared.write("shared.toml", "key = \"shared\"\nshared = 1");
  first.write(".include", &format!("{}\n", shared.0.display()));
  second.write(".include", &format!("{}\n", shared.0.display()));
  main.write(
    ".include",
    &format!("{}\n{}\n", first.0.display(), second.0.display()),
  );
  let config = load(&[&main.0], &["*.toml"], false, false);
  assert_eq!(
    config,
    serde_json::json!({ "key": "shared", "shared": 1 })
  );
}

#[test]
fn include_file_is_not_loaded_as_config() {
  let dir = TestDir::new("include_not_config");
  dir.write("config.toml", "a = 1");
  dir.write(".include", "# nothing\n");
  // No wildcards: every file would otherwise be attempted.
  let config = load(&[&dir.0], &[], false, false);
  assert_eq!(config, serde_json::json!({ "a": 1 }));
}

#[test]
fn include_paths_may_contain_hash() {
  let included = TestDir::new("hash#dir");
  included.write("extra.toml", "extra = 1");
  let dir = TestDir::new("hash_include");
  dir.write("main.toml", "main = 1");
  dir.write(
    ".include",
    &format!("{} # trailing comment\n", included.0.display()),
  );
  let config = load(&[&dir.0], &["*.toml"], false, false);
  assert_eq!(config.get("extra"), Some(&serde_json::json!(1)));
}

#[cfg(unix)]
#[test]
fn symlinked_files_in_directories_are_loaded() {
  let real = TestDir::new("symlink_real");
  let target = real.write("real.toml", "linked = 1");
  let dir = TestDir::new("symlink_dir");
  std::os::unix::fs::symlink(&target, dir.0.join("config.toml"))
    .unwrap();
  let config = load(&[&dir.0], &["*.toml"], false, false);
  assert_eq!(config, serde_json::json!({ "linked": 1 }));
}

#[test]
fn interpolated_values_cannot_inject_or_break_json() {
  let var = "MOGH_CONFIG_TEST_INJECTION_VAR";
  let value = "x\",\"admin\":true,\"y\":\"z\\\nline2 $(whoami)";
  unsafe { std::env::set_var(var, value) };
  let dir = TestDir::new("interpolation_injection");
  let toml = dir.write(
    "config.toml",
    &format!("value = \"${{{var}}}\"\n[nested]\ninner = \"${{{var}}}\"\nlist = [\"${{{var}}}\"]"),
  );
  let config = load(&[&toml], &[], false, false);
  assert_eq!(
    config,
    serde_json::json!({
      "value": value,
      "nested": { "inner": value, "list": [value] }
    })
  );
}

#[test]
fn shell_output_and_env_values_are_not_reinterpolated() {
  // The output of $(env) contains this literal `${...}` text,
  // which must be kept verbatim rather than expanded.
  let literal_var = "MOGH_CONFIG_TEST_LITERAL_VAR";
  unsafe {
    std::env::set_var(
      literal_var,
      "keep ${MOGH_CONFIG_TEST_UNSET} literal",
    )
  };
  // An env var whose value references another env var expands
  // one level, but `$(...)` in either value is never executed.
  let outer = "MOGH_CONFIG_TEST_OUTER_VAR";
  let inner = "MOGH_CONFIG_TEST_INNER_VAR";
  unsafe {
    std::env::set_var(outer, format!("outer ${{{inner}}} $(whoami)"));
    std::env::set_var(inner, "inner $(whoami)");
  }
  let dir = TestDir::new("interpolation_no_reinterpolation");
  let toml = dir.write(
    "config.toml",
    &format!("from_shell = \"$(env)\"\nfrom_env = \"${{{outer}}}\""),
  );
  let config = load(&[&toml], &[], false, false);
  let from_shell = config["from_shell"].as_str().unwrap();
  assert!(
    from_shell.contains("keep ${MOGH_CONFIG_TEST_UNSET} literal"),
    "{from_shell}"
  );
  assert_eq!(
    config["from_env"],
    serde_json::json!("outer inner $(whoami) $(whoami)")
  );
}

#[test]
fn interpolates_shell_commands_and_keys() {
  let dir = TestDir::new("interpolation_shell");
  let toml = dir.write(
    "config.toml",
    "value = \"$(true)\"\n\"${MOGH_CONFIG_TEST_DEFINITELY_UNSET_VAR}key\" = 1",
  );
  let config = load(&[&toml], &[], false, false);
  assert_eq!(config, serde_json::json!({ "value": "", "key": 1 }));
}

#[test]
fn errors_do_not_leak_config_values() {
  #[derive(serde::Deserialize, Debug)]
  #[allow(dead_code)]
  struct Typed {
    port: u16,
  }
  let dir = TestDir::new("error_redaction");
  let toml = dir.write("config.toml", "port = \"hunter2secret\"");
  let err = ConfigLoader {
    paths: &[&toml],
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: false,
    extend_array: false,
    debug_print: false,
  }
  .load::<Typed>()
  .unwrap_err();
  let message = err.to_string();
  assert!(!message.contains("hunter2secret"), "{message}");
  assert!(message.contains("expected u16"), "{message}");
}

#[cfg(not(feature = "cicada"))]
#[test]
fn cicada_path_without_the_feature_is_an_error() {
  // Skipping it would start the app with defaults.
  let err = (ConfigLoader {
    paths: &[std::path::Path::new(
      "cicada://filesystem/config.yaml?env=prod",
    )],
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  })
  .load::<serde_json::Value>()
  .unwrap_err();
  assert!(
    matches!(err, mogh_config::Error::CicadaFeatureDisabled { .. }),
    "{err}"
  );
  assert!(err.to_string().contains("'cicada' feature"));
}

#[derive(serde::Deserialize, Debug, PartialEq)]
struct Typed {
  db_password: String,
  port: u16,
  debug: bool,
  #[serde(default)]
  allowed_hosts: Vec<String>,
  #[serde(default)]
  region: Option<String>,
  #[serde(default = "default_title")]
  title: String,
}

fn default_title() -> String {
  String::from("untitled")
}

fn load_typed(paths: &[&Path]) -> mogh_config::Result<Typed> {
  ConfigLoader {
    paths,
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  }
  .load::<Typed>()
}

#[test]
fn env_files_are_config_sources_with_envy_semantics() {
  let dir = TestDir::new("env_file_source");
  let toml = dir.write(
    "defaults.toml",
    "port = 1\ndebug = false\ntitle = \"app\"",
  );
  // Names lowercase to the struct's fields, values coerce into
  // their types, comma lists become vectors.
  let env = dir.write(
    ".env",
    "# secrets\nexport DB_PASSWORD=\"hunter2 \\\"quoted\\\"\"\nPORT=8080\nDEBUG=true\nALLOWED_HOSTS=a.example.com, b.example.com\nREGION=eu\n",
  );
  let config = load_typed(&[&toml, &env]).unwrap();
  assert_eq!(
    config,
    Typed {
      db_password: "hunter2 \"quoted\"".into(),
      port: 8080,
      debug: true,
      allowed_hosts: vec![
        "a.example.com".into(),
        "b.example.com".into()
      ],
      region: Some("eu".into()),
      title: "app".into(),
    }
  );
  // Later paths still win: a toml after the env file overrides it.
  let override_toml = dir.write("override.toml", "port = 9090");
  let config = load_typed(&[&toml, &env, &override_toml]).unwrap();
  assert_eq!(config.port, 9090);
  assert_eq!(config.db_password, "hunter2 \"quoted\"");
}

#[test]
fn env_extension_files_are_env_files_too() {
  let dir = TestDir::new("env_extension");
  let env = dir.write(
    "app.env",
    "DB_PASSWORD=x\nPORT=443\nDEBUG=false\nALLOWED_HOSTS=\n",
  );
  let config = load_typed(&[&env]).unwrap();
  assert_eq!(config.port, 443);
  // An empty list value is an empty vector, not one empty entry.
  assert!(config.allowed_hosts.is_empty());
  assert_eq!(config.region, None);
  assert_eq!(config.title, "untitled");
}

#[test]
fn env_file_values_are_never_interpolated() {
  let var = "MOGH_CONFIG_TEST_ENV_FILE_VAR";
  unsafe { std::env::set_var(var, "expanded") };
  let dir = TestDir::new("env_file_verbatim");
  // The toml value interpolates, the env file's does not (a secret
  // holding `$(...)` must not run anything).
  let toml = dir
    .write("config.toml", &format!("interpolated = \"${{{var}}}\""));
  let env = dir
    .write(".env", &format!("VERBATIM=${{{var}}} $(echo) still\n"));
  let config = load(&[&toml, &env], &[], true, false);
  assert_eq!(
    config,
    serde_json::json!({
      "interpolated": "expanded",
      "verbatim": format!("${{{var}}} $(echo) still"),
    })
  );
}

#[test]
fn string_values_coerce_from_interpolation_too() {
  let var = "MOGH_CONFIG_TEST_PORT_VAR";
  unsafe { std::env::set_var(var, "7070") };
  let dir = TestDir::new("interpolated_coercion");
  let toml = dir.write(
    "config.toml",
    &format!(
      "db_password = \"x\"\nport = \"${{{var}}}\"\ndebug = \"true\""
    ),
  );
  let config = load_typed(&[&toml]).unwrap();
  assert_eq!(config.port, 7070);
  assert!(config.debug);
}

#[test]
fn env_file_errors_name_the_line_not_the_value() {
  let dir = TestDir::new("env_file_errors");
  // A malformed file is reported and skipped like a malformed toml.
  let bad = dir.write(".env", "DB_PASSWORD=x\nnot an entry\n");
  let good = dir.write(
    "app.env",
    "DB_PASSWORD=hunter2secret\nPORT=notaport\nDEBUG=true\n",
  );
  let err = load_typed(&[&bad, &good]).unwrap_err().to_string();
  assert!(err.contains("at 'port'"), "{err}");
  assert!(err.contains("expected u16"), "{err}");
  assert!(!err.contains("notaport"), "{err}");
  assert!(!err.contains("hunter2secret"), "{err}");
  let err = mogh_config::parse_env_file("A=1\nnope").unwrap_err();
  assert_eq!(err.line, 2);
}

#[test]
fn dotted_env_names_nest_into_structs() {
  #[derive(serde::Deserialize, Debug, PartialEq)]
  struct Database {
    address: String,
    username: String,
    password: String,
    #[serde(default)]
    pool_size: u32,
  }
  #[derive(serde::Deserialize, Debug, PartialEq)]
  struct Config {
    title: String,
    database: Database,
  }
  let dir = TestDir::new("dotted_env_names");
  // Defaults in toml, secrets from the env file; the nested merge
  // keeps the toml keys the env file does not set.
  let toml = dir.write(
    "defaults.toml",
    "title = \"app\"\n[database]\naddress = \"localhost:5432\"\npool_size = 4\n",
  );
  let env = dir.write(
    ".env",
    "DATABASE.ADDRESS=db.example.com:5432\nDATABASE.USERNAME=app\nDATABASE.PASSWORD=\"hunter2\"\n",
  );
  let config = ConfigLoader {
    paths: &[&toml, &env],
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  }
  .load::<Config>()
  .unwrap();
  assert_eq!(
    config,
    Config {
      title: "app".into(),
      database: Database {
        address: "db.example.com:5432".into(),
        username: "app".into(),
        password: "hunter2".into(),
        pool_size: 4,
      },
    }
  );
  // A conflicting file is refused (reported and skipped, like a
  // malformed toml), and the error names the line, not the value.
  let bad = dir
    .write("bad.env", "DATABASE=secretvalue\nDATABASE.ADDRESS=x\n");
  let err = mogh_config::parse_env_file_object(
    &std::fs::read_to_string(&bad).unwrap(),
  )
  .unwrap_err();
  assert_eq!(err.line, 2);
  assert!(!err.to_string().contains("secretvalue"));
}

/// Cicada accepts secret names which cannot nest on dots (a
/// Kubernetes style `.dockerconfigjson`, `a..b`): each loads as one
/// flat key rather than failing the whole source, and the rest of
/// the file still nests. Only real conflicts fail it.
#[test]
fn env_names_that_cannot_nest_stay_flat_keys() {
  #[derive(serde::Deserialize, Debug, PartialEq)]
  struct Database {
    address: String,
  }
  #[derive(serde::Deserialize, Debug, PartialEq)]
  struct Config {
    #[serde(rename = ".dockerconfigjson")]
    docker_config_json: String,
    #[serde(rename = "a..b")]
    a_b: u16,
    database: Database,
  }
  let dir = TestDir::new("flat_env_names");
  let env = dir.write(
    ".env",
    ".dockerconfigjson={\"auths\":{}}\nA..B=7\nDATABASE.ADDRESS=db:5432\n",
  );
  let config = ConfigLoader {
    paths: &[&env],
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  }
  .load::<Config>()
  .unwrap();
  assert_eq!(
    config,
    Config {
      docker_config_json: "{\"auths\":{}}".into(),
      a_b: 7,
      database: Database {
        address: "db:5432".into(),
      },
    }
  );
  // Two names which collide after lowercasing still fail, naming
  // the line and both names (never a value).
  let err =
    mogh_config::parse_env_file_object("DB=secretvalue\ndb=other")
      .unwrap_err();
  assert_eq!(err.line, 2);
  assert_eq!(
    err.to_string(),
    "line 2: `db` conflicts with `DB` (line 1): names are case insensitive"
  );
}

#[test]
fn env_lists_extend_arrays_under_extend_array() {
  let dir = TestDir::new("env_list_extend");
  let toml = dir.write("a.toml", "hosts = [\"a\"]\nport = 1\n");
  let env = dir.write("b.env", "HOSTS=b, c\nPORT=2\n");
  // extend_array: the list extends, and the rest of the env file
  // still applies (it used to be dropped with a type mismatch).
  let config = load(&[&toml, &env], &[], true, true);
  assert_eq!(
    config,
    serde_json::json!({ "hosts": ["a", "b", "c"], "port": "2" })
  );
  // Without it, the list replaces.
  let config = load(&[&toml, &env], &[], true, false);
  assert_eq!(
    config,
    serde_json::json!({ "hosts": "b, c", "port": "2" })
  );
}

#[test]
fn directory_scans_only_load_env_files_by_wildcard() {
  let dir = TestDir::new("env_dir_scan");
  dir.write("main.toml", "port = 1\n");
  // A compose style `.env` next to the config.
  dir.write(".env", "PORT=99\nCOMPOSE_PROJECT_NAME=x\n");
  // No wildcards: every toml, no env file.
  let config = load(&[&dir.0], &[], true, false);
  assert_eq!(config, serde_json::json!({ "port": 1 }));
  // Asked for by wildcard: loaded, and later than main.toml (a later
  // wildcard wins within the directory).
  let config = load(&[&dir.0], &["*.toml", ".env"], true, false);
  assert_eq!(
    config,
    serde_json::json!({ "port": "99", "compose_project_name": "x" })
  );
}

#[test]
fn coercion_errors_inside_lists_report_the_string() {
  #[derive(serde::Deserialize, Debug)]
  #[allow(dead_code)]
  struct Pins {
    pins: Vec<u8>,
  }
  let dir = TestDir::new("list_error_path");
  let env = dir.write(".env", "PINS=1, secretx, 3\n");
  let err = ConfigLoader {
    paths: &[&env],
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  }
  .load::<Pins>()
  .unwrap_err()
  .to_string();
  assert!(err.contains("at 'pins[1]'"), "{err}");
  assert!(err.contains("found string"), "{err}");
  assert!(!err.contains("secretx"), "{err}");
}

/// A json key is a string, and it coerces into the map's key type,
/// as it did before the lenient final deserialization: typed toml
/// keys and env file keys alike.
#[test]
fn map_keys_coerce_into_their_types() {
  use std::collections::{BTreeMap, HashMap};

  #[derive(serde::Deserialize, Debug, PartialEq, Eq, Hash)]
  struct Team(String);

  #[derive(serde::Deserialize, Debug, PartialEq, Eq, Hash)]
  #[serde(rename_all = "snake_case")]
  enum Stage {
    PreRelease,
    Stable,
  }

  #[derive(serde::Deserialize, Debug)]
  struct Config {
    ports: HashMap<u16, String>,
    limits: BTreeMap<u64, u32>,
    flags: HashMap<bool, String>,
    owners: HashMap<Team, String>,
    stages: HashMap<Stage, u8>,
  }
  let dir = TestDir::new("map_keys");
  let toml = dir.write(
    "config.toml",
    "[ports]\n8080 = \"api\"\n[limits]\n10 = 1\n[flags]\ntrue = \"on\"\n[owners]\nops = \"max\"\n[stages]\npre_release = 1\n",
  );
  let env = dir.write(
    ".env",
    "PORTS.9090=metrics\nLIMITS.10=2\nSTAGES.STABLE=3\n",
  );
  let config = ConfigLoader {
    paths: &[&toml, &env],
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  }
  .load::<Config>()
  .unwrap();
  assert_eq!(
    config.ports,
    HashMap::from([(8080, "api".into()), (9090, "metrics".into())])
  );
  assert_eq!(config.limits, BTreeMap::from([(10, 2)]));
  assert_eq!(config.flags, HashMap::from([(true, "on".into())]));
  assert_eq!(
    config.owners,
    HashMap::from([(Team("ops".into()), "max".into())])
  );
  assert_eq!(
    config.stages,
    HashMap::from([(Stage::PreRelease, 1), (Stage::Stable, 3)])
  );
}
