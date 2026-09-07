use std::{path::PathBuf, sync::LazyLock};

use colored::Colorize as _;
use regex::{Captures, Regex};

/// Prefer bash, resolved once.
static SHELL: LazyLock<&'static str> = LazyLock::new(|| {
  if PathBuf::from("/bin/bash").exists() {
    "bash"
  } else {
    "sh"
  }
});

/// `${var_name}` syntax
static ENV_REGEX: LazyLock<Regex> =
  LazyLock::new(|| Regex::new(r"\$\{([A-Za-z0-9_]+)\}").unwrap());

/// `$(command)` syntax
static SHELL_REGEX: LazyLock<Regex> =
  LazyLock::new(|| Regex::new(r"\$\(([A-Za-z0-9_]+)\)").unwrap());

/// Either syntax, for a single pass over the input.
static ENV_OR_SHELL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
  Regex::new(r"\$\{([A-Za-z0-9_]+)\}|\$\(([A-Za-z0-9_]+)\)").unwrap()
});

/// Whether the string contains anything to interpolate.
pub fn needs_interpolation(input: &str) -> bool {
  input.contains("${") || input.contains("$(")
}

/// - Supports '${VAR}' -> Env var extended
/// - Supports '$(shell command)' -> 'echo $(shell command)'
///
/// Each `${VAR}` / `$(command)` in the input is substituted once,
/// in a single pass. Substituted text is never itself interpolated,
/// so `$(...)` inside an env var value is not executed and `${...}`
/// inside a command's output is kept verbatim. The one exception is
/// that env var values may reference other env vars (`${OTHER}`),
/// which are expanded one level.
pub fn interpolate_env_and_shell(input: &str) -> String {
  if !needs_interpolation(input) {
    return input.to_string();
  }
  ENV_OR_SHELL_REGEX
    .replace_all(input, |caps: &Captures| {
      if let Some(var_name) = caps.get(1) {
        let value = try_get_env_extended(var_name.as_str(), &SHELL);
        // Env vars may expand to other env vars.
        ENV_REGEX
          .replace_all(&value, |caps: &Captures| {
            try_get_env_extended(&caps[1], &SHELL)
          })
          .into_owned()
      } else {
        run_shell_command(&caps[2], &SHELL)
      }
    })
    .into_owned()
}

/// Applies [interpolate_env_and_shell] to every string in the
/// value, including object keys, in place. Objects are only
/// rebuilt when one of their keys needs interpolation.
pub fn interpolate_value(value: &mut serde_json::Value) {
  match value {
    serde_json::Value::String(s) => {
      if needs_interpolation(s) {
        *s = interpolate_env_and_shell(s);
      }
    }
    serde_json::Value::Array(items) => {
      items.iter_mut().for_each(interpolate_value);
    }
    serde_json::Value::Object(map) => {
      map.values_mut().for_each(interpolate_value);
      if map.keys().any(|key| needs_interpolation(key)) {
        let entries = std::mem::take(map);
        for (key, value) in entries {
          map.insert(interpolate_env_and_shell(&key), value);
        }
      }
    }
    _ => {}
  }
}

/// - Supports '${VAR}' -> Env var extended
pub fn interpolate_env(input: &str, shell: &str) -> String {
  let first_env_pass = ENV_REGEX
    .replace_all(input, |caps: &Captures| {
      try_get_env_extended(&caps[1], shell)
    });

  // Do it twice in case any env vars expand again to env vars
  ENV_REGEX
    .replace_all(&first_env_pass, |caps: &Captures| {
      try_get_env_extended(&caps[1], shell)
    })
    .into_owned()
}

fn try_get_env_extended(var_name: &str, shell: &str) -> String {
  if let Ok(value) = std::env::var(var_name)
    && !value.is_empty()
  {
    return value;
  }
  let Ok(output) = std::process::Command::new(shell)
    .arg("-c")
    .arg(format!("echo ${var_name}"))
    .output()
  else {
    return String::new();
  };
  String::from_utf8(output.stdout)
    .map(|value| value.trim().to_string())
    .inspect_err(|e| println!("{}: Failed to parse shell stdout for ${var_name} as utf-8: {e}", "WARN".yellow()))
    .unwrap_or_default()
}

/// - Supports '$(shell command)' -> 'echo $(shell command)'
pub fn interpolate_shell(input: &str, shell: &str) -> String {
  SHELL_REGEX
    .replace_all(input, |caps: &Captures| {
      run_shell_command(&caps[1], shell)
    })
    .into_owned()
}

fn run_shell_command(command: &str, shell: &str) -> String {
  let Ok(output) = std::process::Command::new(shell)
    .arg("-c")
    .arg(command)
    .output()
    .inspect_err(|e| {
      println!(
        "{}: Failed to get output for $({command}): {e}",
        "WARN".yellow()
      )
    })
  else {
    return String::new();
  };
  String::from_utf8(output.stdout)
    .map(|value| value.trim().to_string())
    .inspect_err(|e| println!("{}: Failed to parse shell stdout for $({command}) as utf-8: {e}", "WARN".yellow()))
    .unwrap_or_default()
}
