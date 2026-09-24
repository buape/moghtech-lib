use serde::{Deserialize, Serialize};

#[derive(
  Debug,
  Clone,
  Copy,
  Default,
  PartialEq,
  Eq,
  Hash,
  Serialize,
  Deserialize,
)]
pub enum StdioLogMode {
  #[default]
  Standard,
  Json,
  None,
}

/// De/serializable log level enum.
/// Implements Into<tracing::Level>.
#[derive(
  Debug,
  Clone,
  Copy,
  Default,
  PartialEq,
  Eq,
  Hash,
  Serialize,
  Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
  Trace,
  Debug,
  #[default]
  Info,
  Warn,
  Error,
}

impl From<LogLevel> for tracing::Level {
  fn from(value: LogLevel) -> Self {
    match value {
      LogLevel::Trace => tracing::Level::TRACE,
      LogLevel::Debug => tracing::Level::DEBUG,
      LogLevel::Info => tracing::Level::INFO,
      LogLevel::Warn => tracing::Level::WARN,
      LogLevel::Error => tracing::Level::ERROR,
    }
  }
}

pub trait LogConfig {
  /// The logging level.
  fn level(&self) -> tracing::Level {
    tracing::Level::INFO
  }

  /// Controls logging format to stdout / stderr
  fn stdio(&self) -> StdioLogMode {
    StdioLogMode::Standard
  }

  /// Use tracing-subscriber's pretty logging output option.
  fn pretty(&self) -> bool {
    false
  }

  /// Include information about the log location (ie the function which produced the log).
  /// Tracing refers to this as the 'target'.
  fn location(&self) -> bool {
    false
  }

  /// Logs use ansi colors for readability.
  fn ansi(&self) -> bool {
    true
  }

  /// Include timestamps with logs
  fn timestamps(&self) -> bool {
    true
  }

  /// Enable opentelemetry exporting.
  /// An empty (or whitespace only) string disables exporting.
  ///
  /// The collector's OTLP/HTTP (protobuf) traces url, eg
  /// `http://localhost:4318/v1/traces`. gRPC (port 4317) is not
  /// supported. A url with a path is used as given, and one without
  /// (`http://localhost:4318`) gets the standard `/v1/traces`.
  ///
  /// Failed exports are logged at WARN / ERROR under the
  /// `opentelemetry*` targets (ie `opentelemetry_sdk`), which
  /// [init](crate::init) lets through while exporting even when
  /// they are not in [targets](LogConfig::targets). Call
  /// [shutdown](crate::shutdown) before exiting, or the spans still
  /// queued are lost.
  fn otlp_endpoint(&self) -> &str {
    ""
  }

  /// Set the OTEL service name for exported traces
  fn opentelemetry_service_name(&self) -> String {
    String::from("MoghApp")
  }

  /// Set the OTEL `service.version` for exported traces, usually
  /// `Some(env!("CARGO_PKG_VERSION").into())` in the application
  /// crate. `None` (the default) leaves it unset, so
  /// `OTEL_RESOURCE_ATTRIBUTES` can still supply it.
  fn opentelemetry_service_version(&self) -> Option<String> {
    None
  }

  /// Set the OTEL scope name for exported traces
  fn opentelemetry_scope_name(&self) -> String {
    String::from("MoghApp")
  }

  /// Specify which module targets (eg the current binary) are included.
  ///
  /// ⚠️ Everything else is filtered out, including the default: with
  /// no targets (the default here) nothing is logged at all.
  ///
  /// ```rust
  /// struct MyConfig;
  ///
  /// impl mogh_logger::LogConfig for MyConfig {
  ///   fn targets(&self) -> &[String] {
  ///     use std::sync::LazyLock;
  ///     static TARGETS: LazyLock<Vec<String>> =
  ///       LazyLock::new(|| {
  ///         ["binary_name"].into_iter().map(str::to_string).collect()
  ///       });
  ///     &TARGETS
  ///   }
  /// }
  /// ```
  fn targets(&self) -> &[String] {
    &[]
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn log_level_parses_lowercase() {
    for (json, expected) in [
      ("\"trace\"", LogLevel::Trace),
      ("\"debug\"", LogLevel::Debug),
      ("\"info\"", LogLevel::Info),
      ("\"warn\"", LogLevel::Warn),
      ("\"error\"", LogLevel::Error),
    ] {
      let parsed: LogLevel = serde_json::from_str(json).unwrap();
      assert_eq!(parsed, expected);
      assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
    }
    // Non lowercase variants are rejected
    assert!(serde_json::from_str::<LogLevel>("\"Info\"").is_err());
  }

  #[test]
  fn log_level_default_is_info() {
    assert_eq!(LogLevel::default(), LogLevel::Info);
  }

  #[test]
  fn log_level_into_tracing_level() {
    assert_eq!(
      tracing::Level::from(LogLevel::Trace),
      tracing::Level::TRACE
    );
    assert_eq!(
      tracing::Level::from(LogLevel::Debug),
      tracing::Level::DEBUG
    );
    assert_eq!(
      tracing::Level::from(LogLevel::Info),
      tracing::Level::INFO
    );
    assert_eq!(
      tracing::Level::from(LogLevel::Warn),
      tracing::Level::WARN
    );
    assert_eq!(
      tracing::Level::from(LogLevel::Error),
      tracing::Level::ERROR
    );
  }

  #[test]
  fn stdio_log_mode_parses() {
    for (json, expected) in [
      ("\"Standard\"", StdioLogMode::Standard),
      ("\"Json\"", StdioLogMode::Json),
      ("\"None\"", StdioLogMode::None),
    ] {
      let parsed: StdioLogMode = serde_json::from_str(json).unwrap();
      assert_eq!(parsed, expected);
      assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
    }
    assert_eq!(StdioLogMode::default(), StdioLogMode::Standard);
  }

  #[test]
  fn log_config_defaults() {
    struct Default_;
    impl LogConfig for Default_ {}
    let config = Default_;
    assert_eq!(config.level(), tracing::Level::INFO);
    assert_eq!(config.stdio(), StdioLogMode::Standard);
    assert!(!config.pretty());
    assert!(!config.location());
    assert!(config.ansi());
    assert!(config.timestamps());
    assert!(config.otlp_endpoint().is_empty());
    assert!(config.opentelemetry_service_version().is_none());
    assert!(config.targets().is_empty());
  }
}
