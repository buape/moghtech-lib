use anyhow::Context;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{
  Layer, filter::Targets, layer::SubscriberExt as _,
  util::SubscriberInitExt,
};

mod config;
mod otel;

pub use config::*;

pub fn init(config: impl config::LogConfig) -> anyhow::Result<()> {
  let mut filter_targets =
    Targets::new().with_default(LevelFilter::OFF);

  for target in config.targets() {
    filter_targets =
      filter_targets.with_target(target, config.level());
  }

  let registry = tracing_subscriber::registry().with(filter_targets);

  let use_otel = !config.otlp_endpoint().is_empty();

  // Boxing the stdio layer keeps a single init path
  // across the different formatter configurations.
  let stdio_layer: Option<Box<dyn Layer<_> + Send + Sync>> =
    match config.stdio() {
      StdioLogMode::Standard => {
        if config.pretty() {
          let layer = tracing_subscriber::fmt::layer()
            .pretty()
            .with_file(false)
            .with_line_number(false)
            .with_target(config.location())
            .with_ansi(config.ansi());
          Some(if config.timestamps() {
            layer.boxed()
          } else {
            layer.without_time().boxed()
          })
        } else {
          let layer = tracing_subscriber::fmt::layer()
            .with_file(false)
            .with_line_number(false)
            .with_target(config.location())
            .with_ansi(config.ansi());
          Some(if config.timestamps() {
            layer.boxed()
          } else {
            layer.without_time().boxed()
          })
        }
      }
      StdioLogMode::Json => {
        let layer = tracing_subscriber::fmt::layer().json();
        Some(if config.timestamps() {
          layer.boxed()
        } else {
          layer.without_time().boxed()
        })
      }
      StdioLogMode::None => None,
    };

  let otel_layer = if use_otel {
    Some(
      otel::layer(&config).context("failed to init otel exporter")?,
    )
  } else {
    None
  };

  if stdio_layer.is_none() && otel_layer.is_none() {
    // Nothing to log to, leave the subscriber uninitialized.
    return Ok(());
  }

  registry
    .with(stdio_layer)
    .with(otel_layer)
    .try_init()
    .context("failed to init logger")
}
