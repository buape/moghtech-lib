use std::{
  sync::{Mutex, PoisonError},
  time::Duration,
};

use anyhow::Context as _;
use opentelemetry::{KeyValue, global, trace::TracerProvider};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
  Resource,
  trace::{Sampler, SdkTracerProvider},
};
use opentelemetry_semantic_conventions::resource::SERVICE_VERSION;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{Layer, registry::LookupSpan};

/// The target prefix of the OpenTelemetry crates' own diagnostics
/// (`opentelemetry_sdk`, `opentelemetry-otlp`, ...), eg the batch
/// processor's export errors.
pub const INTERNAL_TARGET: &str = "opentelemetry";

/// The standard OTLP/HTTP traces path.
const TRACES_PATH: &str = "/v1/traces";

/// The OTLP gRPC port, which this exporter can't talk to.
const GRPC_PORT: &str = "4317";

/// The provider [init](crate::init) installed, kept for
/// [shutdown]. Only the global subscriber holds it otherwise, and
/// that is never dropped.
static PROVIDER: Mutex<Option<SdkTracerProvider>> = Mutex::new(None);

/// Whether the endpoint turns exporting on. A blank one (empty or
/// only whitespace, eg. an unset templated env value) disables it:
/// given to the exporter, it would fall back to
/// `OTEL_EXPORTER_OTLP_ENDPOINT` or localhost instead.
pub fn enabled(endpoint: &str) -> bool {
  !endpoint.trim().is_empty()
}

/// The exporting layer, and its provider to [install] once the
/// subscriber is.
pub fn layer<S>(
  config: &impl crate::LogConfig,
) -> anyhow::Result<(impl Layer<S>, SdkTracerProvider)>
where
  S: tracing::Subscriber + for<'span> LookupSpan<'span>,
{
  let endpoint = config.otlp_endpoint();
  anyhow::ensure!(enabled(endpoint), "otlp endpoint is blank");

  let exporter = opentelemetry_otlp::SpanExporter::builder()
    .with_http()
    .with_endpoint(traces_endpoint(endpoint))
    .with_timeout(Duration::from_secs(3))
    .build()
    .context("failed to build otlp span exporter")?;

  let provider =
    opentelemetry_sdk::trace::TracerProviderBuilder::default()
      .with_resource(resource(config))
      .with_sampler(Sampler::AlwaysOn)
      .with_batch_exporter(exporter)
      .build();

  let layer = OpenTelemetryLayer::new(
    provider.tracer(config.opentelemetry_scope_name()),
  )
  .with_tracked_inactivity(false)
  .with_threads(false)
  .with_target(false);

  Ok((layer, provider))
}

/// Makes `provider` the global tracer provider and keeps it for
/// [shutdown].
pub fn install(provider: SdkTracerProvider) {
  global::set_tracer_provider(provider.clone());
  *PROVIDER.lock().unwrap_or_else(PoisonError::into_inner) =
    Some(provider);
}

/// Exports the spans still queued and stops the exporter. A no-op
/// when nothing is installed, or it already ran.
pub fn shutdown() -> anyhow::Result<()> {
  let provider = PROVIDER
    .lock()
    .unwrap_or_else(PoisonError::into_inner)
    .take();
  match provider {
    Some(provider) => provider
      .shutdown()
      .context("failed to shut down otel exporter"),
    None => Ok(()),
  }
}

/// The resource the traces are exported under. `service.version`
/// is only set when the app gives one: a value set here would also
/// override `OTEL_RESOURCE_ATTRIBUTES`.
fn resource(config: &impl crate::LogConfig) -> Resource {
  let resource = Resource::builder()
    .with_service_name(config.opentelemetry_service_name());
  match config.opentelemetry_service_version() {
    Some(version) => resource
      .with_attribute(KeyValue::new(SERVICE_VERSION, version))
      .build(),
    None => resource.build(),
  }
}

/// The url the exporter posts to. A base url without a path
/// (`http://localhost:4318`) gets the standard `/v1/traces`, like
/// `OTEL_EXPORTER_OTLP_ENDPOINT` does. One with a path is used as
/// given.
fn traces_endpoint(endpoint: &str) -> String {
  let endpoint = endpoint.trim();
  match split_url(endpoint) {
    Some((base, "" | "/", suffix)) => {
      format!("{base}{TRACES_PATH}{suffix}")
    }
    // Anything else, including no scheme (which the exporter
    // rejects), as given.
    _ => endpoint.to_string(),
  }
}

/// Whether the endpoint names the OTLP gRPC port. The exporter
/// speaks OTLP/HTTP only, so it would fail every export.
pub fn uses_grpc_port(endpoint: &str) -> bool {
  let Some((base, _, _)) = split_url(endpoint.trim()) else {
    return false;
  };
  let authority = base
    .split_once("://")
    .map_or(base, |(_, authority)| authority);
  let host = authority
    .rsplit_once('@')
    .map_or(authority, |(_, host)| host);
  // An IPv6 host without a port ends in ']'.
  host
    .rsplit_once(':')
    .is_some_and(|(_, port)| port == GRPC_PORT)
}

/// Splits a url into `scheme://authority`, the path, and the query
/// / fragment. `None` without a scheme.
fn split_url(url: &str) -> Option<(&str, &str, &str)> {
  let authority_start = url.find("://")? + 3;
  let path_start = url[authority_start..]
    .find(['/', '?', '#'])
    .map_or(url.len(), |index| authority_start + index);
  let (base, rest) = url.split_at(path_start);
  let suffix_start = rest.find(['?', '#']).unwrap_or(rest.len());
  let (path, suffix) = rest.split_at(suffix_start);
  Some((base, path, suffix))
}

#[cfg(test)]
mod tests {
  use opentelemetry::Key;

  use super::*;

  #[test]
  fn traces_endpoint_adds_the_traces_path_to_a_base_url() {
    for (endpoint, expected) in [
      ("http://localhost:4318", "http://localhost:4318/v1/traces"),
      ("http://localhost:4318/", "http://localhost:4318/v1/traces"),
      (" https://otel:4318 ", "https://otel:4318/v1/traces"),
      ("http://[::1]:4318", "http://[::1]:4318/v1/traces"),
      (
        "https://user:pass@otel:4318?key=value",
        "https://user:pass@otel:4318/v1/traces?key=value",
      ),
      // A path is used as given.
      (
        "http://localhost:4318/v1/traces",
        "http://localhost:4318/v1/traces",
      ),
      ("https://vendor/otlp/traces", "https://vendor/otlp/traces"),
      // Without a scheme, as given for the exporter to reject.
      ("localhost:4318", "localhost:4318"),
      (
        "http://localhost:4318/custom?key=value",
        "http://localhost:4318/custom?key=value",
      ),
    ] {
      assert_eq!(traces_endpoint(endpoint), expected, "{endpoint}");
    }
  }

  #[test]
  fn uses_grpc_port_detects_port_4317() {
    for endpoint in [
      "http://localhost:4317",
      "http://localhost:4317/v1/traces",
      "https://user:pass@otel:4317?key=value",
      "http://[::1]:4317",
    ] {
      assert!(uses_grpc_port(endpoint), "{endpoint}");
    }
    for endpoint in [
      "http://localhost:4318/v1/traces",
      "http://localhost/4317",
      "http://[2001:db8::4317]",
      "https://otel",
      "localhost:4317",
    ] {
      assert!(!uses_grpc_port(endpoint), "{endpoint}");
    }
  }

  struct EndpointConfig(&'static str);

  impl crate::LogConfig for EndpointConfig {
    fn otlp_endpoint(&self) -> &str {
      self.0
    }
  }

  /// Given a blank endpoint, the exporter falls back to the env or
  /// localhost: blank has to mean off, and never reach it.
  #[test]
  fn blank_endpoint_disables_exporting() {
    for endpoint in ["", " ", "  \t\n"] {
      assert!(!enabled(endpoint), "{endpoint:?}");
      let built = layer::<tracing_subscriber::Registry>(
        &EndpointConfig(endpoint),
      );
      assert!(built.is_err(), "{endpoint:?}");
    }
    assert!(enabled("http://localhost:4318"));
    assert!(enabled(" http://localhost:4318 "));
  }

  struct Config(Option<&'static str>);

  impl crate::LogConfig for Config {
    fn opentelemetry_service_name(&self) -> String {
      String::from("TestApp")
    }
    fn opentelemetry_service_version(&self) -> Option<String> {
      self.0.map(str::to_string)
    }
  }

  #[test]
  fn resource_reports_the_app_service_version() {
    let service_version = Key::from_static_str(SERVICE_VERSION);
    let with_version = resource(&Config(Some("2.3.0")));
    assert_eq!(
      with_version.get(&service_version).map(|v| v.to_string()),
      Some(String::from("2.3.0"))
    );
    assert_eq!(
      with_version
        .get(&Key::from_static_str("service.name"))
        .map(|v| v.to_string()),
      Some(String::from("TestApp"))
    );
    // Not the logger crate's own version.
    assert!(resource(&Config(None)).get(&service_version).is_none());
  }
}
