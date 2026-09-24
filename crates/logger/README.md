# Mogh Logger

Configurable application level logger. Handles internals for multiple output modes including open telemetry.

```rust
struct Config;

// Sets output to JSON
impl mogh_logger::LogConfig for Config {
  fn stdio(&self) -> mogh_logger::StdioLogMode {
    mogh_logger::StdioLogMode::Json
  }

  fn targets(&self) -> &[String] {
    use std::sync::LazyLock;
    static TARGETS: LazyLock<Vec<String>> =
      LazyLock::new(|| {
        ["binary_name"].into_iter().map(str::to_string).collect()
      });
    &TARGETS
  }
}

// On application startup
mogh_logger::init(Config)?;
```

## OpenTelemetry export

`LogConfig::otlp_endpoint` turns on exporting traces to an
OpenTelemetry collector:

- It is the collector's **OTLP/HTTP** (protobuf) traces url, eg.
  `http://localhost:4318/v1/traces`. gRPC (port `4317`) is not
  supported. A url without a path (`http://localhost:4318`) gets the
  standard `/v1/traces`, one with a path is used as given. Empty (or
  whitespace only) disables exporting.
- Failed exports are logged under the `opentelemetry*` targets (eg.
  `ERROR name="BatchSpanProcessor.ExportError"`). While exporting
  these are let through at WARN, even when not in `targets`.
- Set `opentelemetry_service_version` to report the app's version as
  `service.version` (unset by default):

  ```rust
  fn opentelemetry_service_version(&self) -> Option<String> {
    Some(env!("CARGO_PKG_VERSION").into())
  }
  ```

- Spans are exported in batches every few seconds. Call
  `mogh_logger::shutdown()` before the process exits, including after
  a graceful shutdown signal, or the ones still queued are lost. It
  blocks until the export finishes, and is a no-op without an
  endpoint.

  ```rust
  mogh_logger::init(Config)?;
  let res = app().await;
  mogh_logger::shutdown()?;
  res
  ```

## Trace context propagation

With `otlp_endpoint` set on both sides of a request, the caller
sends the W3C `traceparent` of its current span and the callee
parents its span under it, so both land in one trace:

```rust
// Caller: attach to the outgoing request, if this process is exporting.
if let Some(traceparent) = mogh_logger::current_traceparent() {
  request = request.header(mogh_logger::TRACEPARENT_HEADER, traceparent);
}

// Callee: before entering the span that handles the request.
// Only for trusted (eg. authenticated service to service) callers.
let span = tracing::info_span!(parent: None, "HandleRequest");
if let Some(traceparent) = headers
  .get(mogh_logger::TRACEPARENT_HEADER)
  .and_then(|value| value.to_str().ok())
{
  mogh_logger::set_remote_parent(&span, traceparent);
}
```

An inbound `traceparent` is whatever the caller sent: honoring it
lets the caller pick the trace your spans join. Only honor it from
trusted callers (your own services, authenticated as such). Public
traffic (browsers, api keys) should start a fresh trace, as the
[W3C Trace Context security considerations](https://www.w3.org/TR/trace-context/#security-considerations)
recommend.

`opentelemetry` and `tracing_opentelemetry` are re-exported for
anything beyond this, so they always match the layer's version.
