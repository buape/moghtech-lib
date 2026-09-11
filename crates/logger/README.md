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
let span = tracing::info_span!(parent: None, "HandleRequest");
if let Some(traceparent) = headers.get(mogh_logger::TRACEPARENT_HEADER) {
  mogh_logger::set_remote_parent(&span, traceparent);
}
```

`opentelemetry` and `tracing_opentelemetry` are re-exported for
anything beyond this, so they always match the layer's version.
