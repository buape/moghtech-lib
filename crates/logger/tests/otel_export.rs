//! OTLP export end to end, against a local collector stand in.
//! Its own test binary: [mogh_logger::init] installs the process
//! wide subscriber.
#![allow(unused_crate_dependencies)]

use std::{
  io::{BufRead as _, BufReader, Read as _, Write as _},
  net::TcpListener,
  sync::{Arc, Mutex},
};

use mogh_logger::{LogConfig, StdioLogMode};

struct Config {
  otlp_endpoint: String,
  targets: Vec<String>,
}

impl LogConfig for Config {
  fn stdio(&self) -> StdioLogMode {
    StdioLogMode::None
  }
  fn otlp_endpoint(&self) -> &str {
    &self.otlp_endpoint
  }
  fn targets(&self) -> &[String] {
    &self.targets
  }
}

/// A received export: the request line and the body.
type Export = (String, Vec<u8>);

/// Accepts OTLP/HTTP exports, answering each with an empty (ie.
/// fully accepted) response. An export is recorded before it is
/// answered, so it is visible once the exporter returns.
fn collector() -> (u16, Arc<Mutex<Vec<Export>>>) {
  let listener = TcpListener::bind("127.0.0.1:0").unwrap();
  let port = listener.local_addr().unwrap().port();
  let exports = Arc::new(Mutex::new(Vec::new()));
  let recorded = exports.clone();
  std::thread::spawn(move || {
    for stream in listener.incoming() {
      let Ok(mut stream) = stream else { continue };
      let mut reader = BufReader::new(stream.try_clone().unwrap());
      let mut request_line = String::new();
      reader.read_line(&mut request_line).unwrap();
      let mut content_length = 0;
      loop {
        let mut header = String::new();
        reader.read_line(&mut header).unwrap();
        let header = header.trim_end();
        if header.is_empty() {
          break;
        }
        if let Some((name, value)) = header.split_once(':')
          && name.eq_ignore_ascii_case("content-length")
        {
          content_length = value.trim().parse().unwrap();
        }
      }
      let mut body = vec![0; content_length];
      reader.read_exact(&mut body).unwrap();
      recorded
        .lock()
        .unwrap()
        .push((request_line.trim_end().to_string(), body));
      stream
        .write_all(
          b"HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    }
  });
  (port, exports)
}

#[test]
fn shutdown_exports_the_queued_spans() {
  let (port, exports) = collector();
  mogh_logger::init(Config {
    // No path: the standard traces path is added.
    otlp_endpoint: format!("http://127.0.0.1:{port}"),
    targets: vec![String::from("otel_export")],
  })
  .unwrap();

  tracing::info_span!("QueuedSpan").in_scope(|| {
    tracing::info!("inside the span");
  });
  // The batch exporter sends every 5s: nothing has gone out yet,
  // and before 'shutdown' existed nothing ever did at exit.
  assert!(exports.lock().unwrap().is_empty());

  mogh_logger::shutdown().unwrap();

  let exports = exports.lock().unwrap();
  assert_eq!(exports.len(), 1);
  let (request_line, body) = &exports[0];
  assert!(
    request_line.starts_with("POST /v1/traces "),
    "{request_line}"
  );
  assert!(
    body.windows(10).any(|window| window == b"QueuedSpan"),
    "the span is in the export"
  );
  drop(exports);

  // Once shut down, it is a no-op.
  mogh_logger::shutdown().unwrap();
}
