//! Bounds how long a client may hold a connection open without
//! sending a request, see [crate::ServerConfig::header_read_timeout].

use std::{
  io,
  pin::Pin,
  task::{Context, Poll},
  time::Duration,
};

use axum_server::accept::Accept;
use hyper_util::{
  rt::{TokioExecutor, TokioTimer},
  server::conn::auto::Builder,
};
use tokio::{
  io::{AsyncRead, AsyncWrite, ReadBuf},
  time::Sleep,
};

/// Configures the connections' http/1 header read timeout (which
/// hyper only applies with a timer), and http/2 keep alive pings,
/// which close the connections of clients no longer there.
pub(crate) fn configure_http(
  builder: &mut Builder<TokioExecutor>,
  header_read_timeout: Option<Duration>,
) {
  builder
    .http1()
    .timer(TokioTimer::new())
    .header_read_timeout(header_read_timeout);
  builder
    .http2()
    .timer(TokioTimer::new())
    .keep_alive_interval(Duration::from_secs(20));
}

/// The first bytes of an http/2 connection.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// The length of an http/2 frame header.
const FRAME_HEADER_LEN: usize = 9;
/// http/2 frame types starting (HEADERS) and continuing
/// (CONTINUATION) a header block.
const HEADERS: u8 = 0x1;
const CONTINUATION: u8 = 0x9;
/// The http/2 flag ending a header block.
const END_HEADERS: u8 = 0x4;

/// Wraps the streams of the `inner` acceptor (after the TLS
/// handshake, with TLS) in a [HeaderTimeout].
///
/// The server reads the first bytes of a connection to tell http/1
/// from http/2 before either protocol's own timeouts apply, and
/// waits for them without a limit, and hyper's http/2 server has no
/// header read timeout at all: a client sending nothing, the start
/// of the http/2 preface, or only http/2 frames other than a
/// request's headers would hold the connection forever.
#[derive(Clone)]
pub(crate) struct HeaderTimeoutAcceptor<A> {
  pub(crate) inner: A,
  pub(crate) timeout: Option<Duration>,
}

type AcceptFuture<S, M> = Pin<
  Box<dyn Future<Output = io::Result<(HeaderTimeout<S>, M)>> + Send>,
>;

impl<A, I, S> Accept<I, S> for HeaderTimeoutAcceptor<A>
where
  A: Accept<I, S>,
  A::Future: Send + 'static,
  A::Stream: Send + 'static,
  A::Service: Send + 'static,
{
  type Stream = HeaderTimeout<A::Stream>;
  type Service = A::Service;
  type Future = AcceptFuture<A::Stream, A::Service>;

  fn accept(&self, stream: I, service: S) -> Self::Future {
    let accepted = self.inner.accept(stream, service);
    let timeout = self.timeout;
    Box::pin(async move {
      let (stream, service) = accepted.await?;
      Ok((HeaderTimeout::new(stream, timeout), service))
    })
  }
}

/// A stream whose reads fail once the client owes the headers of a
/// request for longer than the timeout:
/// - From the connection being accepted until the client sent
///   enough to tell its protocol. http/1 is told as soon as the
///   bytes stop matching the http/2 preface; hyper's http/1 header
///   read timeout then applies.
/// - On http/2, until the first header block (a HEADERS frame and
///   its CONTINUATION frames) arrived whole, and again from the
///   start of each later header block until it arrived whole.
pub(crate) struct HeaderTimeout<S> {
  inner: S,
  timeout: Option<Duration>,
  /// While the client owes headers.
  deadline: Option<Pin<Box<Sleep>>>,
  protocol: Protocol,
}

enum Protocol {
  /// How many bytes of the http/2 preface were read so far.
  Unknown {
    matched: usize,
  },
  /// hyper's own header read timeout applies.
  Http1,
  Http2(Frames),
}

/// Follows the frames an http/2 client sends.
#[derive(Default)]
struct Frames {
  /// The frame header read so far.
  header: [u8; FRAME_HEADER_LEN],
  header_len: usize,
  /// The bytes left of the current frame's payload.
  payload_left: usize,
  /// Whether the current frame ends a header block.
  ends_headers: bool,
}

impl<S> HeaderTimeout<S> {
  pub(crate) fn new(inner: S, timeout: Option<Duration>) -> Self {
    HeaderTimeout {
      inner,
      timeout,
      deadline: timeout
        .map(|timeout| Box::pin(tokio::time::sleep(timeout))),
      protocol: Protocol::Unknown { matched: 0 },
    }
  }

  /// Follows the `read` bytes, lifting the deadline once the client
  /// sent a request's headers, and setting it again when an http/2
  /// client starts another header block.
  fn on_read(&mut self, mut read: &[u8]) {
    let Some(timeout) = self.timeout else {
      return;
    };
    while !read.is_empty() {
      match &mut self.protocol {
        Protocol::Http1 => return,
        Protocol::Unknown { matched } => {
          let expected = &H2_PREFACE[*matched..];
          let len = read.len().min(expected.len());
          if read[..len] != expected[..len] {
            self.protocol = Protocol::Http1;
            self.deadline = None;
            return;
          }
          *matched += len;
          read = &read[len..];
          if *matched == H2_PREFACE.len() {
            self.protocol = Protocol::Http2(Frames::default());
          }
        }
        Protocol::Http2(frames) => {
          if frames.header_len < FRAME_HEADER_LEN {
            let len =
              read.len().min(FRAME_HEADER_LEN - frames.header_len);
            frames.header[frames.header_len..][..len]
              .copy_from_slice(&read[..len]);
            frames.header_len += len;
            read = &read[len..];
            if frames.header_len < FRAME_HEADER_LEN {
              return;
            }
            let [l0, l1, l2, kind, flags, ..] = frames.header;
            frames.payload_left =
              u32::from_be_bytes([0, l0, l1, l2]) as usize;
            frames.ends_headers =
              matches!(kind, HEADERS | CONTINUATION)
                && flags & END_HEADERS != 0;
            if kind == HEADERS && self.deadline.is_none() {
              self.deadline =
                Some(Box::pin(tokio::time::sleep(timeout)));
            }
          }
          let len = read.len().min(frames.payload_left);
          frames.payload_left -= len;
          read = &read[len..];
          if frames.payload_left == 0 {
            // The frame arrived whole.
            frames.header_len = 0;
            if frames.ends_headers {
              self.deadline = None;
            }
          }
        }
      }
    }
  }

  /// Whether the deadline passed, which stays so: every later read
  /// fails too.
  fn expired(&mut self, cx: &mut Context<'_>) -> bool {
    self
      .deadline
      .as_mut()
      .is_some_and(|deadline| deadline.as_mut().poll(cx).is_ready())
  }
}

impl<S: AsyncRead + Unpin> AsyncRead for HeaderTimeout<S> {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    let this = self.get_mut();
    let before = buf.filled().len();
    let poll = match Pin::new(&mut this.inner).poll_read(cx, buf) {
      Poll::Ready(Ok(())) => {
        this.on_read(&buf.filled()[before..]);
        Poll::Ready(Ok(()))
      }
      poll => poll,
    };
    // Checked after reads which return bytes too, not only when a
    // read waits, as a client may keep sending http/2 frames other
    // than headers (eg. pings).
    if !matches!(poll, Poll::Ready(Err(_))) && this.expired(cx) {
      return Poll::Ready(Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "client sent no request headers in time",
      )));
    }
    poll
  }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HeaderTimeout<S> {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
  }

  fn poll_write_vectored(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[io::IoSlice<'_>],
  ) -> Poll<io::Result<usize>> {
    Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
  }

  fn is_write_vectored(&self) -> bool {
    self.inner.is_write_vectored()
  }

  fn poll_flush(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<io::Result<()>> {
    Pin::new(&mut self.get_mut().inner).poll_flush(cx)
  }

  fn poll_shutdown(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<io::Result<()>> {
    Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn stream() -> HeaderTimeout<()> {
    HeaderTimeout::new((), Some(Duration::from_secs(3600)))
  }

  /// An http/2 frame header.
  fn frame(len: u32, kind: u8, flags: u8) -> Vec<u8> {
    let mut header = len.to_be_bytes()[1..].to_vec();
    header.extend([kind, flags, 0, 0, 0, 1]);
    header
  }

  #[tokio::test]
  async fn the_deadline_lasts_until_the_protocol_is_told() {
    // http/1: the first byte tells.
    let mut http1 = stream();
    http1.on_read(b"G");
    assert!(http1.deadline.is_none());
    // Methods starting like the preface.
    let mut http1 = stream();
    http1.on_read(b"P");
    assert!(http1.deadline.is_some());
    http1.on_read(b"OST / HTTP/1.1\r\n");
    assert!(http1.deadline.is_none());
    // Then never set again: hyper's timeout applies.
    http1.on_read(&[H2_PREFACE, &frame(0, HEADERS, 0)].concat());
    assert!(http1.deadline.is_none());
    // http/2: the whole preface, however it is split, is not enough.
    let mut http2 = stream();
    http2.on_read(&H2_PREFACE[..10]);
    http2.on_read(&[]);
    http2.on_read(&H2_PREFACE[10..23]);
    http2.on_read(&H2_PREFACE[23..]);
    assert!(matches!(http2.protocol, Protocol::Http2(_)));
    assert!(http2.deadline.is_some());
  }

  #[tokio::test]
  async fn http2_deadlines_last_until_a_header_block_arrived() {
    // Frames other than headers, eg. SETTINGS and PING.
    let mut http2 = stream();
    http2.on_read(H2_PREFACE);
    http2.on_read(&frame(0, 0x4, 0));
    http2.on_read(&[frame(8, 0x6, 0), vec![7; 8]].concat());
    // A DATA frame with the END_HEADERS bit set.
    http2.on_read(&[frame(1, 0x0, END_HEADERS), vec![1]].concat());
    assert!(http2.deadline.is_some());

    // A HEADERS frame ending the block, split anywhere: only once
    // its payload arrived.
    let headers =
      [frame(3, HEADERS, END_HEADERS), vec![1, 2, 3]].concat();
    for split in 0..headers.len() {
      let mut http2 = stream();
      http2.on_read(H2_PREFACE);
      http2.on_read(&headers[..split]);
      assert!(http2.deadline.is_some(), "{split}");
      http2.on_read(&headers[split..]);
      assert!(http2.deadline.is_none(), "{split}");
    }

    // Along with the preface and other frames in one read.
    let mut http2 = stream();
    http2.on_read(
      &[H2_PREFACE, &frame(0, 0x4, 0), &headers, &frame(2, 0x0, 0)]
        .concat(),
    );
    assert!(http2.deadline.is_none());
    // The DATA frame's payload: not a frame header.
    http2.on_read(&frame(0, HEADERS, 0)[..2]);
    assert!(http2.deadline.is_none());

    // A block continued by CONTINUATION frames.
    let mut http2 = stream();
    http2.on_read(H2_PREFACE);
    http2.on_read(&[frame(2, HEADERS, 0), vec![1, 2]].concat());
    http2.on_read(&[frame(2, CONTINUATION, 0), vec![3, 4]].concat());
    assert!(http2.deadline.is_some());
    http2.on_read(
      &[frame(1, CONTINUATION, END_HEADERS), vec![5]].concat(),
    );
    assert!(http2.deadline.is_none());

    // A later block sets the deadline again, until it arrived.
    http2.on_read(&frame(0, 0x4, 1));
    assert!(http2.deadline.is_none());
    http2.on_read(&[frame(2, HEADERS, 0), vec![1, 2]].concat());
    assert!(http2.deadline.is_some());
    http2.on_read(&frame(0, CONTINUATION, END_HEADERS));
    assert!(http2.deadline.is_none());
  }

  #[tokio::test]
  async fn no_timeout_follows_nothing() {
    let mut http2 = HeaderTimeout::new((), None);
    http2.on_read(H2_PREFACE);
    http2.on_read(&frame(0, HEADERS, 0));
    assert!(http2.deadline.is_none());
    assert!(matches!(
      http2.protocol,
      Protocol::Unknown { matched: 0 }
    ));
  }
}
