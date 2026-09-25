use std::time::Duration;

pub mod external;
pub mod jwt;
pub mod load_cache;
pub mod named;
pub mod oidc;
pub mod passkey;
pub mod token_exchange;
pub mod workload;

/// How long a request to a login provider (discovery, the code
/// exchange, user info) may take. A provider which accepts the
/// connection but never answers fails the login after this,
/// instead of leaving it (and the browser) hanging.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long connecting to a login provider may take.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The url of a server which accepts connections and
/// reads the requests, but never answers them.
#[cfg(test)]
pub(crate) async fn stalled_server() -> String {
  use tokio::io::AsyncReadExt as _;
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  tokio::spawn(async move {
    while let Ok((mut connection, _)) = listener.accept().await {
      // Open until the client gives up
      tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while connection.read(&mut buf).await.is_ok_and(|n| n > 0) {}
      });
    }
  });
  format!("http://{address}")
}
