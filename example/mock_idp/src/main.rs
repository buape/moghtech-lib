// The dependencies are used by the library.
#![allow(unused_crate_dependencies)]

//! Runs the mock identity provider on its own, eg. for the UI tests.
//!
//! `example_mock_idp [port]`, default port 9221.

use example_mock_idp::{IdpUser, MockIdp};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let port = std::env::args()
    .nth(1)
    .map(|port| port.parse::<u16>())
    .transpose()?
    .unwrap_or(9221);
  let idp = MockIdp::spawn(port).await?;
  for (sub, username, groups) in [
    (
      "alice-sub",
      "alice",
      vec!["example-users", "example-admins"],
    ),
    ("bob-sub", "bob", vec!["example-users"]),
    ("mallory-sub", "mallory", vec![]),
  ] {
    idp.upsert_user(IdpUser {
      sub: sub.to_string(),
      preferred_username: Some(username.to_string()),
      email: Some(format!("{username}@example.com")),
      groups: Some(groups.into_iter().map(str::to_string).collect()),
      ..Default::default()
    });
  }
  println!("Mock idp listening at {}", idp.issuer);
  println!("Client id: {}", idp.client_id);
  println!("Client secret: {}", idp.client_secret);
  // Serves until the process is stopped.
  std::future::pending::<()>().await;
  Ok(())
}
