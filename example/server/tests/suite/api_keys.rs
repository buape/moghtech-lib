//! Api keys: V1 (key + secret) and V2 (requests signed with a private key).

use example_client::{
  ClientAuth, ExampleClient,
  api::{
    execute::GenerateKeyPair,
    read::{GetCoreInfo, GetRequestInfo, ListApiKeys},
  },
  auth::api::manage::{
    CreateApiKey, CreateApiKeyV2, DeleteApiKey, DeleteApiKeyV2,
  },
  entities::{ApiKeyKind, AuthMethod},
  sign_request,
};
use reqwest::StatusCode;

use crate::common::*;

async fn create_v1(
  client: &ExampleClient,
  name: &str,
  expires: u64,
  cidr_whitelist: &[&str],
) -> (String, String) {
  let res = client
    .manage(CreateApiKey {
      name: name.into(),
      expires,
      cidr_whitelist: cidr_whitelist
        .iter()
        .map(|entry| entry.to_string())
        .collect(),
    })
    .await
    .unwrap();
  (res.key, res.secret)
}

fn v1_client(
  client: &ExampleClient,
  key: &str,
  secret: &str,
) -> ExampleClient {
  client.with_auth(ClientAuth::ApiKey {
    key: key.into(),
    secret: secret.into(),
  })
}

async fn v2_client(
  client: &ExampleClient,
  private_key: &str,
) -> ExampleClient {
  let server_public_key =
    client.read(GetCoreInfo {}).await.unwrap().public_key;
  client.with_auth(ClientAuth::PrivateKey {
    private_key: private_key.into(),
    server_public_key,
  })
}

#[tokio::test]
async fn v1_key_authenticates_until_deleted() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let (key, secret) = create_v1(&admin, "ci", 0, &[]).await;
  assert!(key.starts_with("K_") && secret.starts_with("S_"));

  let api = v1_client(&admin, &key, &secret);
  let info = api.read(GetRequestInfo {}).await.unwrap();
  assert_eq!(info.auth_method, AuthMethod::ApiKey);
  assert_eq!(info.user_id, get_user(&admin).await.id);

  // The secret is only stored as a hash, and never listed.
  let keys = admin.read(ListApiKeys {}).await.unwrap();
  assert_eq!(keys.len(), 1);
  assert_eq!(keys[0].kind, ApiKeyKind::V1);
  let db = std::fs::read(app.path("data/example.db")).unwrap();
  let wal = std::fs::read(app.path("data/example.db-wal"))
    .unwrap_or_default();
  for file in [&db, &wal] {
    assert!(
      !file
        .windows(secret.len())
        .any(|window| window == secret.as_bytes()),
      "The api secret is stored in plain text"
    );
  }

  // Wrong secret, unknown key, missing secret
  for (key, secret) in [
    (key.as_str(), "S_wrong_S"),
    ("K_unknown_K", secret.as_str()),
    (key.as_str(), ""),
  ] {
    let res =
      v1_client(&admin, key, secret).read(GetRequestInfo {}).await;
    assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  }

  admin
    .manage(DeleteApiKey { key: key.clone() })
    .await
    .unwrap();
  let res = api.read(GetRequestInfo {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_key_names_and_whitelists_are_validated() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  for (name, cidr_whitelist) in [
    ("a".repeat(201), vec![]),
    ("has\u{0}control".to_string(), vec![]),
    ("ok".to_string(), vec!["not-an-ip".to_string()]),
    ("ok".to_string(), vec!["10.0.0.0/33".to_string()]),
  ] {
    let res = admin
      .manage(CreateApiKey {
        name: name.clone(),
        expires: 0,
        cidr_whitelist: cidr_whitelist.clone(),
      })
      .await;
    assert_eq!(
      status_of(res),
      StatusCode::BAD_REQUEST,
      "{name:?} {cidr_whitelist:?}"
    );
  }
  assert!(admin.read(ListApiKeys {}).await.unwrap().is_empty());

  // Entries are trimmed, empty ones dropped.
  create_v1(&admin, "ok", 0, &[" 127.0.0.1 ", "", "10.0.0.0/8"])
    .await;
  let keys = admin.read(ListApiKeys {}).await.unwrap();
  assert_eq!(keys[0].cidr_whitelist, ["127.0.0.1", "10.0.0.0/8"]);
}

#[tokio::test]
async fn api_key_cidr_whitelist_is_enforced() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  let (key, secret) =
    create_v1(&admin, "local", 0, &["127.0.0.0/8"]).await;
  v1_client(&admin, &key, &secret)
    .read(GetRequestInfo {})
    .await
    .unwrap();

  let (key, secret) =
    create_v1(&admin, "elsewhere", 0, &["203.0.113.0/24"]).await;
  let api = v1_client(&admin, &key, &secret);
  let res = api.read(GetRequestInfo {}).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  // Also for the auth management api.
  let res = api
    .manage(example_client::auth::api::manage::GetUserId {})
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn expired_api_keys_stop_working_and_can_be_deleted() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  let soon = unix_timestamp_ms() + 1_500;
  let (key, secret) =
    create_v1(&admin, "short-lived", soon, &[]).await;
  let private_key = admin
    .manage(CreateApiKeyV2 {
      name: "short-lived-v2".into(),
      expires: soon,
      cidr_whitelist: Vec::new(),
      public_key: String::new(),
    })
    .await
    .unwrap()
    .private_key
    .unwrap();
  let v1 = v1_client(&admin, &key, &secret);
  let v2 = v2_client(&admin, &private_key).await;
  v1.read(GetRequestInfo {}).await.unwrap();
  v2.read(GetRequestInfo {}).await.unwrap();

  tokio::time::sleep(std::time::Duration::from_millis(1_600)).await;
  assert_eq!(
    status_of(v1.read(GetRequestInfo {}).await),
    StatusCode::UNAUTHORIZED
  );
  assert_eq!(
    status_of(v2.read(GetRequestInfo {}).await),
    StatusCode::UNAUTHORIZED
  );

  // The owner can still clean them up.
  let keys = admin.read(ListApiKeys {}).await.unwrap();
  assert_eq!(keys.len(), 2);
  admin.manage(DeleteApiKey { key }).await.unwrap();
  let public_key = keys
    .iter()
    .find(|key| key.kind == ApiKeyKind::V2)
    .unwrap()
    .key
    .clone();
  admin.manage(DeleteApiKeyV2 { public_key }).await.unwrap();
  assert!(admin.read(ListApiKeys {}).await.unwrap().is_empty());
}

#[tokio::test]
async fn users_cannot_delete_api_keys_of_others() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let other = app.sign_up("other").await;

  let (key, _) = create_v1(&other, "mine", 0, &[]).await;
  other
    .manage(CreateApiKeyV2 {
      name: "mine-v2".into(),
      expires: 0,
      cidr_whitelist: Vec::new(),
      public_key: String::new(),
    })
    .await
    .unwrap();
  let public_key = other
    .read(ListApiKeys {})
    .await
    .unwrap()
    .into_iter()
    .find(|key| key.kind == ApiKeyKind::V2)
    .unwrap()
    .key;

  // Not even the admin.
  let res = admin.manage(DeleteApiKey { key }).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  let res = admin.manage(DeleteApiKeyV2 { public_key }).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  assert_eq!(other.read(ListApiKeys {}).await.unwrap().len(), 2);

  // Unknown keys
  let res = admin
    .manage(DeleteApiKey {
      key: "K_unknown_K".into(),
    })
    .await;
  assert!(status_of(res).is_client_error());
}

#[tokio::test]
async fn v2_key_signs_requests() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  // The server generates the key pair, and only keeps the public key.
  let private_key = admin
    .manage(CreateApiKeyV2 {
      name: "generated".into(),
      expires: 0,
      cidr_whitelist: Vec::new(),
      public_key: String::new(),
    })
    .await
    .unwrap()
    .private_key
    .expect("No private key for a generated pair");
  let api = v2_client(&admin, &private_key).await;
  let info = api.read(GetRequestInfo {}).await.unwrap();
  assert_eq!(info.auth_method, AuthMethod::PublicKey);
  // Works for the auth management api too.
  api
    .manage(example_client::auth::api::manage::GetUserId {})
    .await
    .unwrap();

  // A key pair the server doesn't know
  let unknown = admin.execute(GenerateKeyPair {}).await.unwrap();
  let res = v2_client(&admin, &unknown.private_key)
    .await
    .read(GetRequestInfo {})
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn v2_key_accepts_own_public_key_in_any_encoding() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  for (name, pem) in [("base64", false), ("pem", true)] {
    let pair = admin.execute(GenerateKeyPair {}).await.unwrap();
    let public_key = if pem {
      format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        pair.public_key
      )
    } else {
      pair.public_key.clone()
    };
    let res = admin
      .manage(CreateApiKeyV2 {
        name: name.into(),
        expires: 0,
        cidr_whitelist: Vec::new(),
        public_key,
      })
      .await
      .unwrap();
    // The client keeps its own private key.
    assert!(res.private_key.is_none());
    v2_client(&admin, &pair.private_key)
      .await
      .read(GetRequestInfo {})
      .await
      .unwrap_or_else(|e| panic!("{name} public key: {e:#}"));
  }

  // What isn't a public key is refused rather than stored.
  for public_key in
    ["not a key", "AAAA", "-----BEGIN PUBLIC KEY-----"]
  {
    let res = admin
      .manage(CreateApiKeyV2 {
        name: "invalid".into(),
        expires: 0,
        cidr_whitelist: Vec::new(),
        public_key: public_key.into(),
      })
      .await;
    assert_eq!(
      status_of(res),
      StatusCode::BAD_REQUEST,
      "{public_key:?}"
    );
  }
}

#[tokio::test]
async fn v2_signature_is_bound_to_the_request_and_time() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let private_key = admin
    .manage(CreateApiKeyV2 {
      name: "generated".into(),
      expires: 0,
      cidr_whitelist: Vec::new(),
      public_key: String::new(),
    })
    .await
    .unwrap()
    .private_key
    .unwrap();
  let server_public_key =
    admin.read(GetCoreInfo {}).await.unwrap().public_key;

  let send =
    |path: &'static str, signature: String, timestamp: i64| {
      let reqwest = admin.reqwest.clone();
      let url = format!("{}{path}", app.address);
      async move {
        reqwest
          .post(url)
          .header("x-api-signature", signature)
          .header("x-api-timestamp", timestamp)
          .json(&serde_json::json!({}))
          .send()
          .await
          .unwrap()
          .status()
      }
    };
  let now = unix_timestamp_ms() as i64;
  let sign = |method: &str, path: &str, timestamp: i64| {
    sign_request(
      &private_key,
      &server_public_key,
      method,
      path,
      timestamp,
    )
    .unwrap()
  };

  let path = "/read/GetRequestInfo";
  assert_eq!(
    send(path, sign("POST", path, now), now).await,
    StatusCode::OK
  );
  // Signed for another path, method, or time
  for (signature, timestamp) in [
    (sign("POST", "/read/GetUser", now), now),
    (sign("GET", path, now), now),
    (sign("POST", path, now), now + 1),
    // A captured request can't be replayed later on.
    (sign("POST", path, now - 60_000), now - 60_000),
    (sign("POST", path, now + 60_000), now + 60_000),
    ("not-a-signature".to_string(), now),
  ] {
    let status = send(path, signature, timestamp).await;
    assert!(
      status == StatusCode::UNAUTHORIZED
        || status == StatusCode::BAD_REQUEST,
      "{status}"
    );
  }
}
