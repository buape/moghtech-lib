//! Api keys (key + secret) and signing keys (requests signed with a
//! private key).

use example_client::{
  ClientAuth, ExampleClient,
  api::{
    execute::GenerateKeyPair,
    read::{GetCoreInfo, GetRequestInfo, ListApiKeys},
  },
  auth::{
    api::manage::{
      CreateApiKey, CreateSigningKey, CreateTrustedIssuer,
      DeleteApiKey, DeleteSigningKey, ListTrustedIssuers,
    },
    config::{
      TrustedIssuer, TrustedIssuerKeys, WorkloadClaim, WorkloadRule,
    },
  },
  entities::{ApiKeyKind, AuthMethod},
  sign_request,
};
use reqwest::StatusCode;
use serde_json::json;

use crate::common::*;

async fn create_api_key(
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

fn api_key_client(
  client: &ExampleClient,
  key: &str,
  secret: &str,
) -> ExampleClient {
  client.with_auth(ClientAuth::ApiKey {
    key: key.into(),
    secret: secret.into(),
  })
}

async fn signing_key_client(
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
async fn api_key_authenticates_until_deleted() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let (key, secret) = create_api_key(&admin, "ci", 0, &[]).await;
  assert!(key.starts_with("K_") && secret.starts_with("S_"));

  let api = api_key_client(&admin, &key, &secret);
  let info = api.read(GetRequestInfo {}).await.unwrap();
  assert_eq!(info.auth_method, AuthMethod::ApiKey);
  assert_eq!(info.user_id, get_user(&admin).await.id);

  // The secret is only stored as a hash, and never listed.
  let keys = admin.read(ListApiKeys {}).await.unwrap();
  assert_eq!(keys.len(), 1);
  assert_eq!(keys[0].kind, ApiKeyKind::ApiKey);
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
    let res = api_key_client(&admin, key, secret)
      .read(GetRequestInfo {})
      .await;
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
  create_api_key(&admin, "ok", 0, &[" 127.0.0.1 ", "", "10.0.0.0/8"])
    .await;
  let keys = admin.read(ListApiKeys {}).await.unwrap();
  assert_eq!(keys[0].cidr_whitelist, ["127.0.0.1", "10.0.0.0/8"]);
}

#[tokio::test]
async fn api_key_cidr_whitelist_is_enforced() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  let (key, secret) =
    create_api_key(&admin, "local", 0, &["127.0.0.0/8"]).await;
  api_key_client(&admin, &key, &secret)
    .read(GetRequestInfo {})
    .await
    .unwrap();

  let (key, secret) =
    create_api_key(&admin, "elsewhere", 0, &["203.0.113.0/24"]).await;
  let api = api_key_client(&admin, &key, &secret);
  let res = api.read(GetRequestInfo {}).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  // Also for the auth management api.
  let res = api
    .manage(example_client::auth::api::manage::GetUserId {})
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn expired_keys_stop_working_and_can_be_deleted() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  let soon = unix_timestamp_ms() + 1_500;
  let (key, secret) =
    create_api_key(&admin, "short-lived", soon, &[]).await;
  let private_key = admin
    .manage(CreateSigningKey {
      name: "short-lived-signing".into(),
      expires: soon,
      cidr_whitelist: Vec::new(),
      public_key: String::new(),
    })
    .await
    .unwrap()
    .private_key
    .unwrap();
  let api_key = api_key_client(&admin, &key, &secret);
  let signing_key = signing_key_client(&admin, &private_key).await;
  api_key.read(GetRequestInfo {}).await.unwrap();
  signing_key.read(GetRequestInfo {}).await.unwrap();

  tokio::time::sleep(std::time::Duration::from_millis(1_600)).await;
  assert_eq!(
    status_of(api_key.read(GetRequestInfo {}).await),
    StatusCode::UNAUTHORIZED
  );
  assert_eq!(
    status_of(signing_key.read(GetRequestInfo {}).await),
    StatusCode::UNAUTHORIZED
  );

  // The owner can still clean them up.
  let keys = admin.read(ListApiKeys {}).await.unwrap();
  assert_eq!(keys.len(), 2);
  admin.manage(DeleteApiKey { key }).await.unwrap();
  let public_key = keys
    .iter()
    .find(|key| key.kind == ApiKeyKind::SigningKey)
    .unwrap()
    .key
    .clone();
  admin.manage(DeleteSigningKey { public_key }).await.unwrap();
  assert!(admin.read(ListApiKeys {}).await.unwrap().is_empty());
}

#[tokio::test]
async fn users_cannot_delete_keys_of_others() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let other = app.sign_up("other").await;

  let (key, _) = create_api_key(&other, "mine", 0, &[]).await;
  other
    .manage(CreateSigningKey {
      name: "mine-signing".into(),
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
    .find(|key| key.kind == ApiKeyKind::SigningKey)
    .unwrap()
    .key;

  // Not even the admin.
  let res = admin.manage(DeleteApiKey { key }).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  let res = admin.manage(DeleteSigningKey { public_key }).await;
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
async fn signing_key_signs_requests() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  // The server generates the key pair, and only keeps the public key.
  let private_key = admin
    .manage(CreateSigningKey {
      name: "generated".into(),
      expires: 0,
      cidr_whitelist: Vec::new(),
      public_key: String::new(),
    })
    .await
    .unwrap()
    .private_key
    .expect("No private key for a generated pair");
  let api = signing_key_client(&admin, &private_key).await;
  let info = api.read(GetRequestInfo {}).await.unwrap();
  assert_eq!(info.auth_method, AuthMethod::PublicKey);
  // Works for the auth management api too.
  api
    .manage(example_client::auth::api::manage::GetUserId {})
    .await
    .unwrap();

  // A key pair the server doesn't know
  let unknown = admin.execute(GenerateKeyPair {}).await.unwrap();
  let res = signing_key_client(&admin, &unknown.private_key)
    .await
    .read(GetRequestInfo {})
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn signing_key_accepts_own_public_key_in_any_encoding() {
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
      .manage(CreateSigningKey {
        name: name.into(),
        expires: 0,
        cidr_whitelist: Vec::new(),
        public_key,
      })
      .await
      .unwrap();
    // The client keeps its own private key.
    assert!(res.private_key.is_none());
    signing_key_client(&admin, &pair.private_key)
      .await
      .read(GetRequestInfo {})
      .await
      .unwrap_or_else(|e| panic!("{name} public key: {e:#}"));
  }

  // What isn't a public key is refused rather than stored. So is a
  // low order point (the all zero key): a request "signed" as it
  // needs no private key at all.
  for public_key in [
    "not a key",
    "AAAA",
    "-----BEGIN PUBLIC KEY-----",
    "MCowBQYDK2VuAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  ] {
    let res = admin
      .manage(CreateSigningKey {
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
async fn signing_keys_cannot_be_registered_twice() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let other = app.sign_up("other").await;

  // Public keys are not secret, eg. published with a deployment.
  let pair = admin.execute(GenerateKeyPair {}).await.unwrap();
  let create = |public_key: &str| CreateSigningKey {
    name: "deploy".into(),
    expires: 0,
    cidr_whitelist: Vec::new(),
    public_key: public_key.into(),
  };
  admin.manage(create(&pair.public_key)).await.unwrap();

  // Nobody can register it again, in any encoding.
  let pem = format!(
    "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
    pair.public_key
  );
  for (client, public_key) in [
    (&other, pair.public_key.as_str()),
    (&other, pem.as_str()),
    (&admin, pair.public_key.as_str()),
  ] {
    let res = client.manage(create(public_key)).await;
    assert_eq!(status_of(res), StatusCode::CONFLICT);
  }
  assert!(
    other
      .read(ListApiKeys {})
      .await
      .unwrap()
      .iter()
      .all(|key| key.kind != ApiKeyKind::SigningKey)
  );

  // Requests signed with it are still the owner's, who alone can
  // delete it.
  let info = signing_key_client(&admin, &pair.private_key)
    .await
    .read(GetRequestInfo {})
    .await
    .unwrap();
  assert_eq!(info.user_id, get_user(&admin).await.id);
  let res = other
    .manage(DeleteSigningKey {
      public_key: pair.public_key.clone(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  admin
    .manage(DeleteSigningKey {
      public_key: pair.public_key,
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn signature_is_bound_to_the_request_and_time() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let private_key = admin
    .manage(CreateSigningKey {
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

  let send = |path: &'static str,
              body: Vec<u8>,
              signature: String,
              timestamp: i64| {
    let reqwest = admin.reqwest.clone();
    let url = format!("{}{path}", app.address);
    async move {
      reqwest
        .post(url)
        .header("x-api-signature", signature)
        .header("x-api-timestamp", timestamp)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap()
        .status()
    }
  };
  let now = unix_timestamp_ms() as i64;
  let sign =
    |method: &str, path: &str, timestamp: i64, body: &[u8]| {
      sign_request(
        &private_key,
        &server_public_key,
        method,
        path,
        timestamp,
        body,
      )
      .unwrap()
    };

  let path = "/read/GetRequestInfo";
  let body = b"{}".to_vec();
  assert_eq!(
    send(path, body.clone(), sign("POST", path, now, &body), now)
      .await,
    StatusCode::OK
  );
  // Signed for another path, method, body or time
  for (signature, timestamp) in [
    (sign("POST", "/read/GetUser", now, &body), now),
    (sign("GET", path, now, &body), now),
    (sign("POST", path, now, b""), now),
    (sign("POST", path, now, b"{ }"), now),
    (sign("POST", path, now, &body), now + 1),
    // A captured request can't be replayed later on.
    (sign("POST", path, now - 60_000, &body), now - 60_000),
    (sign("POST", path, now + 60_000, &body), now + 60_000),
    ("not-a-signature".to_string(), now),
  ] {
    let status = send(path, body.clone(), signature, timestamp).await;
    assert!(
      status == StatusCode::UNAUTHORIZED
        || status == StatusCode::BAD_REQUEST,
      "{status}"
    );
  }
}

#[tokio::test]
async fn signature_headers_cannot_carry_another_body() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let private_key = admin
    .manage(CreateSigningKey {
      name: "terraform".into(),
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

  // The admin key runs a harmless request on the route which takes
  // every request type in the body.
  let path = "/auth/manage";
  let listed = serde_json::to_vec(&json!({
    "type": "ListTrustedIssuers",
    "params": {},
  }))
  .unwrap();
  let timestamp = unix_timestamp_ms() as i64;
  let signature = sign_request(
    &private_key,
    &server_public_key,
    "POST",
    path,
    timestamp,
    &listed,
  )
  .unwrap();
  let send = |body: Vec<u8>| {
    admin
      .reqwest
      .post(format!("{}{path}", app.address))
      .header("x-api-signature", signature.clone())
      .header("x-api-timestamp", timestamp)
      .header("content-type", "application/json")
      .body(body)
      .send()
  };
  assert_eq!(send(listed).await.unwrap().status(), StatusCode::OK);

  // Whoever sees its headers can't send another request with them
  // while the timestamp is valid, eg. one creating a trusted issuer
  // whose tokens are exchanged for an admin.
  let created = serde_json::to_vec(&json!({
    "type": "CreateTrustedIssuer",
    "params": CreateTrustedIssuer {
      issuer: TrustedIssuer {
        id: String::new(),
        name: "Admin CI".into(),
        enabled: true,
        issuer: app.idp.issuer.clone(),
        keys: TrustedIssuerKeys::Discovery {},
        audiences: vec!["https://example-app.test".into()],
        max_token_age_secs: 300,
        rules: vec![WorkloadRule {
          id: String::new(),
          name: "Admin".into(),
          enabled: true,
          claims: vec![WorkloadClaim {
            claim: "repository_id".into(),
            pattern: "12345".into(),
          }],
          groups: Vec::new(),
          admin: true,
          token_ttl_secs: 900,
        }],
      },
    },
  }))
  .unwrap();
  assert_eq!(
    send(created.clone()).await.unwrap().status(),
    StatusCode::UNAUTHORIZED
  );
  assert!(
    admin
      .manage(ListTrustedIssuers {})
      .await
      .unwrap()
      .is_empty()
  );

  // Signed by the key itself it is accepted.
  let timestamp = unix_timestamp_ms() as i64;
  let status = admin
    .reqwest
    .post(format!("{}{path}", app.address))
    .header(
      "x-api-signature",
      sign_request(
        &private_key,
        &server_public_key,
        "POST",
        path,
        timestamp,
        &created,
      )
      .unwrap(),
    )
    .header("x-api-timestamp", timestamp)
    .header("content-type", "application/json")
    .body(created)
    .send()
    .await
    .unwrap()
    .status();
  assert_eq!(status, StatusCode::OK);
  assert_eq!(
    admin.manage(ListTrustedIssuers {}).await.unwrap().len(),
    1
  );
}

#[tokio::test]
async fn signature_works_over_http2() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let private_key = admin
    .manage(CreateSigningKey {
      name: "h2".into(),
      expires: 0,
      cidr_whitelist: Vec::new(),
      public_key: String::new(),
    })
    .await
    .unwrap()
    .private_key
    .unwrap();
  let api = signing_key_client(&admin, &private_key).await;

  // The server sees the scheme and authority in the uri of an HTTP/2
  // request, the client signs the path and query.
  let mut h2 = api.clone();
  h2.reqwest = reqwest::Client::builder()
    .http2_prior_knowledge()
    .build()
    .unwrap();
  let info = h2.read(GetRequestInfo {}).await.unwrap();
  assert_eq!(info.auth_method, AuthMethod::PublicKey);
  h2.manage(example_client::auth::api::manage::GetUserId {})
    .await
    .unwrap();
}
