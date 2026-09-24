//! Workload identity: machines exchange the token their platform
//! issues them for a short lived app token at `POST /auth/token`.

use example_client::{
  ClientAuth, ExampleClient,
  api::{
    read::{GetRequestInfo, ListUsers},
    write::{CreateNote, UpdateUserAccess},
  },
  auth::{
    api::{
      manage::{
        CreateApiKey, CreateTrustedIssuer, DeleteTrustedIssuer,
        GetUserId, ListTrustedIssuers, UpdatePassword,
        UpdateTrustedIssuer,
      },
      token::TOKEN_TYPE_JWT,
    },
    config::{
      TrustedIssuer, TrustedIssuerKeys, WorkloadClaim, WorkloadRule,
    },
  },
};
use example_mock_idp::{MintToken, Signer};
use reqwest::StatusCode;
use serde_json::json;

use crate::common::*;

const AUDIENCE: &str = "https://example-app.test";

fn claim(claim: &str, pattern: &str) -> WorkloadClaim {
  WorkloadClaim {
    claim: claim.into(),
    pattern: pattern.into(),
  }
}

fn deploy_rule() -> WorkloadRule {
  WorkloadRule {
    id: String::new(),
    name: "Deploy".into(),
    enabled: true,
    claims: vec![
      claim("repository_id", "12345"),
      claim("ref", "refs/heads/release/*"),
    ],
    groups: vec!["deployers".into()],
    admin: false,
    token_ttl_secs: 900,
  }
}

fn issuer(app: &TestApp, rules: Vec<WorkloadRule>) -> TrustedIssuer {
  TrustedIssuer {
    id: String::new(),
    name: "Mock CI".into(),
    enabled: true,
    issuer: app.idp.issuer.clone(),
    keys: TrustedIssuerKeys::Discovery {},
    audiences: vec![AUDIENCE.into()],
    max_token_age_secs: 300,
    rules,
  }
}

fn ci_token(claims: serde_json::Value) -> MintToken {
  MintToken {
    sub: "repo:my-org/my-repo:ref:refs/heads/release/1".into(),
    aud: vec![AUDIENCE.into()],
    claims: claims.as_object().unwrap().clone(),
    ..Default::default()
  }
}

fn release_claims() -> serde_json::Value {
  json!({ "repository_id": "12345", "ref": "refs/heads/release/1" })
}

async fn workload_client(
  app: &TestApp,
  token: MintToken,
) -> ExampleClient {
  let res = app
    .token_exchange(&app.idp.mint(token), TOKEN_TYPE_JWT)
    .await
    .unwrap();
  app.client().with_auth(ClientAuth::Jwt(res.access_token))
}

#[tokio::test]
async fn workload_gets_a_short_lived_token_for_its_rule() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let created = admin
    .manage(CreateTrustedIssuer {
      issuer: issuer(&app, vec![deploy_rule()]),
    })
    .await
    .unwrap();
  assert!(!created.read_only);
  // The server generates the ids, they identify the user of a rule.
  assert!(!created.issuer.id.is_empty());
  assert!(!created.issuer.rules[0].id.is_empty());

  let res = app
    .token_exchange(
      &app.idp.mint(ci_token(release_claims())),
      TOKEN_TYPE_JWT,
    )
    .await
    .unwrap();
  // The ttl of the rule, not the 24h of user logins.
  assert_eq!(res.expires_in, 900);

  let workload =
    app.client().with_auth(ClientAuth::Jwt(res.access_token));
  let info = workload.read(GetRequestInfo {}).await.unwrap();
  let users = admin.read(ListUsers {}).await.unwrap();
  let user =
    users.iter().find(|user| user.id == info.user_id).unwrap();
  assert_eq!(user.username, "workload-deploy");
  assert_eq!(user.groups, ["deployers"]);
  assert!(!user.admin && user.enabled && !user.has_password);
  let link = user.workload.as_ref().unwrap();
  assert_eq!(link.issuer_id, created.issuer.id);
  assert_eq!(link.rule_id, created.issuer.rules[0].id);
  assert!(link.last_subject.starts_with("repo:my-org/my-repo"));

  // It can use the app ...
  workload
    .write(CreateNote {
      title: "Deployed".into(),
      content: "release/1".into(),
    })
    .await
    .unwrap();

  // ... but can't create credentials which would outlive the rule.
  let res = workload
    .manage(CreateApiKey {
      name: "backdoor".into(),
      expires: 0,
      cidr_whitelist: Vec::new(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  let res = workload
    .manage(UpdatePassword {
      password: "a-password-for-later".into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  // Asking who it is stays possible.
  let id = workload.manage(GetUserId {}).await.unwrap().id;
  assert_eq!(id, info.user_id);

  // Every job of the rule is the same user.
  let again = workload_client(
    &app,
    ci_token(json!({ "repository_id": "12345", "ref": "refs/heads/release/2" })),
  )
  .await;
  assert_eq!(
    again.read(GetRequestInfo {}).await.unwrap().user_id,
    info.user_id
  );
  assert_eq!(admin.read(ListUsers {}).await.unwrap().len(), 2);
}

#[tokio::test]
async fn tokens_have_to_match_a_rule() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  admin
    .manage(CreateTrustedIssuer {
      issuer: issuer(&app, vec![deploy_rule()]),
    })
    .await
    .unwrap();

  let rejected = [
    (
      "another repository",
      ci_token(
        json!({ "repository_id": "99999", "ref": "refs/heads/release/1" }),
      ),
    ),
    (
      "another branch",
      ci_token(
        json!({ "repository_id": "12345", "ref": "refs/heads/main" }),
      ),
    ),
    (
      "a prefix of the pattern",
      ci_token(
        json!({ "repository_id": "123456", "ref": "refs/heads/release/1" }),
      ),
    ),
    (
      "a claim is missing",
      ci_token(json!({ "repository_id": "12345" })),
    ),
    (
      "the platform default audience",
      MintToken {
        aud: vec!["https://github.com/my-org".into()],
        ..ci_token(release_claims())
      },
    ),
    (
      "signed by somebody else",
      MintToken {
        signer: Signer::Other,
        ..ci_token(release_claims())
      },
    ),
    (
      "too old",
      MintToken {
        issued_ago: 3_000,
        expires_in: 6_000,
        ..ci_token(release_claims())
      },
    ),
    (
      "expired",
      MintToken {
        issued_ago: 100,
        expires_in: -60,
        ..ci_token(release_claims())
      },
    ),
  ];
  for (why, token) in rejected {
    let (status, error) = app
      .token_exchange(&app.idp.mint(token), TOKEN_TYPE_JWT)
      .await
      .expect_err(why);
    assert_eq!(status, StatusCode::BAD_REQUEST, "{why}");
    assert_eq!(error.error, "invalid_grant", "{why}");
  }
  // `alg: none` with the claims of a matching token, and those
  // claims under the signature of another token.
  let valid = app.idp.mint(ci_token(release_claims()));
  let claims = valid.split('.').nth(1).unwrap();
  let other = app.idp.mint(ci_token(json!({ "repository_id": "1" })));
  let (header, _) = other.split_once('.').unwrap();
  let signature = other.rsplit('.').next().unwrap();
  for (why, token) in [
    // {"alg":"none","typ":"JWT"}
    (
      "unsigned",
      format!("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.{claims}."),
    ),
    ("tampered", format!("{header}.{claims}.{signature}")),
  ] {
    let (status, error) = app
      .token_exchange(&token, TOKEN_TYPE_JWT)
      .await
      .expect_err(why);
    assert_eq!(status, StatusCode::BAD_REQUEST, "{why}");
    assert_eq!(error.error, "invalid_grant", "{why}");
  }
  // No users were created for refused tokens.
  assert_eq!(admin.read(ListUsers {}).await.unwrap().len(), 1);
}

#[tokio::test]
async fn keys_from_a_url_or_a_fixed_key_set() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  for (name, issuer_url, keys) in [
    (
      "jwks-uri",
      "https://ci-one.example".to_string(),
      TrustedIssuerKeys::JwksUri(format!("{}/jwks", app.idp.issuer)),
    ),
    (
      // Eg. a cluster the server can't reach.
      "static",
      "https://kubernetes.default.svc".to_string(),
      TrustedIssuerKeys::Static(app.idp.jwks_json()),
    ),
  ] {
    admin
      .manage(CreateTrustedIssuer {
        issuer: TrustedIssuer {
          name: name.into(),
          issuer: issuer_url.clone(),
          keys,
          rules: vec![WorkloadRule {
            name: name.into(),
            claims: vec![claim(
              "sub",
              "system:serviceaccount:prod:*",
            )],
            ..deploy_rule()
          }],
          ..issuer(&app, Vec::new())
        },
      })
      .await
      .unwrap();
    let workload = workload_client(
      &app,
      MintToken {
        iss: Some(issuer_url),
        sub: "system:serviceaccount:prod:deployer".into(),
        ..ci_token(json!({}))
      },
    )
    .await;
    workload.read(GetRequestInfo {}).await.unwrap();
  }

  // Invalid key sets are refused when saving, not at the first exchange.
  let res = admin
    .manage(CreateTrustedIssuer {
      issuer: TrustedIssuer {
        keys: TrustedIssuerKeys::Static("not a key set".into()),
        ..issuer(&app, vec![deploy_rule()])
      },
    })
    .await;
  assert_eq!(status_of(res), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unsafe_issuers_and_rules_are_refused() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let invalid = [
    (
      "no audience",
      TrustedIssuer {
        audiences: Vec::new(),
        ..issuer(&app, vec![deploy_rule()])
      },
    ),
    (
      "a rule matching every token",
      issuer(
        &app,
        vec![WorkloadRule {
          claims: Vec::new(),
          ..deploy_rule()
        }],
      ),
    ),
    (
      "a claim matching any value",
      issuer(
        &app,
        vec![WorkloadRule {
          claims: vec![claim("repository_id", "*")],
          ..deploy_rule()
        }],
      ),
    ),
    (
      // Every token of the issuer for the audience has it, and
      // on a public platform anybody can request one.
      "a rule on the audience only",
      issuer(
        &app,
        vec![WorkloadRule {
          claims: vec![
            claim("aud", AUDIENCE),
            claim("iss", "https://*"),
          ],
          ..deploy_rule()
        }],
      ),
    ),
    (
      "issuer is not a url",
      TrustedIssuer {
        issuer: "not a url".into(),
        ..issuer(&app, vec![deploy_rule()])
      },
    ),
    (
      "no name",
      TrustedIssuer {
        name: String::new(),
        ..issuer(&app, vec![deploy_rule()])
      },
    ),
  ];
  for (why, issuer) in invalid {
    let res = admin.manage(CreateTrustedIssuer { issuer }).await;
    assert_eq!(status_of(res), StatusCode::BAD_REQUEST, "{why}");
  }
  assert!(
    admin
      .manage(ListTrustedIssuers {})
      .await
      .unwrap()
      .is_empty()
  );

  // Admin only
  let user = app.sign_up("user").await;
  let res = user
    .manage(CreateTrustedIssuer {
      issuer: issuer(&app, vec![deploy_rule()]),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  let res = user.manage(ListTrustedIssuers {}).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_rules_and_the_first_matching_rule() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  admin
    .manage(CreateTrustedIssuer {
      issuer: issuer(
        &app,
        vec![
          WorkloadRule {
            name: "Disabled".into(),
            enabled: false,
            claims: vec![claim("repository_id", "7*")],
            admin: true,
            ..deploy_rule()
          },
          WorkloadRule {
            name: "Infra".into(),
            claims: vec![claim("repository_id", "777")],
            groups: Vec::new(),
            admin: true,
            ..deploy_rule()
          },
          deploy_rule(),
        ],
      ),
    })
    .await
    .unwrap();

  let infra = workload_client(
    &app,
    ci_token(json!({ "repository_id": "777" })),
  )
  .await;
  // Admin, as its rule says: it can do what app admins can.
  assert_eq!(infra.read(ListUsers {}).await.unwrap().len(), 2);

  let deploy =
    workload_client(&app, ci_token(release_claims())).await;
  let res = deploy.read(ListUsers {}).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);

  // The access of a workload can't be changed in the app, only by its rule.
  let deploy_id =
    deploy.read(GetRequestInfo {}).await.unwrap().user_id;
  let res = admin
    .write(UpdateUserAccess {
      user_id: deploy_id,
      enabled: None,
      admin: Some(true),
      groups: None,
    })
    .await;
  assert_eq!(status_of(res), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn removing_a_rule_or_issuer_revokes_its_workloads() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let created = admin
    .manage(CreateTrustedIssuer {
      issuer: issuer(
        &app,
        vec![
          deploy_rule(),
          WorkloadRule {
            name: "Docs".into(),
            claims: vec![claim("repository_id", "555")],
            ..deploy_rule()
          },
        ],
      ),
    })
    .await
    .unwrap()
    .issuer;
  let deploy =
    workload_client(&app, ci_token(release_claims())).await;
  let docs = workload_client(
    &app,
    ci_token(json!({ "repository_id": "555" })),
  )
  .await;
  assert_eq!(admin.read(ListUsers {}).await.unwrap().len(), 3);

  // Drop the docs rule, keeping the deploy rule (by its id).
  let updated = admin
    .manage(UpdateTrustedIssuer {
      issuer: TrustedIssuer {
        rules: vec![created.rules[0].clone()],
        ..created.clone()
      },
    })
    .await
    .unwrap()
    .issuer;
  assert_eq!(updated.rules[0].id, created.rules[0].id);

  // The token of the removed rule stops working right away,
  // even though it would be valid for minutes.
  let res = docs.read(GetRequestInfo {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  deploy.read(GetRequestInfo {}).await.unwrap();
  let (status, _) = app
    .token_exchange(
      &app.idp.mint(ci_token(json!({ "repository_id": "555" }))),
      TOKEN_TYPE_JWT,
    )
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::BAD_REQUEST);

  // Disabling the issuer stops new tokens.
  admin
    .manage(UpdateTrustedIssuer {
      issuer: TrustedIssuer {
        enabled: false,
        ..updated.clone()
      },
    })
    .await
    .unwrap();
  let (status, _) = app
    .token_exchange(
      &app.idp.mint(ci_token(release_claims())),
      TOKEN_TYPE_JWT,
    )
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::BAD_REQUEST);

  admin
    .manage(DeleteTrustedIssuer {
      id: updated.id.clone(),
    })
    .await
    .unwrap();
  let res = deploy.read(GetRequestInfo {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  assert_eq!(admin.read(ListUsers {}).await.unwrap().len(), 1);
}

#[tokio::test]
async fn static_issuers_from_the_config_file() {
  let idp = example_mock_idp::MockIdp::spawn(0).await.unwrap();
  let app = TestApp::spawn_with_idp(
    TestAppOptions {
      config: json!({
        "trusted_issuers": [{
          "id": "mock-ci",
          "name": "Mock CI",
          "enabled": true,
          "issuer": idp.issuer,
          "keys": { "source": "Discovery", "params": {} },
          "audiences": [AUDIENCE],
          "rules": [
            {
              "id": "deploy",
              "name": "Deploy",
              "enabled": true,
              "claims": [{ "claim": "repository_id", "pattern": "12345" }],
              "groups": ["deployers"],
            },
            {
              // Without an id there is nothing to identify its user by.
              "name": "No id",
              "enabled": true,
              "claims": [{ "claim": "repository_id", "pattern": "222" }],
            },
          ],
        }]
      }),
      ..Default::default()
    },
    idp,
  )
  .await;
  let admin = app.sign_up("admin").await;

  let issuers = admin.manage(ListTrustedIssuers {}).await.unwrap();
  assert_eq!(issuers.len(), 1);
  assert!(issuers[0].read_only);
  let res = admin
    .manage(DeleteTrustedIssuer {
      id: "mock-ci".into(),
    })
    .await;
  assert!(status_of(res).is_client_error());

  let workload =
    workload_client(&app, ci_token(release_claims())).await;
  workload.read(GetRequestInfo {}).await.unwrap();

  // The config is at fault here, not the token: the workload
  // gets no token, and the reason is in the server log.
  let (status, error) = app
    .token_exchange(
      &app.idp.mint(ci_token(json!({ "repository_id": "222" }))),
      TOKEN_TYPE_JWT,
    )
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
  assert_eq!(error.error, "server_error");
  assert!(app.logs().contains("need a unique id"));
}

#[tokio::test]
async fn fetched_keys_are_cached() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  admin
    .manage(CreateTrustedIssuer {
      issuer: issuer(&app, vec![deploy_rule()]),
    })
    .await
    .unwrap();
  // Eg. a CI matrix starting many jobs at once.
  let exchanges = (0..10)
    .map(|_| {
      let token = app.idp.mint(ci_token(release_claims()));
      tokio::spawn(token_exchange(app.address.clone(), token))
    })
    .collect::<Vec<_>>();
  for exchange in exchanges {
    exchange.await.unwrap().unwrap();
  }
  // They shared one load of the key set.
  assert_eq!(app.idp.jwks_requests(), 1);
}

/// A CI matrix starting: many jobs exchange their first token for a
/// rule at once, while its user doesn't exist yet. All of them get
/// a token, and all of them act as the one user of the rule. The
/// app creates it once, even with its first username taken.
#[tokio::test]
async fn concurrent_first_exchanges_share_one_user() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  // Takes the username the workload user would get.
  app.sign_up("workload-deploy").await;
  admin
    .manage(CreateTrustedIssuer {
      issuer: issuer(&app, vec![deploy_rule()]),
    })
    .await
    .unwrap();
  // Load the keys first (a token matching no rule), so the
  // exchanges below meet at the user, not at the key load.
  let (status, _) = app
    .token_exchange(
      &app.idp.mint(ci_token(json!({ "repository_id": "1" }))),
      TOKEN_TYPE_JWT,
    )
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::BAD_REQUEST);

  // Every job has its connection open, and they all
  // exchange at the same moment.
  const JOBS: usize = 24;
  let start = std::sync::Arc::new(tokio::sync::Barrier::new(JOBS));
  let mut exchanges = Vec::new();
  for _ in 0..JOBS {
    let reqwest = reqwest::Client::new();
    reqwest
      .get(format!("{}/version", app.address))
      .send()
      .await
      .unwrap();
    let token = app.idp.mint(ci_token(release_claims()));
    let address = app.address.clone();
    let start = start.clone();
    exchanges.push(tokio::spawn(async move {
      start.wait().await;
      example_client::auth::request::token_exchange(
        &reqwest,
        &format!("{address}/auth"),
        &example_client::auth::api::token::TokenExchangeRequest::jwt(
          token,
        ),
      )
      .await
    }));
  }
  let mut user_ids = Vec::new();
  for exchange in exchanges {
    let res = exchange.await.unwrap().unwrap();
    let workload =
      app.client().with_auth(ClientAuth::Jwt(res.access_token));
    user_ids
      .push(workload.read(GetRequestInfo {}).await.unwrap().user_id);
  }
  user_ids.dedup();
  assert_eq!(user_ids.len(), 1, "{user_ids:?}");

  let users = admin.read(ListUsers {}).await.unwrap();
  let workloads = users
    .iter()
    .filter(|user| user.workload.is_some())
    .collect::<Vec<_>>();
  assert_eq!(workloads.len(), 1);
  assert_eq!(workloads[0].id, user_ids[0]);
  assert!(workloads[0].username.starts_with("workload-deploy-"));
  assert!(!app.logs().contains("Token exchange failed"));
}

async fn token_exchange(
  address: String,
  token: String,
) -> anyhow::Result<()> {
  example_client::auth::request::token_exchange(
    &reqwest::Client::new(),
    &format!("{address}/auth"),
    &example_client::auth::api::token::TokenExchangeRequest::jwt(
      token,
    ),
  )
  .await
  .map(|_| ())
}
