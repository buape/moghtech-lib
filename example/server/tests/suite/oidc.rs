//! External login with OIDC against the mock identity provider:
//! signup, login, groups, linking, second factor and the callback checks.

use example_client::{
  ClientAuth, ExampleClient,
  auth::api::{
    login::{CompleteTotpLogin, ExchangeForJwt, GetLoginOptions},
    manage::{
      BeginExternalLoginLink, BeginTotpEnrollment,
      ConfirmTotpEnrollment, UnlinkExternalLogin, UnlinkLocalLogin,
      UpdateExternalSkip2fa,
    },
  },
  auth::config::ExternalLoginKind,
};
use example_mock_idp::IdpUser;
use reqwest::StatusCode;
use serde_json::json;

use crate::common::*;

fn oidc_app_options(oidc: serde_json::Value) -> TestAppOptions {
  TestAppOptions {
    static_oidc: true,
    config: json!({ "oidc": oidc }),
    ..Default::default()
  }
}

/// Goes through the browser redirects of an OIDC login as `idp_user`.
/// Returns the client holding the session, and the url it landed on.
async fn browser_login(
  app: &TestApp,
  idp_user: &str,
) -> (ExampleClient, reqwest::Url) {
  app.idp.set_auto_user(Some(&format!("{idp_user}-sub")));
  let client = app.client();
  let landed = follow_external_flow(
    &client,
    &format!("{}/auth/oidc/login", app.address),
  )
  .await;
  (client, landed)
}

/// A full OIDC login, up to the app token.
async fn oidc_login(app: &TestApp, idp_user: &str) -> ExampleClient {
  let (client, landed) = browser_login(app, idp_user).await;
  assert_eq!(landed.query(), Some("redeem_ready=true"), "{landed}");
  let jwt = client.login(ExchangeForJwt {}).await.unwrap().jwt;
  client.with_auth(ClientAuth::Jwt(jwt))
}

/// A login which is expected to fail: the browser is sent back
/// to the login page of the app, with the reason.
async fn failed_browser_login(
  app: &TestApp,
  idp_user: &str,
) -> String {
  let (_, landed) = browser_login(app, idp_user).await;
  assert_eq!(landed.path(), "/login", "{landed}");
  external_error(&landed, "login_error")
}

#[tokio::test]
async fn sign_up_and_log_in_with_oidc() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  app.add_idp_user("alice", &[]);

  let options = app.client().login(GetLoginOptions {}).await.unwrap();
  assert_eq!(options.providers.len(), 1);
  assert_eq!(options.providers[0].id, "oidc");
  assert_eq!(options.providers[0].kind, ExternalLoginKind::Oidc);

  let alice = oidc_login(&app, "alice").await;
  let user = get_user(&alice).await;
  assert_eq!(user.username, "alice");
  // The first user is the admin.
  assert!(user.admin && user.enabled && !user.has_password);
  assert_eq!(user.linked_logins.len(), 1);
  assert_eq!(user.linked_logins[0].provider_id, "oidc");
  assert_eq!(user.linked_logins[0].external_id, "alice-sub");

  // Logging in again finds the same user.
  let again = oidc_login(&app, "alice").await;
  assert_eq!(get_user(&again).await.id, user.id);

  // The exchange only works once per login.
  let res = again.login(ExchangeForJwt {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  // And never without one.
  let res = app.client().login(ExchangeForJwt {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn taken_usernames_get_a_suffix() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  app.sign_up("alice").await;
  app.add_idp_user("alice", &[]);
  let alice = oidc_login(&app, "alice").await;
  let user = get_user(&alice).await;
  assert!(user.username.starts_with("alice-"), "{}", user.username);
  assert!(!user.admin);
}

#[tokio::test]
async fn redirects_back_to_the_app_only() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  app.add_idp_user("alice", &[]);
  app.idp.set_auto_user(Some("alice-sub"));

  for (redirect, expected) in [
    (
      format!("{}/notes?tab=1", app.address),
      format!("{}/notes?tab=1&redeem_ready=true", app.address),
    ),
    (
      "/notes".to_string(),
      format!("{}/notes?redeem_ready=true", app.address),
    ),
    // Open redirects fall back to the app.
    (
      "https://evil.example/steal".to_string(),
      format!("{}?redeem_ready=true", app.address),
    ),
    (
      "//evil.example".to_string(),
      format!("{}?redeem_ready=true", app.address),
    ),
  ] {
    let client = app.client();
    let landed = follow_external_flow(
      &client,
      &format!(
        "{}/auth/oidc/login?redirect={}",
        app.address,
        urlencode(&redirect)
      ),
    )
    .await;
    assert_eq!(
      landed,
      reqwest::Url::parse(&expected).unwrap(),
      "{redirect}"
    );
  }
}

fn urlencode(value: &str) -> String {
  reqwest::Url::parse_with_params("http://x", [("v", value)])
    .unwrap()
    .query()
    .unwrap()
    .trim_start_matches("v=")
    .to_string()
}

#[tokio::test]
async fn registration_can_be_disabled() {
  let app = TestApp::spawn_with(TestAppOptions {
    static_oidc: true,
    config: json!({ "disable_user_registration": true }),
    ..Default::default()
  })
  .await;
  app.add_idp_user("alice", &[]);
  app.add_idp_user("bob", &[]);
  // The first user can always sign up.
  oidc_login(&app, "alice").await;

  let error = failed_browser_login(&app, "bob").await;
  assert!(error.contains("registration is disabled"), "{error}");
  // Existing users still log in.
  oidc_login(&app, "alice").await;
}

#[tokio::test]
async fn groups_are_synced_on_every_login() {
  let app = TestApp::spawn_with(oidc_app_options(json!({
    "groups_claim": "groups",
    "admin_groups": ["example-admins"],
  })))
  .await;
  app.sign_up("local-admin").await;
  app.add_idp_user("alice", &["example-users", "example-admins"]);

  let alice = oidc_login(&app, "alice").await;
  let user = get_user(&alice).await;
  assert_eq!(user.groups, ["example-admins", "example-users"]);
  assert!(user.admin, "Members of an admin group are admins");

  // Removed from the admins at the provider.
  app.add_idp_user("alice", &["example-users"]);
  let alice = oidc_login(&app, "alice").await;
  let user = get_user(&alice).await;
  assert_eq!(user.groups, ["example-users"]);
  assert!(!user.admin);
}

#[tokio::test]
async fn groups_can_come_from_the_user_info() {
  let app = TestApp::spawn_with(oidc_app_options(json!({
    "groups_claim": "groups",
  })))
  .await;
  app.idp.upsert_user(IdpUser {
    sub: "alice-sub".into(),
    preferred_username: Some("alice".into()),
    groups: Some(vec!["from-user-info".into()]),
    groups_in_user_info_only: true,
    ..Default::default()
  });
  let alice = oidc_login(&app, "alice").await;
  assert_eq!(get_user(&alice).await.groups, ["from-user-info"]);
}

#[tokio::test]
async fn allowed_groups_gate_the_login() {
  let app = TestApp::spawn_with(oidc_app_options(json!({
    "allowed_groups": ["example-users"],
  })))
  .await;
  app.add_idp_user("alice", &["example-users"]);
  app.add_idp_user("mallory", &["other"]);
  app.idp.upsert_user(IdpUser {
    sub: "nogroups-sub".into(),
    preferred_username: Some("nogroups".into()),
    ..Default::default()
  });

  oidc_login(&app, "alice").await;
  for user in ["mallory", "nogroups"] {
    let error = failed_browser_login(&app, user).await;
    assert!(
      error.to_lowercase().contains("group"),
      "{user}: {error}"
    );
  }
  // Nobody was signed up by the refused logins.
  let users = alice_users(&app).await;
  assert_eq!(users, ["alice"]);

  // Losing the group locks an existing user out as well.
  app.add_idp_user("alice", &["other"]);
  let error = failed_browser_login(&app, "alice").await;
  assert!(error.to_lowercase().contains("group"), "{error}");
}

async fn alice_users(app: &TestApp) -> Vec<String> {
  app.add_idp_user("alice", &["example-users"]);
  let alice = oidc_login(app, "alice").await;
  alice
    .read(example_client::api::read::ListUsers {})
    .await
    .unwrap()
    .into_iter()
    .map(|user| user.username)
    .collect()
}

#[tokio::test]
async fn link_and_unlink_a_login() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  app.add_idp_user("alice", &[]);
  app.add_idp_user("bob", &[]);
  let admin = app.sign_up("admin").await;
  let admin_id = get_user(&admin).await.id;

  // Linking needs the signed in user to begin it on the session.
  let link_url = format!("{}/auth/external/oidc/link", app.address);
  let landed = follow_external_flow(&admin, &link_url).await;
  let error = external_error(&landed, "link_error");
  assert!(error.contains("not been initiated"), "{error}");

  app.idp.set_auto_user(Some("alice-sub"));
  admin.manage(BeginExternalLoginLink {}).await.unwrap();
  let landed = follow_external_flow(&admin, &link_url).await;
  assert_eq!(landed.path(), "/profile");
  let user = get_user(&admin).await;
  assert_eq!(user.linked_logins.len(), 1);
  assert_eq!(user.linked_logins[0].external_id, "alice-sub");

  // Now alice logs in as the existing user.
  let alice = oidc_login(&app, "alice").await;
  assert_eq!(get_user(&alice).await.id, admin_id);

  // The same login can't be linked to somebody else.
  let other = app.sign_up("other").await;
  other.manage(BeginExternalLoginLink {}).await.unwrap();
  // Back where logins are linked, with the reason.
  let landed = follow_external_flow(&other, &link_url).await;
  assert_eq!(landed.path(), "/profile");
  let error = external_error(&landed, "link_error");
  assert!(error.contains("already linked"), "{error}");
  assert!(get_user(&other).await.linked_logins.is_empty());

  // With a password and a linked login, either can be removed.
  admin
    .manage(UnlinkExternalLogin {
      provider_id: "oidc".into(),
    })
    .await
    .unwrap();
  assert!(get_user(&admin).await.linked_logins.is_empty());
  // Alice is a new user now.
  let alice = oidc_login(&app, "alice").await;
  assert_ne!(get_user(&alice).await.id, admin_id);

  // Provider ids are checked before they reach storage.
  let res = admin
    .manage(UnlinkExternalLogin {
      provider_id: "../etc".into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::BAD_REQUEST);

  // A user who signed up with OIDC can set a password and drop it again.
  admin.manage(UnlinkLocalLogin {}).await.unwrap();
  assert!(!get_user(&admin).await.has_password);
}

#[tokio::test]
async fn external_login_can_require_the_second_factor() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  app.add_idp_user("alice", &[]);
  let alice = oidc_login(&app, "alice").await;

  let enrollment =
    alice.manage(BeginTotpEnrollment {}).await.unwrap();
  let totp = totp_from_uri(&enrollment.uri);
  alice
    .manage(ConfirmTotpEnrollment {
      code: totp.generate_current().to_string(),
    })
    .await
    .unwrap();

  // The provider is trusted with the second factor by default in this app.
  assert!(!get_user(&alice).await.external_skip_2fa);
  let (client, landed) = browser_login(&app, "alice").await;
  assert_eq!(landed.query(), Some("totp=true"));
  // The session isn't authenticated yet.
  let res = client.login(ExchangeForJwt {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  let jwt = client
    .login(CompleteTotpLogin {
      code: totp
        .generate(unix_timestamp_ms() / 1000 + 30)
        .to_string(),
    })
    .await
    .unwrap()
    .jwt;
  get_user(&client.with_auth(ClientAuth::Jwt(jwt))).await;

  alice
    .manage(UpdateExternalSkip2fa {
      external_skip_2fa: true,
    })
    .await
    .unwrap();
  oidc_login(&app, "alice").await;
}

#[tokio::test]
async fn callback_is_bound_to_the_session_which_started_the_login() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  app.add_idp_user("alice", &[]);
  app.idp.set_auto_user(Some("alice-sub"));

  // The victim starts a login, the attacker gets hold of the callback url.
  let victim = app.client();
  let res = victim
    .reqwest
    .get(format!("{}/auth/oidc/login", app.address))
    .send()
    .await
    .unwrap();
  let authorize_url = res.headers()["location"].to_str().unwrap();
  let res = victim.reqwest.get(authorize_url).send().await.unwrap();
  let callback_url =
    res.headers()["location"].to_str().unwrap().to_string();
  assert!(callback_url.contains("/auth/oidc/callback"));

  // Another session can't complete it.
  let attacker = app.client();
  let landed = follow_external_flow(&attacker, &callback_url).await;
  let error = external_error(&landed, "login_error");
  assert!(error.contains("not been initiated"), "{error}");
  // The attacker's session didn't get authenticated by it.
  let res = attacker.login(ExchangeForJwt {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);

  // Neither can a callback with another state (CSRF).
  let mut forged = reqwest::Url::parse(&callback_url).unwrap();
  let pairs = forged
    .query_pairs()
    .map(|(key, value)| {
      let value = if key == "state" {
        "forged".to_string()
      } else {
        value.to_string()
      };
      (key.to_string(), value)
    })
    .collect::<Vec<_>>();
  forged.query_pairs_mut().clear().extend_pairs(pairs);
  let landed = follow_external_flow(&victim, forged.as_str()).await;
  let error = external_error(&landed, "login_error");
  assert!(error.contains("State mismatch"), "{error}");

  // The failed attempt used up the login, it has to be started again.
  let landed = follow_external_flow(&victim, &callback_url).await;
  external_error(&landed, "login_error");
  let res = victim.login(ExchangeForJwt {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  // Nobody got signed up along the way.
  assert!(
    app
      .sign_up("first")
      .await
      .read(example_client::api::read::ListUsers {})
      .await
      .unwrap()
      .len()
      == 1
  );
}

#[tokio::test]
async fn denied_login_and_unknown_providers() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  let client = app.client();

  // The user denies the login at the provider.
  client
    .reqwest
    .get(format!("{}/auth/oidc/login", app.address))
    .send()
    .await
    .unwrap();
  let landed = follow_external_flow(
    &client,
    &format!(
      "{}/auth/oidc/callback?error=access_denied&state=x",
      app.address
    ),
  )
  .await;
  assert_eq!(landed.path(), "/login");
  let error = external_error(&landed, "login_error");
  assert!(error.contains("access_denied"), "{error}");

  for path in [
    "/auth/external/unknown/login",
    "/auth/github/login",
    "/auth/google/login",
  ] {
    let landed = follow_external_flow(
      &client,
      &format!("{}{path}", app.address),
    )
    .await;
    assert_eq!(landed.path(), "/login", "{path}");
    external_error(&landed, "login_error");
  }
}

#[tokio::test]
async fn failures_are_json_errors_without_the_redirect() {
  // What apps get which don't configure a page to send failures to.
  let app = TestApp::spawn_with(TestAppOptions {
    static_oidc: true,
    config: json!({
      "login_error_redirect": false,
      "disable_user_registration": true,
    }),
    ..Default::default()
  })
  .await;
  app.add_idp_user("alice", &[]);
  app.add_idp_user("bob", &[]);
  oidc_login(&app, "alice").await;

  app.idp.set_auto_user(Some("bob-sub"));
  let client = app.client();
  let mut url = format!("{}/auth/oidc/login", app.address);
  let res = loop {
    let res = client.reqwest.get(&url).send().await.unwrap();
    if !res.status().is_redirection() {
      break res;
    }
    url = res.headers()["location"].to_str().unwrap().to_string();
  };
  assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
  let body: serde_json::Value = res.json().await.unwrap();
  assert!(
    body["error"]
      .as_str()
      .unwrap()
      .contains("registration is disabled"),
    "{body}"
  );

  let res = client
    .reqwest
    .get(format!("{}/auth/external/unknown/login", app.address))
    .send()
    .await
    .unwrap();
  assert!(res.status().is_client_error(), "{}", res.status());
}

#[tokio::test]
async fn unreachable_provider_fails_without_taking_the_app_down() {
  let app = TestApp::spawn_with(TestAppOptions {
    config: json!({
      "oidc": {
        "enabled": true,
        // Nothing listens here.
        "provider": "http://127.0.0.1:9",
        "client_id": "id",
        "client_secret": "secret",
      }
    }),
    ..Default::default()
  })
  .await;
  let landed = follow_external_flow(
    &app.client(),
    &format!("{}/auth/oidc/login", app.address),
  )
  .await;
  // Server errors are only reported as such, the reason is in the log.
  let error = external_error(&landed, "login_error");
  assert!(error.contains("Login failed"), "{error}");
  assert!(!landed.as_str().contains("127.0.0.1%3A9"), "{landed}");
  assert!(app.logs().contains("127.0.0.1:9"));
  // Local login is unaffected.
  app.sign_up("admin").await;
}
