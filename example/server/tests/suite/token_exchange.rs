//! RFC 8693 token exchange for users of a login provider: `POST /auth/token`
//! and the `ExchangeExternalForJwt` login request.

use example_client::{
  ClientAuth, ExampleClient,
  auth::api::{
    login::{
      CompleteTotpLogin, ExchangeExternalForJwt, ExchangeForJwt,
      JwtOrTwoFactor,
    },
    manage::{
      BeginTotpEnrollment, ConfirmTotpEnrollment, CreateApiKey,
      UpdatePassword,
    },
    token::{
      TOKEN_TYPE_ACCESS_TOKEN, TOKEN_TYPE_ID_TOKEN, TOKEN_TYPE_JWT,
    },
  },
};
use example_mock_idp::{MintToken, Signer};
use reqwest::StatusCode;
use serde_json::json;

use crate::{common::*, reauth::assert_reauthentication_required};

fn exchange_options(
  token_exchange: serde_json::Value,
) -> TestAppOptions {
  TestAppOptions {
    static_oidc: true,
    config: json!({ "oidc_token_exchange": token_exchange }),
    ..Default::default()
  }
}

/// Signs alice up through the browser, so the user exists and is linked.
async fn sign_up_alice(app: &TestApp) -> ExampleClient {
  app.add_idp_user("alice", &["example-users"]);
  app.idp.set_auto_user(Some("alice-sub"));
  let client = app.client();
  follow_external_flow(
    &client,
    &format!("{}/auth/oidc/login", app.address),
  )
  .await;
  let jwt = client.login(ExchangeForJwt {}).await.unwrap().jwt;
  client.with_auth(ClientAuth::Jwt(jwt))
}

fn alice_token(app: &TestApp) -> MintToken {
  MintToken {
    sub: "alice-sub".into(),
    aud: vec![app.idp.client_id.clone()],
    ..Default::default()
  }
}

#[tokio::test]
async fn exchange_is_off_by_default() {
  let app = TestApp::spawn_with(TestAppOptions {
    static_oidc: true,
    ..Default::default()
  })
  .await;
  sign_up_alice(&app).await;
  let token = app.idp.mint(alice_token(&app));
  let (status, error) = app
    .token_exchange(&token, TOKEN_TYPE_ID_TOKEN)
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::BAD_REQUEST);
  assert_eq!(error.error, "invalid_grant");
}

#[tokio::test]
async fn exchange_a_provider_token_for_an_app_token() {
  let app =
    TestApp::spawn_with(exchange_options(json!({ "enabled": true })))
      .await;
  let alice = sign_up_alice(&app).await;
  let alice_id = get_user(&alice).await.id;

  let token = app.idp.mint_id_token("alice-sub", &app.idp.client_id);
  let res = app
    .token_exchange(&token, TOKEN_TYPE_ID_TOKEN)
    .await
    .unwrap();
  assert_eq!(res.issued_token_type, TOKEN_TYPE_ACCESS_TOKEN);
  assert_eq!(res.token_type, "Bearer");
  assert_eq!(res.expires_in, 24 * 60 * 60);

  let client =
    app.client().with_auth(ClientAuth::Jwt(res.access_token));
  assert_eq!(get_user(&client).await.id, alice_id);

  // The jwt token type is accepted for the same token.
  app.token_exchange(&token, TOKEN_TYPE_JWT).await.unwrap();

  // The response must not be cached (it carries a credential).
  let res = reqwest::Client::new()
    .post(format!("{}/auth/token", app.address))
    .form(&[
      (
        "grant_type",
        "urn:ietf:params:oauth:grant-type:token-exchange",
      ),
      ("subject_token", token.as_str()),
      ("subject_token_type", TOKEN_TYPE_ID_TOKEN),
    ])
    .send()
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::OK);
  assert_eq!(res.headers()["cache-control"], "no-store");
}

#[tokio::test]
async fn exchange_never_signs_up_users() {
  let app =
    TestApp::spawn_with(exchange_options(json!({ "enabled": true })))
      .await;
  let alice = sign_up_alice(&app).await;
  app.add_idp_user("bob", &[]);

  // A valid token of the provider, for somebody the app doesn't know.
  let token = app.idp.mint_id_token("bob-sub", &app.idp.client_id);
  let (status, error) = app
    .token_exchange(&token, TOKEN_TYPE_ID_TOKEN)
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::BAD_REQUEST);
  assert_eq!(error.error, "invalid_grant");

  let users = alice
    .read(example_client::api::read::ListUsers {})
    .await
    .unwrap();
  assert_eq!(users.len(), 1);
}

#[tokio::test]
async fn rejected_tokens() {
  let app = TestApp::spawn_with(exchange_options(json!({
    "enabled": true,
    "audiences": ["my-cli"],
    "max_token_age_secs": 120,
  })))
  .await;
  sign_up_alice(&app).await;
  let valid = alice_token(&app);

  // Issued to the cli, which is an accepted audience.
  app
    .token_exchange(
      &app.idp.mint(MintToken {
        aud: vec!["my-cli".into()],
        ..valid.clone()
      }),
      TOKEN_TYPE_ID_TOKEN,
    )
    .await
    .unwrap();

  let rejected = [
    (
      "issued to another app",
      app.idp.mint(MintToken {
        aud: vec!["some-other-app".into()],
        ..valid.clone()
      }),
    ),
    (
      "expired",
      app.idp.mint(MintToken {
        expires_in: -120,
        issued_ago: 60,
        ..valid.clone()
      }),
    ),
    (
      "too old",
      app.idp.mint(MintToken {
        issued_ago: 600,
        ..valid.clone()
      }),
    ),
    (
      "signed by somebody else",
      app.idp.mint(MintToken {
        signer: Signer::Other,
        ..valid.clone()
      }),
    ),
    (
      "another issuer",
      app.idp.mint(MintToken {
        iss: Some("https://evil.example".into()),
        ..valid.clone()
      }),
    ),
    ("unsigned", unsigned_token(&app)),
    ("not a token", "not-a-token".to_string()),
    ("empty", String::new()),
  ];
  for (why, token) in rejected {
    let (status, error) = app
      .token_exchange(&token, TOKEN_TYPE_ID_TOKEN)
      .await
      .expect_err(why);
    assert_eq!(status, StatusCode::BAD_REQUEST, "{why}");
    assert!(
      error.error == "invalid_grant"
        || error.error == "invalid_request",
      "{why}: {error:?}"
    );
    // Why exactly stays in the server log.
    let description = error.error_description.unwrap_or_default();
    assert!(!description.contains("alice"), "{why}: {description}");
  }

  // Opaque access tokens can't be tied to an audience.
  let (status, error) = app
    .token_exchange(&app.idp.mint(valid), TOKEN_TYPE_ACCESS_TOKEN)
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::BAD_REQUEST);
  assert_eq!(error.error, "invalid_request");
}

/// `alg: none` with the claims of a valid token.
fn unsigned_token(app: &TestApp) -> String {
  let token = app.idp.mint(alice_token(app));
  let claims = token.split('.').nth(1).unwrap();
  // {"alg":"none","typ":"JWT"}
  format!("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.{claims}.")
}

#[tokio::test]
async fn malformed_requests_use_the_oauth_error_format() {
  let app =
    TestApp::spawn_with(exchange_options(json!({ "enabled": true })))
      .await;
  let reqwest = reqwest::Client::new();
  let url = format!("{}/auth/token", app.address);
  let forms: [&[(&str, &str)]; 4] = [
    &[],
    &[("grant_type", "password"), ("subject_token", "x")],
    &[(
      "grant_type",
      "urn:ietf:params:oauth:grant-type:token-exchange",
    )],
    &[
      (
        "grant_type",
        "urn:ietf:params:oauth:grant-type:token-exchange",
      ),
      ("subject_token", "x"),
      ("subject_token_type", "urn:made:up"),
    ],
  ];
  for form in forms {
    let res = reqwest.post(&url).form(form).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{form:?}");
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body["error"].is_string(), "{form:?} -> {body}");
  }
  // Json isn't accepted, the RFC requires a form.
  let res = reqwest
    .post(&url)
    .json(&json!({ "grant_type": "x" }))
    .send()
    .await
    .unwrap();
  assert!(res.status().is_client_error());
  let body: serde_json::Value = res.json().await.unwrap();
  assert!(body["error"].is_string(), "{body}");
}

#[tokio::test]
async fn failed_exchanges_are_rate_limited() {
  let app = TestApp::spawn_with(TestAppOptions {
    rate_limit: Some((3, 60)),
    ..exchange_options(json!({ "enabled": true }))
  })
  .await;
  sign_up_alice(&app).await;
  // A failure keeps its OAuth error code, noting the attempts left.
  let (status, error) =
    app.token_exchange("x", "urn:made:up").await.unwrap_err();
  assert_eq!(status, StatusCode::BAD_REQUEST);
  assert_eq!(error.error, "invalid_request");
  assert!(
    error
      .error_description
      .as_deref()
      .is_some_and(|d| d.ends_with("You have 2 attempts remaining")),
    "{error:?}"
  );
  for _ in 0..2 {
    let (status, _) = app
      .token_exchange("not-a-token", TOKEN_TYPE_ID_TOKEN)
      .await
      .unwrap_err();
    assert_eq!(status, StatusCode::BAD_REQUEST);
  }
  let token = app.idp.mint(alice_token(&app));
  let (status, error) = app
    .token_exchange(&token, TOKEN_TYPE_ID_TOKEN)
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
  assert_eq!(error.error, "temporarily_unavailable");
}

#[tokio::test]
async fn second_factor_is_not_skipped_by_the_exchange() {
  let app =
    TestApp::spawn_with(exchange_options(json!({ "enabled": true })))
      .await;
  let alice = sign_up_alice(&app).await;
  let enrollment =
    alice.manage(BeginTotpEnrollment {}).await.unwrap();
  let totp = totp_from_uri(&enrollment.uri);
  alice
    .manage(ConfirmTotpEnrollment {
      code: totp.generate_current().to_string(),
    })
    .await
    .unwrap();

  // `/token` has no way to ask for the code.
  let token = app.idp.mint(alice_token(&app));
  let (status, error) = app
    .token_exchange(&token, TOKEN_TYPE_ID_TOKEN)
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::BAD_REQUEST);
  assert_eq!(error.error, "invalid_grant");

  // The login api variant continues with the second factor.
  let client = app.client();
  let res = client
    .login(ExchangeExternalForJwt {
      token: token.clone(),
    })
    .await
    .unwrap();
  assert!(matches!(res, JwtOrTwoFactor::Totp {}), "{res:?}");
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
}

/// A provider token can be exchanged again until it expires. The app
/// token counts as a login when the provider authenticated the user,
/// so a leaked old one (or one refreshed without a login) gets the
/// app, but not the account: the reauthentication window applies.
#[tokio::test]
async fn an_old_provider_token_is_not_a_recent_login() {
  let app = TestApp::spawn_with(TestAppOptions {
    env: vec![(
      "EXAMPLE_REAUTHENTICATION_WINDOW_SECONDS".into(),
      "60".into(),
    )],
    // No limit on the token age, the default.
    ..exchange_options(json!({ "enabled": true }))
  })
  .await;
  sign_up_alice(&app).await;
  let now = unix_timestamp_ms() / 1000;

  let old_tokens = [
    (
      "issued 10 minutes ago, valid for another hour",
      app.idp.mint(MintToken {
        issued_ago: 600,
        expires_in: 3600,
        ..alice_token(&app)
      }),
    ),
    (
      "issued now, for a login 10 minutes ago",
      app.idp.mint(MintToken {
        claims: json!({ "auth_time": now - 600 })
          .as_object()
          .unwrap()
          .clone(),
        ..alice_token(&app)
      }),
    ),
  ];
  let key = || CreateApiKey {
    name: "backdoor".into(),
    expires: 0,
    cidr_whitelist: Vec::new(),
  };
  let password = || UpdatePassword {
    password: "attacker-password".into(),
  };
  for (why, token) in old_tokens {
    let res = app
      .token_exchange(&token, TOKEN_TYPE_ID_TOKEN)
      .await
      .unwrap();
    let from_token =
      app.client().with_auth(ClientAuth::Jwt(res.access_token));
    let client = app.client();
    let JwtOrTwoFactor::Jwt(jwt) = client
      .login(ExchangeExternalForJwt { token })
      .await
      .unwrap()
    else {
      panic!("{why}: expected a jwt");
    };
    let from_login = client.with_auth(ClientAuth::Jwt(jwt.jwt));
    for client in [from_token, from_login] {
      // The app, yes
      get_user(&client).await;
      // The account, no
      assert_reauthentication_required(
        client.manage(key()).await,
        &format!("CreateApiKey ({why})"),
      );
      assert_reauthentication_required(
        client.manage(password()).await,
        &format!("UpdatePassword ({why})"),
      );
    }
  }

  // A freshly issued token is a recent login.
  let fresh = app.idp.mint(alice_token(&app));
  let res = app
    .token_exchange(&fresh, TOKEN_TYPE_ID_TOKEN)
    .await
    .unwrap();
  let client =
    app.client().with_auth(ClientAuth::Jwt(res.access_token));
  client.manage(key()).await.unwrap();
  let login = app.client();
  let JwtOrTwoFactor::Jwt(jwt) = login
    .login(ExchangeExternalForJwt { token: fresh })
    .await
    .unwrap()
  else {
    panic!("expected a jwt");
  };
  login
    .with_auth(ClientAuth::Jwt(jwt.jwt))
    .manage(password())
    .await
    .unwrap();
}

#[tokio::test]
async fn allowed_groups_apply_to_the_exchange() {
  let app = TestApp::spawn_with(TestAppOptions {
    static_oidc: true,
    config: json!({
      "oidc": { "allowed_groups": ["example-users"] },
      "oidc_token_exchange": { "enabled": true },
    }),
    ..Default::default()
  })
  .await;
  sign_up_alice(&app).await;

  // The groups come from the token itself here.
  let token = app.idp.mint(MintToken {
    claims: json!({ "groups": ["example-users"] })
      .as_object()
      .unwrap()
      .clone(),
    ..alice_token(&app)
  });
  app
    .token_exchange(&token, TOKEN_TYPE_ID_TOKEN)
    .await
    .unwrap();

  for claims in [json!({ "groups": ["other"] }), json!({})] {
    let token = app.idp.mint(MintToken {
      claims: claims.as_object().unwrap().clone(),
      ..alice_token(&app)
    });
    let (status, _) = app
      .token_exchange(&token, TOKEN_TYPE_ID_TOKEN)
      .await
      .unwrap_err();
    assert!(status.is_client_error(), "{claims}: {status}");
  }
}
