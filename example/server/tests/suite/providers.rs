//! Login providers stored by the app and managed by admins over the auth api.

use example_client::{
  ClientAuth, ExampleClient,
  auth::{
    api::{
      login::{ExchangeForJwt, GetLoginOptions},
      manage::{
        CreateExternalLoginProvider, DeleteExternalLoginProvider,
        ListExternalLoginProviders, UpdateExternalLoginProvider,
      },
    },
    config::{
      ExternalLoginProviderConfig, NamedOauthConfig, OidcConfig,
      REDACTED,
    },
  },
};
use reqwest::StatusCode;

use crate::common::*;

fn oidc_config(app: &TestApp) -> OidcConfig {
  OidcConfig {
    enabled: true,
    provider: app.idp.issuer.clone(),
    client_id: app.idp.client_id.clone(),
    client_secret: app.idp.client_secret.clone(),
    ..Default::default()
  }
}

fn create_request(
  name: &str,
  config: ExternalLoginProviderConfig,
) -> CreateExternalLoginProvider {
  CreateExternalLoginProvider {
    slug: String::new(),
    name: name.into(),
    registration_disabled: false,
    token_exchange: Default::default(),
    config,
  }
}

/// Logs in at the provider's login url, which names it by slug.
async fn login_with(
  app: &TestApp,
  provider_slug: &str,
  idp_user: &str,
) -> ExampleClient {
  app.idp.set_auto_user(Some(&format!("{idp_user}-sub")));
  let client = app.client();
  let landed = follow_external_flow(
    &client,
    &format!("{}/auth/external/{provider_slug}/login", app.address),
  )
  .await;
  assert_eq!(landed.query(), Some("redeem_ready=true"), "{landed}");
  let jwt = client.login(ExchangeForJwt {}).await.unwrap().jwt;
  client.with_auth(ClientAuth::Jwt(jwt))
}

#[tokio::test]
async fn only_admins_manage_providers() {
  let app = TestApp::spawn().await;
  app.sign_up("admin").await;
  let user = app.sign_up("user").await;

  let res = user.manage(ListExternalLoginProviders {}).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  let res = user
    .manage(create_request(
      "Mine",
      ExternalLoginProviderConfig::Oidc(oidc_config(&app)),
    ))
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  let res = user
    .manage(DeleteExternalLoginProvider { id: "oidc".into() })
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  let res = app.client().manage(ListExternalLoginProviders {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn stored_provider_lifecycle() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  app.add_idp_user("alice", &[]);

  let created = admin
    .manage(create_request(
      "Company SSO",
      ExternalLoginProviderConfig::Oidc(oidc_config(&app)),
    ))
    .await
    .unwrap();
  let id = created.provider.id.clone();
  assert!(!created.read_only);
  // The urls use the slug, made from the name.
  let slug = created.provider.slug.clone();
  assert_eq!(slug, "company-sso");
  assert_eq!(
    created.redirect_uri,
    format!("{}/auth/external/{slug}/callback", app.address)
  );
  // The secret never comes back.
  assert_eq!(created.provider.config.client_secret(), REDACTED);

  // It shows up on the login page right away, without the config.
  let options = app.client().login(GetLoginOptions {}).await.unwrap();
  assert_eq!(options.providers.len(), 1);
  assert_eq!(options.providers[0].name, "Company SSO");

  // The secret is encrypted in the database.
  for file in ["data/example.db", "data/example.db-wal"] {
    let contents = std::fs::read(app.path(file)).unwrap_or_default();
    let secret = app.idp.client_secret.as_bytes();
    assert!(
      !contents.windows(secret.len()).any(|w| w == secret),
      "The client secret is stored in plain text in {file}"
    );
  }

  // Logging in works, which needs the stored secret.
  let alice = login_with(&app, &slug, "alice").await;
  let user = get_user(&alice).await;
  // Links carry the id, which a slug change never touches.
  assert_eq!(user.linked_logins[0].provider_id, id);

  // An update with the redacted / an empty secret keeps the stored one.
  for client_secret in [REDACTED, ""] {
    let updated = admin
      .manage(UpdateExternalLoginProvider {
        slug: String::new(),
        id: id.clone(),
        name: "Renamed SSO".into(),
        registration_disabled: true,
        token_exchange: Default::default(),
        config: ExternalLoginProviderConfig::Oidc(OidcConfig {
          client_secret: client_secret.into(),
          ..oidc_config(&app)
        }),
        clear_client_secret: false,
      })
      .await
      .unwrap();
    assert_eq!(updated.provider.name, "Renamed SSO");
    // An empty slug keeps the existing one, whatever the name.
    assert_eq!(updated.provider.slug, slug);
    login_with(&app, &slug, "alice").await;
  }
  let options = app.client().login(GetLoginOptions {}).await.unwrap();
  assert!(options.providers[0].registration_disabled);

  // A wrong secret is used right away (no stale cached client).
  admin
    .manage(UpdateExternalLoginProvider {
      slug: String::new(),
      id: id.clone(),
      name: "Renamed SSO".into(),
      registration_disabled: false,
      token_exchange: Default::default(),
      config: ExternalLoginProviderConfig::Oidc(OidcConfig {
        client_secret: "wrong-secret".into(),
        ..oidc_config(&app)
      }),
      clear_client_secret: false,
    })
    .await
    .unwrap();
  app.idp.set_auto_user(Some("alice-sub"));
  let client = app.client();
  let landed = follow_external_flow(
    &client,
    &format!("{}/auth/external/{slug}/login", app.address),
  )
  .await;
  // The provider refuses the wrong secret, which is a server side
  // problem: the user is only told that the login failed.
  let error = external_error(&landed, "login_error");
  assert!(error.contains("Login failed"), "{error}");
  assert!(!landed.as_str().contains("wrong-secret"));

  // Deleting removes the login option and the links of its users.
  admin
    .manage(DeleteExternalLoginProvider { id: id.clone() })
    .await
    .unwrap();
  assert!(
    app
      .client()
      .login(GetLoginOptions {})
      .await
      .unwrap()
      .providers
      .is_empty()
  );
  assert!(get_user(&alice).await.linked_logins.is_empty());
  let landed = follow_external_flow(
    &client,
    &format!("{}/auth/external/{slug}/login", app.address),
  )
  .await;
  external_error(&landed, "login_error");
  let res = admin.manage(DeleteExternalLoginProvider { id }).await;
  assert!(status_of(res).is_client_error());
}

#[tokio::test]
async fn provider_configs_are_validated() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  let invalid = [
    // No name
    create_request(
      "",
      ExternalLoginProviderConfig::Oidc(oidc_config(&app)),
    ),
    // Not a url
    create_request(
      "Bad url",
      ExternalLoginProviderConfig::Oidc(OidcConfig {
        provider: "not a url".into(),
        ..oidc_config(&app)
      }),
    ),
    create_request(
      "Bad scheme",
      ExternalLoginProviderConfig::Oidc(OidcConfig {
        provider: "javascript:alert(1)".into(),
        ..oidc_config(&app)
      }),
    ),
    // Enabled Github / Google providers need a secret.
    create_request(
      "Github",
      ExternalLoginProviderConfig::Github(NamedOauthConfig {
        enabled: true,
        client_id: "id".into(),
        client_secret: String::new(),
      }),
    ),
  ];
  for request in invalid {
    let name = request.name.clone();
    let res = admin.manage(request).await;
    assert_eq!(status_of(res), StatusCode::BAD_REQUEST, "{name:?}");
  }
  assert!(
    admin
      .manage(ListExternalLoginProviders {})
      .await
      .unwrap()
      .is_empty()
  );

  // The kind of a provider can't change.
  let created = admin
    .manage(create_request(
      "Github",
      ExternalLoginProviderConfig::Github(NamedOauthConfig {
        enabled: true,
        client_id: "id".into(),
        client_secret: "secret".into(),
      }),
    ))
    .await
    .unwrap();
  let res = admin
    .manage(UpdateExternalLoginProvider {
      slug: String::new(),
      id: created.provider.id.clone(),
      name: "Now OIDC".into(),
      registration_disabled: false,
      token_exchange: Default::default(),
      config: ExternalLoginProviderConfig::Oidc(oidc_config(&app)),
      clear_client_secret: false,
    })
    .await;
  assert_eq!(status_of(res), StatusCode::BAD_REQUEST);

  // Github has no signed tokens to exchange.
  let res = admin
    .manage(UpdateExternalLoginProvider {
      slug: String::new(),
      id: created.provider.id,
      name: "Github".into(),
      registration_disabled: false,
      token_exchange:
        example_client::auth::config::TokenExchangeConfig {
          enabled: true,
          ..Default::default()
        },
      config: ExternalLoginProviderConfig::Github(NamedOauthConfig {
        enabled: true,
        client_id: "id".into(),
        client_secret: String::new(),
      }),
      clear_client_secret: false,
    })
    .await;
  assert_eq!(status_of(res), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn static_providers_are_read_only() {
  let app = TestApp::spawn_with(TestAppOptions {
    static_oidc: true,
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;

  let providers =
    admin.manage(ListExternalLoginProviders {}).await.unwrap();
  assert_eq!(providers.len(), 1);
  assert!(providers[0].read_only);
  assert_eq!(providers[0].provider.id, "oidc");
  // The reserved id keeps the original callback path.
  assert_eq!(
    providers[0].redirect_uri,
    format!("{}/auth/oidc/callback", app.address)
  );
  assert_eq!(providers[0].provider.config.client_secret(), REDACTED);

  let res = admin
    .manage(UpdateExternalLoginProvider {
      slug: String::new(),
      id: "oidc".into(),
      name: "Hijacked".into(),
      registration_disabled: false,
      token_exchange: Default::default(),
      config: ExternalLoginProviderConfig::Oidc(OidcConfig {
        provider: "https://evil.example".into(),
        ..oidc_config(&app)
      }),
      clear_client_secret: false,
    })
    .await;
  assert!(status_of(res).is_client_error());
  let res = admin
    .manage(DeleteExternalLoginProvider { id: "oidc".into() })
    .await;
  assert!(status_of(res).is_client_error());

  // A second provider of the same kind works next to it.
  app.add_idp_user("alice", &[]);
  let created = admin
    .manage(create_request(
      "Second",
      ExternalLoginProviderConfig::Oidc(oidc_config(&app)),
    ))
    .await
    .unwrap();
  assert_ne!(created.provider.id, "oidc");
  let first = login_with(&app, "oidc", "alice").await;
  let second =
    login_with(&app, &created.provider.slug, "alice").await;
  // The same subject at another provider is another user.
  assert_ne!(get_user(&first).await.id, get_user(&second).await.id);
}

#[tokio::test]
async fn stored_providers_survive_a_restart() {
  let mut app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  app.add_idp_user("alice", &[]);
  let slug = admin
    .manage(create_request(
      "Company SSO",
      ExternalLoginProviderConfig::Oidc(oidc_config(&app)),
    ))
    .await
    .unwrap()
    .provider
    .slug;
  let alice = login_with(&app, &slug, "alice").await;
  let alice_id = get_user(&alice).await.id;

  app.restart().await;

  // Decrypted with the key file generated on the first start.
  let again = login_with(&app, &slug, "alice").await;
  assert_eq!(get_user(&again).await.id, alice_id);
  // Tokens signed before the restart are still valid (same jwt secret).
  assert_eq!(get_user(&alice).await.id, alice_id);
}
