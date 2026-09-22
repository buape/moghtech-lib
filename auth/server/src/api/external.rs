use anyhow::{Context as _, anyhow};
use axum::{
  Router,
  extract::{Path, Query},
  http::StatusCode,
  response::Redirect,
  routing::get,
};
use mogh_auth_client::{
  api::login::UserIdOrTwoFactor,
  config::{
    ExternalLoginKind, ExternalLoginProvider,
    ExternalLoginProviderConfig,
  },
};
use mogh_error::AddStatusCodeError;
use mogh_rate_limit::WithFailureRateLimit;
use mogh_request_ip::RequestIp;
use serde::Deserialize;
use std::{net::IpAddr, sync::Arc};
use tracing::{error, info, instrument};

use crate::{
  AuthImpl,
  api::{
    RedirectQuery, StandardCallbackQuery, get_user_id_or_two_factor,
    unique_username, user_id_or_two_factor_redirect,
  },
  middleware::check_user_cidr_whitelist,
  provider::{
    external::{
      BuiltProvider, CompletedExternalLogin, SessionExternalLogin,
      load_built_provider, resolve_external_provider_by_slug,
    },
    load_cache::LoadFailedRecently,
  },
  session::Session,
  validations::constant_time_eq,
};
use crate::{Login, api::provider_login};

/// The urls name the provider by its slug (its id for a provider
/// without one), see `ExternalLoginProvider::slug`.
#[derive(Deserialize)]
struct ProviderPath {
  slug: String,
}

pub fn router<I: AuthImpl>() -> Router {
  let mut router = Router::new()
    .route(
      "/external/{slug}/login",
      get(|Path(ProviderPath { slug }), ip, session, query| {
        external_login::<I>(slug, ip, session, query)
      }),
    )
    .route(
      "/external/{slug}/link",
      get(|Path(ProviderPath { slug }), ip, session| {
        external_link::<I>(slug, ip, session)
      }),
    )
    .route(
      "/external/{slug}/callback",
      get(|Path(ProviderPath { slug }), ip, session, query| {
        external_callback::<I>(slug, ip, session, query)
      }),
    );

  // Providers using the reserved id of their kind keep the original
  // paths, so existing redirect URIs registered at the provider keep working.
  for kind in [
    ExternalLoginKind::Oidc,
    ExternalLoginKind::Github,
    ExternalLoginKind::Google,
  ] {
    let id = kind.reserved_id();
    router = router
      .route(
        &format!("/{id}/login"),
        get(move |ip, session, query| {
          external_login::<I>(id.to_string(), ip, session, query)
        }),
      )
      .route(
        &format!("/{id}/link"),
        get(move |ip, session| {
          external_link::<I>(id.to_string(), ip, session)
        }),
      )
      .route(
        &format!("/{id}/callback"),
        get(move |ip, session, query| {
          external_callback::<I>(id.to_string(), ip, session, query)
        }),
      );
  }

  router
}

/// Resolves the provider of the url's slug and its client,
/// ensuring it's enabled.
async fn load_enabled_provider<I: AuthImpl>(
  auth: &I,
  slug: &str,
) -> mogh_error::Result<(ExternalLoginProvider, Arc<BuiltProvider>)> {
  let provider = resolve_external_provider_by_slug(auth, slug)
    .await?
    .provider;

  if !provider.enabled() {
    return Err(
      anyhow!("Login with '{}' is not enabled", provider.name)
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  let built = load_provider_client(auth, &provider).await?;

  Ok((provider, built))
}

/// Loads the client of an already resolved provider.
pub(crate) async fn load_provider_client<I: AuthImpl + ?Sized>(
  auth: &I,
  provider: &ExternalLoginProvider,
) -> mogh_error::Result<Arc<BuiltProvider>> {
  // The app name is the user agent for provider discovery,
  // only require apps to implement it for the kinds using it.
  let app_user_agent = match provider.kind() {
    ExternalLoginKind::Oidc | ExternalLoginKind::Google => {
      auth.app_name()
    }
    ExternalLoginKind::Github => "",
  };

  // These endpoints are unauthenticated. The reason may include
  // internal addresses or configuration details, so it is only logged.
  let built = load_built_provider(
    app_user_agent,
    auth.host(),
    auth.path(),
    provider,
  )
  .await
  .map_err(|e| {
    // Logged once per attempt, not by every request while it is down.
    if !LoadFailedRecently::is(&e) {
      error!(
        provider_id = provider.id,
        provider = provider.name,
        "Failed to initialize external login provider | {e:#}"
      );
    }
    anyhow!("Login provider '{}' is not available", provider.name)
      .status_code(StatusCode::SERVICE_UNAVAILABLE)
  })?;

  Ok(built)
}

pub async fn external_login<I: AuthImpl>(
  slug: String,
  RequestIp(ip): RequestIp,
  session: Session,
  Query(RedirectQuery { redirect }): Query<RedirectQuery>,
) -> mogh_error::Result<Redirect> {
  let auth = I::new();
  let res = async {
    let (provider, built) =
      load_enabled_provider(&auth, &slug).await?;

    let begin = built.begin_login();

    // Data inserted here will be matched on callback side for csrf protection.
    session
      .insert_external_login(&SessionExternalLogin {
        provider_id: provider.id.clone(),
        link_user_id: None,
        state: begin.state,
        nonce: begin.nonce,
        pkce_verifier: begin.pkce_verifier,
        redirect,
      })
      .await?;

    provider_redirect(&provider, &begin.url)
  }
  .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), &ip)
  .await;
  error_redirect(&auth, ExternalFlow::Login, res)
}

pub async fn external_link<I: AuthImpl>(
  slug: String,
  RequestIp(ip): RequestIp,
  session: Session,
) -> mogh_error::Result<Redirect> {
  let auth = I::new();
  let res = async {
    let (provider, built) =
      load_enabled_provider(&auth, &slug).await?;

    let user_id = session.retrieve_external_link_user_id().await?;

    let user = auth.get_user(user_id.clone()).await?;
    auth.check_username_locked(user.username())?;
    check_user_cidr_whitelist(user.as_ref(), ip)?;

    let begin = built.begin_login();

    session
      .insert_external_login(&SessionExternalLogin {
        provider_id: provider.id.clone(),
        link_user_id: Some(user_id),
        state: begin.state,
        nonce: begin.nonce,
        pkce_verifier: begin.pkce_verifier,
        redirect: None,
      })
      .await?;

    info!(
      user_id = user.id(),
      username = user.username(),
      provider_id = provider.id,
      provider = provider.name,
      "External login link flow initiated"
    );

    provider_redirect(&provider, &begin.url)
  }
  .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), &ip)
  .await;
  error_redirect(&auth, ExternalFlow::Link, res)
}

/// Whether an external flow logs a user in, or links
/// the provider to the user who is already logged in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExternalFlow {
  Login,
  Link,
}

/// External logins are browser navigations, so with
/// [AuthImpl::external_login_error_redirect] configured a failure sends
/// the user back to the app with the reason, rather than leaving them
/// on a page showing the JSON error.
fn error_redirect<I: AuthImpl>(
  auth: &I,
  flow: ExternalFlow,
  res: mogh_error::Result<Redirect>,
) -> mogh_error::Result<Redirect> {
  let e = match res {
    Ok(redirect) => return Ok(redirect),
    Err(e) => e,
  };
  let Some(login_page) = auth.external_login_error_redirect() else {
    return Err(e);
  };
  let (target, param) = match flow {
    ExternalFlow::Login => (login_page, "login_error"),
    ExternalFlow::Link => (auth.post_link_redirect(), "link_error"),
  };
  let message = if e.status.is_server_error() {
    // The details are for the operator, not for the url bar.
    error!("External login failed | {:#}", e.error);
    String::from("Login failed, see the server logs for details")
  } else {
    format!("{:#}", e.error)
  };
  let splitter = if target.contains('?') { '&' } else { '?' };
  Ok(Redirect::to(&format!(
    "{target}{splitter}{param}={}",
    urlencoding::encode(&message)
  )))
}

/// Applies the OIDC 'redirect_host'
fn provider_redirect(
  provider: &ExternalLoginProvider,
  url: &str,
) -> mogh_error::Result<Redirect> {
  match &provider.config {
    ExternalLoginProviderConfig::Oidc(config) => {
      auth_redirect(url, &config.redirect_host)
    }
    _ => Ok(Redirect::to(url)),
  }
}

/// Applies 'oidc_redirect_host'
fn auth_redirect(
  auth_url: &str,
  redirect_host: &str,
) -> mogh_error::Result<Redirect> {
  let redirect = if !redirect_host.is_empty() {
    let (protocol, rest) = auth_url
      .split_once("://")
      .context("Invalid URL: Missing protocol (eg 'https://')")?;
    let host = rest
      .split_once(['/', '?'])
      .map(|(host, _)| host)
      .unwrap_or(rest);
    Redirect::to(
      &auth_url
        .replace(&format!("{protocol}://{host}"), redirect_host),
    )
  } else {
    Redirect::to(auth_url)
  };
  Ok(redirect)
}

#[instrument(
  "ExternalLoginCallback",
  skip_all,
  fields(ip = ip.to_string(), slug)
)]
pub async fn external_callback<I: AuthImpl>(
  slug: String,
  RequestIp(ip): RequestIp,
  session: Session,
  Query(query): Query<StandardCallbackQuery>,
) -> mogh_error::Result<Redirect> {
  let auth = I::new();
  // Known once the login which was started is read from the session.
  let mut flow = ExternalFlow::Login;
  let res = async {
    let (client_state, code) = query.open()?;

    let (provider, built) =
      load_enabled_provider(&auth, &slug).await?;

    let login = session.retrieve_external_login().await?;

    if login.link_user_id.is_some() {
      flow = ExternalFlow::Link;
    }

    // The provider the url named, by its id: the slug may have
    // changed while the login was in flight.
    validate_callback(&login, &provider.id, &client_state)?;

    let link_user_id = login.link_user_id.clone();
    let redirect = login.redirect.clone();

    let completed = built
      .complete_login(&provider, login, client_state, code)
      .await?;

    match link_user_id {
      Some(user_id) => {
        link_callback(&auth, &provider, user_id, completed).await
      }
      None => {
        login_callback(
          &auth, &session, &provider, &built, completed, redirect, ip,
        )
        .await
      }
    }
  }
  .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), &ip)
  .await;
  error_redirect(&auth, flow, res)
}

/// The callback must be for the provider the login was started
/// with, otherwise the code of one provider could be redeemed
/// at another (mix-up), and carry the CSRF state stored on the session.
fn validate_callback(
  login: &SessionExternalLogin,
  provider_id: &str,
  client_state: &str,
) -> mogh_error::Result<()> {
  if login.provider_id != provider_id {
    return Err(
      anyhow!("Login was initiated with another provider")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }
  if !constant_time_eq(client_state, &login.state) {
    return Err(
      anyhow!("State mismatch").status_code(StatusCode::UNAUTHORIZED),
    );
  }
  Ok(())
}

async fn login_callback<I: AuthImpl>(
  auth: &I,
  session: &Session,
  provider: &ExternalLoginProvider,
  built: &BuiltProvider,
  completed: CompletedExternalLogin,
  redirect: Option<String>,
  ip: IpAddr,
) -> mogh_error::Result<Redirect> {
  let info = completed.info.clone();

  let user = auth
    .find_user_with_external_login(
      info.provider_id.clone(),
      info.external_id.clone(),
    )
    .await?;

  let user_id_or_two_factor = match user {
    // Log in existing user
    Some(user) => {
      // Users outside their whitelist are rejected
      // before the login has any effect on them.
      check_user_cidr_whitelist(user.as_ref(), ip)?;
      // Sync before the session is authenticated,
      // so a failed sync does not leave a logged in session.
      auth.sync_external_user(user.id().to_string(), info).await?;
      get_user_id_or_two_factor(auth, session, &user, ip, provider)
        .await?
    }
    // Sign up user
    None => {
      let no_users_exist = auth.no_users_exist().await?;

      if auth.external_registration_disabled(provider)
        && !no_users_exist
      {
        return Err(
          anyhow!("User registration is disabled")
            .status_code(StatusCode::UNAUTHORIZED),
        );
      }

      let username = completed.username(built).await;

      // Modify username if it already exists
      let username = unique_username(auth, username).await?;

      let user_id = auth
        .sign_up_external_user(
          username.clone(),
          info.clone(),
          no_users_exist,
        )
        .await?;

      info!(
        user_id,
        username,
        provider_id = provider.id,
        provider = provider.name,
        "New user registration (external)"
      );

      auth.sync_external_user(user_id.clone(), info).await?;

      auth
        .record_login(Login {
          user_id: user_id.clone(),
          username,
          ip,
          kind: provider_login(provider),
          second_factor: None,
        })
        .await?;
      session.insert_authenticated_user_id(&user_id).await?;

      UserIdOrTwoFactor::UserId(user_id)
    }
  };

  user_id_or_two_factor_redirect(
    auth,
    user_id_or_two_factor,
    redirect.as_deref(),
  )
}

async fn link_callback<I: AuthImpl>(
  auth: &I,
  provider: &ExternalLoginProvider,
  user_id: String,
  completed: CompletedExternalLogin,
) -> mogh_error::Result<Redirect> {
  let info = completed.info;

  // Ensure there are no other existing users with this login linked.
  if let Some(existing_user) = auth
    .find_user_with_external_login(
      info.provider_id.clone(),
      info.external_id.clone(),
    )
    .await?
  {
    if existing_user.id() == user_id {
      // Link is already complete, only need to sync
      auth.sync_external_user(user_id, info).await?;
      return Ok(Redirect::to(auth.post_link_redirect()));
    } else {
      return Err(
        anyhow!("Account already linked to another user.")
          .status_code(StatusCode::CONFLICT),
      );
    }
  }

  auth
    .link_external_login(user_id.clone(), info.clone())
    .await?;

  info!(
    user_id,
    provider_id = provider.id,
    provider = provider.name,
    "External login linked"
  );

  auth.sync_external_user(user_id, info).await?;

  Ok(Redirect::to(auth.post_link_redirect()))
}

#[cfg(test)]
mod tests {
  use axum::response::IntoResponse;

  use super::*;
  use crate::{LoginKind, provider::external::ExternalLoginInfo};

  fn location(redirect: Redirect) -> String {
    redirect
      .into_response()
      .headers()
      .get("location")
      .unwrap()
      .to_str()
      .unwrap()
      .to_string()
  }

  fn session_login(provider_id: &str) -> SessionExternalLogin {
    SessionExternalLogin {
      provider_id: provider_id.to_string(),
      link_user_id: None,
      state: "expected-state".to_string(),
      nonce: None,
      pkce_verifier: None,
      redirect: None,
    }
  }

  struct TestUser {
    id: String,
    cidr_whitelist: Vec<String>,
  }

  impl crate::user::AuthUserImpl for TestUser {
    fn id(&self) -> &str {
      &self.id
    }
    fn username(&self) -> &str {
      "user"
    }
    fn cidr_whitelist(&self) -> &[String] {
      &self.cidr_whitelist
    }
  }

  /// Records what the flows ask the app to do.
  #[derive(Default)]
  struct Calls {
    /// (provider_id, external_id) -> user id
    logins: Vec<((String, String), String)>,
    synced: Vec<(String, ExternalLoginInfo)>,
    signed_up: Vec<String>,
    recorded: Vec<Login>,
  }

  #[derive(Default)]
  struct TestAuth {
    static_providers: Vec<ExternalLoginProvider>,
    registration_disabled: bool,
    no_users_exist: bool,
    sync_fails: bool,
    cidr_whitelist: Vec<String>,
    error_redirect: Option<&'static str>,
    calls: Arc<std::sync::Mutex<Calls>>,
  }

  impl TestAuth {
    fn with_login(
      self,
      provider_id: &str,
      external_id: &str,
    ) -> Self {
      self.calls.lock().unwrap().logins.push((
        (provider_id.to_string(), external_id.to_string()),
        "existing-user".to_string(),
      ));
      self
    }
  }

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      TestAuth::default()
    }

    fn host(&self) -> &str {
      "https://example.com"
    }

    fn post_link_redirect(&self) -> &str {
      "https://example.com/profile"
    }

    fn external_login_error_redirect(&self) -> Option<&str> {
      self.error_redirect
    }

    fn registration_disabled(&self) -> bool {
      self.registration_disabled
    }

    fn no_users_exist(
      &self,
    ) -> crate::DynFuture<mogh_error::Result<bool>> {
      let no_users_exist = self.no_users_exist;
      Box::pin(async move { Ok(no_users_exist) })
    }

    fn static_external_providers(
      &self,
    ) -> Vec<ExternalLoginProvider> {
      self.static_providers.clone()
    }

    fn find_user_with_username(
      &self,
      _username: String,
    ) -> crate::DynFuture<
      mogh_error::Result<Option<crate::user::BoxAuthUser>>,
    > {
      Box::pin(async { Ok(None) })
    }

    fn record_login(
      &self,
      login: Login,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      self.calls.lock().unwrap().recorded.push(login);
      Box::pin(async { Ok(()) })
    }

    fn find_user_with_external_login(
      &self,
      provider_id: String,
      external_id: String,
    ) -> crate::DynFuture<
      mogh_error::Result<Option<crate::user::BoxAuthUser>>,
    > {
      let user = self
        .calls
        .lock()
        .unwrap()
        .logins
        .iter()
        .find(|(login, _)| {
          *login == (provider_id.clone(), external_id.clone())
        })
        .map(|(_, user_id)| {
          Box::new(TestUser {
            id: user_id.clone(),
            cidr_whitelist: self.cidr_whitelist.clone(),
          }) as crate::user::BoxAuthUser
        });
      Box::pin(async move { Ok(user) })
    }

    fn sign_up_external_user(
      &self,
      username: String,
      info: ExternalLoginInfo,
      _no_users_exist: bool,
    ) -> crate::DynFuture<mogh_error::Result<String>> {
      let mut calls = self.calls.lock().unwrap();
      calls.signed_up.push(username);
      calls.logins.push((
        (info.provider_id, info.external_id),
        "new-user".into(),
      ));
      Box::pin(async { Ok("new-user".to_string()) })
    }

    fn sync_external_user(
      &self,
      user_id: String,
      info: ExternalLoginInfo,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      if self.sync_fails {
        return Box::pin(async {
          Err(anyhow!("sync failed").into())
        });
      }
      self.calls.lock().unwrap().synced.push((user_id, info));
      Box::pin(async { Ok(()) })
    }

    fn link_external_login(
      &self,
      user_id: String,
      info: ExternalLoginInfo,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      self
        .calls
        .lock()
        .unwrap()
        .logins
        .push(((info.provider_id, info.external_id), user_id));
      Box::pin(async { Ok(()) })
    }

    fn get_user(
      &self,
      _user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<crate::user::BoxAuthUser>>
    {
      Box::pin(async { Err(anyhow!("not implemented").into()) })
    }

    fn handle_request_authentication(
      &self,
      _auth: crate::RequestAuthentication,
      _ip: IpAddr,
      _require_user_enabled: bool,
      _req: axum::extract::Request,
    ) -> crate::DynFuture<mogh_error::Result<axum::extract::Request>>
    {
      Box::pin(async { Err(anyhow!("not implemented").into()) })
    }

    fn jwt_provider(&self) -> &crate::provider::jwt::JwtProvider {
      panic!("not needed for these tests")
    }
  }

  const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));

  fn github(
    id: &str,
    enabled: bool,
    client_secret: &str,
  ) -> ExternalLoginProvider {
    ExternalLoginProvider {
      id: id.to_string(),
      name: "Github".to_string(),
      registration_disabled: false,
      slug: String::new(),
      token_exchange: Default::default(),
      config: ExternalLoginProviderConfig::Github(
        mogh_auth_client::config::NamedOauthConfig {
          enabled,
          client_id: "client-id".to_string(),
          client_secret: client_secret.to_string(),
        },
      ),
    }
  }

  async fn built(
    provider: &ExternalLoginProvider,
  ) -> Arc<BuiltProvider> {
    load_built_provider(
      "test",
      "https://example.com",
      "/auth",
      provider,
    )
    .await
    .unwrap()
  }

  fn completed(
    provider: &ExternalLoginProvider,
    external_id: &str,
    admin: Option<bool>,
  ) -> CompletedExternalLogin {
    CompletedExternalLogin::known(
      ExternalLoginInfo {
        provider_id: provider.id.clone(),
        kind: provider.kind(),
        external_id: external_id.to_string(),
        avatar_url: None,
        groups: None,
        admin,
      },
      "octocat",
    )
  }

  fn session() -> Session {
    Session(tower_sessions::Session::new(
      None,
      Arc::new(tower_sessions::MemoryStore::default()),
      None,
    ))
  }

  async fn run_login(
    auth: &TestAuth,
    session: &Session,
    provider: &ExternalLoginProvider,
    external_id: &str,
  ) -> mogh_error::Result<Redirect> {
    login_callback(
      auth,
      session,
      provider,
      built(provider).await.as_ref(),
      completed(provider, external_id, Some(true)),
      None,
      IP,
    )
    .await
  }

  #[tokio::test]
  async fn test_load_provider_unknown_and_disabled() {
    let auth = TestAuth {
      static_providers: vec![github(
        "flow-disabled",
        false,
        "secret",
      )],
      ..Default::default()
    };
    let err =
      load_enabled_provider(&auth, "unknown").await.err().unwrap();
    assert_eq!(err.status, StatusCode::NOT_FOUND);
    let err = load_enabled_provider(&auth, "flow-disabled")
      .await
      .err()
      .unwrap();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  /// The login endpoints are unauthenticated, the reason
  /// a provider can't be built is only logged.
  #[tokio::test]
  async fn test_load_provider_failure_does_not_leak_details() {
    let auth = TestAuth {
      static_providers: vec![github("flow-broken", true, "")],
      ..Default::default()
    };
    let err = load_enabled_provider(&auth, "flow-broken")
      .await
      .err()
      .unwrap();
    assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
    let message = format!("{:#}", err.error);
    assert!(message.contains("not available"), "{message}");
    assert!(!message.contains("client_secret"), "{message}");
  }

  #[tokio::test]
  async fn test_login_existing_user_syncs_and_authenticates() {
    let provider = github("flow-a", true, "secret");
    let auth = TestAuth::default().with_login("flow-a", "42");
    let session = session();

    let redirect =
      run_login(&auth, &session, &provider, "42").await.unwrap();
    assert!(location(redirect).contains("redeem_ready=true"));

    {
      let calls = auth.calls.lock().unwrap();
      assert!(calls.signed_up.is_empty());
      assert_eq!(calls.synced.len(), 1);
      assert_eq!(calls.synced[0].0, "existing-user");
      assert_eq!(calls.synced[0].1.provider_id, "flow-a");
      assert_eq!(calls.synced[0].1.admin, Some(true));
      // The login is recorded as one through the provider
      assert_eq!(calls.recorded.len(), 1);
      assert_eq!(calls.recorded[0].user_id, "existing-user");
      assert!(calls.recorded[0].second_factor.is_none());
      assert_eq!(
        calls.recorded[0].kind,
        LoginKind::Provider {
          provider_id: "flow-a".into(),
          provider_name: provider.name.clone(),
        }
      );
    }
    assert_eq!(
      session.retrieve_authenticated_user_id().await.unwrap(),
      "existing-user"
    );
  }

  /// External ids are only unique per provider: the same id at
  /// another provider must never log in as the existing user.
  #[tokio::test]
  async fn test_login_same_external_id_at_other_provider_is_other_user()
   {
    let provider = github("flow-b", true, "secret");
    let auth = TestAuth::default().with_login("flow-a", "42");
    let session = session();

    let _redirect =
      run_login(&auth, &session, &provider, "42").await.unwrap();

    assert_eq!(auth.calls.lock().unwrap().signed_up, ["octocat"]);
    assert_eq!(
      session.retrieve_authenticated_user_id().await.unwrap(),
      "new-user"
    );
  }

  #[tokio::test]
  async fn test_signup_respects_registration_disabled() {
    let provider = github("flow-a", true, "secret");
    let auth = TestAuth {
      registration_disabled: true,
      ..Default::default()
    };
    let session = session();
    let err = run_login(&auth, &session, &provider, "42")
      .await
      .err()
      .unwrap();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(auth.calls.lock().unwrap().signed_up.is_empty());
    assert!(auth.calls.lock().unwrap().recorded.is_empty());
    assert!(session.retrieve_authenticated_user_id().await.is_err());

    // Provider level setting
    let mut disabled = github("flow-a", true, "secret");
    disabled.registration_disabled = true;
    let auth = TestAuth::default();
    assert!(
      run_login(&auth, &session, &disabled, "42").await.is_err()
    );
    assert!(auth.calls.lock().unwrap().recorded.is_empty());

    // The first user can always sign up, which logs them in
    let auth = TestAuth {
      registration_disabled: true,
      no_users_exist: true,
      ..Default::default()
    };
    let _redirect =
      run_login(&auth, &session, &provider, "42").await.unwrap();
    let calls = auth.calls.lock().unwrap();
    assert_eq!(calls.signed_up, ["octocat"]);
    assert_eq!(calls.recorded.len(), 1);
    assert_eq!(calls.recorded[0].username, "octocat");
    assert_eq!(calls.recorded[0].ip, IP);
    assert!(calls.recorded[0].second_factor.is_none());
    assert_eq!(
      calls.recorded[0].kind,
      LoginKind::Provider {
        provider_id: "flow-a".into(),
        provider_name: provider.name.clone(),
      }
    );
  }

  #[tokio::test]
  async fn test_failed_sync_fails_login_without_session() {
    let provider = github("flow-a", true, "secret");
    let auth = TestAuth {
      sync_fails: true,
      ..Default::default()
    }
    .with_login("flow-a", "42");
    let session = session();
    assert!(
      run_login(&auth, &session, &provider, "42").await.is_err()
    );
    assert!(session.retrieve_authenticated_user_id().await.is_err());
  }

  #[tokio::test]
  async fn test_cidr_whitelist_rejected_before_sync() {
    let provider = github("flow-a", true, "secret");
    let auth = TestAuth {
      cidr_whitelist: vec!["192.168.0.0/16".to_string()],
      ..Default::default()
    }
    .with_login("flow-a", "42");
    let session = session();
    let err = run_login(&auth, &session, &provider, "42")
      .await
      .err()
      .unwrap();
    assert_eq!(err.status, StatusCode::FORBIDDEN);
    assert!(auth.calls.lock().unwrap().synced.is_empty());
    assert!(session.retrieve_authenticated_user_id().await.is_err());
  }

  #[tokio::test]
  async fn test_link_new_login_links_and_syncs() {
    let provider = github("flow-a", true, "secret");
    let auth = TestAuth::default();
    let redirect = link_callback(
      &auth,
      &provider,
      "linking-user".to_string(),
      completed(&provider, "42", None),
    )
    .await
    .unwrap();
    assert_eq!(location(redirect), "https://example.com/profile");
    let calls = auth.calls.lock().unwrap();
    assert_eq!(
      calls.logins,
      [(("flow-a".into(), "42".into()), "linking-user".into())]
    );
    assert_eq!(calls.synced.len(), 1);
    assert_eq!(calls.synced[0].0, "linking-user");
  }

  fn rejected() -> mogh_error::Result<Redirect> {
    Err(
      anyhow!("User registration is disabled & more")
        .status_code(StatusCode::UNAUTHORIZED),
    )
  }

  #[test]
  fn test_error_redirect_is_opt_in() {
    // By default the JSON error is the response, as before.
    let auth = TestAuth::default();
    let err = error_redirect(&auth, ExternalFlow::Login, rejected())
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    // Successful flows are never touched.
    let auth = TestAuth {
      error_redirect: Some("https://example.com/login"),
      ..Default::default()
    };
    let ok = error_redirect(
      &auth,
      ExternalFlow::Login,
      Ok(Redirect::to("https://idp.example.com/authorize")),
    )
    .unwrap();
    assert_eq!(location(ok), "https://idp.example.com/authorize");
  }

  #[test]
  fn test_error_redirect_sends_the_reason_to_the_app() {
    let auth = TestAuth {
      error_redirect: Some("https://example.com/login"),
      ..Default::default()
    };
    let redirect =
      error_redirect(&auth, ExternalFlow::Login, rejected()).unwrap();
    assert_eq!(
      location(redirect),
      "https://example.com/login?login_error=User%20registration%20is%20disabled%20%26%20more"
    );
    // A failed link goes back to where links are managed.
    let redirect =
      error_redirect(&auth, ExternalFlow::Link, rejected()).unwrap();
    assert!(
      location(redirect)
        .starts_with("https://example.com/profile?link_error=User")
    );
    // An existing query is kept.
    let auth = TestAuth {
      error_redirect: Some("https://example.com/login?theme=dark"),
      ..Default::default()
    };
    let redirect =
      error_redirect(&auth, ExternalFlow::Login, rejected()).unwrap();
    assert!(location(redirect).starts_with(
      "https://example.com/login?theme=dark&login_error=User"
    ));
  }

  #[test]
  fn test_error_redirect_hides_server_errors() {
    let auth = TestAuth {
      error_redirect: Some("https://example.com/login"),
      ..Default::default()
    };
    let redirect = error_redirect(
      &auth,
      ExternalFlow::Login,
      Err(anyhow!("connection refused to 10.0.0.5:5432").into()),
    )
    .unwrap();
    let location = location(redirect);
    assert!(location.contains("login_error=Login%20failed"));
    assert!(!location.contains("10.0.0.5"), "{location}");
  }

  #[tokio::test]
  async fn test_link_rejects_login_linked_to_another_user() {
    let provider = github("flow-a", true, "secret");
    let auth = TestAuth::default().with_login("flow-a", "42");
    let err = link_callback(
      &auth,
      &provider,
      "linking-user".to_string(),
      completed(&provider, "42", None),
    )
    .await
    .unwrap_err();
    // Not a server error, the login belongs to somebody else.
    assert_eq!(err.status, StatusCode::CONFLICT);
    let calls = auth.calls.lock().unwrap();
    assert_eq!(calls.logins.len(), 1);
    assert!(calls.synced.is_empty());
  }

  #[tokio::test]
  async fn test_empty_provider_username_falls_back_to_external_id() {
    let provider = github("flow-a", true, "secret");
    let completed = CompletedExternalLogin::known(
      completed(&provider, "42", None).info,
      "  ",
    );
    assert_eq!(
      completed.username(built(&provider).await.as_ref()).await,
      "42"
    );
  }

  /// Axum panics on conflicting or malformed routes when the
  /// router is built, which covers the reserved id paths
  /// living next to `/external/{provider_id}`.
  #[test]
  fn test_router_builds_without_route_conflicts() {
    let _ = router::<TestAuth>();
    let _ = crate::api::router::<TestAuth>();
  }

  #[test]
  fn test_validate_callback_accepts_matching_provider_and_state() {
    assert!(
      validate_callback(
        &session_login("abc"),
        "abc",
        "expected-state"
      )
      .is_ok()
    );
  }

  #[test]
  fn test_validate_callback_rejects_other_provider() {
    let err = validate_callback(
      &session_login("abc"),
      "other",
      "expected-state",
    )
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_validate_callback_rejects_state_mismatch() {
    let err =
      validate_callback(&session_login("abc"), "abc", "forged-state")
        .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_auth_redirect_no_redirect_host() {
    let redirect =
      auth_redirect("https://idp.internal/authorize?a=1", "")
        .unwrap();
    assert_eq!(
      location(redirect),
      "https://idp.internal/authorize?a=1"
    );
  }

  #[test]
  fn test_auth_redirect_replaces_host() {
    let redirect = auth_redirect(
      "https://idp.internal/authorize?a=1",
      "https://idp.external",
    )
    .unwrap();
    assert_eq!(
      location(redirect),
      "https://idp.external/authorize?a=1"
    );
  }

  #[test]
  fn test_auth_redirect_host_without_path() {
    let redirect =
      auth_redirect("https://idp.internal", "https://idp.external")
        .unwrap();
    assert_eq!(location(redirect), "https://idp.external");
  }

  #[test]
  fn test_auth_redirect_missing_protocol_errors() {
    assert!(
      auth_redirect("idp.internal/authorize", "https://external")
        .is_err()
    );
  }
}
