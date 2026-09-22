use std::{
  net::IpAddr,
  sync::{Arc, LazyLock},
};

use anyhow::{Context as _, anyhow};
use axum::{extract::Request, http::StatusCode};
use mogh_auth_client::{
  api::manage::CreateApiKey,
  config::{ExternalLoginProvider, TrustedIssuer},
  passkey::Passkey,
};
use mogh_error::{AddStatusCode, AddStatusCodeError};
use mogh_pki::RotatableKeyPair;
use mogh_rate_limit::RateLimiter;
use serde::{Deserialize, Serialize};

pub mod api;
pub mod api_key;
pub mod middleware;
pub mod provider;
pub mod rand;
pub mod user;
pub mod validations;

mod session;

use crate::{
  api_key::BoxAuthApiKey,
  provider::{
    external::ExternalLoginInfo, jwt::JwtProvider,
    passkey::PasskeyProvider, workload::WorkloadIdentity,
  },
  user::BoxAuthUser,
  validations::{
    validate_api_key_name, validate_cidr_whitelist,
    validate_password, validate_username,
  },
};

/// Client ip extraction. The `RequestIp` extractor believes
/// forwarding headers only from the [TrustedProxies][request_ip::TrustedProxies]
/// attached to the request by `mogh_server::serve_app`
/// (`ServerConfig::trusted_proxies`), else private ranges.
/// Apps not using `mogh_server` should add
/// `TrustedProxies::layer()` to their router.
pub mod request_ip {
  pub use mogh_request_ip::*;
}

pub type BoxAuthImpl = Box<dyn AuthImpl>;
pub type DynFuture<O> =
  std::pin::Pin<Box<dyn Future<Output = O> + Send>>;

#[derive(Clone)]
pub enum RequestAuthentication {
  /// Jwt's coming through the AUTHORIZATION header.
  /// DANGER ⚠️ the jwt must still be validated as belonging to a particular client.
  Jwt(String),
  /// The api key and secret from X-API-KEY and X-API-SECRET.
  /// DANGER ⚠️ the secret needs bcrypt compare with matching
  /// api key's hashed secret to be validated as belonging to a particular client.
  ApiKey { key: String, secret: String },
  /// X-API-SIGNATURE and X-API-TIMESTAMP. The handshake produces the public key.
  /// DANGER ⚠️ the public key must still be validated as belonging to a particular client.
  PublicKey(String),
}

/// A login the auth server completed, see [AuthImpl::record_login].
/// Built by the server ([Login::of]); apps read it. Fields may be
/// added.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Login {
  /// The user who logged in.
  pub user_id: String,
  /// Their username at the time (for a user just signed up through
  /// a provider, the one the server made unique).
  pub username: String,
  /// The client ip the login came from (the request's, forwarding
  /// headers honored from the trusted proxies only).
  pub ip: IpAddr,
  /// How the user was authenticated.
  pub kind: LoginKind,
  /// The second factor the login was completed with, for a user
  /// enrolled in one. Never for a workload, nor for a `POST /token`
  /// exchange (which refuses such users); an `ExchangeExternalForJwt`
  /// can be completed with one.
  pub second_factor: Option<SecondFactor>,
}

impl Login {
  /// The login of `user`.
  pub fn of(
    user: &dyn crate::user::AuthUserImpl,
    ip: IpAddr,
    kind: LoginKind,
    second_factor: Option<SecondFactor>,
  ) -> Login {
    Login {
      user_id: user.id().to_string(),
      username: user.username().to_string(),
      ip,
      kind,
      second_factor,
    }
  }
}

/// How a login authenticated the user.
///
/// Matched exhaustively on purpose, like
/// [ExchangedLogin](api::token::ExchangedLogin): a new kind of login
/// is meant to be a compile error for an app recording them, not a
/// silently unrecorded login. Its serde form is kept on the session
/// between the two factors of a login, so it stays backwards
/// compatible (a value the server can't read counts as a local
/// login).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoginKind {
  /// Username and password (`LoginLocalUser`).
  Local,
  /// Through a login provider: the user logged in at the provider
  /// and came back to its callback (`/external/{slug}/callback`),
  /// or a token of the provider was exchanged (`POST /token`,
  /// `ExchangeExternalForJwt`).
  Provider {
    provider_id: String,
    provider_name: String,
  },
  /// A workload's token exchanged (`POST /token`): verified by a
  /// trusted issuer and matched to one of its rules, whose user
  /// logged in.
  Workload {
    issuer_id: String,
    issuer_name: String,
    rule_id: String,
    rule_name: String,
  },
}

impl From<api::token::ExchangedLogin> for LoginKind {
  fn from(login: api::token::ExchangedLogin) -> LoginKind {
    match login {
      api::token::ExchangedLogin::Provider {
        provider_id,
        provider_name,
      } => LoginKind::Provider {
        provider_id,
        provider_name,
      },
      api::token::ExchangedLogin::Workload {
        issuer_id,
        issuer_name,
        rule_id,
        rule_name,
      } => LoginKind::Workload {
        issuer_id,
        issuer_name,
        rule_id,
        rule_name,
      },
    }
  }
}

/// The second factor a login was completed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondFactor {
  Passkey,
  Totp,
  /// A TOTP recovery code.
  TotpRecovery,
}

/// This trait is implemented at the app level
/// to support custom schemas, storage providers, and business logic.
pub trait AuthImpl: Send + Sync + 'static {
  /// Construct the auth implementation for extraction.
  /// Only use this at the top level of a client request.
  fn new() -> Self
  where
    Self: Sized;

  /// Provide a static app name. Used for passkeys, as the TOTP issuer,
  /// and as the user agent for OIDC / Google provider discovery.
  fn app_name(&self) -> &'static str {
    panic!(
      "Must implement 'AuthImpl::app_name' in order for passkey / totp 2fa and OIDC / Google login to work."
    )
  }

  /// Provide the app 'host' config.
  /// Example: https://example.com
  fn host(&self) -> &str {
    panic!(
      "Must implement 'AuthImpl::host' in order for external logins and other features to work."
    )
  }

  /// This should be the path to where the auth server is nested on 'host'.
  /// Default is "/auth".
  fn path(&self) -> &str {
    "/auth"
  }

  /// Disable new user registration (all providers).
  fn registration_disabled(&self) -> bool {
    false
  }

  /// Disable new user registration for local (username/password) signups only.
  /// Defaults to [Self::registration_disabled].
  fn local_registration_disabled(&self) -> bool {
    self.registration_disabled()
  }

  /// Disable new user registration with the given external login provider.
  /// Defaults to [Self::registration_disabled], or the providers own
  /// `registration_disabled` setting.
  fn external_registration_disabled(
    &self,
    provider: &ExternalLoginProvider,
  ) -> bool {
    self.registration_disabled() || provider.registration_disabled
  }

  /// Validate api key CIDR whitelist entries.
  fn validate_cidr_whitelist(
    &self,
    cidr_whitelist: &[String],
  ) -> mogh_error::Result<()> {
    validate_cidr_whitelist(cidr_whitelist)
      .status_code(StatusCode::BAD_REQUEST)
  }

  /// Provide usernames to lock credential updates for,
  /// such as demo users.
  fn locked_usernames(&self) -> &'static [String] {
    &[]
  }

  /// If the locked usernames includes '__ALL__',
  /// this will always error.
  fn check_username_locked(
    &self,
    username: &str,
  ) -> mogh_error::Result<()> {
    if self
      .locked_usernames()
      .iter()
      .any(|locked| locked == username || locked == "__ALL__")
    {
      Err(
        anyhow!("Login credentials are locked for this user")
          .status_code(StatusCode::UNAUTHORIZED),
      )
    } else {
      Ok(())
    }
  }

  /// Allow user to register even when registration is disabled
  /// when no users exist. If not implemented, this always evaluates
  /// to false and does not change any behavior.
  fn no_users_exist(&self) -> DynFuture<mogh_error::Result<bool>> {
    Box::pin(async { Ok(false) })
  }

  /// Get's the user using the user id, returning UNAUTHORIZED if none exists.
  fn get_user(
    &self,
    user_id: String,
  ) -> DynFuture<mogh_error::Result<BoxAuthUser>>;

  /// Handle incoming request authentication in middleware.
  /// Can attach a client struct as request extension here.
  ///
  /// `ip` is the client request ip, which must be checked against
  /// the api key's [AuthApiKeyImpl::cidr_whitelist][api_key::AuthApiKeyImpl::cidr_whitelist]
  /// and the user's [AuthUserImpl::cidr_whitelist][user::AuthUserImpl::cidr_whitelist].
  /// [Self::get_user_id_from_request_authentication] handles the api key
  /// whitelist, and [middleware::get_user_from_request_authentication]
  /// additionally handles the user whitelist. See also
  /// [middleware::check_api_key_cidr_whitelist] and
  /// [middleware::check_user_cidr_whitelist] for custom implementations.
  fn handle_request_authentication(
    &self,
    auth: RequestAuthentication,
    ip: IpAddr,
    require_user_enabled: bool,
    req: Request,
  ) -> DynFuture<mogh_error::Result<Request>>;

  /// Authenticates the request credentials and returns the user id.
  ///
  /// - [RequestAuthentication::Jwt]: validated with
  ///   [middleware::get_jwt_user_id].
  /// - [RequestAuthentication::ApiKey]: secret verified and mapped
  ///   with [Self::get_api_key].
  /// - [RequestAuthentication::PublicKey]: mapped with
  ///   [Self::get_api_key_v2].
  ///
  /// For api keys, the request `ip` is checked against the key's
  /// [AuthApiKeyImpl::cidr_whitelist][api_key::AuthApiKeyImpl::cidr_whitelist].
  ///
  /// DANGER ⚠️ The user's own
  /// [AuthUserImpl::cidr_whitelist][user::AuthUserImpl::cidr_whitelist]
  /// is not checked here, as the user is not loaded.
  /// Use [middleware::get_user_from_request_authentication] or
  /// [middleware::check_user_cidr_whitelist] after loading the user.
  fn get_user_id_from_request_authentication(
    &self,
    auth: RequestAuthentication,
    ip: IpAddr,
  ) -> DynFuture<mogh_error::Result<String>> {
    let api_key = match auth {
      RequestAuthentication::Jwt(jwt) => {
        let user_id = middleware::get_jwt_user_id(self, &jwt);
        return Box::pin(async move { user_id });
      }
      RequestAuthentication::ApiKey { key, secret } => {
        self.get_api_key(key, secret)
      }
      RequestAuthentication::PublicKey(public_key) => {
        self.get_api_key_v2(public_key)
      }
    };
    Box::pin(async move {
      let api_key = api_key.await?;
      middleware::check_api_key_cidr_whitelist(api_key.as_ref(), ip)?;
      Ok(api_key.user_id().to_string())
    })
  }

  // =========
  // = STATE =
  // =========

  /// Get the jwt provider.
  fn jwt_provider(&self) -> &JwtProvider;

  /// Get the webauthn passkey provider
  fn passkey_provider(&self) -> Option<&PasskeyProvider> {
    None
  }

  /// Provide a rate limiter for
  /// general authenticated requests.
  ///
  /// It also limits failed external logins and token exchanges
  /// (`POST /token`) by client ip. Note that hosted CI runners share
  /// their ips between many customers, so with workload identity a
  /// strict limit lets one failing job (or somebody else on the same
  /// runners) get your other jobs limited. Keep it generous if
  /// workloads come from shared ips.
  fn general_rate_limiter(&self) -> &RateLimiter {
    static DISABLED_RATE_LIMITER: LazyLock<Arc<RateLimiter>> =
      LazyLock::new(|| RateLimiter::new(true, 0, Default::default()));
    &DISABLED_RATE_LIMITER
  }

  /// Requests of the auth management API which change how a user (or
  /// anyone, for the admin requests) can log in are only accepted with
  /// a token issued at most this many seconds ago: passwords, usernames,
  /// 2fa, linked logins, new api keys, login providers, trusted issuers.
  /// A token which leaked is then not enough to take over the account
  /// for good. `0` disables the check. Default: 15 minutes.
  ///
  /// - Older tokens get `403 Forbidden`, with a message starting with
  ///   [REAUTHENTICATION_REQUIRED][mogh_auth_client::api::manage::REAUTHENTICATION_REQUIRED].
  ///   The user has to log in again, which includes their second factor.
  /// - Api keys have no login to be recent, and are refused for these
  ///   requests while the check is enabled.
  /// - The time is the `iat` of a token of [Self::jwt_provider]. Apps
  ///   validating other tokens in [Self::get_user_id_from_request_authentication]
  ///   should disable this, or those tokens are always refused.
  fn reauthentication_window_secs(&self) -> u64 {
    15 * 60
  }

  /// Where the browser is sent when an external login fails, usually
  /// the login page of the app: `https://example.com/login`.
  ///
  /// External logins are browser navigations, not api calls. With the
  /// default (`None`) a failure (registration disabled, not in an allowed
  /// group, denied at the provider, ...) answers with the JSON error,
  /// which leaves the user on a blank page showing it. With this set
  /// they are redirected here instead, with the reason in the
  /// `login_error` query parameter for the login page to show (the
  /// `mogh_ui` login does). Failed links go to [Self::post_link_redirect]
  /// with `link_error`.
  ///
  /// Server errors are logged and only reported as such.
  fn external_login_error_redirect(&self) -> Option<&str> {
    None
  }

  /// Where to default redirect after linking an external login method.
  fn post_link_redirect(&self) -> &str {
    panic!(
      "Must implement 'AuthImpl::post_link_redirect' in order for linking to work. This is usually the application profile or settings page."
    )
  }

  /// A user logged in: they are authenticated, the hooks the login
  /// needed have run (`sign_up_local_user` / `sign_up_external_user`,
  /// `sync_external_user`, `get_or_create_workload_user`), and their
  /// session or token is issued right after. For the app's own audit
  /// trail; the server logs every login itself, so the default does
  /// nothing.
  ///
  /// Called once per login, at the step which grants it: a local
  /// sign up or login when the password is verified, or once its
  /// second factor is complete; an external sign up or login at the
  /// provider's callback (redeeming the jwt on the same session
  /// afterwards is not another login), or once its second factor is
  /// complete; a token exchange, a user's (`POST /token` or
  /// `ExchangeExternalForJwt`, the latter possibly after a second
  /// factor) or a workload's, when the token is issued.
  ///
  /// An error fails the login. By then a one-time credential may
  /// have been consumed (the TOTP step, a recovery code), so an app
  /// whose recording can fail should log and continue rather than
  /// refuse; and the rare failure after the hook (the session
  /// store, encoding the token) leaves a recorded login the user
  /// did not get.
  fn record_login(
    &self,
    _login: Login,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async { Ok(()) })
  }

  // ==============
  // = LOCAL AUTH =
  // ==============

  /// Whether local auth is enabled.
  fn local_auth_enabled(&self) -> bool {
    true
  }

  /// Set the password hash bcrypt cost.
  fn local_auth_bcrypt_cost(&self) -> u32 {
    10
  }

  /// Local login method can have it's own rate limiter
  /// for 1 to 1 user feedback on remaining attempts.
  /// By default uses the general rate limiter.
  fn local_login_rate_limiter(&self) -> &RateLimiter {
    self.general_rate_limiter()
  }

  /// Validate usernames.
  fn validate_username(
    &self,
    username: &str,
  ) -> mogh_error::Result<()> {
    validate_username(username).status_code(StatusCode::BAD_REQUEST)
  }

  /// Validate passwords.
  fn validate_password(
    &self,
    password: &str,
  ) -> mogh_error::Result<()> {
    validate_password(password).status_code(StatusCode::BAD_REQUEST)
  }

  /// Returns created user id, or error.
  /// The username and password have already been validated.
  fn sign_up_local_user(
    &self,
    _username: String,
    _hashed_password: String,
    _no_users_exist: bool,
  ) -> DynFuture<mogh_error::Result<String>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::sign_up_local_user' in order for local login to work."
        )
        .into(),
      )
    })
  }

  /// Finds user using the username, returning UNAUTHORIZED if none exists.
  fn find_user_with_username(
    &self,
    _username: String,
  ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::find_user_with_username' in order for local login to work."
        )
        .into(),
      )
    })
  }

  fn update_user_username(
    &self,
    _user_id: String,
    _username: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::update_user_username'.")
          .into(),
      )
    })
  }

  fn update_user_password(
    &self,
    _user_id: String,
    _hashed_password: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::update_user_password'.")
          .into(),
      )
    })
  }

  // ==================
  // = EXTERNAL LOGIN =
  // ==================

  /// The external login providers from static app
  /// configuration (file / env). These are read only in the API,
  /// and take precedence over stored providers with the same id.
  ///
  /// A provider using the reserved id of its kind (`oidc`, `github`, `google`,
  /// see [ExternalLoginKind::reserved_id][mogh_auth_client::config::ExternalLoginKind::reserved_id])
  /// keeps the original callback path, eg. `/oidc/callback`, so
  /// redirect URIs already registered at the provider keep working.
  fn static_external_providers(&self) -> Vec<ExternalLoginProvider> {
    Vec::new()
  }

  /// List the external login providers stored by the app (eg. in the database).
  /// These are managed over the API by admins ([AuthUserImpl::is_admin][crate::user::AuthUserImpl::is_admin]).
  ///
  /// The provider configurations include the client secret,
  /// which should be encrypted at rest.
  ///
  /// Note. This is called by the unauthenticated `GetLoginOptions`,
  /// and [Self::get_external_provider] on every external login,
  /// so apps should serve them from a cache rather than hit the
  /// database every time.
  fn list_external_providers(
    &self,
  ) -> DynFuture<mogh_error::Result<Vec<ExternalLoginProvider>>> {
    Box::pin(async { Ok(Vec::new()) })
  }

  /// Get a stored external login provider by id.
  /// Defaults to searching [Self::list_external_providers].
  fn get_external_provider(
    &self,
    id: String,
  ) -> DynFuture<mogh_error::Result<Option<ExternalLoginProvider>>>
  {
    let providers = self.list_external_providers();
    Box::pin(async move {
      let provider = providers
        .await?
        .into_iter()
        .find(|provider| provider.id == id);
      Ok(provider)
    })
  }

  /// Store a new external login provider.
  /// The id is generated by the auth server, and must be stored as is.
  fn create_external_provider(
    &self,
    _provider: ExternalLoginProvider,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::create_external_provider'."
        )
        .into(),
      )
    })
  }

  /// Replace the stored external login provider with the same id.
  fn update_external_provider(
    &self,
    _provider: ExternalLoginProvider,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::update_external_provider'."
        )
        .into(),
      )
    })
  }

  /// Delete the stored external login provider.
  ///
  /// This should also remove the links to the provider from all users.
  /// Users who only have this login can then no longer log in.
  fn delete_external_provider(
    &self,
    _id: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::delete_external_provider'."
        )
        .into(),
      )
    })
  }

  /// Find the user linked to the external user id **at this provider**.
  ///
  /// ⚠️ External user ids are only unique per provider. The lookup must
  /// match both `provider_id` and `external_id`, otherwise another
  /// provider can issue the same id and log in as the user.
  fn find_user_with_external_login(
    &self,
    _provider_id: String,
    _external_id: String,
  ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::find_user_with_external_login'."
        )
        .into(),
      )
    })
  }

  /// Returns created user id, or error.
  ///
  /// The user should be stored with `info.provider_id` and
  /// `info.external_id` so it can be found by
  /// [AuthImpl::find_user_with_external_login].
  /// `info.groups` / `info.admin` are available to create the
  /// user with the correct access, or to reject the signup.
  /// [AuthImpl::sync_external_user] is also called directly after signup.
  fn sign_up_external_user(
    &self,
    _username: String,
    _info: ExternalLoginInfo,
    _no_users_exist: bool,
  ) -> DynFuture<mogh_error::Result<String>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::sign_up_external_user'.")
          .into(),
      )
    })
  }

  /// Called on every successful external authentication of a user:
  /// login, directly after signup, directly after linking,
  /// and token exchange (`POST /token`, RFC 8693).
  /// Use this to sync the users groups (`info.groups`) and
  /// admin status (`info.admin`) from the provider.
  /// Both are `None` when no information is available,
  /// in which case the user should be left as is.
  ///
  /// Runs before the session is authenticated,
  /// returning an error fails the login.
  ///
  /// Note. Changes at the provider only apply on the users next external login.
  fn sync_external_user(
    &self,
    _user_id: String,
    _info: ExternalLoginInfo,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async { Ok(()) })
  }

  /// Link `info.provider_id` / `info.external_id` to the existing user.
  fn link_external_login(
    &self,
    _user_id: String,
    _info: ExternalLoginInfo,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::link_external_login'.")
          .into(),
      )
    })
  }

  /// Remove the users link to the provider.
  fn unlink_external_login(
    &self,
    _user_id: String,
    _provider_id: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::unlink_external_login'.")
          .into(),
      )
    })
  }

  // =====================
  // = WORKLOAD IDENTITY =
  // =====================

  /// The token issuers trusted for workload identity from static app
  /// configuration (file / env). These are read only in the API,
  /// and take precedence over stored issuers with the same id.
  fn static_trusted_issuers(&self) -> Vec<TrustedIssuer> {
    Vec::new()
  }

  /// List the trusted issuers stored by the app (eg. in the database).
  /// These are managed over the API by admins ([AuthUserImpl::is_admin][crate::user::AuthUserImpl::is_admin]).
  ///
  /// Note. This is called on every token exchange (`POST /token`),
  /// which is unauthenticated, so apps should serve
  /// them from a cache rather than hit the database every time.
  fn list_trusted_issuers(
    &self,
  ) -> DynFuture<mogh_error::Result<Vec<TrustedIssuer>>> {
    Box::pin(async { Ok(Vec::new()) })
  }

  /// Store a new trusted issuer. The ids of the issuer and its
  /// rules are generated by the auth server, and must be stored as is.
  fn create_trusted_issuer(
    &self,
    _issuer: TrustedIssuer,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::create_trusted_issuer'.")
          .into(),
      )
    })
  }

  /// Replace the stored trusted issuer with the same id.
  ///
  /// Rules which are no longer part of the issuer can't be used anymore,
  /// their users ([Self::get_or_create_workload_user]) should be removed.
  fn update_trusted_issuer(
    &self,
    _issuer: TrustedIssuer,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::update_trusted_issuer'.")
          .into(),
      )
    })
  }

  /// Delete the stored trusted issuer.
  /// This should also remove the users of its rules.
  fn delete_trusted_issuer(
    &self,
    _id: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::delete_trusted_issuer'.")
          .into(),
      )
    })
  }

  /// Returns the id of the user a workload acts as, creating it if it
  /// doesn't exist yet. Called on every workload token exchange, after
  /// the token is verified and matched a rule.
  ///
  /// - There is one user per (`identity.issuer_id`, `identity.rule_id`).
  ///   Store both with the user to find it again.
  /// - `identity.groups` and `identity.admin` must be applied every time,
  ///   they are the full definition of what the user can do.
  /// - The user must report [AuthUserImpl::is_workload][crate::user::AuthUserImpl::is_workload],
  ///   otherwise the exchange is refused. It stops the workload from
  ///   creating credentials which outlive its rule.
  /// - Never apply signup logic like making the first user an admin.
  fn get_or_create_workload_user(
    &self,
    _identity: WorkloadIdentity,
  ) -> DynFuture<mogh_error::Result<String>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::get_or_create_workload_user'."
        )
        .into(),
      )
    })
  }

  /// Remove the users password, disabling local login.
  fn unlink_local_login(
    &self,
    _user_id: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::unlink_local_login'.")
          .into(),
      )
    })
  }

  // ===============
  // = PASSKEY 2FA =
  // ===============

  /// If Some(Passkey) is passed, it should be stored,
  /// overriding any passkey which was on the User.
  ///
  /// If None is passed, the user passkey should be removed,
  /// unenrolling the user from passkey 2fa.
  fn update_user_stored_passkey(
    &self,
    _user_id: String,
    _passkey: Option<Passkey>,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::update_user_stored_passkey'."
        )
        .into(),
      )
    })
  }

  // ============
  // = TOTP 2FA =
  // ============

  fn update_user_stored_totp(
    &self,
    _user_id: String,
    _encoded_secret: String,
    _hashed_recovery_codes: Vec<String>,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::update_user_stored_totp'."
        )
        .into(),
      )
    })
  }

  fn remove_user_stored_totp(
    &self,
    _user_id: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::remove_user_stored_totp'."
        )
        .into(),
      )
    })
  }

  /// Returns whether the TOTP `step` is fresh for this user (not
  /// previously accepted), marking it as consumed if so. Ensures each
  /// TOTP code is only accepted once (RFC 6238 §5.2).
  ///
  /// The default implementation tracks accepted steps in process
  /// memory, which is best-effort protection scoped to a single
  /// instance. Implement with app-level storage to enforce this
  /// across multiple instances and restarts.
  fn consume_totp_step(
    &self,
    user_id: String,
    step: u64,
  ) -> DynFuture<mogh_error::Result<bool>> {
    Box::pin(async move {
      Ok(api::login::totp::consume_totp_step_in_process(
        &user_id, step,
      ))
    })
  }

  /// Remove a used TOTP recovery code for the user, identified by its
  /// bcrypt hash exactly as returned from
  /// [AuthUserImpl][user::AuthUserImpl]::hashed_totp_recovery_codes,
  /// so the code cannot be used again.
  ///
  /// Must be implemented for
  /// [CompleteTotpRecoveryLogin][mogh_auth_client::api::login::CompleteTotpRecoveryLogin]
  /// to be usable.
  fn remove_totp_recovery_code(
    &self,
    _user_id: String,
    _hashed_code: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::remove_totp_recovery_code'."
        )
        .into(),
      )
    })
  }

  fn make_totp(
    &self,
    secret_bytes: Vec<u8>,
    account_name: Option<String>,
  ) -> anyhow::Result<totp_rs::Totp> {
    totp_rs::Builder::new()
      .with_issuer(Some(String::from(self.app_name())))
      .with_account_name(account_name.unwrap_or_default())
      .with_algorithm(totp_rs::Algorithm::SHA1)
      .with_digits(6)
      .with_skew(1)
      .with_step_duration(30)
      .with_secret(secret_bytes)
      .build()
      .context("Failed to construct TOTP")
  }

  // ============
  // = SKIP 2FA =
  // ============
  fn update_user_external_skip_2fa(
    &self,
    _user_id: String,
    _external_skip_2fa: bool,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::update_user_external_skip_2fa'."
        )
        .into(),
      )
    })
  }

  // ============
  // = API KEYS =
  // ============
  /// Validate api key name.
  fn validate_api_key_name(
    &self,
    api_key_name: &str,
  ) -> mogh_error::Result<()> {
    validate_api_key_name(api_key_name)
      .status_code(StatusCode::BAD_REQUEST)
  }

  /// Set custom API key length. Default is 40.
  fn api_key_secret_length(&self) -> usize {
    40
  }

  /// Set the api secret hash bcrypt cost.
  fn api_secret_bcrypt_cost(&self) -> u32 {
    self.local_auth_bcrypt_cost()
  }

  fn create_api_key(
    &self,
    _user_id: String,
    _body: CreateApiKey,
    _key: String,
    _hashed_secret: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::create_api_key'.").into(),
      )
    })
  }

  /// Get the api key ([AuthApiKeyImpl][api_key::AuthApiKeyImpl])
  /// for a given API key, returning UNAUTHORIZED if none exists.
  ///
  /// DANGER ⚠️ the incoming secret must still be validated as matching the
  /// known hashed secret for the api key. Use
  /// [middleware::verify_api_key_secret] with the stored hash
  /// (or `None` if the key does not exist) to do so.
  ///
  /// The returned [cidr_whitelist][api_key::AuthApiKeyImpl::cidr_whitelist]
  /// is enforced by [Self::get_user_id_from_request_authentication].
  fn get_api_key(
    &self,
    _key: String,
    _secret: String,
  ) -> DynFuture<mogh_error::Result<BoxAuthApiKey>> {
    Box::pin(async {
      Err(anyhow!("Must implement 'AuthImpl::get_api_key'.").into())
    })
  }

  /// Get the user id which owns the api key, without secret
  /// verification. Used to check ownership before deletion.
  fn get_api_key_owner_id(
    &self,
    _key: String,
  ) -> DynFuture<mogh_error::Result<String>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::get_api_key_owner_id'.")
          .into(),
      )
    })
  }

  fn delete_api_key(
    &self,
    _key: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::delete_api_key'.").into(),
      )
    })
  }

  /// Pass the server private key to use with api key v2 handshakes.
  fn server_private_key(&self) -> Option<&RotatableKeyPair> {
    None
  }

  /// How far the `X-API-TIMESTAMP` of an api key v2 request may be
  /// from the server time, in milliseconds. Default: 1 second.
  ///
  /// The signature covers the timestamp, so this is how long a
  /// captured request can be replayed for, and at the same time how
  /// much clock difference (plus latency) clients can have before
  /// their requests are refused. Raise it for clients without
  /// synchronized clocks, always use TLS either way.
  fn api_key_v2_timestamp_tolerance_ms(&self) -> u64 {
    1_000
  }

  fn create_api_key_v2(
    &self,
    _user_id: String,
    _body: CreateApiKey,
    _public_key: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::create_api_key_v2'.")
          .into(),
      )
    })
  }

  /// Get the api key ([AuthApiKeyImpl][api_key::AuthApiKeyImpl])
  /// for a given public key, returning UNAUTHORIZED if none exists.
  ///
  /// The returned [cidr_whitelist][api_key::AuthApiKeyImpl::cidr_whitelist]
  /// is enforced by [Self::get_user_id_from_request_authentication].
  fn get_api_key_v2(
    &self,
    _public_key: String,
  ) -> DynFuture<mogh_error::Result<BoxAuthApiKey>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::get_api_key_v2'.").into(),
      )
    })
  }

  /// Get the user id which owns the api key (v2), without it
  /// having to be usable. Used to check ownership before deletion.
  ///
  /// Defaults to [Self::get_api_key_v2]. Implement this if that
  /// rejects keys which should still be deletable, eg. expired ones.
  fn get_api_key_v2_owner_id(
    &self,
    public_key: String,
  ) -> DynFuture<mogh_error::Result<String>> {
    let api_key = self.get_api_key_v2(public_key);
    Box::pin(async move { Ok(api_key.await?.user_id().to_string()) })
  }

  fn delete_api_key_v2(
    &self,
    _public_key: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::delete_api_key_v2'.")
          .into(),
      )
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use crate::api_key::AuthApiKey;

  const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 2, 3));

  struct TestAuth {
    jwt_provider: JwtProvider,
    /// Simulates the stored bcrypt hash for any api key.
    /// None simulates an unknown api key.
    hashed_secret: Option<String>,
    /// Simulates the stored cidr whitelist for any api key.
    cidr_whitelist: Vec<String>,
  }

  impl TestAuth {
    fn with_hashed_secret(hashed_secret: Option<String>) -> Self {
      Self {
        jwt_provider: JwtProvider::new(b"secret", 60_000),
        hashed_secret,
        cidr_whitelist: Vec::new(),
      }
    }
  }

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      Self::with_hashed_secret(None)
    }
    fn get_user(
      &self,
      _user_id: String,
    ) -> DynFuture<mogh_error::Result<BoxAuthUser>> {
      Box::pin(async { Err(anyhow!("unimplemented").into()) })
    }
    fn handle_request_authentication(
      &self,
      _auth: RequestAuthentication,
      _ip: IpAddr,
      _require_user_enabled: bool,
      req: Request,
    ) -> DynFuture<mogh_error::Result<Request>> {
      Box::pin(async { Ok(req) })
    }
    fn jwt_provider(&self) -> &JwtProvider {
      &self.jwt_provider
    }
    // Low cost to keep the unknown-key dummy hash fast.
    fn api_secret_bcrypt_cost(&self) -> u32 {
      4
    }
    /// The intended implementation shape: one lookup for the key,
    /// then verify the secret with the helper.
    fn get_api_key(
      &self,
      key: String,
      secret: String,
    ) -> DynFuture<mogh_error::Result<BoxAuthApiKey>> {
      let verified = middleware::verify_api_key_secret(
        self,
        &secret,
        self.hashed_secret.as_deref(),
      );
      let cidr_whitelist = self.cidr_whitelist.clone();
      Box::pin(async move {
        verified?;
        Ok(
          AuthApiKey {
            user_id: format!("user-of-{key}"),
            cidr_whitelist,
          }
          .into(),
        )
      })
    }
    fn get_api_key_v2(
      &self,
      public_key: String,
    ) -> DynFuture<mogh_error::Result<BoxAuthApiKey>> {
      let cidr_whitelist = self.cidr_whitelist.clone();
      Box::pin(async move {
        Ok(
          AuthApiKey {
            user_id: format!("user-of-{public_key}"),
            cidr_whitelist,
          }
          .into(),
        )
      })
    }
  }

  #[tokio::test]
  async fn test_get_user_id_from_jwt() {
    let auth = TestAuth::new();
    let jwt = auth.jwt_provider().encode_sub("user-1").unwrap().jwt;
    let user_id = auth
      .get_user_id_from_request_authentication(
        RequestAuthentication::Jwt(jwt),
        IP,
      )
      .await
      .unwrap();
    assert_eq!(user_id, "user-1");
  }

  #[tokio::test]
  async fn test_get_user_id_from_jwt_rejects_forged() {
    let auth = TestAuth::new();
    let forged = JwtProvider::new(b"other", 60_000)
      .encode_sub("user-1")
      .unwrap()
      .jwt;
    let err = auth
      .get_user_id_from_request_authentication(
        RequestAuthentication::Jwt(forged),
        IP,
      )
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn test_get_user_id_from_api_key_verifies_secret() {
    let hashed = bcrypt::hash("S_def_S", 4).unwrap();
    let auth = TestAuth::with_hashed_secret(Some(hashed));
    let user_id = auth
      .get_user_id_from_request_authentication(
        RequestAuthentication::ApiKey {
          key: "K_abc_K".into(),
          secret: "S_def_S".into(),
        },
        IP,
      )
      .await
      .unwrap();
    assert_eq!(user_id, "user-of-K_abc_K");

    let err = auth
      .get_user_id_from_request_authentication(
        RequestAuthentication::ApiKey {
          key: "K_abc_K".into(),
          secret: "S_wrong_S".into(),
        },
        IP,
      )
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn test_get_user_id_from_api_key_enforces_cidr_whitelist() {
    let hashed = bcrypt::hash("S_def_S", 4).unwrap();
    let mut auth = TestAuth::with_hashed_secret(Some(hashed));
    auth.cidr_whitelist = vec!["10.0.0.0/8".into()];
    let api_key = || RequestAuthentication::ApiKey {
      key: "K_abc_K".into(),
      secret: "S_def_S".into(),
    };

    // In whitelist
    let user_id = auth
      .get_user_id_from_request_authentication(api_key(), IP)
      .await
      .unwrap();
    assert_eq!(user_id, "user-of-K_abc_K");

    // Not in whitelist
    let err = auth
      .get_user_id_from_request_authentication(
        api_key(),
        "8.8.8.8".parse().unwrap(),
      )
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::FORBIDDEN);

    // Wrong secret is still UNAUTHORIZED, checked before whitelist
    let err = auth
      .get_user_id_from_request_authentication(
        RequestAuthentication::ApiKey {
          key: "K_abc_K".into(),
          secret: "S_wrong_S".into(),
        },
        "8.8.8.8".parse().unwrap(),
      )
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn test_get_user_id_from_api_key_v2_enforces_cidr_whitelist()
  {
    let mut auth = TestAuth::new();
    auth.cidr_whitelist = vec!["10.1.2.3".into()];
    let public_key =
      || RequestAuthentication::PublicKey("PUBKEY".into());

    let user_id = auth
      .get_user_id_from_request_authentication(public_key(), IP)
      .await
      .unwrap();
    assert_eq!(user_id, "user-of-PUBKEY");

    let err = auth
      .get_user_id_from_request_authentication(
        public_key(),
        "10.1.2.4".parse().unwrap(),
      )
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::FORBIDDEN);
  }

  #[tokio::test]
  async fn test_get_user_id_from_api_key_empty_whitelist_allows_all()
  {
    let auth = TestAuth::new();
    let user_id = auth
      .get_user_id_from_request_authentication(
        RequestAuthentication::PublicKey("PUBKEY".into()),
        "8.8.8.8".parse().unwrap(),
      )
      .await
      .unwrap();
    assert_eq!(user_id, "user-of-PUBKEY");
  }
}
