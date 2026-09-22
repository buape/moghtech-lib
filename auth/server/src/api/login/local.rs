use std::net::IpAddr;

use anyhow::{Context, anyhow};
use axum::http::StatusCode;
use mogh_auth_client::api::login::{
  JwtOrTwoFactor, JwtResponse, LoginLocalUser, SignUpLocalUser,
};
use mogh_error::{AddStatusCode, AddStatusCodeError};
use mogh_rate_limit::WithFailureRateLimit;
use mogh_resolver::Resolve;
use tracing::{info, instrument};

use crate::{
  AuthImpl, Login, LoginKind, api::login::LoginArgs,
  middleware::check_user_cidr_whitelist, session::Session,
};

pub async fn sign_up_local_user<I: AuthImpl + ?Sized>(
  auth: &I,
  ip: IpAddr,
  username: String,
  password: &str,
) -> mogh_error::Result<JwtResponse> {
  if !auth.local_auth_enabled() {
    return Err(
      anyhow!("Local auth is not enabled")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  let no_users_exist = auth.no_users_exist().await?;

  if auth.local_registration_disabled() && !no_users_exist {
    return Err(
      anyhow!("User registration is disabled")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  auth.validate_username(&username)?;
  auth.validate_password(password)?;
  check_username_available(auth, &username, None).await?;

  let hashed_password =
    bcrypt::hash(password.as_bytes(), auth.local_auth_bcrypt_cost())?;

  let user_id = auth
    .sign_up_local_user(
      username.clone(),
      hashed_password,
      no_users_exist,
    )
    .await?;

  info!(user_id, username, "New user registration (Local)");

  // Signing up logs the new user in.
  auth
    .record_login(Login {
      user_id: user_id.clone(),
      username,
      ip,
      kind: LoginKind::Local,
      second_factor: None,
    })
    .await?;

  auth.jwt_provider().encode_sub(&user_id).map_err(Into::into)
}

/// Rejects a username another user already has with CONFLICT,
/// rather than leaving it to the app storage to fail with whatever
/// error (and status) a broken unique constraint produces.
///
/// `user_id` is the user taking the username, who may already have it.
///
/// Note. Two requests can still race past this check, so
/// app storage must keep usernames unique as well.
pub async fn check_username_available<I: AuthImpl + ?Sized>(
  auth: &I,
  username: &str,
  user_id: Option<&str>,
) -> mogh_error::Result<()> {
  match auth.find_user_with_username(username.to_string()).await? {
    Some(existing) if Some(existing.id()) != user_id => Err(
      anyhow!("Username is already taken")
        .status_code(StatusCode::CONFLICT),
    ),
    _ => Ok(()),
  }
}

impl Resolve<LoginArgs> for SignUpLocalUser {
  #[instrument("SignUpLocalUser", skip_all, fields(ip = ip.to_string()))]
  async fn resolve(
    self,
    LoginArgs { auth, ip, .. }: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    sign_up_local_user(
      auth.as_ref(),
      *ip,
      self.username,
      &self.password,
    )
    .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), ip)
    .await
  }
}

/// When there is no user or stored password hash to verify against,
/// still run bcrypt before failing so response timing does not
/// reveal whether the username exists.
fn invalid_credentials_after_dummy_hash<I: AuthImpl + ?Sized>(
  auth: &I,
  password: &str,
) -> mogh_error::Error {
  let _ =
    bcrypt::hash(password.as_bytes(), auth.local_auth_bcrypt_cost());
  anyhow!("Invalid login credentials")
    .status_code(StatusCode::UNAUTHORIZED)
}

pub async fn login_local_user<I: AuthImpl + ?Sized>(
  auth: &I,
  session: &Session,
  ip: IpAddr,
  username: String,
  password: &str,
) -> mogh_error::Result<JwtOrTwoFactor> {
  if !auth.local_auth_enabled() {
    return Err(
      anyhow!("Local auth is not enabled")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  auth.validate_username(&username)?;

  let Some(user) = auth.find_user_with_username(username).await?
  else {
    return Err(invalid_credentials_after_dummy_hash(auth, password));
  };

  let Some(hashed_password) = user.hashed_password() else {
    return Err(invalid_credentials_after_dummy_hash(auth, password));
  };

  let verified = bcrypt::verify(password, hashed_password)
    .context("Invalid login credentials")
    .status_code(StatusCode::UNAUTHORIZED)?;

  if !verified {
    return Err(
      anyhow!("Invalid login credentials")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  // Checked after credential verification so the
  // whitelist does not reveal whether the username exists.
  check_user_cidr_whitelist(user.as_ref(), ip)?;

  let res = match (user.passkey(), user.totp_secret()) {
    // Passkey 2FA
    (Some(passkey), _) => {
      let provider = auth.passkey_provider().context(
        "No passkey provider available, possibly invalid 'host' config.",
      )?;
      let (response, state) = provider
        .start_passkey_authentication(passkey)
        .context("Failed to start passkey authentication flow")?;
      session.insert_passkey_login(user.id(), &state).await?;
      session.insert_login_kind(&LoginKind::Local).await?;

      info!(
        user_id = user.id(),
        username = user.username(),
        "Passkey 2FA flow initiated"
      );

      JwtOrTwoFactor::Passkey(response)
    }
    // TOTP 2FA
    (None, Some(_)) => {
      session.insert_totp_login_user_id(user.id()).await?;
      session.insert_login_kind(&LoginKind::Local).await?;

      info!(
        user_id = user.id(),
        username = user.username(),
        "TOTP 2FA flow initiated"
      );

      JwtOrTwoFactor::Totp {}
    }
    (None, None) => {
      auth
        .record_login(Login::of(
          user.as_ref(),
          ip,
          LoginKind::Local,
          None,
        ))
        .await?;

      info!(
        user_id = user.id(),
        username = user.username(),
        "User logged in"
      );

      JwtOrTwoFactor::Jwt(auth.jwt_provider().encode_sub(user.id())?)
    }
  };

  Ok(res)
}

impl Resolve<LoginArgs> for LoginLocalUser {
  #[instrument(
    "LoginLocalUser",
    skip_all,
    fields(
      ip = ip.to_string(),
    )
  )]
  async fn resolve(
    self,
    LoginArgs { auth, session, ip }: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    login_local_user(
      auth.as_ref(),
      session,
      *ip,
      self.username,
      &self.password,
    )
    .with_failure_rate_limit_using_ip(
      auth.local_login_rate_limiter(),
      ip,
    )
    .await
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Mutex;

  use crate::{
    DynFuture, RequestAuthentication,
    provider::jwt::JwtProvider,
    user::{AuthUserImpl, BoxAuthUser},
  };

  use super::*;

  struct TestUser {
    id: String,
    username: String,
    hashed_password: Option<String>,
  }

  impl AuthUserImpl for TestUser {
    fn id(&self) -> &str {
      &self.id
    }
    fn username(&self) -> &str {
      &self.username
    }
    fn hashed_password(&self) -> Option<&str> {
      self.hashed_password.as_deref()
    }
  }

  const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 7));

  #[derive(Default)]
  struct TestAuth {
    /// (id, username)
    users: Mutex<Vec<(String, String)>>,
    /// user id -> hashed password
    hashes: Mutex<std::collections::HashMap<String, String>>,
    logins: Mutex<Vec<Login>>,
  }

  fn session() -> Session {
    Session(tower_sessions::Session::new(
      None,
      std::sync::Arc::new(tower_sessions::MemoryStore::default()),
      None,
    ))
  }

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      Self::default()
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
      req: axum::extract::Request,
    ) -> DynFuture<mogh_error::Result<axum::extract::Request>> {
      Box::pin(async { Ok(req) })
    }
    fn jwt_provider(&self) -> &JwtProvider {
      static PROVIDER: std::sync::LazyLock<JwtProvider> =
        std::sync::LazyLock::new(|| {
          JwtProvider::new(b"secret", 60_000)
        });
      &PROVIDER
    }
    fn local_auth_bcrypt_cost(&self) -> u32 {
      4
    }
    fn find_user_with_username(
      &self,
      username: String,
    ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>> {
      let user = self
        .users
        .lock()
        .unwrap()
        .iter()
        .find(|(_, name)| name == &username)
        .map(|(id, username)| {
          Box::new(TestUser {
            id: id.clone(),
            username: username.clone(),
            hashed_password: self
              .hashes
              .lock()
              .unwrap()
              .get(id)
              .cloned(),
          }) as BoxAuthUser
        });
      Box::pin(async { Ok(user) })
    }
    fn sign_up_local_user(
      &self,
      username: String,
      hashed_password: String,
      _no_users_exist: bool,
    ) -> DynFuture<mogh_error::Result<String>> {
      let mut users = self.users.lock().unwrap();
      let id = format!("id-{}", users.len());
      users.push((id.clone(), username));
      self
        .hashes
        .lock()
        .unwrap()
        .insert(id.clone(), hashed_password);
      Box::pin(async { Ok(id) })
    }
    fn record_login(
      &self,
      login: Login,
    ) -> DynFuture<mogh_error::Result<()>> {
      self.logins.lock().unwrap().push(login);
      Box::pin(async { Ok(()) })
    }
  }

  /// A sign up and a verified password are logins the app hears
  /// about, a refused password is not.
  #[tokio::test]
  async fn test_login_is_recorded() {
    let auth = TestAuth::default();
    sign_up_local_user(&auth, IP, "user".into(), "password-1")
      .await
      .unwrap();
    {
      let logins = auth.logins.lock().unwrap();
      assert_eq!(logins.len(), 1, "signing up logs the user in");
      assert_eq!(logins[0].user_id, "id-0");
      assert_eq!(logins[0].username, "user");
      assert_eq!(logins[0].ip, IP);
      assert_eq!(logins[0].kind, LoginKind::Local);
      assert!(logins[0].second_factor.is_none());
    }
    let ip = IpAddr::from([127, 0, 0, 1]);
    let res = login_local_user(
      &auth,
      &session(),
      ip,
      "user".into(),
      "password-1",
    )
    .await
    .unwrap();
    assert!(matches!(res, JwtOrTwoFactor::Jwt(_)));
    {
      let logins = auth.logins.lock().unwrap();
      assert_eq!(logins.len(), 2);
      assert_eq!(logins[1].user_id, "id-0");
      assert_eq!(logins[1].ip, ip);
      assert_eq!(logins[1].kind, LoginKind::Local);
      assert!(logins[1].second_factor.is_none());
    }
    let err = login_local_user(
      &auth,
      &session(),
      ip,
      "user".into(),
      "wrong-password",
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert_eq!(auth.logins.lock().unwrap().len(), 2);
  }

  #[tokio::test]
  async fn test_sign_up_rejects_taken_username_with_conflict() {
    let auth = TestAuth::default();
    sign_up_local_user(&auth, IP, "user".into(), "password-1")
      .await
      .unwrap();
    let err =
      sign_up_local_user(&auth, IP, "user".into(), "password-2")
        .await
        .unwrap_err();
    assert_eq!(err.status, StatusCode::CONFLICT);
    // The app storage was never asked to create the duplicate.
    assert_eq!(auth.users.lock().unwrap().len(), 1);
  }

  #[tokio::test]
  async fn test_check_username_available() {
    let auth = TestAuth::default();
    sign_up_local_user(&auth, IP, "user".into(), "password-1")
      .await
      .unwrap();
    // Free
    check_username_available(&auth, "other", None)
      .await
      .unwrap();
    // The user already has it
    check_username_available(&auth, "user", Some("id-0"))
      .await
      .unwrap();
    // Somebody else has it
    let err = check_username_available(&auth, "user", Some("id-1"))
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::CONFLICT);
  }
}
