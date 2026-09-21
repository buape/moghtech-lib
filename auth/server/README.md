# Mogh Auth Library

Provides trait-driven server and client implementations for robust application authentication. Compatible with axum.

- Local login with usernames and passwords
- OIDC / social login
- Two factor authentication with webauthn passkey or TOTP code
- JWT token generation and validation utilities
- Request rate limiting by IP for brute force mitigation
- Typescript types / client to layer with app-specific typescript client.

## Usage (Server)

Implement the necessary traits and mount the router.

### Implement AuthUserImpl

```rust
pub struct AuthUser(UserRecord);

impl mogh_auth_server::user::AuthUserImpl for AuthUser {
  fn id(&self) -> &str {
    &self.0.id.0
  }

  fn username(&self) -> &str {
    &self.0.username
  }

  fn hashed_password(&self) -> Option<&str> {
    if self.0.password.is_empty() {
      None
    } else {
      Some(&self.0.password)
    }
  }

  fn passkey(&self) -> Option<Passkey> {
    let passkey = self.0.passkey.as_ref()?;
    serde_json::from_str(&serde_json::to_string(passkey).ok()?)
      .inspect_err(|e| {
        warn!(
          "User {} ({}) | Invalid passkey on database | {e:?}",
          self.username(),
          self.id(),
        )
      })
      .ok()
  }

  fn totp_secret(&self) -> Option<&str> {
    if self.0.totp_secret.is_empty() {
      None
    } else {
      Some(&self.0.totp_secret)
    }
  }

  fn external_skip_2fa(&self) -> bool {
    self.0.external_skip_2fa
  }

  /// Admins can manage the stored external login providers over the API.
  fn is_admin(&self) -> bool {
    self.0.admin
  }
}
```

### Implement AppImpl

```rust
pub struct AppAuthImpl {
  client: RequestClientArgs,
}

impl mogh_auth_server::AuthImpl for AppAuthImpl {
  fn from_client(client: RequestClientArgs) -> Self
  where
    Self: Sized,
  {
    Self { client }
  }

  fn client(&self) -> &RequestClientArgs {
    &self.client
  }

  fn app_name(&self) -> &'static str {
    "AppName"
  }

  fn host(&self) -> &str {
    static AUTH_HOST: LazyLock<String> =
      LazyLock::new(|| format!("{}/auth", core_config().host));
    &AUTH_HOST
  }

  fn post_link_redirect(&self) -> &str {
    static POST_LINK_REDIRECT: LazyLock<String> =
      LazyLock::new(|| format!("{}/profile", core_config().host));
    &POST_LINK_REDIRECT
  }

  fn get_user(
    &self,
    user_id: String,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<BoxAuthUser>>
  {
    Box::pin(async move {
      Ok(Box::new(AuthUser(get_user(&user_id).await?)) as BoxAuthUser)
    })
  }

  fn no_users_exist(
    &self,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<bool>> {
    Box::pin(async { no_users_exist().await.map_err(Into::into) })
  }

  fn locked_usernames(&self) -> &'static [String] {
    &core_config().lock_login_credentials_for
  }

  fn registration_disabled(&self) -> bool {
    core_config().disable_user_registration
  }

  // =========
  // = STATE =
  // =========

  fn jwt_provider(&self) -> &JwtProvider {
    &JWT_PROVIDER
  }

  fn passkey_provider(&self) -> Option<&PasskeyProvider> {
    static PASSKEY_PROVIDER: LazyLock<Option<PasskeyProvider>> =
      LazyLock::new(|| {
        PasskeyProvider::new(&core_config().host)
          .inspect_err(|e| {
            warn!("Invalid 'host' for passkey provider | {e:#}")
          })
          .ok()
      });
    PASSKEY_PROVIDER.as_ref()
  }

  fn general_rate_limiter(&self) -> &RateLimiter {
    &GENERAL_RATE_LIMITER
  }

  // ==============
  // = LOCAL AUTH =
  // ==============

  fn local_auth_enabled(&self) -> bool {
    core_config().local_auth
  }

  fn local_login_rate_limiter(&self) -> &RateLimiter {
    &LOCAL_LOGIN_RATE_LIMITER
  }

  fn sign_up_local_user(
    &self,
    username: String,
    hashed_password: String,
    no_users_exist: bool,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<String>> {
    Box::pin(async move {
      sign_up_local_user(
        username,
        hashed_password,
        no_users_exist || core_config().enable_new_users,
      )
      .await
      .map_err(Into::into)
    })
  }

  fn find_user_with_username(
    &self,
    username: String,
  ) -> mogh_auth_server::DynFuture<
    mogh_error::Result<Option<BoxAuthUser>>,
  > {
    Box::pin(async move {
      let user = find_user_with_username(username)
        .await?
        .map(|user| Box::new(AuthUser(user)) as BoxAuthUser);
      Ok(user)
    })
  }

  fn update_user_username(
    &self,
    user_id: String,
    username: String,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      update_user_fields(
        user_id,
        UpdateUser {
          name: Some(username),
          ..Default::default()
        },
      )
      .await
      .map(|_| ())
      .map_err(Into::into)
    })
  }

  fn update_user_password(
    &self,
    user_id: String,
    password: String,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      update_user_fields(
        user_id,
        UpdateUser {
          password: Some(password),
          ..Default::default()
        },
      )
      .await
      .map(|_| ())
      .map_err(Into::into)
    })
  }

  // ==================
  // = EXTERNAL LOGIN =
  // ==================

  /// Providers from the app config file / env. Read only in the API.
  /// The reserved ids (`oidc`, `github`, `google`) keep the original
  /// callback paths, eg. `/auth/oidc/callback`.
  fn static_external_providers(&self) -> Vec<ExternalLoginProvider> {
    let config = core_config();
    vec![
      ExternalLoginProvider {
        id: ExternalLoginKind::Oidc.reserved_id().to_string(),
        name: String::from("OIDC"),
        registration_disabled: false,
        config: ExternalLoginProviderConfig::Oidc(config.oidc.clone()),
      },
      ExternalLoginProvider {
        id: ExternalLoginKind::Github.reserved_id().to_string(),
        name: String::from("Github"),
        registration_disabled: false,
        config: ExternalLoginProviderConfig::Github(
          config.github_oauth.clone(),
        ),
      },
    ]
  }

  /// Providers stored in the database, managed by admins over the API
  /// (`ListExternalLoginProviders`, `CreateExternalLoginProvider`, ...).
  /// The config includes the client secret, encrypt it at rest.
  fn list_external_providers(
    &self,
  ) -> mogh_auth_server::DynFuture<
    mogh_error::Result<Vec<ExternalLoginProvider>>,
  > {
    Box::pin(async move {
      list_stored_login_providers().await.map_err(Into::into)
    })
  }

  fn create_external_provider(
    &self,
    provider: ExternalLoginProvider,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      // The id is generated by the auth server, store it as is.
      insert_stored_login_provider(provider)
        .await
        .map_err(Into::into)
    })
  }

  fn update_external_provider(
    &self,
    provider: ExternalLoginProvider,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      replace_stored_login_provider(provider)
        .await
        .map_err(Into::into)
    })
  }

  fn delete_external_provider(
    &self,
    id: String,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      delete_stored_login_provider(&id).await?;
      // Also remove the links to the provider from all users.
      remove_external_logins_with_provider(&id).await?;
      Ok(())
    })
  }

  /// ⚠️ External user ids are only unique per provider,
  /// always match on both the provider id and the external id.
  fn find_user_with_external_login(
    &self,
    provider_id: String,
    external_id: String,
  ) -> mogh_auth_server::DynFuture<
    mogh_error::Result<Option<BoxAuthUser>>,
  > {
    Box::pin(async move {
      let user =
        find_user_with_external_login(&provider_id, &external_id)
          .await?
          .map(|user| Box::new(AuthUser(user)) as BoxAuthUser);
      Ok(user)
    })
  }

  fn sign_up_external_user(
    &self,
    username: String,
    info: ExternalLoginInfo,
    no_users_exist: bool,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<String>> {
    Box::pin(async move {
      sign_up_external_user(
        username,
        info.provider_id,
        info.external_id,
        info.avatar_url,
        no_users_exist || core_config().enable_new_users,
      )
      .await
      .map_err(Into::into)
    })
  }

  /// Optional. Called on every external login, and directly after signup / link.
  /// `groups` requires `groups_claim` in the OidcConfig, `admin` requires `admin_groups`.
  /// The `groups` scope is requested automatically if the provider advertises it.
  /// Both are None when the provider sent no group information,
  /// the user should then be left as is.
  fn sync_external_user(
    &self,
    user_id: String,
    info: ExternalLoginInfo,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      if let Some(groups) = info.groups {
        // Replace only the memberships managed by this provider,
        // keeping any assigned manually in the app.
        set_user_provider_groups(&user_id, &info.provider_id, groups)
          .await?;
      }
      if let Some(admin) = info.admin {
        set_user_admin(&user_id, admin).await?;
      }
      Ok(())
    })
  }

  fn link_external_login(
    &self,
    user_id: String,
    info: ExternalLoginInfo,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      link_external_login(
        user_id,
        info.provider_id,
        info.external_id,
        info.avatar_url,
      )
      .await
      .map(|_| ())
      .map_err(Into::into)
    })
  }

  // ==========
  // = UNLINK =
  // ==========

  fn unlink_external_login(
    &self,
    user_id: String,
    provider_id: String,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      unlink_external_login(user_id, &provider_id).await?;
      Ok(())
    })
  }

  fn unlink_local_login(
    &self,
    user_id: String,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      // Handle password updates using field updater
      let update = UpdateUser {
        password: Some(String::new()),
        ..Default::default()
      };
      update_user_fields(user_id, update)
        .await
        .map(|_| ())
        .map_err(Into::into)
    })
  }

  // ===============
  // = PASSKEY 2FA =
  // ===============

  fn update_user_stored_passkey(
    &self,
    user_id: String,
    passkey: Option<Passkey>,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      update_user_passkey(user_id, passkey)
        .await
        .map(|_| ())
        .map_err(Into::into)
    })
  }

  // ============
  // = TOTP 2FA =
  // ============

  fn update_user_stored_totp(
    &self,
    user_id: String,
    totp_secret: String,
    _hashed_recovery_codes: Vec<String>,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      update_user_fields(
        user_id,
        UpdateUser {
          totp_secret: Some(totp_secret),
          ..Default::default()
        },
      )
      .await
      .map(|_| ())
      .map_err(Into::into)
    })
  }

  fn remove_user_stored_totp(
    &self,
    user_id: String,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      update_user_fields(
        user_id,
        UpdateUser {
          totp_secret: Some(String::new()),
          ..Default::default()
        },
      )
      .await
      .map(|_| ())
      .map_err(Into::into)
    })
  }

  // ============
  // = SKIP 2FA =
  // ============
  fn update_user_external_skip_2fa(
    &self,
    user_id: String,
    external_skip_2fa: bool,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      update_user_fields(
        user_id,
        UpdateUser {
          external_skip_2fa: Some(external_skip_2fa),
          ..Default::default()
        },
      )
      .await
      .map(|_| ())
      .map_err(Into::into)
    })
  }
}
```

### Nest the router

Requires Session middleware layer on or outide the auth api router.

```rust
struct MemorySessionConfig;

impl mogh_server::session::SessionConfig for MemorySessionConfig {
  fn host() -> &str {
    &core_config().host
  }
  fn host_env_field(&self) -> &str {
    "APP_HOST"
  }
}

axum::Router::new()
  .nest("/auth", mogh_auth_server::api::router::<AppAuthImpl>())
  .layer(mogh_server::session::memory_session_layer(MemorySessionConfig))
```