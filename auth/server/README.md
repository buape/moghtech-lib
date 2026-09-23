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
        slug: String::new(),
        token_exchange: Default::default(),
        config: ExternalLoginProviderConfig::Oidc(config.oidc.clone()),
      },
      ExternalLoginProvider {
        id: ExternalLoginKind::Github.reserved_id().to_string(),
        name: String::from("Github"),
        registration_disabled: false,
        slug: String::new(),
        token_exchange: Default::default(),
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
### App tokens

The tokens issued by `JwtProvider` are standard JWTs: `iat` / `exp` are unix
timestamps in **seconds** (RFC 7519), validated with 10 seconds of clock skew
tolerance. Tokens issued before 4.0 carried milliseconds and are rejected, so
users have to log in once after upgrading.

### Reauthentication

Requests of the management API which change how a user can log in (username,
password, 2FA, linked logins, new api keys), or how anybody can (login
providers, trusted issuers), are only accepted with a token issued in the
last 15 minutes, so a token which leaked is not enough to take the account over
for good. Reading, `GetUserId` and deleting api keys are not affected.

```rust
/// Seconds. `0` disables the check for sessions (api keys stay refused).
fn reauthentication_window_secs(&self) -> u64 {
  15 * 60
}
```

- Older tokens get `403 Forbidden` with a message starting with
  `mogh_auth_client::api::manage::REAUTHENTICATION_REQUIRED`
  (`isReauthenticationRequired(e)` in the typescript client). The user logs in
  again, including their second factor, and retries. `mogh_ui` does this on
  its own: it tells the user why and sends them to `/login?backto=<page>`
  (`setOnReauthenticationRequired` to change that).
- Api keys are not a login, and are always refused the account requests,
  whatever the window (`0` included): a leaked key must not be able to set a
  password, unenroll 2FA or mint a replacement key. The requests which manage
  resources rather than the caller's account — the login providers and
  trusted issuers, whose handlers require an admin — take them, so an admin's
  key can run Terraform against them; whether keys reach the management api
  at all is the app's `get_user_id_from_request_authentication`.
- The time is the `iat` of a `JwtProvider` token. Other tokens which
  `get_user_id_from_request_authentication` accepts have no known login and
  count as api keys: they are refused the account requests whatever the window,
  and may make only the resource requests.

### Failed external logins

External logins are browser navigations. By default a failure (registration
disabled, not in an allowed group, denied at the provider, ...) answers with the
JSON error, which the user sees as a blank page of JSON. Configure where to
send them instead:

```rust
fn external_login_error_redirect(&self) -> Option<&str> {
  // https://example.com/login
  Some(&LOGIN_PAGE)
}
```

Failed logins then redirect to `{login page}?login_error=<reason>`, failed links
to `{post_link_redirect}?link_error=<reason>`. The `mogh_ui` `useAuthState` hook
shows both as a notification. Server errors are logged and only reported as
"Login failed".

### Login records

The server logs every login. For the app's own audit trail, implement
`record_login`: it is called once per login, at the step which grants it (a
local sign up or login once the password, and any second factor, is verified;
an external sign up or login at the provider's callback, or once its second
factor is complete; a token exchange when the token is issued — an
`ExchangeExternalForJwt` can end in a second factor too), after the hooks the
login needed (`sign_up_local_user` / `sign_up_external_user`,
`sync_external_user`, `get_or_create_workload_user`) and immediately before the
session or token is issued. An error fails the login; by then a one-time
credential (a TOTP step, a recovery code) may be consumed, so an app whose
recording can fail should log and continue instead.

```rust
fn record_login(&self, login: Login) -> DynFuture<mogh_error::Result<()>> {
  // login.user_id, login.username, login.ip,
  // login.second_factor: Option<Passkey | Totp | TotpRecovery>, and
  // login.kind: Local | Provider { provider_id, provider_name }
  //   | Workload { issuer_id, issuer_name, rule_id, rule_name }
  Box::pin(async move { audit(login).await })
}
```

Refused logins (a wrong password, a token no provider accepts) are not
reported: the server rate limits and logs them.

### Api keys (v2)

Clients sign each request with their private key instead of sending a secret
(`X-API-SIGNATURE` / `X-API-TIMESTAMP`). The rust client has the helpers behind
its `pki` feature: `mogh_auth_client::signature::signed_request_headers`.

- The signature is accepted for one second around the server time by default,
  `AuthImpl::api_key_v2_timestamp_tolerance_ms` raises that for clients without
  synchronized clocks. It is also how long a captured request can be replayed,
  always use TLS.
- A public key given to `CreateApiKeyV2` can be base64 or pem, anything else is
  refused. Implement `get_api_key_v2_owner_id` if `get_api_key_v2` rejects keys
  which should stay deletable (eg. expired ones).
- Invalid signatures count against the general rate limiter.

### Token exchange (RFC 8693)

A client which already holds a token for a user from one of the external
login providers (eg. a CLI, a script, or another app) can exchange it for
an app token at `POST {path}/token`, without sending the user through the browser.

It is off by default, and enabled per provider (OIDC and Google):

```rust
ExternalLoginProvider {
  id: String::from("oidc"),
  name: String::from("OIDC"),
  registration_disabled: false,
  slug: String::new(),
  token_exchange: TokenExchangeConfig {
    enabled: true,
    // Accept tokens the provider issued to these apps,
    // in addition to the client id of the provider.
    audiences: vec![String::from("my-cli-client-id")],
    // Only accept tokens issued in the last 5 minutes (0 = until they expire).
    max_token_age_secs: 300,
  },
  config: ExternalLoginProviderConfig::Oidc(config.oidc.clone()),
}
```

```sh
curl https://app.example.com/auth/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token_type=urn:ietf:params:oauth:token-type:id_token \
  -d subject_token=$ID_TOKEN
# {"access_token":"<app jwt>","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":86400}

curl https://app.example.com/api/... -H "Authorization: Bearer <app jwt>"
```

Or with the rust client: `mogh_auth_client::request::token_exchange`.

A provider's login and callback urls name it by its **slug**
(`/external/{slug}/login`, `/external/{slug}/callback`): lowercase letters,
digits and single hyphens, unique among all providers, made from the name
unless the create request gives one. Users' links to the provider carry its
id, never the slug, so changing the slug only changes the redirect URI to
register at the provider. Providers stored before slugs existed have an empty
`slug` and keep their id in the urls (`ExternalLoginProvider::slug()`). So do
providers from the app configuration, which under the reserved id of their kind
also keep the original paths (`/oidc/callback`); while such a provider exists,
its id is a slug no stored provider can take.

The same exchange is part of the login api as `ExchangeExternalForJwt { token }`,
for clients already using it (`authClient().login("ExchangeExternalForJwt", { token })`).
It responds like `LoginLocalUser`: either the JWT, or the second factor to
complete with `CompleteTotpLogin` / `CompletePasskeyLogin` on the same session,
so the client has to keep cookies between the requests. `/token` has no way to
continue, and rejects users who need a second factor for external logins.

- Only tokens **signed by the provider** are accepted (ID tokens / JWTs),
  verified against the keys it publishes. The provider is selected by the
  `iss` claim of the token. Opaque access tokens are rejected, they can't
  be tied to an audience.
- The token must be issued to the client id of the provider, or one of
  `audiences`. ⚠️ Tokens the provider issues to every app listed there
  can be used to log in to this app.
- The user must already exist and be linked to the provider.
  The endpoint never signs up users. If several providers share the
  issuer, the first which accepts the token and knows the user decides.
- A captured token can be exchanged by anyone until it expires, and some
  providers issue tokens valid for hours. `max_token_age_secs` limits this
  to the time since the token was issued. Clients should exchange a token
  right after receiving it, and keep the app token.
- 'allowed_groups' and the user cidr whitelist apply like for a login,
  and `AuthImpl::sync_external_user` is called. Groups can only come
  from the token itself here, there is no user info request.
- Users who need a second factor for external logins are rejected
  by `/token`, and continue with it using `ExchangeExternalForJwt`.
- Errors use the OAuth format: `{"error":"invalid_grant","error_description":"..."}`.

### Workload identity

Machines can use the same `/token` endpoint: a CI job or Kubernetes service
account exchanges the short lived token its platform issues it for a short
lived app token, so it doesn't need an api key stored as a secret.

Instead of a login provider this uses a `TrustedIssuer`, which only needs
the keys the platform signs with, and rules deciding which tokens are accepted:

```rust
fn static_trusted_issuers(&self) -> Vec<TrustedIssuer> {
  vec![TrustedIssuer {
    id: String::from("github-actions"),
    name: String::from("Github Actions"),
    enabled: true,
    issuer: String::from("https://token.actions.githubusercontent.com"),
    // Or `JwksUri(url)`, or `Static(jwks_json)` for issuers the server can't
    // reach, like most clusters: `kubectl get --raw /openid/v1/jwks`
    keys: TrustedIssuerKeys::Discovery {},
    // ⚠️ An audience specific to this app, which the workload requests its
    // token for. The platform default is shared with every other service.
    audiences: vec![String::from("https://app.example.com")],
    max_token_age_secs: 300,
    rules: vec![WorkloadRule {
      id: String::from("deploy"),
      name: String::from("Deploy"),
      enabled: true,
      // All have to match, `*` is a wildcard. Prefer ids over names.
      claims: vec![
        WorkloadClaim { claim: "repository_id".into(), pattern: "12345".into() },
        WorkloadClaim { claim: "ref".into(), pattern: "refs/heads/release/*".into() },
      ],
      groups: vec![String::from("deployers")],
      admin: false,
      token_ttl_secs: 900,
    }],
  }]
}
```

Keys which are fetched are cached for 5 minutes. The same goes for the
discovery data of login providers (OIDC 1 minute, Google 1 hour), and both
are loaded the same way, as they are loaded on demand by unauthenticated requests:

- Concurrent requests share one load, eg. a CI matrix starting many jobs at once.
- A load is given 15 seconds, so a hanging server can't block the others waiting on it.
- A failed load is only tried again after 30 seconds. Requests in between
  get `503` right away (`temporarily_unavailable` from `/token`), and the
  reason is logged once per attempt, not by every request.
- While the source can't be reached, what was loaded before stays in use for
  up to an hour, so a short outage doesn't stop every login or workload.

Issuers can also be stored by the app and managed by admins over the API
(`ListTrustedIssuers`, `CreateTrustedIssuer`, ...), with the same storage
methods as for login providers (`list_trusted_issuers`, `create_trusted_issuer`, ...).

Each rule has its own user, which the app provides:

```rust
fn get_or_create_workload_user(
  &self,
  identity: WorkloadIdentity,
) -> mogh_auth_server::DynFuture<mogh_error::Result<String>> {
  Box::pin(async move {
    // One user per (issuer_id, rule_id). Apply the groups and admin
    // status every time, they are the full definition of the user.
    let user = get_or_create_service_user(
      &identity.issuer_id,
      &identity.rule_id,
      &identity.rule_name,
    )
    .await?;
    set_user_groups(&user.id, identity.groups).await?;
    set_user_admin(&user.id, identity.admin).await?;
    // `identity.claims` tell which repository / run / service account it was.
    Ok(user.id)
  })
}
```

- That user must report `AuthUserImpl::is_workload`, otherwise the exchange
  is refused. Workload users are refused by the whole auth management API
  (all but `GetUserId`),
  so a workload can't create an api key (or password, 2fa, linked login,
  login provider, ...) which outlives its rule. ⚠️ Apps with their own ways to
  create credentials must refuse workload users there as well.
- Rules of static issuers need an `id` which is unique within the issuer,
  it identifies the user of the rule. Tokens matching a rule without one
  are refused. Ids of rules managed over the API are generated.
- An admin user is only accepted if the rule has `admin` set.
- The user cidr whitelist applies. Users requiring a second factor are refused.
- The app token is valid for `token_ttl_secs`, capped at the app default.
- Every exchange is logged with the issuer, rule, subject and matched claims.

⚠️ **Rate limiting and shared runners.** Failed exchanges count against
`AuthImpl::general_rate_limiter` by client ip, like failed logins. Hosted CI
runners (eg. Github's) share their ips between many customers and jobs, so with a
strict limit one misconfigured job failing repeatedly, or anyone else running jobs
on the same runners and sending tokens no rule accepts, can get the ip limited and
make your other jobs fail with `429` / `temporarily_unavailable` for a while.
If workloads come from shared ips, keep the failure limit generous, make jobs
retry an exchange with a delay rather than in a tight loop, or use self hosted
runners with their own ips. Successful exchanges are never rate limited.

### The exchange on another surface

Apps serving the exchange elsewhere, eg. a Vault compatible `auth/jwt/login`
whose `client_token` is the app token, call what the endpoint calls:

```rust
use mogh_auth_server::api::token::{
  ExchangedLogin, RoleNotFound, TokenExchangeOptions, exchange_token,
  token_exchange_error,
};

let exchanged = exchange_token(
  &auth,
  ip,
  TokenExchangeRequest::id_token(jwt),
  TokenExchangeOptions {
    // Vault's `role`: only log in through the login provider or workload
    // rule with this id or name. A workload token is then matched against
    // that rule alone (not the first matching rule of its issuer), and a
    // role nothing of that name accepts is refused before the exchange
    // has any effect, as `RoleNotFound` (an `invalid_grant`).
    role: Some(String::from("deploy")),
  },
)
.await;

match exchanged {
  Ok(exchanged) => {
    // exchanged.response is what `/token` answers; exchanged.user_id and
    // exchanged.login (the provider, or the issuer + rule) say who it is.
    if let ExchangedLogin::Workload { rule_name, .. } = &exchanged.login {}
  }
  Err(e) => {
    if e.error.downcast_ref::<RoleNotFound>().is_some() {}
    // The OAuth error and status the endpoint would answer with
    let (status, error) = token_exchange_error(&e);
  }
}
```

It is exactly the endpoint's exchange: the failure rate limit by ip included,
the app told about the login through the same hooks.

Github Actions:

```yaml
permissions:
  id-token: write
steps:
  - run: |
      ID_TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://app.example.com" | jq -r .value)
      APP_TOKEN=$(curl -s https://app.example.com/auth/token \
        -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
        -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
        -d subject_token=$ID_TOKEN | jq -r .access_token)
```

Kubernetes, with a projected service account token for the audience
(`serviceAccountToken: { audience: https://app.example.com, path: token }`),
matching eg. `sub` = `system:serviceaccount:<namespace>:<name>`.
