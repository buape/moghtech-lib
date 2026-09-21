//! Management of the external login providers stored by the app.
//! Admin only, see [AuthUserImpl::is_admin].

use anyhow::{Context as _, anyhow};
use axum::http::StatusCode;
use mogh_auth_client::{
  api::manage::{
    CreateExternalLoginProvider, DeleteExternalLoginProvider,
    DeleteExternalLoginProviderResponse,
    ExternalLoginProviderListItem, ListExternalLoginProviders,
    UpdateExternalLoginProvider,
  },
  config::{
    ExternalLoginProvider, ExternalLoginProviderConfig, REDACTED,
  },
};
use mogh_error::{AddStatusCode as _, AddStatusCodeError as _};
use mogh_resolver::Resolve;
use tracing::{info, instrument};
use zeroize::Zeroize as _;

use crate::{
  AuthImpl,
  api::manage::ManageArgs,
  provider::external::{
    PROVIDER_ID_LENGTH, evict_built_provider,
    list_external_providers, redirect_uri, resolve_external_provider,
  },
  rand::random_string,
  user::AuthUserImpl,
};

const MAX_PROVIDER_NAME_LENGTH: usize = 100;

fn check_admin(user: &dyn AuthUserImpl) -> mogh_error::Result<()> {
  if user.is_admin() {
    Ok(())
  } else {
    Err(
      anyhow!("Only admins can manage external login providers")
        .status_code(StatusCode::FORBIDDEN),
    )
  }
}

/// The client secret never leaves the server.
fn list_item<I: AuthImpl + ?Sized>(
  auth: &I,
  mut provider: ExternalLoginProvider,
  read_only: bool,
) -> ExternalLoginProviderListItem {
  provider.config.redact_secret();
  ExternalLoginProviderListItem {
    redirect_uri: redirect_uri(auth.host(), auth.path(), &provider),
    provider,
    read_only,
  }
}

fn validate_name(name: &str) -> mogh_error::Result<String> {
  let name = name.trim();
  if name.is_empty() {
    return Err(
      anyhow!("Provider name cannot be empty")
        .status_code(StatusCode::BAD_REQUEST),
    );
  }
  if name.chars().count() > MAX_PROVIDER_NAME_LENGTH {
    return Err(
      anyhow!(
        "Provider name cannot be longer than {MAX_PROVIDER_NAME_LENGTH} characters"
      )
      .status_code(StatusCode::BAD_REQUEST),
    );
  }
  Ok(name.to_string())
}

fn validate_http_url(field: &str, url: &str) -> anyhow::Result<()> {
  let parsed = reqwest::Url::parse(url)
    .with_context(|| format!("'{field}' is not a valid URL"))?;
  if !matches!(parsed.scheme(), "http" | "https") {
    return Err(anyhow!("'{field}' must be an http(s) URL"));
  }
  Ok(())
}

fn validate_config(
  config: &ExternalLoginProviderConfig,
) -> mogh_error::Result<()> {
  if config.client_secret() == REDACTED {
    return Err(
      anyhow!(
        "The redacted client secret cannot be used as the secret"
      )
      .status_code(StatusCode::BAD_REQUEST),
    );
  }
  if let ExternalLoginProviderConfig::Oidc(config) = config {
    if !config.provider.is_empty() {
      validate_http_url("provider", &config.provider)
        .status_code(StatusCode::BAD_REQUEST)?;
    }
    if !config.redirect_host.is_empty() {
      validate_http_url("redirect_host", &config.redirect_host)
        .status_code(StatusCode::BAD_REQUEST)?;
    }
  }
  Ok(())
}

/// An empty or redacted client secret keeps the existing one.
///
/// The secret is sent to the token endpoint the OIDC provider url
/// points to. If the url changes, the secret has to be entered again,
/// otherwise pointing the provider at another server would reveal
/// the stored secret, which can't be read over the API.
fn keep_existing_secret(
  config: &mut ExternalLoginProviderConfig,
  existing: &ExternalLoginProviderConfig,
) -> mogh_error::Result<()> {
  let secret = config.client_secret();
  if !secret.is_empty() && secret != REDACTED {
    return Ok(());
  }
  if let (
    ExternalLoginProviderConfig::Oidc(config),
    ExternalLoginProviderConfig::Oidc(existing),
  ) = (&*config, existing)
    && config.provider != existing.provider
    && !existing.client_secret.is_empty()
  {
    return Err(
      anyhow!(
        "The client secret must be entered again when the provider url changes"
      )
      .status_code(StatusCode::BAD_REQUEST),
    );
  }
  *config.client_secret_mut() = existing.client_secret().to_string();
  Ok(())
}

//

pub async fn list_providers<I: AuthImpl + ?Sized>(
  auth: &I,
  user: &dyn AuthUserImpl,
) -> mogh_error::Result<Vec<ExternalLoginProviderListItem>> {
  check_admin(user)?;
  let providers = list_external_providers(auth)
    .await?
    .into_iter()
    .map(|resolved| {
      list_item(auth, resolved.provider, resolved.is_static)
    })
    .collect();
  Ok(providers)
}

impl Resolve<ManageArgs> for ListExternalLoginProviders {
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    list_providers(auth.as_ref(), user.as_ref().as_ref()).await
  }
}

//

pub async fn create_provider<I: AuthImpl + ?Sized>(
  auth: &I,
  user: &dyn AuthUserImpl,
  request: CreateExternalLoginProvider,
) -> mogh_error::Result<ExternalLoginProviderListItem> {
  check_admin(user)?;
  validate_config(&request.config)?;

  let provider = ExternalLoginProvider {
    // Random ids are never reused, so a new provider
    // can't inherit the linked users of a deleted one.
    id: random_string(PROVIDER_ID_LENGTH),
    name: validate_name(&request.name)?,
    registration_disabled: request.registration_disabled,
    config: request.config,
  };

  let item = list_item(auth, provider.clone(), false);

  auth.create_external_provider(provider).await?;

  info!(
    admin_id = user.id(),
    admin = user.username(),
    provider_id = item.provider.id,
    provider = item.provider.name,
    kind = item.provider.kind().to_string(),
    "External login provider created"
  );

  Ok(item)
}

impl Resolve<ManageArgs> for CreateExternalLoginProvider {
  #[instrument(
    "CreateExternalLoginProvider",
    skip_all,
    fields(user_id = user.id(), username = user.username())
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    create_provider(auth.as_ref(), user.as_ref().as_ref(), self).await
  }
}

//

/// Resolves a provider which can be managed over the API.
async fn resolve_managed_provider<I: AuthImpl + ?Sized>(
  auth: &I,
  provider_id: &str,
) -> mogh_error::Result<ExternalLoginProvider> {
  let resolved = resolve_external_provider(auth, provider_id).await?;
  if resolved.is_static {
    return Err(
      anyhow!(
        "Provider '{}' comes from the app configuration and is read only",
        resolved.provider.name
      )
      .status_code(StatusCode::BAD_REQUEST),
    );
  }
  Ok(resolved.provider)
}

/// Validates the updated configuration against the
/// existing one, and carries over the existing secret.
fn merge_update(
  config: &mut ExternalLoginProviderConfig,
  existing: &ExternalLoginProviderConfig,
) -> mogh_error::Result<()> {
  // The external user ids linked to the provider
  // only have meaning for the same kind.
  if config.kind() != existing.kind() {
    return Err(
      anyhow!(
        "The kind of a provider cannot be changed, create a new provider instead"
      )
      .status_code(StatusCode::BAD_REQUEST),
    );
  }
  keep_existing_secret(config, existing)?;
  validate_config(config)
}

pub async fn update_provider<I: AuthImpl + ?Sized>(
  auth: &I,
  user: &dyn AuthUserImpl,
  mut request: UpdateExternalLoginProvider,
) -> mogh_error::Result<ExternalLoginProviderListItem> {
  check_admin(user)?;

  let name = validate_name(&request.name)?;

  let mut existing =
    resolve_managed_provider(auth, &request.id).await?;

  // Wipe the secrets held here however the checks turn out.
  let merged = merge_update(&mut request.config, &existing.config);
  existing.config.zeroize();
  if let Err(e) = merged {
    request.config.zeroize();
    return Err(e);
  }

  let provider = ExternalLoginProvider {
    id: existing.id,
    name,
    registration_disabled: request.registration_disabled,
    config: request.config,
  };

  let item = list_item(auth, provider.clone(), false);

  auth.update_external_provider(provider).await?;

  // Drops the client holding the previous secret.
  evict_built_provider(&item.provider.id);

  info!(
    admin_id = user.id(),
    admin = user.username(),
    provider_id = item.provider.id,
    provider = item.provider.name,
    "External login provider updated"
  );

  Ok(item)
}

impl Resolve<ManageArgs> for UpdateExternalLoginProvider {
  #[instrument(
    "UpdateExternalLoginProvider",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
      provider_id = self.id
    )
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    update_provider(auth.as_ref(), user.as_ref().as_ref(), self).await
  }
}

//

pub async fn delete_provider<I: AuthImpl + ?Sized>(
  auth: &I,
  user: &dyn AuthUserImpl,
  provider_id: &str,
) -> mogh_error::Result<()> {
  check_admin(user)?;

  let mut provider =
    resolve_managed_provider(auth, provider_id).await?;
  provider.config.zeroize();

  auth.delete_external_provider(provider.id.clone()).await?;

  evict_built_provider(&provider.id);

  info!(
    admin_id = user.id(),
    admin = user.username(),
    provider_id = provider.id,
    provider = provider.name,
    "External login provider deleted"
  );

  Ok(())
}

impl Resolve<ManageArgs> for DeleteExternalLoginProvider {
  #[instrument(
    "DeleteExternalLoginProvider",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
      provider_id = self.id
    )
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    delete_provider(auth.as_ref(), user.as_ref().as_ref(), &self.id)
      .await?;
    Ok(DeleteExternalLoginProviderResponse {})
  }
}

#[cfg(test)]
mod tests {
  use std::sync::{Arc, Mutex};

  use mogh_auth_client::config::{NamedOauthConfig, OidcConfig};

  use super::*;

  struct TestUser {
    admin: bool,
  }

  impl AuthUserImpl for TestUser {
    fn id(&self) -> &str {
      "user-id"
    }
    fn username(&self) -> &str {
      "user"
    }
    fn is_admin(&self) -> bool {
      self.admin
    }
  }

  const ADMIN: TestUser = TestUser { admin: true };
  const USER: TestUser = TestUser { admin: false };

  #[derive(Default)]
  struct TestAuth {
    static_providers: Vec<ExternalLoginProvider>,
    stored: Arc<Mutex<Vec<ExternalLoginProvider>>>,
  }

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      Self::default()
    }

    fn host(&self) -> &str {
      "https://example.com"
    }

    fn static_external_providers(
      &self,
    ) -> Vec<ExternalLoginProvider> {
      self.static_providers.clone()
    }

    fn list_external_providers(
      &self,
    ) -> crate::DynFuture<
      mogh_error::Result<Vec<ExternalLoginProvider>>,
    > {
      let stored = self.stored.lock().unwrap().clone();
      Box::pin(async move { Ok(stored) })
    }

    fn create_external_provider(
      &self,
      provider: ExternalLoginProvider,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      self.stored.lock().unwrap().push(provider);
      Box::pin(async { Ok(()) })
    }

    fn update_external_provider(
      &self,
      provider: ExternalLoginProvider,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      let mut stored = self.stored.lock().unwrap();
      let existing = stored
        .iter_mut()
        .find(|existing| existing.id == provider.id)
        .unwrap();
      *existing = provider;
      Box::pin(async { Ok(()) })
    }

    fn delete_external_provider(
      &self,
      id: String,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      self
        .stored
        .lock()
        .unwrap()
        .retain(|provider| provider.id != id);
      Box::pin(async { Ok(()) })
    }

    fn get_user(
      &self,
      _user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<crate::user::BoxAuthUser>>
    {
      Box::pin(async {
        Err(anyhow::anyhow!("not implemented").into())
      })
    }

    fn handle_request_authentication(
      &self,
      _auth: crate::RequestAuthentication,
      _ip: std::net::IpAddr,
      _require_user_enabled: bool,
      _req: axum::extract::Request,
    ) -> crate::DynFuture<mogh_error::Result<axum::extract::Request>>
    {
      Box::pin(async {
        Err(anyhow::anyhow!("not implemented").into())
      })
    }

    fn jwt_provider(&self) -> &crate::provider::jwt::JwtProvider {
      panic!("not needed for these tests")
    }
  }

  fn github_config(secret: &str) -> ExternalLoginProviderConfig {
    ExternalLoginProviderConfig::Github(NamedOauthConfig {
      enabled: true,
      client_id: "client-id".into(),
      client_secret: secret.into(),
    })
  }

  fn create_request(secret: &str) -> CreateExternalLoginProvider {
    CreateExternalLoginProvider {
      name: "  Github  ".into(),
      registration_disabled: false,
      config: github_config(secret),
    }
  }

  fn update_request(
    id: &str,
    config: ExternalLoginProviderConfig,
  ) -> UpdateExternalLoginProvider {
    UpdateExternalLoginProvider {
      id: id.into(),
      name: "Renamed".into(),
      registration_disabled: true,
      config,
    }
  }

  fn stored_secret(auth: &TestAuth, id: &str) -> String {
    auth
      .stored
      .lock()
      .unwrap()
      .iter()
      .find(|provider| provider.id == id)
      .unwrap()
      .config
      .client_secret()
      .to_string()
  }

  #[tokio::test]
  async fn test_non_admins_are_forbidden() {
    let auth = TestAuth::default();
    let id = create_provider(&auth, &ADMIN, create_request("secret"))
      .await
      .unwrap()
      .provider
      .id;

    let statuses = [
      list_providers(&auth, &USER).await.unwrap_err().status,
      create_provider(&auth, &USER, create_request("secret"))
        .await
        .unwrap_err()
        .status,
      update_provider(
        &auth,
        &USER,
        update_request(&id, github_config("other")),
      )
      .await
      .unwrap_err()
      .status,
      delete_provider(&auth, &USER, &id).await.unwrap_err().status,
    ];
    assert!(
      statuses
        .iter()
        .all(|status| *status == StatusCode::FORBIDDEN)
    );
    // Nothing changed
    assert_eq!(auth.stored.lock().unwrap().len(), 1);
    assert_eq!(stored_secret(&auth, &id), "secret");
  }

  #[tokio::test]
  async fn test_create_generates_id_and_redacts_secret() {
    let auth = TestAuth::default();
    let item =
      create_provider(&auth, &ADMIN, create_request("secret"))
        .await
        .unwrap();
    assert_eq!(item.provider.id.len(), PROVIDER_ID_LENGTH);
    assert_eq!(item.provider.name, "Github");
    assert!(!item.read_only);
    assert_eq!(
      item.redirect_uri,
      format!(
        "https://example.com/auth/external/{}/callback",
        item.provider.id
      )
    );
    // The response is redacted, the stored provider is not
    assert_eq!(item.provider.config.client_secret(), REDACTED);
    assert_eq!(stored_secret(&auth, &item.provider.id), "secret");

    // Ids are unique
    let other =
      create_provider(&auth, &ADMIN, create_request("secret"))
        .await
        .unwrap();
    assert_ne!(item.provider.id, other.provider.id);
  }

  #[tokio::test]
  async fn test_create_validates_input() {
    let auth = TestAuth::default();
    let mut bad_name = create_request("secret");
    bad_name.name = "   ".into();
    let mut bad_url = create_request("secret");
    bad_url.config = ExternalLoginProviderConfig::Oidc(OidcConfig {
      provider: "javascript:alert(1)".into(),
      ..Default::default()
    });
    for request in [bad_name, bad_url, create_request(REDACTED)] {
      let err =
        create_provider(&auth, &ADMIN, request).await.unwrap_err();
      assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }
    assert!(auth.stored.lock().unwrap().is_empty());
  }

  #[tokio::test]
  async fn test_update_keeps_secret_when_empty_or_redacted() {
    let auth = TestAuth::default();
    let id = create_provider(&auth, &ADMIN, create_request("secret"))
      .await
      .unwrap()
      .provider
      .id;

    for secret in ["", REDACTED] {
      let item = update_provider(
        &auth,
        &ADMIN,
        update_request(&id, github_config(secret)),
      )
      .await
      .unwrap();
      assert_eq!(item.provider.name, "Renamed");
      assert!(item.provider.registration_disabled);
      assert_eq!(item.provider.config.client_secret(), REDACTED);
      assert_eq!(stored_secret(&auth, &id), "secret");
    }

    update_provider(
      &auth,
      &ADMIN,
      update_request(&id, github_config("rotated")),
    )
    .await
    .unwrap();
    assert_eq!(stored_secret(&auth, &id), "rotated");
  }

  fn oidc_config(
    provider: &str,
    secret: &str,
  ) -> ExternalLoginProviderConfig {
    ExternalLoginProviderConfig::Oidc(OidcConfig {
      enabled: true,
      provider: provider.into(),
      client_id: "client-id".into(),
      client_secret: secret.into(),
      ..Default::default()
    })
  }

  #[tokio::test]
  async fn test_update_provider_url_change_requires_secret() {
    let auth = TestAuth::default();
    let id = create_provider(
      &auth,
      &ADMIN,
      CreateExternalLoginProvider {
        name: "OIDC".into(),
        registration_disabled: false,
        config: oidc_config("https://idp.example.com", "secret"),
      },
    )
    .await
    .unwrap()
    .provider
    .id;

    // Pointing the provider elsewhere can't reuse the stored secret
    for secret in ["", REDACTED] {
      let err = update_provider(
        &auth,
        &ADMIN,
        update_request(
          &id,
          oidc_config("https://evil.example.com", secret),
        ),
      )
      .await
      .unwrap_err();
      assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(stored_secret(&auth, &id), "secret");
    assert_eq!(auth.stored.lock().unwrap()[0].name, "OIDC");

    // Same url keeps the secret, a new url works with a new secret
    update_provider(
      &auth,
      &ADMIN,
      update_request(&id, oidc_config("https://idp.example.com", "")),
    )
    .await
    .unwrap();
    assert_eq!(stored_secret(&auth, &id), "secret");
    update_provider(
      &auth,
      &ADMIN,
      update_request(
        &id,
        oidc_config("https://new.example.com", "new"),
      ),
    )
    .await
    .unwrap();
    assert_eq!(stored_secret(&auth, &id), "new");
  }

  #[tokio::test]
  async fn test_update_rejects_kind_change_and_unknown_provider() {
    let auth = TestAuth::default();
    let id = create_provider(&auth, &ADMIN, create_request("secret"))
      .await
      .unwrap()
      .provider
      .id;

    let err = update_provider(
      &auth,
      &ADMIN,
      update_request(
        &id,
        ExternalLoginProviderConfig::Oidc(OidcConfig::default()),
      ),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);

    let err = update_provider(
      &auth,
      &ADMIN,
      update_request("unknown", github_config("secret")),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::NOT_FOUND);
  }

  #[tokio::test]
  async fn test_static_providers_are_read_only() {
    let auth = TestAuth {
      static_providers: vec![ExternalLoginProvider {
        id: "github".into(),
        name: "Github".into(),
        registration_disabled: false,
        config: github_config("static-secret"),
      }],
      ..Default::default()
    };

    let providers = list_providers(&auth, &ADMIN).await.unwrap();
    assert_eq!(providers.len(), 1);
    assert!(providers[0].read_only);
    assert_eq!(
      providers[0].provider.config.client_secret(),
      REDACTED
    );
    // Reserved id keeps the original callback path
    assert_eq!(
      providers[0].redirect_uri,
      "https://example.com/auth/github/callback"
    );

    let err = update_provider(
      &auth,
      &ADMIN,
      update_request("github", github_config("other")),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);

    let err =
      delete_provider(&auth, &ADMIN, "github").await.unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
  }

  #[tokio::test]
  async fn test_delete_removes_stored_provider() {
    let auth = TestAuth::default();
    let id = create_provider(&auth, &ADMIN, create_request("secret"))
      .await
      .unwrap()
      .provider
      .id;
    delete_provider(&auth, &ADMIN, &id).await.unwrap();
    assert!(auth.stored.lock().unwrap().is_empty());
    let err = delete_provider(&auth, &ADMIN, &id).await.unwrap_err();
    assert_eq!(err.status, StatusCode::NOT_FOUND);
  }
}
