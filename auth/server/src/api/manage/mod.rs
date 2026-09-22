use std::sync::Arc;

use axum::{Router, extract::Path, routing::post};
use mogh_auth_client::api::{NoData, manage::*};
use mogh_error::{AddStatusCodeError as _, Json};
use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumDiscriminants};
use tracing::debug;
use typeshare::typeshare;
use uuid::Uuid;

use crate::{
  AuthImpl, BoxAuthImpl,
  api::{Variant, parse_variant_request},
  session::Session,
  user::BoxAuthUser,
};

pub mod api_key;
pub mod external;
pub mod issuer;
pub mod local;
pub mod passkey;
pub mod provider;
pub mod totp;

mod middleware;

use middleware::{AuthenticatedAt, UserExtractor, attach_user};

pub struct ManageArgs {
  auth: BoxAuthImpl,
  user: Arc<BoxAuthUser>,
  session: Session,
}

#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EnumDiscriminants,
)]
#[args(ManageArgs)]
#[response(mogh_error::Response)]
#[error(mogh_error::Error)]
#[strum_discriminants(name(ManageRequestMethod), derive(Display))]
#[serde(tag = "type", content = "params")]
#[allow(clippy::enum_variant_names, clippy::large_enum_variant)]
pub enum ManageRequest {
  GetUserId(GetUserId),
  // Local
  UpdateUsername(UpdateUsername),
  UpdatePassword(UpdatePassword),
  // External
  BeginExternalLoginLink(BeginExternalLoginLink),
  UnlinkLocalLogin(UnlinkLocalLogin),
  UnlinkExternalLogin(UnlinkExternalLogin),
  // External login providers (admin)
  ListExternalLoginProviders(ListExternalLoginProviders),
  CreateExternalLoginProvider(CreateExternalLoginProvider),
  UpdateExternalLoginProvider(UpdateExternalLoginProvider),
  DeleteExternalLoginProvider(DeleteExternalLoginProvider),
  // Trusted issuers for workload identity (admin)
  ListTrustedIssuers(ListTrustedIssuers),
  CreateTrustedIssuer(CreateTrustedIssuer),
  UpdateTrustedIssuer(UpdateTrustedIssuer),
  DeleteTrustedIssuer(DeleteTrustedIssuer),
  // Passkey
  BeginPasskeyEnrollment(BeginPasskeyEnrollment),
  ConfirmPasskeyEnrollment(ConfirmPasskeyEnrollment),
  UnenrollPasskey(UnenrollPasskey),
  // TOTP
  BeginTotpEnrollment(BeginTotpEnrollment),
  ConfirmTotpEnrollment(ConfirmTotpEnrollment),
  UnenrollTotp(UnenrollTotp),
  // SKIP 2FA
  UpdateExternalSkip2fa(UpdateExternalSkip2fa),
  // API KEY
  CreateApiKey(CreateApiKey),
  DeleteApiKey(DeleteApiKey),
  CreateApiKeyV2(CreateApiKeyV2),
  DeleteApiKeyV2(DeleteApiKeyV2),
}

pub fn router<I: AuthImpl>() -> Router {
  Router::new()
    .route("/", post(handler::<I>))
    .route("/{variant}", post(variant_handler::<I>))
    .layer(axum::middleware::from_fn(attach_user::<I>))
}

async fn variant_handler<I: AuthImpl>(
  session: Session,
  user: UserExtractor,
  authenticated_at: AuthenticatedAt,
  Path(Variant { variant }): Path<Variant>,
  Json(params): Json<serde_json::Value>,
) -> mogh_error::Result<axum::response::Response> {
  let req: ManageRequest = parse_variant_request(variant, params)?;
  handler::<I>(session, user, authenticated_at, Json(req)).await
}

async fn handler<I: AuthImpl>(
  session: Session,
  UserExtractor(user): UserExtractor,
  AuthenticatedAt(authenticated_at): AuthenticatedAt,
  Json(request): Json<ManageRequest>,
) -> mogh_error::Result<axum::response::Response> {
  let req_id = Uuid::new_v4();
  let method: ManageRequestMethod = (&request).into();
  let username = user.username();
  let user_id = user.id();

  debug!(
    api = "Auth Management",
    req_id = req_id.to_string(),
    method = method.to_string(),
    user_id,
    username,
  );

  check_not_workload(user.as_ref().as_ref(), &request)?;

  let auth = I::new();
  check_recent_login(
    auth.reauthentication_window_secs(),
    authenticated_at,
    unix_timestamp_secs(),
    &request,
  )?;

  let args = ManageArgs {
    auth: Box::new(auth),
    user,
    session,
  };

  let res = request.resolve(&args).await;

  if let Err(e) = &res {
    debug!(
      api = "Auth Management",
      req_id = req_id.to_string(),
      method = method.to_string(),
      "ERROR: {:#}",
      e.error
    );
  }

  res.map(|res| res.0)
}

/// Workloads only act through the short lived tokens they get by token
/// exchange. Everything here either creates a way to log in which
/// outlives that (api keys, passwords, 2fa, linked logins) or configures
/// who can log in, so all of it is refused, including any request added
/// in the future.
fn check_not_workload(
  user: &dyn crate::user::AuthUserImpl,
  request: &ManageRequest,
) -> mogh_error::Result<()> {
  if !user.is_workload()
    || matches!(request, ManageRequest::GetUserId(_))
  {
    return Ok(());
  }
  Err(
    anyhow::anyhow!(
      "Workload users can't use the auth management API"
    )
    .status_code(axum::http::StatusCode::FORBIDDEN),
  )
}

fn unix_timestamp_secs() -> u64 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|duration| duration.as_secs())
    .unwrap_or_default()
}

/// Whether the request changes how somebody can log in, see
/// [AuthImpl::reauthentication_window_secs]. Everything does unless it
/// is listed here, including any request added in the future.
fn requires_recent_login(request: &ManageRequest) -> bool {
  !matches!(
    request,
    ManageRequest::GetUserId(_)
      | ManageRequest::ListExternalLoginProviders(_)
      | ManageRequest::ListTrustedIssuers(_)
      // Removing a credential never gives more access.
      | ManageRequest::DeleteApiKey(_)
      | ManageRequest::DeleteApiKeyV2(_)
  )
}

/// The requests which manage resources rather than the caller's
/// account: the login providers and trusted issuers, whose handlers
/// require an admin. A credential without a login (an api key, where
/// the app accepts them at all) may perform these — automation
/// manages them — and nothing else here.
fn manages_resources(request: &ManageRequest) -> bool {
  matches!(
    request,
    ManageRequest::CreateExternalLoginProvider(_)
      | ManageRequest::UpdateExternalLoginProvider(_)
      | ManageRequest::DeleteExternalLoginProvider(_)
      | ManageRequest::CreateTrustedIssuer(_)
      | ManageRequest::UpdateTrustedIssuer(_)
      | ManageRequest::DeleteTrustedIssuer(_)
  )
}

/// `authenticated_at` is when the token was issued, or `None` for
/// credentials without a login (api keys), which the resource
/// requests take ([manages_resources]) and the account requests
/// refuse. A session needs a recent login for both.
fn check_recent_login(
  window_secs: u64,
  authenticated_at: Option<u64>,
  now: u64,
  request: &ManageRequest,
) -> mogh_error::Result<()> {
  if window_secs == 0 || !requires_recent_login(request) {
    return Ok(());
  }
  let reason = match authenticated_at {
    // A token from the future doesn't count as recent either,
    // `saturating_sub` would make its age zero.
    Some(at) if at <= now && now - at <= window_secs => {
      return Ok(());
    }
    Some(_) => format!(
      "log in again to continue, this needs a login within the last {}",
      format_window(window_secs)
    ),
    None if manages_resources(request) => return Ok(()),
    None => String::from(
      "this needs a recent login, api keys can't be used for it",
    ),
  };
  Err(
    anyhow::anyhow!("{REAUTHENTICATION_REQUIRED}: {reason}")
      .status_code(axum::http::StatusCode::FORBIDDEN),
  )
}

fn format_window(secs: u64) -> String {
  if secs >= 120 && secs.is_multiple_of(60) {
    format!("{} minutes", secs / 60)
  } else {
    format!("{secs} seconds")
  }
}

impl Resolve<ManageArgs> for GetUserId {
  async fn resolve(
    self,
    ManageArgs { user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    Ok(GetUserIdResponse {
      id: user.id().to_string(),
    })
  }
}

impl Resolve<ManageArgs> for UpdateExternalSkip2fa {
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    auth.check_username_locked(user.username())?;
    auth
      .update_user_external_skip_2fa(
        user.id().to_string(),
        self.external_skip_2fa,
      )
      .await?;
    Ok(NoData {})
  }
}

#[cfg(test)]
mod tests {
  use axum::http::StatusCode;
  use mogh_auth_client::config::{
    ExternalLoginProviderConfig, NamedOauthConfig,
  };

  use super::*;
  use crate::user::AuthUserImpl;

  struct TestUser {
    workload: bool,
  }

  impl AuthUserImpl for TestUser {
    fn id(&self) -> &str {
      "id"
    }
    fn username(&self) -> &str {
      "user"
    }
    fn is_workload(&self) -> bool {
      self.workload
    }
    // Even an admin workload can't configure logins
    fn is_admin(&self) -> bool {
      true
    }
  }

  /// One of each kind of request.
  fn requests() -> Vec<ManageRequest> {
    vec![
      ManageRequest::UpdatePassword(UpdatePassword {
        password: "password".into(),
      }),
      ManageRequest::BeginExternalLoginLink(
        BeginExternalLoginLink {},
      ),
      ManageRequest::BeginPasskeyEnrollment(
        BeginPasskeyEnrollment {},
      ),
      ManageRequest::BeginTotpEnrollment(BeginTotpEnrollment {}),
      ManageRequest::CreateApiKey(CreateApiKey {
        name: "key".into(),
        expires: 0,
        cidr_whitelist: Vec::new(),
      }),
      ManageRequest::CreateExternalLoginProvider(
        CreateExternalLoginProvider {
          name: "Github".into(),
          registration_disabled: false,
          slug: String::new(),
          token_exchange: Default::default(),
          config: ExternalLoginProviderConfig::Github(
            NamedOauthConfig::default(),
          ),
        },
      ),
      ManageRequest::ListTrustedIssuers(ListTrustedIssuers {}),
      ManageRequest::DeleteTrustedIssuer(DeleteTrustedIssuer {
        id: "id".into(),
      }),
    ]
  }

  #[test]
  fn test_workload_users_are_refused() {
    let workload = TestUser { workload: true };
    for request in requests() {
      let method: ManageRequestMethod = (&request).into();
      let err = check_not_workload(&workload, &request).unwrap_err();
      assert_eq!(err.status, StatusCode::FORBIDDEN, "{method}");
    }
    // Harmless, and lets a workload check who it is
    assert!(
      check_not_workload(
        &workload,
        &ManageRequest::GetUserId(GetUserId {})
      )
      .is_ok()
    );
  }

  const NOW: u64 = 1_800_000_000;
  const WINDOW: u64 = 15 * 60;

  /// Requests which can't change how anybody logs in.
  fn harmless_requests() -> Vec<ManageRequest> {
    vec![
      ManageRequest::GetUserId(GetUserId {}),
      ManageRequest::ListExternalLoginProviders(
        ListExternalLoginProviders {},
      ),
      ManageRequest::ListTrustedIssuers(ListTrustedIssuers {}),
      ManageRequest::DeleteApiKey(DeleteApiKey { key: "key".into() }),
      ManageRequest::DeleteApiKeyV2(DeleteApiKeyV2 {
        public_key: "key".into(),
      }),
    ]
  }

  fn sensitive_requests() -> Vec<ManageRequest> {
    requests()
      .into_iter()
      .filter(requires_recent_login)
      .chain([
        ManageRequest::UpdateUsername(UpdateUsername {
          username: "name".into(),
        }),
        ManageRequest::UnenrollTotp(UnenrollTotp {}),
        ManageRequest::UnenrollPasskey(UnenrollPasskey {}),
        ManageRequest::UnlinkLocalLogin(UnlinkLocalLogin {}),
        ManageRequest::UpdateExternalSkip2fa(UpdateExternalSkip2fa {
          external_skip_2fa: true,
        }),
        ManageRequest::CreateApiKeyV2(CreateApiKeyV2 {
          name: "key".into(),
          expires: 0,
          cidr_whitelist: Vec::new(),
          public_key: String::new(),
        }),
      ])
      .collect()
  }

  #[test]
  fn test_sensitive_requests_need_a_recent_login() {
    let sensitive = sensitive_requests();
    assert!(sensitive.len() > 10);
    for request in sensitive {
      let method: ManageRequestMethod = (&request).into();
      // Just logged in, and at the end of the window.
      for age in [0, 1, WINDOW] {
        check_recent_login(WINDOW, Some(NOW - age), NOW, &request)
          .unwrap_or_else(|_| panic!("{method} at {age}s"));
      }
      // Too old, from the future, or (an account request) not a
      // login at all (api key).
      for authenticated_at in [
        Some(NOW - WINDOW - 1),
        Some(0),
        Some(NOW + 60),
        (!manages_resources(&request)).then_some(None).flatten(),
      ]
      .into_iter()
      .filter(|at| at.is_some() || !manages_resources(&request))
      {
        let err =
          check_recent_login(WINDOW, authenticated_at, NOW, &request)
            .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN, "{method}");
        // Clients recognize the error by the start of its message.
        assert!(
          format!("{:#}", err.error)
            .starts_with(REAUTHENTICATION_REQUIRED),
          "{method}: {:#}",
          err.error
        );
      }
    }
  }

  #[test]
  fn test_harmless_requests_work_with_any_credentials() {
    for request in harmless_requests() {
      for authenticated_at in [Some(0), Some(NOW + 60), None] {
        assert!(
          check_recent_login(WINDOW, authenticated_at, NOW, &request)
            .is_ok()
        );
      }
    }
  }

  /// The resource requests take a credential without a login; a
  /// stale login is still refused them, and the account requests
  /// refuse keys.
  #[test]
  fn test_resource_requests_take_api_keys() {
    let (resources, accounts): (Vec<_>, Vec<_>) =
      sensitive_requests()
        .into_iter()
        .partition(manages_resources);
    // One of each kind is listed, not every resource request.
    assert!(!resources.is_empty());
    assert!(accounts.len() > 6);
    for request in &resources {
      assert!(check_recent_login(WINDOW, None, NOW, request).is_ok());
      let err = check_recent_login(WINDOW, Some(0), NOW, request)
        .unwrap_err();
      assert_eq!(err.status, StatusCode::FORBIDDEN);
    }
    for request in &accounts {
      let err =
        check_recent_login(WINDOW, None, NOW, request).unwrap_err();
      assert_eq!(err.status, StatusCode::FORBIDDEN);
    }
  }

  #[test]
  fn test_recent_login_check_can_be_disabled() {
    for request in sensitive_requests() {
      for authenticated_at in [Some(0), None] {
        assert!(
          check_recent_login(0, authenticated_at, NOW, &request)
            .is_ok()
        );
      }
    }
  }

  #[test]
  fn test_format_window() {
    assert_eq!(format_window(900), "15 minutes");
    assert_eq!(format_window(90), "90 seconds");
    assert_eq!(format_window(1), "1 seconds");
  }

  #[test]
  fn test_other_users_are_not_affected() {
    let user = TestUser { workload: false };
    for request in requests() {
      assert!(check_not_workload(&user, &request).is_ok());
    }
  }
}
