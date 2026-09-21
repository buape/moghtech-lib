use std::sync::Arc;

use axum::{Router, extract::Path, routing::post};
use mogh_auth_client::api::{NoData, manage::*};
use mogh_error::{AddStatusCodeError as _, Json};
use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};
use serde_json::json;
use strum::{Display, EnumDiscriminants};
use tracing::debug;
use typeshare::typeshare;
use uuid::Uuid;

use crate::{
  AuthImpl, BoxAuthImpl, api::Variant, session::Session,
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

use middleware::{UserExtractor, attach_user};

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
  Path(Variant { variant }): Path<Variant>,
  Json(params): Json<serde_json::Value>,
) -> mogh_error::Result<axum::response::Response> {
  let req: ManageRequest = serde_json::from_value(json!({
    "type": variant,
    "params": params,
  }))?;
  handler::<I>(session, user, Json(req)).await
}

async fn handler<I: AuthImpl>(
  session: Session,
  UserExtractor(user): UserExtractor,
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

  let args = ManageArgs {
    auth: Box::new(I::new()),
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

  #[test]
  fn test_other_users_are_not_affected() {
    let user = TestUser { workload: false };
    for request in requests() {
      assert!(check_not_workload(&user, &request).is_ok());
    }
  }
}
