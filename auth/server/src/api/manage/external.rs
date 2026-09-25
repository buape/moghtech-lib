use axum::http::StatusCode;
use mogh_auth_client::api::manage::{
  BeginExternalLoginLink, BeginExternalLoginLinkResponse,
  UnlinkExternalLogin, UnlinkExternalLoginResponse, UnlinkLocalLogin,
  UnlinkLocalLoginResponse,
};
use mogh_error::AddStatusCode as _;
use mogh_resolver::Resolve;
use tracing::instrument;

use crate::{
  AuthImpl, api::manage::ManageArgs,
  provider::external::validate_provider_id,
};

//

impl Resolve<ManageArgs> for BeginExternalLoginLink {
  #[instrument(
    "BeginExternalLoginLink",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
    )
  )]
  async fn resolve(
    self,
    ManageArgs {
      auth,
      user,
      session,
    }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    auth.check_username_locked(user.username())?;

    // Cycles the session id: the response carries the cookie
    // the client has to start the link (`/link`) with.
    session.insert_external_link_user_id(user.id()).await?;

    Ok(BeginExternalLoginLinkResponse {})
  }
}

//

pub async fn unlink_local_login<I: AuthImpl + ?Sized>(
  auth: &I,
  username: &str,
  user_id: String,
) -> mogh_error::Result<()> {
  auth.check_username_locked(username)?;
  auth.unlink_local_login(user_id).await?;
  Ok(())
}

impl Resolve<ManageArgs> for UnlinkLocalLogin {
  #[instrument(
    "UnlinkLocalLogin",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
    )
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    unlink_local_login(
      auth.as_ref(),
      user.username(),
      user.id().to_string(),
    )
    .await?;
    Ok(UnlinkLocalLoginResponse {})
  }
}

//

pub async fn unlink_external_login<I: AuthImpl + ?Sized>(
  auth: &I,
  username: &str,
  user_id: String,
  provider_id: String,
) -> mogh_error::Result<()> {
  auth.check_username_locked(username)?;
  // The provider may already be deleted, only validate the id shape.
  validate_provider_id(&provider_id)
    .status_code(StatusCode::BAD_REQUEST)?;
  auth.unlink_external_login(user_id, provider_id).await?;
  Ok(())
}

impl Resolve<ManageArgs> for UnlinkExternalLogin {
  #[instrument(
    "UnlinkExternalLogin",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
      provider_id = self.provider_id
    )
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    unlink_external_login(
      auth.as_ref(),
      user.username(),
      user.id().to_string(),
      self.provider_id,
    )
    .await?;
    Ok(UnlinkExternalLoginResponse {})
  }
}
