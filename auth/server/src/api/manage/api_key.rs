use anyhow::Context as _;
use mogh_auth_client::api::manage::{
  CreateApiKey, CreateApiKeyResponse, CreateApiKeyV2,
  CreateApiKeyV2Response, DeleteApiKey, DeleteApiKeyResponse,
  DeleteApiKeyV2, DeleteApiKeyV2Response,
};
use mogh_resolver::Resolve;
use tracing::{info, instrument};

use crate::{AuthImpl, api::manage::ManageArgs, rand::random_string};

//

/// Generate a random API (key, secret, bcrypt-hashed secret).
fn generate_api_key_parts(
  secret_length: usize,
  bcrypt_cost: u32,
) -> anyhow::Result<(String, String, String)> {
  let key = format!("K_{}_K", random_string(secret_length));
  let secret = format!("S_{}_S", random_string(secret_length));
  let hashed_secret = bcrypt::hash(&secret, bcrypt_cost)
    .context("Failed at hashing secret string")?;
  Ok((key, secret, hashed_secret))
}

pub async fn create_api_key<I: AuthImpl + ?Sized>(
  auth: &I,
  user_id: String,
  body: CreateApiKey,
) -> mogh_error::Result<CreateApiKeyResponse> {
  auth.validate_api_key_name(&body.name)?;

  let (key, secret, hashed_secret) = generate_api_key_parts(
    auth.api_key_secret_length(),
    auth.api_secret_bcrypt_cost(),
  )?;

  auth
    .create_api_key(user_id.clone(), body, key.clone(), hashed_secret)
    .await?;

  info!(user_id, key, "Api key created");

  Ok(CreateApiKeyResponse { key, secret })
}

impl Resolve<ManageArgs> for CreateApiKey {
  #[instrument(
  "CreateApiKey",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
      name = &self.name,
      expires = &self.expires
    )
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    create_api_key(auth.as_ref(), user.id().to_string(), self).await
  }
}

//

/// The [AuthImpl::delete_api_key] implementation
/// is responsible for scoping the delete to `user_id`.
pub async fn delete_api_key<I: AuthImpl + ?Sized>(
  auth: &I,
  user_id: &str,
  key: String,
) -> mogh_error::Result<()> {
  auth.delete_api_key(user_id.to_string(), key).await
}

impl Resolve<ManageArgs> for DeleteApiKey {
  #[instrument(
    "DeleteApiKey",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
      self.key
    )
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    delete_api_key(auth.as_ref(), user.id(), self.key).await?;
    Ok(DeleteApiKeyResponse {})
  }
}

//

pub async fn create_api_key_v2<I: AuthImpl + ?Sized>(
  auth: &I,
  user_id: String,
  body: CreateApiKeyV2,
) -> mogh_error::Result<CreateApiKeyV2Response> {
  auth.validate_api_key_name(&body.name)?;

  let public_key = body.public_key.trim();

  let (private_key, public_key) = if public_key.is_empty() {
    let key_pair =
      mogh_pki::EncodedKeyPair::generate(mogh_pki::PkiKind::OneWay)?;
    (
      Some(key_pair.private.into_inner()),
      key_pair.public.into_inner(),
    )
  } else {
    (None, public_key.to_string())
  };

  auth
    .create_api_key_v2(
      user_id,
      CreateApiKey {
        name: body.name,
        expires: body.expires,
      },
      public_key,
    )
    .await?;

  Ok(CreateApiKeyV2Response { private_key })
}

impl Resolve<ManageArgs> for CreateApiKeyV2 {
  #[instrument(
  "CreateApiKeyV2",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
      name = &self.name,
      expires = &self.expires
    )
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    create_api_key_v2(auth.as_ref(), user.id().to_string(), self)
      .await
  }
}

//

#[instrument("DeleteApiKeyV2", skip_all, fields(user_id, public_key))]
/// The [AuthImpl::delete_api_key_v2] implementation
/// is responsible for scoping the delete to `user_id`.
pub async fn delete_api_key_v2<I: AuthImpl + ?Sized>(
  auth: &I,
  user_id: &str,
  public_key: String,
) -> mogh_error::Result<()> {
  auth
    .delete_api_key_v2(user_id.to_string(), public_key)
    .await
}

impl Resolve<ManageArgs> for DeleteApiKeyV2 {
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    delete_api_key_v2(auth.as_ref(), user.id(), self.public_key)
      .await?;
    Ok(DeleteApiKeyV2Response {})
  }
}

//

#[cfg(test)]
mod tests {
  use super::*;

  // Low cost to keep tests fast.
  const TEST_BCRYPT_COST: u32 = 4;

  #[test]
  fn test_api_key_parts_format() {
    let (key, secret, _) =
      generate_api_key_parts(40, TEST_BCRYPT_COST).unwrap();
    assert_eq!(key.len(), 44);
    assert!(key.starts_with("K_") && key.ends_with("_K"));
    assert_eq!(secret.len(), 44);
    assert!(secret.starts_with("S_") && secret.ends_with("_S"));
    assert!(
      key[2..42].chars().all(|c| c.is_ascii_alphanumeric()),
      "key body must be alphanumeric"
    );
  }

  #[test]
  fn test_api_key_secret_verifies_against_hash() {
    let (_, secret, hashed_secret) =
      generate_api_key_parts(40, TEST_BCRYPT_COST).unwrap();
    assert!(bcrypt::verify(&secret, &hashed_secret).unwrap());
  }

  #[test]
  fn test_api_key_wrong_secret_fails_verification() {
    let (_, _, hashed_secret) =
      generate_api_key_parts(40, TEST_BCRYPT_COST).unwrap();
    let (_, other_secret, _) =
      generate_api_key_parts(40, TEST_BCRYPT_COST).unwrap();
    assert!(!bcrypt::verify(&other_secret, &hashed_secret).unwrap());
  }

  #[test]
  fn test_api_key_parts_are_unique() {
    let (key_a, secret_a, _) =
      generate_api_key_parts(40, TEST_BCRYPT_COST).unwrap();
    let (key_b, secret_b, _) =
      generate_api_key_parts(40, TEST_BCRYPT_COST).unwrap();
    assert_ne!(key_a, key_b);
    assert_ne!(secret_a, secret_b);
  }

  #[test]
  fn test_api_key_respects_custom_length() {
    let (key, secret, _) =
      generate_api_key_parts(10, TEST_BCRYPT_COST).unwrap();
    assert_eq!(key.len(), 14);
    assert_eq!(secret.len(), 14);
  }
}
