//! # Example Write API
//!
//! Authenticated requests which change stored state.

use mogh_resolver::{HasResponse, Resolve};
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::entities::{NoData, Note, User};

pub trait ExampleWriteRequest: HasResponse {}

//

/// Create a note owned by the calling user.
/// Response: [Note].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(ExampleWriteRequest)]
#[response(CreateNoteResponse)]
#[error(mogh_error::Error)]
pub struct CreateNote {
  pub title: String,
  #[serde(default)]
  pub content: String,
}

/// Response for [CreateNote].
#[typeshare]
pub type CreateNoteResponse = Note;

//

/// Update a note of the calling user.
/// Response: [Note].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(ExampleWriteRequest)]
#[response(UpdateNoteResponse)]
#[error(mogh_error::Error)]
pub struct UpdateNote {
  pub id: String,
  /// The new title. Unchanged if not given.
  pub title: Option<String>,
  /// The new content. Unchanged if not given.
  pub content: Option<String>,
}

/// Response for [UpdateNote].
#[typeshare]
pub type UpdateNoteResponse = Note;

//

/// Delete a note of the calling user.
/// Response: [NoData].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(ExampleWriteRequest)]
#[response(DeleteNoteResponse)]
#[error(mogh_error::Error)]
pub struct DeleteNote {
  pub id: String,
}

/// Response for [DeleteNote].
#[typeshare]
pub type DeleteNoteResponse = NoData;

//

/// Set the ips the calling user can log in / call the api from.
/// Response: [User].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(ExampleWriteRequest)]
#[response(UpdateCidrWhitelistResponse)]
#[error(mogh_error::Error)]
pub struct UpdateCidrWhitelist {
  /// CIDR ranges or ips. Empty allows all.
  pub cidr_whitelist: Vec<String>,
}

/// Response for [UpdateCidrWhitelist].
#[typeshare]
pub type UpdateCidrWhitelistResponse = User;

//

/// Enable / disable a user, make them admin, or set their groups. Admin only.
/// Response: [User].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(ExampleWriteRequest)]
#[response(UpdateUserAccessResponse)]
#[error(mogh_error::Error)]
pub struct UpdateUserAccess {
  pub user_id: String,
  /// Unchanged if not given.
  pub enabled: Option<bool>,
  /// Unchanged if not given.
  pub admin: Option<bool>,
  /// Unchanged if not given.
  pub groups: Option<Vec<String>>,
}

/// Response for [UpdateUserAccess].
#[typeshare]
pub type UpdateUserAccessResponse = User;

//

/// Delete a user and everything they own. Admin only.
/// Response: [NoData].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(ExampleWriteRequest)]
#[response(DeleteUserResponse)]
#[error(mogh_error::Error)]
pub struct DeleteUser {
  pub user_id: String,
}

/// Response for [DeleteUser].
#[typeshare]
pub type DeleteUserResponse = NoData;
