//! # Mogh Auth Login API
//!
//! This module includes *unauthenticated* API methods
//! used in order to gain a temporary access token (JWT)
//! to use with other authenticated API methods.

use mogh_resolver::{HasResponse, Resolve};
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};
use typeshare::typeshare;

use crate::passkey::{PublicKeyCredential, RequestChallengeResponse};

/// JSON containing a jwt authentication token.
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct JwtResponse {
  /// A token the user can use to authenticate their requests.
  pub jwt: String,
}

/// JSON containing either an authentication token or the required 2fa auth check.
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(tag = "type", content = "data")]
pub enum JwtOrTwoFactor {
  Jwt(JwtResponse),
  Passkey(RequestChallengeResponse),
  Totp {},
}

/// JSON containing either an authentication token or the required 2fa auth check.
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(tag = "type", content = "data")]
pub enum UserIdOrTwoFactor {
  UserId(String),
  Passkey(RequestChallengeResponse),
  Totp {},
}

/// The available login providers
#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Display, EnumString,
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum LoginProvider {
  Local,
  Oidc,
  Github,
  Google,
}

/// The available external login providers
#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Display, EnumString,
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum ExternalLoginProvider {
  Oidc,
  Github,
  Google,
}

//

pub trait MoghAuthLoginRequest: HasResponse {}

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/login/GetLoginOptions",
  description = "Get the available options to login, eg. local and external providers.",
  request_body(content = GetLoginOptions),
  responses(
    (status = 200, description = "The available login options", body = GetLoginOptionsResponse)
  ),
)]
fn get_login_options() {}

/// Get the available options to login, eg. local and external providers.
/// Response: [GetLoginOptionsResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthLoginRequest)]
#[response(GetLoginOptionsResponse)]
#[error(mogh_error::Error)]
pub struct GetLoginOptions {}

/// The response for [GetLoginOptions].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct GetLoginOptionsResponse {
  /// Whether Local login is enabled.
  pub local: bool,
  /// Whether OIDC login is enabled.
  pub oidc: bool,
  /// Whether Github login is enabled.
  pub github: bool,
  /// Whether Google login is enabled.
  pub google: bool,
  /// Whether user registration (Sign Up) has been disabled
  pub registration_disabled: bool,
  /// Whether the login page should auto-redirect to the OIDC provider
  pub oidc_auto_redirect: bool,
}

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/login/ExchangeForJwt",
  description = "Retrieve a JWT after completing third party login flows.",
  request_body(content = ExchangeForJwt),
  responses(
    (status = 200, description = "Authentication JWT", body = ExchangeForJwtResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn exchange_for_jwt() {}

/// Retrieve a JWT after completing third party login flows.
/// Response: [ExchangeForJwtResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthLoginRequest)]
#[response(ExchangeForJwtResponse)]
#[error(mogh_error::Error)]
pub struct ExchangeForJwt {}

/// Response for [ExchangeForJwt].
#[typeshare]
pub type ExchangeForJwtResponse = JwtResponse;

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/login/SignUpLocalUser",
  description = "Sign up a new local user account.",
  request_body(content = SignUpLocalUser),
  responses(
    (status = 200, description = "Authentication JWT", body = SignUpLocalUserResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn sign_up_local_user() {}

/// Sign up a new local user account.
/// Response: [SignUpLocalUserResponse].
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthLoginRequest)]
#[response(SignUpLocalUserResponse)]
#[error(mogh_error::Error)]
pub struct SignUpLocalUser {
  /// The username for the new user.
  pub username: String,
  /// The password for the new user.
  /// This cannot be retreived later.
  pub password: String,
}

/// Response for [SignUpLocalUser].
#[typeshare]
pub type SignUpLocalUserResponse = JwtResponse;

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/login/LoginLocalUser",
  description = "Login as a local user.",
  request_body(content = LoginLocalUser),
  responses(
    (status = 200, description = "JWT auth token or 2 factor login continuation", body = LoginLocalUserResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn login_local_user() {}

/// Login as a local user.
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthLoginRequest)]
#[response(LoginLocalUserResponse)]
#[error(mogh_error::Error)]
pub struct LoginLocalUser {
  /// The user's username
  pub username: String,
  /// The user's password
  pub password: String,
}

/// The response for [LoginLocalUser]
#[typeshare]
pub type LoginLocalUserResponse = JwtOrTwoFactor;

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/login/CompletePasskeyLogin",
  description = "Complete login using passkey as second factor.",
  request_body(content = CompletePasskeyLogin),
  responses(
    (status = 200, description = "Authentication JWT", body = CompletePasskeyLoginResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn complete_passkey_login() {}

/// Complete login using passkey as second factor.
/// Response: [CompletePasskeyLoginResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthLoginRequest)]
#[response(CompletePasskeyLoginResponse)]
#[error(mogh_error::Error)]
pub struct CompletePasskeyLogin {
  pub credential: PublicKeyCredential,
}

/// Response for [CompletePasskeyLogin].
#[typeshare]
pub type CompletePasskeyLoginResponse = JwtResponse;

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/login/CompleteTotpLogin",
  description = "Complete login using TOTP code as second factor.",
  request_body(content = CompleteTotpLogin),
  responses(
    (status = 200, description = "Authentication JWT", body = CompleteTotpLoginResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn complete_totp_login() {}

/// Complete login using TOTP code as second factor.
/// Response: [CompleteTotpLoginResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthLoginRequest)]
#[response(CompleteTotpLoginResponse)]
#[error(mogh_error::Error)]
pub struct CompleteTotpLogin {
  /// The time dependent totp code for user.
  pub code: String,
}

/// Response for [CompleteTotpLogin].
#[typeshare]
pub type CompleteTotpLoginResponse = JwtResponse;

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/login/CompleteTotpRecoveryLogin",
  description = "Complete login using a TOTP recovery code as second factor.",
  request_body(content = CompleteTotpRecoveryLogin),
  responses(
    (status = 200, description = "Authentication JWT", body = CompleteTotpRecoveryLoginResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn complete_totp_recovery_login() {}

/// Complete login using a TOTP recovery code as second factor.
/// Each recovery code can only be used once.
/// Response: [CompleteTotpRecoveryLoginResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthLoginRequest)]
#[response(CompleteTotpRecoveryLoginResponse)]
#[error(mogh_error::Error)]
pub struct CompleteTotpRecoveryLogin {
  /// One of the recovery codes issued at TOTP enrollment.
  pub code: String,
}

/// Response for [CompleteTotpRecoveryLogin].
#[typeshare]
pub type CompleteTotpRecoveryLoginResponse = JwtResponse;

#[cfg(test)]
mod tests {
  use std::str::FromStr;

  use mogh_resolver::HasResponse;
  use serde_json::json;

  use super::*;

  #[test]
  fn test_req_types_stable() {
    // These strings are sent as the `type` tag on the wire.
    assert_eq!(GetLoginOptions::req_type(), "GetLoginOptions");
    assert_eq!(ExchangeForJwt::req_type(), "ExchangeForJwt");
    assert_eq!(SignUpLocalUser::req_type(), "SignUpLocalUser");
    assert_eq!(LoginLocalUser::req_type(), "LoginLocalUser");
    assert_eq!(
      CompletePasskeyLogin::req_type(),
      "CompletePasskeyLogin"
    );
    assert_eq!(CompleteTotpLogin::req_type(), "CompleteTotpLogin");
    assert_eq!(
      CompleteTotpRecoveryLogin::req_type(),
      "CompleteTotpRecoveryLogin"
    );
  }

  #[test]
  fn test_jwt_response_wire_format() {
    let value = serde_json::to_value(JwtResponse {
      jwt: "token".into(),
    })
    .unwrap();
    assert_eq!(value, json!({ "jwt": "token" }));
    let res: JwtResponse =
      serde_json::from_value(json!({ "jwt": "token" })).unwrap();
    assert_eq!(res.jwt, "token");
  }

  #[test]
  fn test_jwt_or_two_factor_wire_format() {
    // Tagged with `type` / `data`.
    let value =
      serde_json::to_value(JwtOrTwoFactor::Jwt(JwtResponse {
        jwt: "abc".into(),
      }))
      .unwrap();
    assert_eq!(
      value,
      json!({ "type": "Jwt", "data": { "jwt": "abc" } })
    );
    let res: JwtOrTwoFactor = serde_json::from_value(value).unwrap();
    match res {
      JwtOrTwoFactor::Jwt(res) => assert_eq!(res.jwt, "abc"),
      _ => panic!("expected Jwt variant"),
    }

    let value =
      serde_json::to_value(JwtOrTwoFactor::Totp {}).unwrap();
    assert_eq!(value, json!({ "type": "Totp", "data": {} }));
    let res: JwtOrTwoFactor = serde_json::from_value(value).unwrap();
    assert!(matches!(res, JwtOrTwoFactor::Totp {}));
  }

  #[test]
  fn test_user_id_or_two_factor_wire_format() {
    let value = serde_json::to_value(UserIdOrTwoFactor::UserId(
      "user-id".into(),
    ))
    .unwrap();
    assert_eq!(value, json!({ "type": "UserId", "data": "user-id" }));
    let res: UserIdOrTwoFactor =
      serde_json::from_value(value).unwrap();
    match res {
      UserIdOrTwoFactor::UserId(id) => assert_eq!(id, "user-id"),
      _ => panic!("expected UserId variant"),
    }
  }

  #[test]
  fn test_login_provider_representations() {
    // serde representation
    assert_eq!(
      serde_json::to_value(LoginProvider::Local).unwrap(),
      json!("Local")
    );
    let provider: LoginProvider =
      serde_json::from_value(json!("Github")).unwrap();
    assert!(matches!(provider, LoginProvider::Github));
    // strum Display / FromStr representation
    assert_eq!(LoginProvider::Oidc.to_string(), "Oidc");
    assert!(matches!(
      LoginProvider::from_str("Google").unwrap(),
      LoginProvider::Google
    ));
    assert!(LoginProvider::from_str("Unknown").is_err());
    // External providers
    assert_eq!(ExternalLoginProvider::Oidc.to_string(), "Oidc");
    assert!(matches!(
      ExternalLoginProvider::from_str("Github").unwrap(),
      ExternalLoginProvider::Github
    ));
  }

  #[test]
  fn test_get_login_options_response_wire_format() {
    let value = serde_json::to_value(GetLoginOptionsResponse {
      local: true,
      oidc: false,
      github: true,
      google: false,
      registration_disabled: true,
      oidc_auto_redirect: false,
    })
    .unwrap();
    assert_eq!(
      value,
      json!({
        "local": true,
        "oidc": false,
        "github": true,
        "google": false,
        "registration_disabled": true,
        "oidc_auto_redirect": false,
      })
    );
  }

  #[test]
  fn test_login_local_user_wire_format() {
    let value = serde_json::to_value(LoginLocalUser {
      username: "user".into(),
      password: "pass".into(),
    })
    .unwrap();
    assert_eq!(
      value,
      json!({ "username": "user", "password": "pass" })
    );
  }
}
