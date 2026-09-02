use anyhow::{Context as _, anyhow};
use axum::{Router, response::Redirect, routing::get};
use data_encoding::BASE64URL;
use mogh_auth_client::api::login::UserIdOrTwoFactor;
use mogh_error::{AddStatusCode as _, AddStatusCodeError as _};
use reqwest::StatusCode;
use serde::Deserialize;
use tracing::info;
use utoipa::ToSchema;

use crate::{AuthImpl, session::Session, user::BoxAuthUser};

pub mod login;
pub mod manage;
pub mod named;
pub mod oidc;

/// This router should be nested without any additional middleware
pub fn router<I: AuthImpl>() -> Router {
  Router::new()
    .route("/version", get(|| async { env!("CARGO_PKG_VERSION") }))
    .nest("/login", login::router::<I>())
    .nest("/manage", manage::router::<I>())
    .nest("/oidc", oidc::router::<I>())
    .merge(named::router::<I>())
}

#[derive(serde::Deserialize)]
struct Variant {
  variant: String,
}

#[derive(serde::Deserialize)]
pub struct RedirectQuery {
  redirect: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct StandardCallbackQuery {
  pub state: Option<String>,
  pub code: Option<String>,
  pub error: Option<String>,
}

impl StandardCallbackQuery {
  /// Returns (state, code)
  pub fn open(self) -> mogh_error::Result<(String, String)> {
    if let Some(e) = self.error {
      return Err(
        anyhow!("Provider returned error: {e}")
          .status_code(StatusCode::UNAUTHORIZED),
      );
    }
    let state = self
      .state
      .context("Callback query does not contain state")
      .status_code(StatusCode::UNAUTHORIZED)?;
    let code = self
      .code
      .context("Callback query does not contain code")
      .status_code(StatusCode::UNAUTHORIZED)?;

    Ok((state, code))
  }
}

fn format_redirect(
  host: &str,
  redirect: Option<&str>,
  extra: &str,
) -> Redirect {
  let redirect_url = if let Some(redirect) = redirect
    && !redirect.is_empty()
  {
    let splitter = if extra.is_empty() {
      ""
    } else if redirect.contains('?') {
      "&"
    } else {
      "?"
    };
    format!("{redirect}{splitter}{extra}")
  } else {
    format!(
      "{host}{}{extra}",
      if extra.is_empty() { "" } else { "?" }
    )
  };
  Redirect::to(&redirect_url)
}

/// Append a random suffix to the username if it is already taken.
async fn unique_username<I: AuthImpl>(
  auth: &I,
  mut username: String,
) -> mogh_error::Result<String> {
  if auth
    .find_user_with_username(username.clone())
    .await?
    .is_some()
  {
    username.push('-');
    username.push_str(&crate::rand::random_string(5));
  }
  Ok(username)
}

async fn get_user_id_or_two_factor<I: AuthImpl>(
  auth: &I,
  session: &Session,
  user: &BoxAuthUser,
) -> mogh_error::Result<UserIdOrTwoFactor> {
  let res = match (
    user.external_skip_2fa(),
    user.passkey(),
    user.totp_secret(),
  ) {
    // Skip / No 2FA
    (true, _, _) | (false, None, None) => {
      session.insert_authenticated_user_id(user.id()).await?;

      info!(
        user_id = user.id(),
        username = user.username(),
        "User logged in"
      );

      UserIdOrTwoFactor::UserId(user.id().to_string())
    }
    // WebAuthn Passkey 2FA
    (false, Some(passkey), _) => {
      let provider = auth.passkey_provider().context(
        "No passkey provider available, possibly invalid 'host' config.",
      )?;
      let (response, state) = provider
        .start_passkey_authentication(passkey)
        .context("Failed to start passkey authentication flow")?;
      session.insert_passkey_login(user.id(), &state).await?;

      info!(
        user_id = user.id(),
        username = user.username(),
        "Passkey 2FA flow initiated"
      );

      UserIdOrTwoFactor::Passkey(response)
    }
    // TOTP 2FA
    (false, None, Some(_)) => {
      session.insert_totp_login_user_id(user.id()).await?;

      info!(
        user_id = user.id(),
        username = user.username(),
        "TOTP 2FA flow initiated"
      );

      UserIdOrTwoFactor::Totp {}
    }
  };
  Ok(res)
}

fn user_id_or_two_factor_redirect<I: AuthImpl>(
  auth: &I,
  user_id_or_two_factor: UserIdOrTwoFactor,
  redirect: Option<&str>,
) -> mogh_error::Result<Redirect> {
  match user_id_or_two_factor {
    UserIdOrTwoFactor::UserId(_) => {
      Ok(format_redirect(auth.host(), redirect, "redeem_ready=true"))
    }
    UserIdOrTwoFactor::Totp {} => {
      Ok(format_redirect(auth.host(), redirect, "totp=true"))
    }
    UserIdOrTwoFactor::Passkey(passkey) => {
      let passkey = serde_json::to_vec(&passkey)
        .context("Failed to serialize passkey response")?;
      let passkey = BASE64URL.encode(&passkey);
      Ok(format_redirect(
        auth.host(),
        redirect,
        &format!("passkey={passkey}"),
      ))
    }
  }
}

#[cfg(test)]
mod tests {
  use axum::response::IntoResponse;

  use super::*;

  fn location(redirect: Redirect) -> String {
    redirect
      .into_response()
      .headers()
      .get("location")
      .unwrap()
      .to_str()
      .unwrap()
      .to_string()
  }

  #[test]
  fn test_format_redirect_with_redirect_no_query() {
    let redirect = format_redirect(
      "https://example.com",
      Some("https://example.com/dest"),
      "redeem_ready=true",
    );
    assert_eq!(
      location(redirect),
      "https://example.com/dest?redeem_ready=true"
    );
  }

  #[test]
  fn test_format_redirect_with_redirect_existing_query() {
    let redirect = format_redirect(
      "https://example.com",
      Some("https://example.com/dest?a=1"),
      "totp=true",
    );
    assert_eq!(
      location(redirect),
      "https://example.com/dest?a=1&totp=true"
    );
  }

  #[test]
  fn test_format_redirect_without_redirect_falls_back_to_host() {
    let redirect = format_redirect(
      "https://example.com",
      None,
      "redeem_ready=true",
    );
    assert_eq!(
      location(redirect),
      "https://example.com?redeem_ready=true"
    );
  }

  #[test]
  fn test_format_redirect_empty_redirect_falls_back_to_host() {
    let redirect =
      format_redirect("https://example.com", Some(""), "totp=true");
    assert_eq!(location(redirect), "https://example.com?totp=true");
  }

  #[test]
  fn test_format_redirect_empty_extra() {
    let redirect = format_redirect(
      "https://example.com",
      Some("https://example.com/dest"),
      "",
    );
    assert_eq!(location(redirect), "https://example.com/dest");
    let redirect = format_redirect("https://example.com", None, "");
    assert_eq!(location(redirect), "https://example.com");
  }

  #[test]
  fn test_standard_callback_query_open() {
    let (state, code) = StandardCallbackQuery {
      state: Some("state".into()),
      code: Some("code".into()),
      error: None,
    }
    .open()
    .unwrap();
    assert_eq!(state, "state");
    assert_eq!(code, "code");
  }

  #[test]
  fn test_standard_callback_query_open_error_cases() {
    // Provider error is surfaced
    assert!(
      StandardCallbackQuery {
        state: Some("state".into()),
        code: Some("code".into()),
        error: Some("access_denied".into()),
      }
      .open()
      .is_err()
    );
    // Missing state
    assert!(
      StandardCallbackQuery {
        state: None,
        code: Some("code".into()),
        error: None,
      }
      .open()
      .is_err()
    );
    // Missing code
    assert!(
      StandardCallbackQuery {
        state: Some("state".into()),
        code: None,
        error: None,
      }
      .open()
      .is_err()
    );
  }
}
