use std::net::IpAddr;

use anyhow::{Context as _, anyhow};
use axum::{Router, response::Redirect, routing::get};
use data_encoding::BASE64URL;
use mogh_auth_client::{
  api::login::UserIdOrTwoFactor, config::ExternalLoginProvider,
  passkey::RequestChallengeResponse,
};
use mogh_error::{AddStatusCode as _, AddStatusCodeError as _};
use reqwest::StatusCode;
use serde::Deserialize;
use tracing::info;
use utoipa::ToSchema;

use crate::{
  AuthImpl, Login, LoginKind, middleware::check_user_cidr_whitelist,
  session::Session, user::BoxAuthUser,
};

pub mod external;
pub mod login;
pub mod manage;
pub mod token;

/// This router should be nested without any additional middleware
pub fn router<I: AuthImpl>() -> Router {
  Router::new()
    .route("/version", get(|| async { env!("CARGO_PKG_VERSION") }))
    .nest("/login", login::router::<I>())
    .nest("/manage", manage::router::<I>())
    .merge(external::router::<I>())
    .merge(token::router::<I>())
}

#[derive(serde::Deserialize)]
struct Variant {
  variant: String,
}

/// Builds the tagged request (`{ type, params }`) of the
/// `/{variant}` routes. An unknown variant or invalid params
/// is the clients fault (BAD_REQUEST), not a server error.
fn parse_variant_request<R: serde::de::DeserializeOwned>(
  variant: String,
  params: serde_json::Value,
) -> mogh_error::Result<R> {
  serde_json::from_value(serde_json::json!({
    "type": variant,
    "params": params,
  }))
  .context("Invalid request")
  .status_code(StatusCode::BAD_REQUEST)
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

/// The longest post-login `redirect` which is kept. The login
/// is started by unauthenticated requests, which store it on the
/// session until the callback.
pub const MAX_REDIRECT_LENGTH: usize = 2048;

/// Only allow post-login redirects back to the app itself,
/// preventing open redirects through the `redirect` query param.
/// The redirect is resolved against `host` (so absolute urls, paths
/// and relative paths all work) and must be http(s) on the same
/// hostname, any scheme or port. Anything else (other origins,
/// protocol-relative `//evil`, scheme tricks) is dropped.
fn sanitize_redirect(
  host: &str,
  redirect: &str,
) -> Option<reqwest::Url> {
  let redirect = redirect.trim();
  if redirect.is_empty() {
    return None;
  }
  let host = reqwest::Url::parse(host).ok()?;
  let host_name = host.host_str()?;
  let target = host.join(redirect).ok()?;
  if !matches!(target.scheme(), "http" | "https") {
    return None;
  }
  if !target.host_str()?.eq_ignore_ascii_case(host_name) {
    return None;
  }
  Some(target)
}

/// The `redirect` of a login as it is stored on the session until
/// the callback: sanitized ([sanitize_redirect]), and dropped if longer
/// than [MAX_REDIRECT_LENGTH]. Without one, the login ends at `host`.
fn login_redirect(
  host: &str,
  redirect: Option<String>,
) -> Option<String> {
  redirect
    .filter(|redirect| redirect.len() <= MAX_REDIRECT_LENGTH)
    .and_then(|redirect| sanitize_redirect(host, &redirect))
    .map(String::from)
    .filter(|redirect| redirect.len() <= MAX_REDIRECT_LENGTH)
}

/// The url the browser is sent to after an external login, with the
/// `extra` query for the app (`redeem_ready=true`, `totp=true`,
/// `passkey=...`). The query is placed before the redirect's fragment,
/// where the app reads it.
fn format_redirect(
  host: &str,
  redirect: Option<&str>,
  extra: &str,
) -> Redirect {
  let redirect_url = if let Some(mut redirect) =
    redirect.and_then(|redirect| sanitize_redirect(host, redirect))
  {
    if !extra.is_empty() {
      let query = match redirect.query() {
        Some(query) if !query.is_empty() => {
          format!("{query}&{extra}")
        }
        _ => extra.to_string(),
      };
      redirect.set_query(Some(&query));
    }
    redirect.to_string()
  } else {
    format!(
      "{host}{}{extra}",
      if extra.is_empty() { "" } else { "?" }
    )
  };
  Redirect::to(&redirect_url)
}

/// The length of the suffix [unique_username] appends.
const UNIQUE_USERNAME_SUFFIX_LENGTH: usize = 6;

/// Append a random suffix to the username if it is already taken.
/// The name is shortened to make room for it, so the result
/// is at most [MAX_USERNAME_LENGTH][crate::validations::MAX_USERNAME_LENGTH].
async fn unique_username<I: AuthImpl>(
  auth: &I,
  mut username: String,
) -> mogh_error::Result<String> {
  if auth
    .find_user_with_username(username.clone())
    .await?
    .is_some()
  {
    truncate_chars(
      &mut username,
      crate::validations::MAX_USERNAME_LENGTH
        - UNIQUE_USERNAME_SUFFIX_LENGTH,
    );
    username.push('-');
    username.push_str(&crate::rand::random_string(
      UNIQUE_USERNAME_SUFFIX_LENGTH - 1,
    ));
  }
  Ok(username)
}

/// Keeps the first `max` characters.
fn truncate_chars(text: &mut String, max: usize) {
  if let Some((end, _)) = text.char_indices().nth(max) {
    text.truncate(end);
  }
}

/// Whether an external login of the user has to be completed with a
/// second factor, matching [get_user_id_or_two_factor].
pub(crate) fn external_login_requires_two_factor(
  user: &dyn crate::user::AuthUserImpl,
) -> bool {
  !user.external_skip_2fa()
    && (user.passkey().is_some() || user.totp_secret().is_some())
}

/// The kind of a login through `provider`, for its record.
pub(crate) fn provider_login(
  provider: &ExternalLoginProvider,
) -> LoginKind {
  LoginKind::Provider {
    provider_id: provider.id.clone(),
    provider_name: provider.name.clone(),
  }
}

/// The second factor an external login has to be completed with.
pub(crate) enum ExternalTwoFactor {
  Passkey(RequestChallengeResponse),
  Totp,
}

/// Begins the second factor of an external login on the session if the
/// user requires one ([external_login_requires_two_factor]). It is
/// completed with `CompletePasskeyLogin` / `CompleteTotpLogin`, which
/// record the login as one through `provider`.
pub(crate) async fn begin_external_two_factor<
  I: AuthImpl + ?Sized,
>(
  auth: &I,
  session: &Session,
  user: &dyn crate::user::AuthUserImpl,
  provider: &ExternalLoginProvider,
) -> mogh_error::Result<Option<ExternalTwoFactor>> {
  if !external_login_requires_two_factor(user) {
    return Ok(None);
  }
  match (user.passkey(), user.totp_secret()) {
    // WebAuthn Passkey 2FA
    (Some(passkey), _) => {
      let passkeys = auth.passkey_provider().context(
        "No passkey provider available, possibly invalid 'host' config.",
      )?;
      let (response, state) = passkeys
        .start_passkey_authentication(passkey)
        .context("Failed to start passkey authentication flow")?;
      session.insert_passkey_login(user.id(), &state).await?;
      session.insert_login_kind(&provider_login(provider)).await?;

      info!(
        user_id = user.id(),
        username = user.username(),
        "Passkey 2FA flow initiated"
      );

      Ok(Some(ExternalTwoFactor::Passkey(response)))
    }
    // TOTP 2FA
    (None, Some(_)) => {
      session.insert_totp_login_user_id(user.id()).await?;
      session.insert_login_kind(&provider_login(provider)).await?;

      info!(
        user_id = user.id(),
        username = user.username(),
        "TOTP 2FA flow initiated"
      );

      Ok(Some(ExternalTwoFactor::Totp))
    }
    (None, None) => Ok(None),
  }
}

/// Logs in an existing user found by an external provider,
/// initiating 2FA if required. Enforces the user cidr whitelist.
async fn get_user_id_or_two_factor<I: AuthImpl>(
  auth: &I,
  session: &Session,
  user: &BoxAuthUser,
  ip: IpAddr,
  provider: &ExternalLoginProvider,
) -> mogh_error::Result<UserIdOrTwoFactor> {
  check_user_cidr_whitelist(user.as_ref(), ip)?;

  let res = match begin_external_two_factor(
    auth,
    session,
    user.as_ref(),
    provider,
  )
  .await?
  {
    // Skip / No 2FA
    None => {
      auth
        .record_login(Login::of(
          user.as_ref(),
          ip,
          provider_login(provider),
          None,
        ))
        .await?;
      session.insert_authenticated_user_id(user.id()).await?;

      info!(
        user_id = user.id(),
        username = user.username(),
        "User logged in"
      );

      UserIdOrTwoFactor::UserId(user.id().to_string())
    }
    Some(ExternalTwoFactor::Passkey(response)) => {
      UserIdOrTwoFactor::Passkey(response)
    }
    Some(ExternalTwoFactor::Totp) => UserIdOrTwoFactor::Totp {},
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

  struct TwoFactorUser {
    external_skip_2fa: bool,
    totp: bool,
  }

  impl crate::user::AuthUserImpl for TwoFactorUser {
    fn id(&self) -> &str {
      "id"
    }
    fn username(&self) -> &str {
      "user"
    }
    fn external_skip_2fa(&self) -> bool {
      self.external_skip_2fa
    }
    fn totp_secret(&self) -> Option<&str> {
      self.totp.then_some("secret")
    }
  }

  #[test]
  fn test_external_login_requires_two_factor() {
    for (external_skip_2fa, totp, required) in [
      (true, true, false),
      (true, false, false),
      (false, false, false),
      (false, true, true),
    ] {
      let user = TwoFactorUser {
        external_skip_2fa,
        totp,
      };
      assert_eq!(
        external_login_requires_two_factor(&user),
        required,
        "skip: {external_skip_2fa}, totp: {totp}"
      );
    }
  }

  struct TakenUsernames;

  impl AuthImpl for TakenUsernames {
    fn new() -> Self {
      TakenUsernames
    }
    fn find_user_with_username(
      &self,
      _username: String,
    ) -> crate::DynFuture<mogh_error::Result<Option<BoxAuthUser>>>
    {
      Box::pin(async {
        Ok(Some(Box::new(TwoFactorUser {
          external_skip_2fa: false,
          totp: false,
        }) as BoxAuthUser))
      })
    }
    fn get_user(
      &self,
      _user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<BoxAuthUser>> {
      Box::pin(async { Err(anyhow!("not implemented").into()) })
    }
    fn handle_request_authentication(
      &self,
      _auth: crate::RequestAuthentication,
      _ip: IpAddr,
      _require_user_enabled: bool,
      _req: axum::extract::Request,
    ) -> crate::DynFuture<mogh_error::Result<axum::extract::Request>>
    {
      Box::pin(async { Err(anyhow!("not implemented").into()) })
    }
    fn jwt_provider(&self) -> &crate::provider::jwt::JwtProvider {
      panic!("not needed for these tests")
    }
  }

  /// The suffix fits: a taken name at the length limit stays valid.
  #[tokio::test]
  async fn test_unique_username_stays_within_the_limit() {
    use crate::validations::{
      MAX_USERNAME_LENGTH, validate_username,
    };
    for name in [
      "alice".to_string(),
      "a".repeat(MAX_USERNAME_LENGTH),
      "é".repeat(MAX_USERNAME_LENGTH),
    ] {
      let unique = unique_username(&TakenUsernames, name.clone())
        .await
        .unwrap();
      assert_ne!(unique, name);
      assert!(unique.chars().count() <= MAX_USERNAME_LENGTH);
      assert_eq!(
        unique.chars().count(),
        name
          .chars()
          .count()
          .min(MAX_USERNAME_LENGTH - UNIQUE_USERNAME_SUFFIX_LENGTH)
          + UNIQUE_USERNAME_SUFFIX_LENGTH
      );
      if name.is_ascii() {
        validate_username(&unique).unwrap();
      }
    }
  }

  #[test]
  fn test_parse_variant_request() {
    use mogh_auth_client::api::login::{
      LoginLocalUser, SignUpLocalUser,
    };

    #[derive(Deserialize)]
    #[serde(tag = "type", content = "params")]
    enum TestRequest {
      LoginLocalUser(LoginLocalUser),
      #[allow(unused)]
      SignUpLocalUser(SignUpLocalUser),
    }

    let req: TestRequest = parse_variant_request(
      "LoginLocalUser".into(),
      serde_json::json!({ "username": "user", "password": "pass" }),
    )
    .unwrap();
    assert!(matches!(
      req,
      TestRequest::LoginLocalUser(LoginLocalUser { username, .. })
        if username == "user"
    ));

    // The client sent these, so they aren't server errors.
    for (variant, params) in [
      ("Unknown", serde_json::json!({})),
      ("LoginLocalUser", serde_json::json!({})),
      ("LoginLocalUser", serde_json::json!({ "username": 1 })),
      ("LoginLocalUser", serde_json::json!(null)),
    ] {
      let err = parse_variant_request::<TestRequest>(
        variant.into(),
        params.clone(),
      )
      .err()
      .unwrap();
      assert_eq!(
        err.status,
        StatusCode::BAD_REQUEST,
        "{variant} {params}"
      );
    }
  }

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
  fn test_format_redirect_rejects_other_origins() {
    // Open redirect attempts fall back to the host.
    for evil in [
      "https://evil.com",
      "https://evil.com/?next=https://example.com",
      "https://example.com.evil.com/dest",
      "https://example.com@evil.com",
      "//evil.com/dest",
      "/\\evil.com",
      "\\\\evil.com",
      "javascript:alert(1)",
      "data:text/html,hi",
    ] {
      let redirect = format_redirect(
        "https://example.com",
        Some(evil),
        "redeem_ready=true",
      );
      assert_eq!(
        location(redirect),
        "https://example.com?redeem_ready=true",
        "{evil}"
      );
    }
  }

  #[test]
  fn test_format_redirect_allows_same_host() {
    let cases = [
      ("https://example.com", "https://example.com/?totp=true"),
      (
        "/servers/abc?tab=1",
        "https://example.com/servers/abc?tab=1&totp=true",
      ),
      ("servers/abc", "https://example.com/servers/abc?totp=true"),
      ("?tab=1", "https://example.com/?tab=1&totp=true"),
      // Same host, other scheme / port (eg TLS at the proxy).
      (
        "http://example.com/dest",
        "http://example.com/dest?totp=true",
      ),
      (
        "https://example.com:8443/dest",
        "https://example.com:8443/dest?totp=true",
      ),
      (
        "https://EXAMPLE.com/dest",
        "https://example.com/dest?totp=true",
      ),
      // Same scheme without `//` is a relative path on the host.
      ("https:evil.com", "https://example.com/evil.com?totp=true"),
    ];
    for (redirect, expected) in cases {
      let redirect = format_redirect(
        "https://example.com",
        Some(redirect),
        "totp=true",
      );
      assert_eq!(location(redirect), expected);
    }
    // Trailing slash on host is tolerated.
    let redirect = format_redirect(
      "https://example.com/",
      Some("/dest"),
      "totp=true",
    );
    assert_eq!(
      location(redirect),
      "https://example.com/dest?totp=true"
    );
  }

  /// The query goes before the fragment, where the app reads it.
  #[test]
  fn test_format_redirect_keeps_the_fragment_last() {
    let cases = [
      (
        "https://example.com/dest#frag",
        "https://example.com/dest?totp=true#frag",
      ),
      (
        "/dest?a=1#frag",
        "https://example.com/dest?a=1&totp=true#frag",
      ),
      // A '?' in the fragment is not the query.
      ("/x#a?b=1", "https://example.com/x?totp=true#a?b=1"),
      ("/x?#frag", "https://example.com/x?totp=true#frag"),
    ];
    for (redirect, expected) in cases {
      let redirect = format_redirect(
        "https://example.com",
        Some(redirect),
        "totp=true",
      );
      assert_eq!(location(redirect), expected);
    }
    let redirect = format_redirect(
      "https://example.com",
      Some("/stacks/abc#logs"),
      "passkey=eyJhIjoiYiJ9",
    );
    let url = reqwest::Url::parse(&location(redirect)).unwrap();
    assert_eq!(url.query(), Some("passkey=eyJhIjoiYiJ9"));
    assert_eq!(url.fragment(), Some("logs"));
  }

  #[test]
  fn test_login_redirect_is_sanitized_and_bounded() {
    let host = "https://example.com";
    assert_eq!(
      login_redirect(host, Some("/notes?tab=1".into())).as_deref(),
      Some("https://example.com/notes?tab=1")
    );
    for dropped in [
      None,
      Some(String::new()),
      Some("https://evil.example/steal".into()),
      Some("//evil.example".into()),
      Some(format!("/{}", "a".repeat(MAX_REDIRECT_LENGTH))),
      Some(format!("/{}", "a".repeat(60 * 1024))),
      // Short, but longer once resolved and encoded.
      Some(format!("/{}", "\"".repeat(MAX_REDIRECT_LENGTH / 2))),
    ] {
      assert_eq!(login_redirect(host, dropped.clone()), None);
    }
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
