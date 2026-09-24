#[allow(unused)]
#[utoipa::path(
  get,
  path = "/github/login",
  security(()),
  description = "Login using Github",
  params(
    ("redirect" = Option<String>, Query, description = "Optional path to redirect back to after login.")
  ),
  responses(
    (status = 303, description = "Redirect to Github for login"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn github_login() {}

#[allow(unused)]
#[utoipa::path(
  get,
  path = "/github/link",
  security(()),
  description = "Link existing account to Github user",
  responses(
    (status = 303, description = "Redirect to Github for link"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn github_link() {}

#[allow(unused)]
#[utoipa::path(
  get,
  path = "/github/callback",
  security(()),
  description = "Callback to finish Github login",
  params(
    ("state" = Option<String>, Query, description = "Callback state."),
    ("code" = Option<String>, Query, description = "Callback code."),
    ("error" = Option<String>, Query, description = "Callback error.")
  ),
  responses(
    (status = 303, description = "Redirect back to app to continue login steps."),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn github_callback() {}
