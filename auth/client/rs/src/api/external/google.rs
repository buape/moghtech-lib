#[allow(unused)]
#[utoipa::path(
  get,
  path = "/google/login",
  security(()),
  description = "Login using Google",
  params(
    ("redirect" = Option<String>, Query, description = "Optional path to redirect back to after login.")
  ),
  responses(
    (status = 303, description = "Redirect to Google for login"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn google_login() {}

#[allow(unused)]
#[utoipa::path(
  get,
  path = "/google/link",
  security(()),
  description = "Link existing account to Google user",
  responses(
    (status = 303, description = "Redirect to Google for link"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn google_link() {}

#[allow(unused)]
#[utoipa::path(
  get,
  path = "/google/callback",
  security(()),
  description = "Callback to finish Google login",
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
fn google_callback() {}
