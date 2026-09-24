#[allow(unused)]
#[utoipa::path(
  get,
  path = "/external/{slug}/login",
  security(()),
  description = "Login using an external login provider. Providers using the reserved id of their kind are also available at `/oidc/login`, `/github/login` and `/google/login`.",
  params(
    ("slug" = String, Path, description = "The slug of the external login provider (`slug` in the providers of GetLoginOptions), not its id."),
    ("redirect" = Option<String>, Query, description = "Optional path to redirect back to after login.")
  ),
  responses(
    (status = 303, description = "Redirect to the provider for login"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 404, description = "No provider with the given slug", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn external_login() {}

#[allow(unused)]
#[utoipa::path(
  get,
  path = "/external/{slug}/link",
  security(()),
  description = "Link the existing account to a user of an external login provider. BeginExternalLoginLink must be called first.",
  params(
    ("slug" = String, Path, description = "The slug of the external login provider (`slug` in the providers of GetLoginOptions), not its id."),
  ),
  responses(
    (status = 303, description = "Redirect to the provider for link"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 404, description = "No provider with the given slug", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn external_link() {}

#[allow(unused)]
#[utoipa::path(
  get,
  path = "/external/{slug}/callback",
  security(()),
  description = "Callback to finish external login. This is the redirect URI to register at the provider, see ListExternalLoginProviders.",
  params(
    ("slug" = String, Path, description = "The slug of the external login provider, see ListExternalLoginProviders."),
    ("state" = Option<String>, Query, description = "Callback state."),
    ("code" = Option<String>, Query, description = "Callback code."),
    ("error" = Option<String>, Query, description = "Callback error.")
  ),
  responses(
    (status = 303, description = "Redirect back to app to continue login steps."),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 404, description = "No provider with the given slug", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn external_callback() {}
