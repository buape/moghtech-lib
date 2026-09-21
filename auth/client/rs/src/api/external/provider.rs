#[allow(unused)]
#[utoipa::path(
  get,
  path = "/external/{provider_id}/login",
  description = "Login using an external login provider. Providers using the reserved id of their kind are also available at `/oidc/login`, `/github/login` and `/google/login`.",
  params(
    ("provider_id", description = "The id of the external login provider, see GetLoginOptions."),
    ("redirect", description = "Optional path to redirect back to after login.")
  ),
  responses(
    (status = 303, description = "Redirect to the provider for login"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 404, description = "No provider with the given id", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn external_login() {}

#[allow(unused)]
#[utoipa::path(
  get,
  path = "/external/{provider_id}/link",
  description = "Link the existing account to a user of an external login provider. BeginExternalLoginLink must be called first.",
  params(
    ("provider_id", description = "The id of the external login provider, see GetLoginOptions."),
  ),
  responses(
    (status = 303, description = "Redirect to the provider for link"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 404, description = "No provider with the given id", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn external_link() {}

#[allow(unused)]
#[utoipa::path(
  get,
  path = "/external/{provider_id}/callback",
  description = "Callback to finish external login. This is the redirect URI to register at the provider, see ListExternalLoginProviders.",
  params(
    ("provider_id", description = "The id of the external login provider."),
    ("state", description = "Callback state."),
    ("code", description = "Callback code."),
    ("error", description = "Callback error.")
  ),
  responses(
    (status = 303, description = "Redirect back to app to continue login steps."),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 404, description = "No provider with the given id", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn external_callback() {}
