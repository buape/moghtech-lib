use std::sync::LazyLock;

use axum::http::HeaderValue;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

pub trait CorsConfig {
  /// Origins allowed to make cross origin requests,
  /// in addition to the app's own origin.
  ///
  /// `*` allows any origin. ⚠️ Combined with
  /// [allow_credentials][Self::allow_credentials] (the default),
  /// any site can then make requests carrying the user's cookies
  /// (eg the login session) and read the responses. List the
  /// exact origins instead, or disable credentials.
  ///
  /// Default: none.
  fn allowed_origins(&self) -> &[String] {
    &[]
  }
  /// Whether cross origin requests may carry credentials
  /// (cookies), eg the UI's login session requests.
  ///
  /// Default: `true`
  fn allow_credentials(&self) -> bool {
    true
  }
}

static ANY_ORIGIN: LazyLock<String> =
  LazyLock::new(|| String::from("*"));

/// Creates a CORS layer based on the Core configuration.
///
/// - If the allowed origins contains '*', uses 'Any' allowed origin.
///   With credentials allowed, `*` isn't valid, so the request
///   origin is mirrored instead: ⚠️ any site can make credentialed
///   requests and read the responses, see
///   [CorsConfig::allowed_origins].
/// - Methods and headers are always allowed (Mirrored)
/// - Credentials are only allowed if `cors_allow_credentials` is true
pub fn cors_layer(config: impl CorsConfig) -> CorsLayer {
  let allowed_origins = config.allowed_origins();
  let allow_credentials = config.allow_credentials();
  let mut cors = CorsLayer::new()
    .allow_methods(tower_http::cors::AllowMethods::mirror_request())
    .allow_headers(tower_http::cors::AllowHeaders::mirror_request())
    .allow_credentials(allow_credentials);
  if allowed_origins.is_empty() {
    info!("CORS using no additional allowed origins.");
  } else if allowed_origins.contains(&ANY_ORIGIN) {
    if allow_credentials {
      // tower-http panics at request time if the wildcard
      // allowed origin is combined with credentials.
      // Mirroring the request origin allows any origin
      // while staying spec-valid alongside credentials.
      warn!(
        "CORS using allowed origin 'Any' (*) with credentials: mirroring the request origin, any site can make credentialed requests and read the responses. List the allowed origins instead, or disable credentials.",
      );
      cors = cors
        .allow_origin(tower_http::cors::AllowOrigin::mirror_request())
    } else {
      warn!("CORS using allowed origin 'Any' (*).",);
      cors = cors.allow_origin(tower_http::cors::Any)
    }
  } else {
    let allowed_origins = allowed_origins
      .iter()
      .filter_map(|origin| {
        HeaderValue::from_str(origin)
          .inspect_err(|e| {
            warn!("Invalid CORS allowed origin: {origin} | {e:?}")
          })
          .ok()
      })
      .collect::<Vec<_>>();
    info!("CORS using allowed origin/s: {allowed_origins:?}");
    cors = cors.allow_origin(allowed_origins);
  };
  if allow_credentials {
    info!("CORS allowing credentials");
  }
  cors
}
