//! TOTP second factor: enrollment, login, replay protection and
//! recovery codes. Passkeys need an authenticator, and are covered by
//! the UI tests using the virtual authenticator of the browser.

use example_client::{
  ClientAuth, ExampleClient,
  auth::api::{
    login::{
      CompleteTotpLogin, CompleteTotpRecoveryLogin, JwtOrTwoFactor,
      LoginLocalUser,
    },
    manage::{
      BeginTotpEnrollment, ConfirmTotpEnrollment, UnenrollTotp,
    },
  },
};
use reqwest::StatusCode;
use serde_json::json;

use crate::common::*;

struct Enrolled {
  totp: totp_rs::Totp,
  recovery_codes: Vec<String>,
}

async fn enroll(client: &ExampleClient) -> Enrolled {
  let enrollment =
    client.manage(BeginTotpEnrollment {}).await.unwrap();
  assert!(enrollment.uri.starts_with("otpauth://totp/"));
  assert!(!enrollment.png.is_empty());
  let totp = totp_from_uri(&enrollment.uri);
  let recovery_codes = client
    .manage(ConfirmTotpEnrollment {
      code: totp.generate_current().to_string(),
    })
    .await
    .unwrap()
    .recovery_codes;
  Enrolled {
    totp,
    recovery_codes,
  }
}

/// Logs in with the password, which has to ask for the code.
async fn begin_login(app: &TestApp, username: &str) -> ExampleClient {
  let client = app.client();
  let res = client
    .login(LoginLocalUser {
      username: username.into(),
      password: PASSWORD.into(),
    })
    .await
    .unwrap();
  assert!(matches!(res, JwtOrTwoFactor::Totp {}), "{res:?}");
  client
}

/// A valid code which wasn't used yet: the one of the next step,
/// which the server accepts because of its skew of one step.
fn next_code(totp: &totp_rs::Totp) -> String {
  totp.generate(unix_timestamp_ms() / 1000 + 30).to_string()
}

#[tokio::test]
async fn enroll_and_log_in_with_totp() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  assert!(!get_user(&admin).await.totp_enrolled);

  let enrolled = enroll(&admin).await;
  assert_eq!(enrolled.recovery_codes.len(), 10);
  assert!(get_user(&admin).await.totp_enrolled);

  // The secret is encrypted in the database.
  let db = std::fs::read(app.path("data/example.db")).unwrap();
  let wal = std::fs::read(app.path("data/example.db-wal"))
    .unwrap_or_default();
  let secret = data_encoding_base32(enrolled.totp.secret());
  for file in [&db, &wal] {
    assert!(
      !contains(file, secret.as_bytes()),
      "The TOTP secret is stored in plain text"
    );
  }

  // The password alone doesn't give a token anymore.
  let client = begin_login(&app, "admin").await;
  // The code used for enrollment can't be replayed as a login,
  // the next one works.
  let replayed = client
    .login(CompleteTotpLogin {
      code: enrolled.totp.generate_current().to_string(),
    })
    .await;
  assert_eq!(status_of(replayed), StatusCode::UNAUTHORIZED);

  let jwt = client
    .login(CompleteTotpLogin {
      code: next_code(&enrolled.totp),
    })
    .await
    .unwrap()
    .jwt;
  let user = get_user(&client.with_auth(ClientAuth::Jwt(jwt))).await;
  assert_eq!(user.username, "admin");
}

#[tokio::test]
async fn mistyped_code_can_be_retried_a_few_times() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let enrolled = enroll(&admin).await;

  let client = begin_login(&app, "admin").await;
  for _ in 0..3 {
    let res = client
      .login(CompleteTotpLogin {
        code: "000000".into(),
      })
      .await;
    assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  }
  // Still the same login, no need to enter the password again.
  client
    .login(CompleteTotpLogin {
      code: next_code(&enrolled.totp),
    })
    .await
    .unwrap();

  // An accepted code ends the login.
  let res = client
    .login(CompleteTotpLogin {
      code: next_code(&enrolled.totp),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);

  // Too many wrong codes end it as well.
  let client = begin_login(&app, "admin").await;
  for _ in 0..5 {
    let res = client
      .login(CompleteTotpLogin {
        code: "000000".into(),
      })
      .await;
    assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  }
  let e = client
    .login(CompleteTotpRecoveryLogin {
      code: enrolled.recovery_codes[0].clone(),
    })
    .await
    .unwrap_err();
  assert!(format!("{e:#}").contains("Too many"), "{e:#}");
}

#[tokio::test]
async fn second_factor_needs_the_first_factor_on_the_same_session() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let enrolled = enroll(&admin).await;

  begin_login(&app, "admin").await;
  // Another session (cookie jar) never entered the password.
  let other_session = app.client();
  let res = other_session
    .login(CompleteTotpLogin {
      code: next_code(&enrolled.totp),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  let res = other_session
    .login(CompleteTotpRecoveryLogin {
      code: enrolled.recovery_codes[0].clone(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_code_is_only_accepted_once_even_after_a_restart() {
  let mut app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let enrolled = enroll(&admin).await;
  let code = next_code(&enrolled.totp);

  let client = begin_login(&app, "admin").await;
  client
    .login(CompleteTotpLogin { code: code.clone() })
    .await
    .unwrap();

  // Somebody who watched the code being entered can't use it,
  // also not right after a restart (the used steps are stored).
  app.restart().await;
  let client = begin_login(&app, "admin").await;
  let e = client.login(CompleteTotpLogin { code }).await.unwrap_err();
  assert!(format!("{e:#}").contains("already used"), "{e:#}");
}

#[tokio::test]
async fn recovery_codes_work_once() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let enrolled = enroll(&admin).await;
  let code = enrolled.recovery_codes[3].clone();

  let client = begin_login(&app, "admin").await;
  let res = client
    .login(CompleteTotpRecoveryLogin {
      code: "not-a-recovery-code".into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  client
    .login(CompleteTotpRecoveryLogin { code: code.clone() })
    .await
    .unwrap();

  let client = begin_login(&app, "admin").await;
  let res = client.login(CompleteTotpRecoveryLogin { code }).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  // The others still work.
  client
    .login(CompleteTotpRecoveryLogin {
      code: enrolled.recovery_codes[4].clone(),
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn enrollment_needs_a_valid_code_and_unenroll_removes_2fa() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  // Confirm without begin
  let res = admin
    .manage(ConfirmTotpEnrollment {
      code: "123456".into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);

  admin.manage(BeginTotpEnrollment {}).await.unwrap();
  let res = admin
    .manage(ConfirmTotpEnrollment {
      code: "000000".into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::BAD_REQUEST);
  assert!(!get_user(&admin).await.totp_enrolled);

  enroll(&admin).await;
  admin.manage(UnenrollTotp {}).await.unwrap();
  assert!(!get_user(&admin).await.totp_enrolled);
  // Back to password only.
  app.log_in("admin").await;
}

#[tokio::test]
async fn locked_usernames_cannot_enroll() {
  let app = TestApp::spawn_with(TestAppOptions {
    config: json!({ "lock_login_credentials_for": ["__ALL__"] }),
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;
  let res = admin.manage(BeginTotpEnrollment {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
  haystack
    .windows(needle.len())
    .any(|window| window == needle)
}

/// RFC 4648 base32 without padding.
fn data_encoding_base32(bytes: &[u8]) -> String {
  const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let mut out = String::new();
  let mut bits = 0u32;
  let mut bit_count = 0;
  for byte in bytes {
    bits = (bits << 8) | *byte as u32;
    bit_count += 8;
    while bit_count >= 5 {
      bit_count -= 5;
      out.push(ALPHABET[((bits >> bit_count) & 31) as usize] as char);
    }
    bits &= (1 << bit_count) - 1;
  }
  if bit_count > 0 {
    out.push(
      ALPHABET[((bits << (5 - bit_count)) & 31) as usize] as char,
    );
  }
  out
}
