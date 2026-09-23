use std::{
  fmt,
  net::IpAddr,
  sync::Arc,
  time::{Duration, Instant},
};

use anyhow::anyhow;
use axum::http::{HeaderMap, StatusCode};
use mogh_cache::CloneCache;
use mogh_error::AddStatusCodeError;
use tokio::sync::RwLock;

pub use mogh_request_ip::{TrustedProxies, get_client_ip};

/// The context the error of a failed attempt is returned with,
/// noting how many attempts are left.
///
/// The attempt's own error stays underneath it, so its types are
/// still found with `error.downcast_ref::<T>()`. The error displays
/// as the attempt's error (with its causes) followed by the note:
/// `Invalid login credentials | You have 2 attempts remaining`.
/// Rendering the whole chain (`{:#}`, or the `trace` of a
/// serialized error) lists the attempt's error again below it.
#[derive(Debug)]
pub struct FailedAttempt {
  /// The attempt's error with its causes, as `{:#}` renders it.
  error: String,
  remaining_attempts: usize,
}

impl FailedAttempt {
  /// How many more attempts from the ip may fail within the
  /// window before it is refused with `429 Too Many Requests`.
  pub fn remaining_attempts(&self) -> usize {
    self.remaining_attempts
  }

  /// `message` followed by the note, the way the
  /// attempt's error is displayed:
  /// `{message} | You have N attempts remaining`.
  pub fn annotate(&self, message: impl fmt::Display) -> String {
    format!(
      "{message} | You have {} attempts remaining",
      self.remaining_attempts
    )
  }
}

impl fmt::Display for FailedAttempt {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(&self.annotate(&self.error))
  }
}

/// Trait to extend fallible futures with stateful
/// rate limiting.
pub trait WithFailureRateLimit<R>
where
  Self: Future<Output = mogh_error::Result<R>> + Sized,
{
  /// Ensure the given IP 'ip' is
  /// not violating the given 'limiter' rate limit rules
  /// before executing this fallible future.
  ///
  /// If the rules are violated, will return `429 Too Many Requests`.
  ///
  /// If the rate limiting rules are not violated, the
  /// future will be executed, and if it fails then the
  /// attempt time will be recorded for rate limit,
  /// and original error returned with a [FailedAttempt]
  /// context noting the attempts remaining. The original
  /// error's status, headers and types are kept.
  ///
  /// The end result rate limits failing requests,
  /// while succeeding requests are not rate limited.
  fn with_failure_rate_limit_using_ip(
    self,
    limiter: &RateLimiter,
    ip: &IpAddr,
  ) -> impl Future<Output = mogh_error::Result<R>> {
    async {
      if limiter.disabled {
        return self.await;
      }

      // Only locks if entry at key does not exist yet.
      let attempts = limiter.attempts.get_or_insert_default(ip).await;

      // RwLock allows multiple readers, minimizing locking effect.
      let read = attempts.read().await;

      let now = Instant::now();
      // `now.duration_since(time)` saturates to zero (rather than
      // panicking) if `time` is somehow later than `now`, and avoids
      // the panic `now - window` can hit early in process lifetime
      // when the platform's Instant cannot represent times before
      // process start.
      let in_window =
        |time: Instant| now.duration_since(time) < limiter.window;

      let (first, count) =
        read.iter().filter(|&&time| in_window(time)).fold(
          (Option::<Instant>::None, 0),
          |(first, count), &time| {
            (Some(first.unwrap_or(time)), count + 1)
          },
        );

      // Drop the read lock immediately
      drop(read);

      // Don't allow future to be executed if rate limiter violated
      if count >= limiter.max_attempts {
        // Use this opportunity to take write lock and clear the attempts cache
        attempts.write().await.retain(|&time| in_window(time));
        return Err(
          anyhow!(
            "Too many attempts | Try again in {:.0?}",
            limiter.window.saturating_sub(
              first
                .map(|first| now.duration_since(first))
                .unwrap_or_default()
            ),
          )
          .status_code(StatusCode::TOO_MANY_REQUESTS),
        );
      }

      match self.await {
        // The succeeding branch has no write locks
        // after the initial attempt array initializes.
        Ok(res) => Ok(res),
        Err(mut e) => {
          // Record the failure at completion time, so slow-failing
          // futures don't get a head start on window expiry.
          let now = Instant::now();
          // Failing branch takes exclusive write lock.
          let mut write = attempts.write().await;
          // Use this opportunity to clear the attempts cache
          write.retain(|&time| {
            now.duration_since(time) < limiter.window
          });
          // Always push after failed attempts, eg failed api key check.
          write.push(now);
          // Add 1 to count because it doesn't include this attempt.
          let remaining_attempts = limiter.max_attempts - (count + 1);
          // Return original error with remaining attempts shown.
          // As context, not a new error with its message, so
          // callers can still downcast to the original error.
          let attempt = FailedAttempt {
            error: format!("{:#}", e.error),
            remaining_attempts,
          };
          e.error = e.error.context(attempt);
          Err(e)
        }
      }
    }
  }

  /// [Self::with_failure_rate_limit_using_ip], with the ip
  /// determined from the request headers and socket `peer`
  /// using [get_client_ip], so forwarding headers are only
  /// believed from `trusted_proxies`.
  fn with_failure_rate_limit_using_headers(
    self,
    limiter: &RateLimiter,
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    trusted_proxies: &TrustedProxies,
  ) -> impl Future<Output = mogh_error::Result<R>> {
    async move {
      // Can skip header ip extraction if disabled
      if limiter.disabled {
        return self.await;
      }
      let ip = get_client_ip(headers, peer, trusted_proxies)?;
      self.with_failure_rate_limit_using_ip(limiter, &ip).await
    }
  }
}

impl<F, R> WithFailureRateLimit<R> for F where
  F: Future<Output = mogh_error::Result<R>> + Sized
{
}

type RateLimiterMapEntry = Arc<RwLock<Vec<Instant>>>;

pub struct RateLimiter {
  attempts: CloneCache<IpAddr, RateLimiterMapEntry>,
  disabled: bool,
  max_attempts: usize,
  window: Duration,
}

impl RateLimiter {
  /// Create a new rate limiter. Also spawns tokio task
  /// to cleanup stale keys (ones which haven't been accessed in 15+ minutes).
  ///
  /// # Arguments
  ///
  /// * `disabled` - Whether rate limiter is disabled
  /// * `max_attempts` - Maximum number of attempts allowed in given window
  /// * `window` - Time window duration
  pub fn new(
    disabled: bool,
    max_attempts: usize,
    window: Duration,
  ) -> Arc<Self> {
    let limiter = Arc::new(Self {
      attempts: CloneCache::default(),
      disabled,
      max_attempts,
      window,
    });
    if !disabled {
      spawn_cleanup_task(limiter.clone());
    }
    limiter
  }
}

/// Task to run every minute and clear off
/// the best guess of stale entries (ones with no attempts
/// in the last 15 minutes). Note that
/// repeatedly succeeding calls from IP will end up with
/// "empty" attempts array, and will be cleared off when this runs.
/// The impact on performance should be negligible until very large scale.
fn spawn_cleanup_task(limiter: Arc<RateLimiter>) {
  const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
  tokio::spawn(async move {
    // The first tick of a plain `interval` completes
    // immediately, there is nothing to clean up yet.
    let mut interval = tokio::time::interval_at(
      tokio::time::Instant::now() + CLEANUP_INTERVAL,
      CLEANUP_INTERVAL,
    );
    loop {
      interval.tick().await;
      limiter.cleanup().await;
    }
  });
}

impl RateLimiter {
  /// Removes the best guess of stale entries, see [spawn_cleanup_task].
  async fn cleanup(&self) {
    const STALE_AFTER: Duration = Duration::from_secs(15 * 60);
    self
      .attempts
      .retain(|_, attempts| {
        // An in flight request holds its own reference to the
        // attempts while its future runs, and records a failure on
        // it afterwards. Removing the entry now would lose that
        // failure (it would be pushed to attempts no longer on the
        // map), giving the ip a free attempt. New requests can't
        // take a reference meanwhile, this holds the map lock.
        if Arc::strong_count(attempts) > 1 {
          return true;
        }
        let Ok(attempts) = attempts.try_read() else {
          // Retain any locked attempts, they are being actively used and not stale.
          return true;
        };
        let Some(last) = attempts.last() else {
          // Remove any empty attempts arrays
          return false;
        };
        // `elapsed` saturates to zero rather than panicking.
        last.elapsed() < STALE_AFTER
      })
      .await;
  }
}

#[cfg(test)]
mod tests {
  use std::sync::atomic::{AtomicUsize, Ordering};

  use axum::http::HeaderValue;

  use super::*;

  const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4));

  async fn failing(
    executions: &AtomicUsize,
  ) -> mogh_error::Result<()> {
    executions.fetch_add(1, Ordering::SeqCst);
    Err(anyhow!("bad credentials").into())
  }

  #[tokio::test]
  async fn blocks_after_max_failed_attempts() {
    let limiter = RateLimiter::new(false, 3, Duration::from_secs(60));
    let executions = AtomicUsize::new(0);
    for i in 0..3 {
      let err = failing(&executions)
        .with_failure_rate_limit_using_ip(&limiter, &IP)
        .await
        .unwrap_err();
      assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
      let msg = format!("{:#}", err.error);
      assert!(
        msg.contains(&format!(
          "You have {} attempts remaining",
          2 - i
        )),
        "unexpected message: {msg}"
      );
    }
    // 4th attempt is refused without executing the future.
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(format!("{:#}", err.error).contains("Too many attempts"));
    assert_eq!(executions.load(Ordering::SeqCst), 3);
  }

  #[derive(Debug)]
  struct BadCredentials;

  impl fmt::Display for BadCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str("bad credentials")
    }
  }

  impl std::error::Error for BadCredentials {}

  #[tokio::test]
  async fn failed_attempts_keep_the_original_error() {
    let limiter = RateLimiter::new(false, 3, Duration::from_secs(60));
    let failing_typed = || async {
      Err::<(), _>(
        anyhow::Error::new(BadCredentials)
          .context("Login failed")
          .status_code(StatusCode::UNAUTHORIZED)
          .header("x-test", HeaderValue::from_static("kept")),
      )
    };
    let err = failing_typed()
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();

    // Status and headers of the original error are kept.
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert_eq!(err.headers.as_ref().unwrap()["x-test"], "kept");
    // The error's types are still found.
    assert!(err.error.downcast_ref::<BadCredentials>().is_some());
    let attempt = err.error.downcast_ref::<FailedAttempt>().unwrap();
    assert_eq!(attempt.remaining_attempts(), 2);
    // Displayed as the original error with its causes, then the note.
    assert_eq!(
      err.error.to_string(),
      "Login failed: bad credentials | You have 2 attempts remaining"
    );
    // With the original error below it in the chain.
    assert_eq!(
      err
        .error
        .chain()
        .skip(1)
        .map(|e| e.to_string())
        .collect::<Vec<_>>(),
      ["Login failed", "bad credentials"]
    );
    assert_eq!(
      attempt.annotate("Denied"),
      "Denied | You have 2 attempts remaining"
    );

    let err = failing_typed()
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert!(err.error.downcast_ref::<BadCredentials>().is_some());
    assert_eq!(
      err
        .error
        .downcast_ref::<FailedAttempt>()
        .unwrap()
        .remaining_attempts(),
      1
    );
  }

  /// Fails after giving other tasks (the cleanup) time to run.
  async fn failing_slowly() -> mogh_error::Result<()> {
    tokio::time::sleep(Duration::from_millis(50)).await;
    Err(anyhow!("bad credentials").into())
  }

  fn remaining(err: &mogh_error::Error) -> String {
    let msg = err.error.to_string();
    msg
      .split("You have ")
      .nth(1)
      .unwrap_or_else(|| panic!("unexpected message: {msg}"))
      .to_string()
  }

  #[tokio::test]
  async fn first_failure_after_creation_is_counted() {
    // Limiters are usually created lazily by the first request using
    // them. The cleanup task must not drop the (still empty) entry
    // of that request while it is in flight.
    let limiter = RateLimiter::new(false, 3, Duration::from_secs(60));
    let err = failing_slowly()
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(remaining(&err), "2 attempts remaining");
    let err = failing_slowly()
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(remaining(&err), "1 attempts remaining");
  }

  #[tokio::test]
  async fn cleanup_keeps_entries_of_in_flight_requests() {
    let limiter = RateLimiter::new(false, 3, Duration::from_secs(60));
    let in_flight = tokio::spawn({
      let limiter = limiter.clone();
      async move {
        failing_slowly()
          .with_failure_rate_limit_using_ip(&limiter, &IP)
          .await
          .unwrap_err()
      }
    });
    // Runs while the request is in flight, with empty attempts.
    tokio::time::sleep(Duration::from_millis(10)).await;
    limiter.cleanup().await;
    let err = in_flight.await.unwrap();
    assert_eq!(remaining(&err), "2 attempts remaining");

    // The failure was recorded on the entry which is still on the map.
    let executions = AtomicUsize::new(0);
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(remaining(&err), "1 attempts remaining");
  }

  #[tokio::test]
  async fn cleanup_removes_entries_without_attempts() {
    let limiter = RateLimiter::new(false, 3, Duration::from_secs(60));
    let res: mogh_error::Result<()> = async { Ok(()) }
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await;
    res.unwrap();
    assert_eq!(limiter.attempts.get_keys().await.len(), 1);
    limiter.cleanup().await;
    assert!(limiter.attempts.get_keys().await.is_empty());
  }

  #[tokio::test]
  async fn successes_are_not_rate_limited() {
    let limiter = RateLimiter::new(false, 2, Duration::from_secs(60));
    for _ in 0..10 {
      let res: mogh_error::Result<u64> = async { Ok(7) }
        .with_failure_rate_limit_using_ip(&limiter, &IP)
        .await;
      assert_eq!(res.unwrap(), 7);
    }
    // Failure budget still fully available after successes.
    let executions = AtomicUsize::new(0);
    for _ in 0..2 {
      failing(&executions)
        .with_failure_rate_limit_using_ip(&limiter, &IP)
        .await
        .unwrap_err();
    }
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(executions.load(Ordering::SeqCst), 2);
  }

  #[tokio::test]
  async fn disabled_limiter_never_blocks() {
    let limiter = RateLimiter::new(true, 1, Duration::from_secs(60));
    let executions = AtomicUsize::new(0);
    for _ in 0..5 {
      let err = failing(&executions)
        .with_failure_rate_limit_using_ip(&limiter, &IP)
        .await
        .unwrap_err();
      assert_ne!(err.status, StatusCode::TOO_MANY_REQUESTS);
    }
    assert_eq!(executions.load(Ordering::SeqCst), 5);
  }

  #[tokio::test]
  async fn window_expiry_allows_new_attempts() {
    let limiter =
      RateLimiter::new(false, 1, Duration::from_millis(200));
    let executions = AtomicUsize::new(0);
    failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    // Immediately blocked
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(executions.load(Ordering::SeqCst), 1);
    // After the window passes, attempts are allowed again.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_ne!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(executions.load(Ordering::SeqCst), 2);
  }

  #[tokio::test]
  async fn limits_are_tracked_per_ip() {
    let limiter = RateLimiter::new(false, 1, Duration::from_secs(60));
    let other = IpAddr::V4(std::net::Ipv4Addr::new(5, 6, 7, 8));
    let executions = AtomicUsize::new(0);
    failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    // Different IP still has its own budget.
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &other)
      .await
      .unwrap_err();
    assert_ne!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(executions.load(Ordering::SeqCst), 2);
  }

  #[tokio::test]
  async fn zero_max_attempts_blocks_everything() {
    let limiter = RateLimiter::new(false, 0, Duration::from_secs(60));
    let executions = AtomicUsize::new(0);
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(executions.load(Ordering::SeqCst), 0);
  }

  #[tokio::test]
  async fn rate_limit_using_headers() {
    let limiter = RateLimiter::new(false, 1, Duration::from_secs(60));
    let mut headers = HeaderMap::new();
    headers.insert(
      "x-forwarded-for",
      HeaderValue::from_static("1.2.3.4, 10.0.0.1"),
    );
    let proxy: IpAddr = "10.0.0.1".parse().unwrap();
    let trusted = TrustedProxies::parse(["10.0.0.0/8"]).unwrap();
    let executions = AtomicUsize::new(0);
    failing(&executions)
      .with_failure_rate_limit_using_headers(
        &limiter,
        &headers,
        Some(proxy),
        &trusted,
      )
      .await
      .unwrap_err();
    let err = failing(&executions)
      .with_failure_rate_limit_using_headers(
        &limiter,
        &headers,
        Some(proxy),
        &trusted,
      )
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(executions.load(Ordering::SeqCst), 1);
    // The limit was recorded against the forwarded client ip.
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
  }

  #[tokio::test]
  async fn rate_limit_using_headers_ignores_untrusted_peer() {
    let limiter = RateLimiter::new(false, 1, Duration::from_secs(60));
    let mut headers = HeaderMap::new();
    headers
      .insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
    let peer: IpAddr = "203.0.113.7".parse().unwrap();
    let executions = AtomicUsize::new(0);
    failing(&executions)
      .with_failure_rate_limit_using_headers(
        &limiter,
        &headers,
        Some(peer),
        &TrustedProxies::None,
      )
      .await
      .unwrap_err();
    // Recorded against the peer, not the spoofed header.
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &peer)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_ne!(err.status, StatusCode::TOO_MANY_REQUESTS);
  }
}
