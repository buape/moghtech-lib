use std::{
  net::IpAddr,
  sync::Arc,
  time::{Duration, Instant},
};

use anyhow::anyhow;
use axum::http::{HeaderMap, StatusCode};
use mogh_cache::CloneCache;
use mogh_error::{AddStatusCode, AddStatusCodeError};
use tokio::sync::RwLock;

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
  /// and original error returned.
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
          // Return original error with remaining attempts shown
          e.error = anyhow!(
            "{:#} | You have {remaining_attempts} attempts remaining",
            e.error,
          );
          Err(e)
        }
      }
    }
  }

  fn with_failure_rate_limit_using_headers(
    self,
    limiter: &RateLimiter,
    headers: &HeaderMap,
    fallback: Option<IpAddr>,
  ) -> impl Future<Output = mogh_error::Result<R>> {
    async move {
      // Can skip header ip extraction if disabled
      if limiter.disabled {
        return self.await;
      }
      let ip = get_ip_from_headers(headers, fallback)?;
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
  const STALE_AFTER: Duration = Duration::from_secs(15 * 60);
  tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
      interval.tick().await;
      limiter
        .attempts
        .retain(|_, attempts| {
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
  });
}

pub fn get_ip_from_headers(
  headers: &HeaderMap,
  fallback: Option<IpAddr>,
) -> mogh_error::Result<IpAddr> {
  // Check X-Forwarded-For header (first IP in chain)
  if let Some(forwarded) = headers.get("x-forwarded-for")
    && let Ok(forwarded_str) = forwarded.to_str()
    && let Some(ip) = forwarded_str.split(',').next()
    && !ip.trim().is_empty()
  {
    return ip.trim().parse().status_code(StatusCode::UNAUTHORIZED);
  }

  // Check X-Real-IP header
  if let Some(real_ip) = headers.get("x-real-ip")
    && let Ok(ip) = real_ip.to_str()
    && !ip.trim().is_empty()
  {
    return ip.trim().parse().status_code(StatusCode::UNAUTHORIZED);
  }

  if let Some(fallback) = fallback {
    return Ok(fallback);
  }

  Err(
    anyhow!("'x-forwarded-for' and 'x-real-ip' headers are both missing, and no fallback ip could be extracted from the request.")
      .status_code(StatusCode::UNAUTHORIZED),
  )
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
    let executions = AtomicUsize::new(0);
    failing(&executions)
      .with_failure_rate_limit_using_headers(&limiter, &headers, None)
      .await
      .unwrap_err();
    let err = failing(&executions)
      .with_failure_rate_limit_using_headers(&limiter, &headers, None)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(executions.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn get_ip_prefers_first_forwarded_for() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "x-forwarded-for",
      HeaderValue::from_static(" 1.2.3.4 , 10.0.0.1"),
    );
    headers.insert("x-real-ip", HeaderValue::from_static("9.9.9.9"));
    assert_eq!(get_ip_from_headers(&headers, None).unwrap(), IP);
  }

  #[test]
  fn get_ip_falls_back_to_real_ip_then_fallback() {
    let mut headers = HeaderMap::new();
    headers
      .insert("x-real-ip", HeaderValue::from_static(" 9.9.9.9 "));
    assert_eq!(
      get_ip_from_headers(&headers, None).unwrap(),
      "9.9.9.9".parse::<IpAddr>().unwrap()
    );

    let headers = HeaderMap::new();
    assert_eq!(get_ip_from_headers(&headers, Some(IP)).unwrap(), IP);

    let err = get_ip_from_headers(&headers, None).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn get_ip_empty_headers_fall_through() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("  "));
    headers.insert("x-real-ip", HeaderValue::from_static(""));
    assert_eq!(get_ip_from_headers(&headers, Some(IP)).unwrap(), IP);
  }

  #[test]
  fn get_ip_invalid_ip_is_unauthorized() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "x-forwarded-for",
      HeaderValue::from_static("not-an-ip"),
    );
    let err = get_ip_from_headers(&headers, Some(IP)).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }
}
