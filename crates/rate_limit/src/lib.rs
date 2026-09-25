use std::{
  collections::HashMap,
  fmt,
  mem::ManuallyDrop,
  net::{IpAddr, Ipv6Addr},
  sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError},
  time::{Duration, Instant},
};

use anyhow::anyhow;
use axum::http::{HeaderMap, StatusCode};
use mogh_error::AddStatusCodeError;
use tokio::sync::{Notify, RwLock};

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
///
/// A server error (5xx) displays without its causes when the app
/// hides server error details
/// ([mogh_error::set_server_error_detail] other than `Full`), as
/// the response then carries this message alone.
#[derive(Debug)]
pub struct FailedAttempt {
  /// The attempt's error with its causes, as `{:#}` renders it
  /// (only its top-level message for a hidden server error).
  error: String,
  remaining_attempts: usize,
}

impl FailedAttempt {
  /// How many more attempts from the client (its IPv4 address,
  /// or IPv6 prefix, see [RateLimiterBuilder::ipv6_prefix_len])
  /// may fail within the window before it is refused with
  /// `429 Too Many Requests`.
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
///
/// Attempts are counted per client: per IPv4 address, and per
/// IPv6 prefix (a `/64` by default, see
/// [RateLimiterBuilder::ipv6_prefix_len]), since an IPv6 client
/// usually controls a whole `/64` and could otherwise use a
/// fresh address for every attempt.
///
/// There are two ways to limit an attempt:
///
/// - [with_strict_failure_rate_limit_using_ip](Self::with_strict_failure_rate_limit_using_ip)
///   counts the attempts in flight against the budget, so no
///   more than `max_attempts` attempts can fail within the window,
///   however many are sent at once. Use it where the attempt
///   checks a secret which can be guessed, like a password or a
///   TOTP code.
/// - [with_failure_rate_limit_using_ip](Self::with_failure_rate_limit_using_ip)
///   only counts the failures recorded so far. It never holds an
///   attempt back, but attempts sent at the same time all run
///   before any of them is recorded, so it doesn't bound a burst.
///   Use it where requests legitimately run in parallel and the
///   secret can't be guessed, like the credential check of every
///   authenticated request.
///
/// Both count failures only, and share the budget of the client
/// on the same [RateLimiter].
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
  ///
  /// This is best effort under concurrency: only the failures
  /// recorded so far are counted, so attempts which are sent at
  /// the same time all run, and are all recorded once they fail.
  /// Use [Self::with_strict_failure_rate_limit_using_ip] to
  /// protect secrets which can be guessed.
  fn with_failure_rate_limit_using_ip(
    self,
    limiter: &RateLimiter,
    ip: &IpAddr,
  ) -> impl Future<Output = mogh_error::Result<R>> {
    async move {
      if limiter.disabled {
        return self.await;
      }

      let key = limiter.key(ip);

      // Clients without failures have no entry, and aren't
      // added one until they fail.
      let entry = limiter.get(&key).await;
      limiter.check(entry.as_deref())?;

      match self.await {
        Ok(res) => Ok(res),
        Err(e) => {
          // Looked up again, the entry may have been cleaned up
          // (without failures in the window) in the meantime.
          let entry = limiter.get_or_insert(key).await;
          let remaining_attempts = limiter.record_failure(&entry);
          Err(failed_attempt(e, remaining_attempts))
        }
      }
    }
  }

  /// [Self::with_failure_rate_limit_using_ip], counting the
  /// attempts in flight against the budget, so no more than
  /// `max_attempts` attempts from the client can fail within the
  /// window, however many it sends at once.
  ///
  /// Before the future is executed it reserves one of the
  /// remaining attempts. Attempts in flight never cause a
  /// refusal, only recorded failures do: once they use up the
  /// budget, every attempt (waiting ones included) is refused
  /// with `429 Too Many Requests`, as with
  /// [Self::with_failure_rate_limit_using_ip]. While the remaining
  /// attempts are all reserved by attempts in flight, the next
  /// one waits for one of them to finish (a success gives its
  /// reservation back without using up an attempt, a failure
  /// uses it up), or for a recorded failure to leave the window.
  /// No more than `max_attempts` attempts from one client run at
  /// the same time.
  ///
  /// The reservation is given back if the future is dropped
  /// before it finishes (eg the client disconnects).
  fn with_strict_failure_rate_limit_using_ip(
    self,
    limiter: &RateLimiter,
    ip: &IpAddr,
  ) -> impl Future<Output = mogh_error::Result<R>> {
    async move {
      if limiter.disabled {
        return self.await;
      }

      let entry = limiter.get_or_insert(limiter.key(ip)).await;

      let reservation = loop {
        // Created before the check, so it is woken by any release
        // after the check (see `Notify::notify_waiters`).
        let released = entry.released.notified();
        match limiter.reserve(&entry)? {
          Reserve::Reserved(reservation) => break reservation,
          Reserve::Wait(None) => released.await,
          Reserve::Wait(Some(expiry)) => {
            // Check again once either frees an attempt,
            // whichever comes first.
            let _ =
              tokio::time::timeout_at(expiry.into(), released).await;
          }
        }
      };

      match self.await {
        Ok(res) => Ok(res),
        Err(e) => {
          let remaining_attempts = reservation.fail(limiter);
          Err(failed_attempt(e, remaining_attempts))
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

  /// [Self::with_strict_failure_rate_limit_using_ip], with the ip
  /// determined from the request headers and socket `peer`
  /// using [get_client_ip], so forwarding headers are only
  /// believed from `trusted_proxies`.
  fn with_strict_failure_rate_limit_using_headers(
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
      self
        .with_strict_failure_rate_limit_using_ip(limiter, &ip)
        .await
    }
  }
}

impl<F, R> WithFailureRateLimit<R> for F where
  F: Future<Output = mogh_error::Result<R>> + Sized
{
}

/// Returns the attempt's error `e` with a [FailedAttempt]
/// context noting the attempts remaining. As context, not a new
/// error with its message, so callers can still downcast to the
/// original error.
fn failed_attempt(
  mut e: mogh_error::Error,
  remaining_attempts: usize,
) -> mogh_error::Error {
  // When the app hides the details of server errors, their
  // response carries only the top-level message, which is this
  // context: it must not repeat the causes (internal hosts, urls,
  // driver messages). They stay below it in the chain, for logs.
  let hide_causes = e.status.is_server_error()
    && mogh_error::server_error_detail()
      != mogh_error::ServerErrorDetail::Full;
  let error = if hide_causes {
    e.error.to_string()
  } else {
    format!("{:#}", e.error)
  };
  let attempt = FailedAttempt {
    error,
    remaining_attempts,
  };
  e.error = e.error.context(attempt);
  e
}

/// The attempts of one client, see [RateLimiter::key].
#[derive(Default)]
struct Entry {
  /// Never held across an await, so a std mutex, which the
  /// [Reservation] can also lock when it is dropped.
  attempts: Mutex<Attempts>,
  /// Notified when a strict attempt finishes, waking the strict
  /// attempts waiting for the budget it had reserved.
  released: Notify,
}

impl Entry {
  fn lock(&self) -> MutexGuard<'_, Attempts> {
    // Nothing panics while holding the lock, and the attempts
    // stay valid even if something did.
    self.attempts.lock().unwrap_or_else(PoisonError::into_inner)
  }

  /// `None` when the attempts are locked.
  fn try_lock(&self) -> Option<MutexGuard<'_, Attempts>> {
    match self.attempts.try_lock() {
      Ok(attempts) => Some(attempts),
      Err(TryLockError::Poisoned(e)) => Some(e.into_inner()),
      Err(TryLockError::WouldBlock) => None,
    }
  }
}

#[derive(Default)]
struct Attempts {
  /// When the failures happened, oldest first. Taken while
  /// holding the lock, so they stay in order.
  failures: Vec<Instant>,
  /// How many strict attempts are in flight, each reserving
  /// one of the remaining attempts.
  in_flight: usize,
}

impl Attempts {
  /// Drops the failures which are no longer in the `window`.
  fn prune(&mut self, now: Instant, window: Duration) {
    // `now.duration_since(time)` saturates to zero (rather than
    // panicking) if `time` is somehow later than `now`, and avoids
    // the panic `now - window` can hit early in process lifetime
    // when the platform's Instant cannot represent times before
    // process start.
    self
      .failures
      .retain(|&time| now.duration_since(time) < window);
  }
}

/// The outcome of [RateLimiter::reserve].
enum Reserve<'a> {
  Reserved(Reservation<'a>),
  /// The remaining attempts are all reserved by attempts in
  /// flight. One is freed when one of those finishes, or at the
  /// given time, when the oldest failure leaves the window.
  Wait(Option<Instant>),
}

/// A strict attempt's reservation of one of the remaining
/// attempts. Given back when dropped, so an attempt which is
/// cancelled (eg the client disconnects) or panics can't keep it.
struct Reservation<'a> {
  entry: &'a Entry,
}

impl Reservation<'_> {
  /// Records the attempt's failure, in the same lock as giving
  /// back the reservation, so the budget passes straight to the
  /// failure. Returns the attempts remaining.
  fn fail(self, limiter: &RateLimiter) -> usize {
    // Released here instead.
    let reservation = ManuallyDrop::new(self);
    let entry = reservation.entry;
    let remaining_attempts = {
      let mut attempts = entry.lock();
      attempts.in_flight = attempts.in_flight.saturating_sub(1);
      limiter.push_failure(&mut attempts)
    };
    entry.released.notify_waiters();
    remaining_attempts
  }
}

impl Drop for Reservation<'_> {
  fn drop(&mut self) {
    {
      let mut attempts = self.entry.lock();
      attempts.in_flight = attempts.in_flight.saturating_sub(1);
    }
    self.entry.released.notify_waiters();
  }
}

/// Limits the failed attempts per client within a time window,
/// see [WithFailureRateLimit].
pub struct RateLimiter {
  /// Only clients with failures in the window, or strict
  /// attempts, are on the map.
  attempts: RwLock<HashMap<IpAddr, Arc<Entry>>>,
  disabled: bool,
  max_attempts: usize,
  window: Duration,
  ipv6_prefix_len: u8,
  max_entries: usize,
}

impl RateLimiter {
  /// The default [RateLimiterBuilder::ipv6_prefix_len].
  pub const DEFAULT_IPV6_PREFIX_LEN: u8 = 64;

  /// The default [RateLimiterBuilder::max_entries].
  pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

  /// Create a new rate limiter, with the defaults of
  /// [RateLimiter::builder] for everything else. Also spawns a
  /// tokio task to clean up the clients whose failures have all
  /// left the window, see [RateLimiterBuilder::build].
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
    Self::builder(max_attempts, window)
      .disabled(disabled)
      .build()
  }

  /// Configure a new rate limiter allowing `max_attempts` failed
  /// attempts per client within `window`.
  pub fn builder(
    max_attempts: usize,
    window: Duration,
  ) -> RateLimiterBuilder {
    RateLimiterBuilder {
      disabled: false,
      max_attempts,
      window,
      ipv6_prefix_len: Self::DEFAULT_IPV6_PREFIX_LEN,
      max_entries: Self::DEFAULT_MAX_ENTRIES,
    }
  }
}

/// Configures a [RateLimiter], see [RateLimiter::builder].
#[derive(Debug, Clone)]
pub struct RateLimiterBuilder {
  disabled: bool,
  max_attempts: usize,
  window: Duration,
  ipv6_prefix_len: u8,
  max_entries: usize,
}

impl RateLimiterBuilder {
  /// Whether the limiter is disabled, letting every attempt
  /// through. Default: `false`.
  pub fn disabled(mut self, disabled: bool) -> Self {
    self.disabled = disabled;
    self
  }

  /// How many leading bits of an IPv6 address identify the
  /// client. All the addresses sharing them share one budget, the
  /// way the users behind one IPv4 address (NAT) do.
  ///
  /// Default: `64`, the smallest block usually assigned to one
  /// host or home, so a client can't reset its budget by moving
  /// to another address in it. Lower it (eg `56` or `48`) to also
  /// cover clients which are assigned more, or raise it up to
  /// `128` (one budget per address) where unrelated clients share
  /// a `/64`. Values above `128` are treated as `128`. IPv4
  /// addresses, including IPv4-mapped IPv6 ones, always count
  /// per address.
  pub fn ipv6_prefix_len(mut self, len: u8) -> Self {
    self.ipv6_prefix_len = len.min(128);
    self
  }

  /// The most clients the limiter keeps track of (those with
  /// failures within the window, or strict attempts in flight).
  /// Default: [RateLimiter::DEFAULT_MAX_ENTRIES]. At least `1`.
  ///
  /// When a new client would go over it, the clients whose
  /// failures have all left the window are removed first. If that
  /// is not enough, the ones whose last failure is the oldest are
  /// removed (never the ones with attempts in flight), down to
  /// 90% of the maximum. Those lose their failures early, which
  /// only happens once more clients failed within the window than
  /// the limiter holds, so memory stays bounded however many
  /// addresses an attacker uses.
  pub fn max_entries(mut self, max_entries: usize) -> Self {
    self.max_entries = max_entries.max(1);
    self
  }

  /// Builds the limiter. Unless it is disabled, and when called
  /// within a tokio runtime, this also spawns a task which removes
  /// the clients whose failures have all left the window once a
  /// minute, and stops once the limiter is dropped. Outside of a
  /// runtime, they are only removed when the map reaches
  /// [Self::max_entries].
  pub fn build(self) -> Arc<RateLimiter> {
    let limiter = Arc::new(RateLimiter {
      attempts: Default::default(),
      disabled: self.disabled,
      max_attempts: self.max_attempts,
      window: self.window,
      ipv6_prefix_len: self.ipv6_prefix_len,
      max_entries: self.max_entries,
    });
    if !limiter.disabled {
      spawn_cleanup_task(&limiter);
    }
    limiter
  }
}

/// Task to run every minute and remove the clients whose failures
/// have all left the window, see [RateLimiter::cleanup].
fn spawn_cleanup_task(limiter: &Arc<RateLimiter>) {
  const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
  let Ok(runtime) = tokio::runtime::Handle::try_current() else {
    return;
  };
  // Doesn't keep the limiter alive.
  let limiter = Arc::downgrade(limiter);
  runtime.spawn(async move {
    // The first tick of a plain `interval` completes
    // immediately, there is nothing to clean up yet.
    let mut interval = tokio::time::interval_at(
      tokio::time::Instant::now() + CLEANUP_INTERVAL,
      CLEANUP_INTERVAL,
    );
    loop {
      interval.tick().await;
      let Some(limiter) = limiter.upgrade() else {
        return;
      };
      limiter.cleanup().await;
    }
  });
}

impl RateLimiter {
  /// The key the attempts from `ip` count under: IPv4 addresses
  /// (including IPv4-mapped IPv6 ones) as they are, and IPv6
  /// addresses by their first [Self::ipv6_prefix_len] bits.
  fn key(&self, ip: &IpAddr) -> IpAddr {
    // Canonical first, IPv4-mapped addresses would otherwise
    // all share the `::/64` budget.
    match ip.to_canonical() {
      IpAddr::V4(ip) => IpAddr::V4(ip),
      IpAddr::V6(ip) => {
        // A shift by 128 (prefix 0) overflows, no bits are kept.
        let mask = u128::MAX
          .checked_shl(128 - u32::from(self.ipv6_prefix_len))
          .unwrap_or(0);
        IpAddr::V6(Ipv6Addr::from_bits(ip.to_bits() & mask))
      }
    }
  }

  async fn get(&self, key: &IpAddr) -> Option<Arc<Entry>> {
    self.attempts.read().await.get(key).cloned()
  }

  /// Takes the map write lock only when `key` has no entry yet.
  async fn get_or_insert(&self, key: IpAddr) -> Arc<Entry> {
    if let Some(entry) = self.get(&key).await {
      return entry;
    }
    let mut map = self.attempts.write().await;
    if let Some(entry) = map.get(&key) {
      return entry.clone();
    }
    if map.len() >= self.max_entries {
      self.make_room(&mut map, Instant::now());
    }
    let entry = Arc::<Entry>::default();
    map.insert(key, entry.clone());
    entry
  }

  /// Refuses an attempt when the recorded failures of the client
  /// with `entry` have used up the budget.
  fn check(&self, entry: Option<&Entry>) -> mogh_error::Result<()> {
    let now = Instant::now();
    let Some(entry) = entry else {
      return if self.max_attempts == 0 {
        Err(self.too_many_attempts(&[], now))
      } else {
        Ok(())
      };
    };
    let mut attempts = entry.lock();
    attempts.prune(now, self.window);
    if attempts.failures.len() >= self.max_attempts {
      return Err(self.too_many_attempts(&attempts.failures, now));
    }
    Ok(())
  }

  /// Reserves one of the remaining attempts of the client with
  /// `entry`, or `Err` when the recorded failures have used up
  /// the budget.
  fn reserve<'a>(
    &self,
    entry: &'a Entry,
  ) -> mogh_error::Result<Reserve<'a>> {
    let now = Instant::now();
    let mut attempts = entry.lock();
    attempts.prune(now, self.window);
    if attempts.failures.len() >= self.max_attempts {
      return Err(self.too_many_attempts(&attempts.failures, now));
    }
    if attempts.failures.len() + attempts.in_flight
      >= self.max_attempts
    {
      let expiry = attempts
        .failures
        .first()
        .and_then(|&first| first.checked_add(self.window));
      return Ok(Reserve::Wait(expiry));
    }
    attempts.in_flight += 1;
    Ok(Reserve::Reserved(Reservation { entry }))
  }

  /// Records a failure of the client with `entry`, returning the
  /// attempts remaining.
  fn record_failure(&self, entry: &Entry) -> usize {
    self.push_failure(&mut entry.lock())
  }

  fn push_failure(&self, attempts: &mut Attempts) -> usize {
    // At completion time, so slow-failing futures don't get a
    // head start on window expiry. Under the lock, so the
    // failures stay in order.
    let now = Instant::now();
    attempts.prune(now, self.window);
    attempts.failures.push(now);
    self.max_attempts.saturating_sub(attempts.failures.len())
  }

  /// The `429 Too Many Requests` refusing an attempt, with the
  /// time until enough of the (ordered) `failures` leave the
  /// window to allow the next one.
  fn too_many_attempts(
    &self,
    failures: &[Instant],
    now: Instant,
  ) -> mogh_error::Error {
    // Attempts which ran at the same time can record more
    // failures than the budget, all of those above it have to
    // leave the window too.
    let retry_in = failures
      .len()
      .checked_sub(self.max_attempts)
      .and_then(|index| failures.get(index))
      .map(|&time| {
        self.window.saturating_sub(now.duration_since(time))
      })
      .unwrap_or(self.window);
    anyhow!("Too many attempts | Try again in {retry_in:.0?}")
      .status_code(StatusCode::TOO_MANY_REQUESTS)
  }

  /// Whether the `entry` can be removed at `now` without losing
  /// anything: it has no failures within the window, and no
  /// attempt is using it.
  fn is_stale(&self, entry: &Arc<Entry>, now: Instant) -> bool {
    // An attempt in flight may hold its own reference to the
    // entry, and record a failure on it afterwards. Removing the
    // entry now would lose that failure (it would be pushed to an
    // entry no longer on the map), giving the client a free
    // attempt. New attempts can't take a reference meanwhile, the
    // caller holds the map write lock.
    if Arc::strong_count(entry) > 1 {
      return false;
    }
    let Some(attempts) = entry.try_lock() else {
      // Being used, not stale.
      return false;
    };
    attempts.in_flight == 0
      && attempts.failures.last().is_none_or(|&last| {
        // Saturates to zero rather than panicking.
        now.duration_since(last) >= self.window
      })
  }

  /// Makes room on the full `map` for a new client, see
  /// [RateLimiterBuilder::max_entries]. Removing a batch at a
  /// time keeps the cost per new client low.
  fn make_room(
    &self,
    map: &mut HashMap<IpAddr, Arc<Entry>>,
    now: Instant,
  ) {
    map.retain(|_, entry| !self.is_stale(entry, now));
    let target = self.max_entries - (self.max_entries / 10).max(1);
    let excess = map.len().saturating_sub(target);
    if excess == 0 {
      return;
    }
    let mut removable = map
      .iter()
      .filter(|(_, entry)| Arc::strong_count(entry) == 1)
      .filter_map(|(key, entry)| {
        let attempts = entry.try_lock()?;
        (attempts.in_flight == 0)
          .then(|| (attempts.failures.last().copied(), *key))
      })
      .collect::<Vec<_>>();
    let excess = excess.min(removable.len());
    if excess == 0 {
      // All in use, allowed over the maximum until they finish.
      return;
    }
    if excess < removable.len() {
      removable
        .select_nth_unstable_by_key(excess - 1, |(last, _)| *last);
    }
    for (_, key) in &removable[..excess] {
      map.remove(key);
    }
  }

  /// Removes the clients whose failures have all left the window,
  /// and which no attempt is using. See [spawn_cleanup_task].
  async fn cleanup(&self) {
    self.cleanup_at(Instant::now()).await
  }

  async fn cleanup_at(&self, now: Instant) {
    let mut map = self.attempts.write().await;
    map.retain(|_, entry| !self.is_stale(entry, now));
    // Give back the memory of a map grown by a burst of clients.
    if map.capacity() > 4 * map.len().max(16) {
      let len = map.len();
      map.shrink_to(2 * len);
    }
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

  async fn map_len(limiter: &RateLimiter) -> usize {
    limiter.attempts.read().await.len()
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

    // The strict variant returns it the same way.
    let err = failing_typed()
      .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert_eq!(err.headers.as_ref().unwrap()["x-test"], "kept");
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
    // them. The cleanup task must not lose the failure of that
    // request while it is in flight.
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
    for strict in [false, true] {
      let in_flight = tokio::spawn({
        let limiter = limiter.clone();
        async move {
          if strict {
            failing_slowly()
              .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
              .await
              .unwrap_err()
          } else {
            failing_slowly()
              .with_failure_rate_limit_using_ip(&limiter, &IP)
              .await
              .unwrap_err()
          }
        }
      });
      // Runs while the request is in flight.
      tokio::time::sleep(Duration::from_millis(10)).await;
      limiter.cleanup().await;
      in_flight.await.unwrap();
    }

    // Both failures were recorded on the entry which is still on
    // the map.
    let executions = AtomicUsize::new(0);
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(remaining(&err), "0 attempts remaining");
  }

  #[tokio::test]
  async fn successes_add_no_entries() {
    let limiter = RateLimiter::new(false, 3, Duration::from_secs(60));
    let res: mogh_error::Result<()> = async { Ok(()) }
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await;
    res.unwrap();
    assert_eq!(map_len(&limiter).await, 0);

    // A strict attempt adds one for its reservation, which the
    // cleanup removes.
    let res: mogh_error::Result<()> = async { Ok(()) }
      .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
      .await;
    res.unwrap();
    assert_eq!(map_len(&limiter).await, 1);
    limiter.cleanup().await;
    assert_eq!(map_len(&limiter).await, 0);
  }

  #[tokio::test]
  async fn successes_are_not_rate_limited() {
    let limiter = RateLimiter::new(false, 2, Duration::from_secs(60));
    for _ in 0..10 {
      let res: mogh_error::Result<u64> = async { Ok(7) }
        .with_failure_rate_limit_using_ip(&limiter, &IP)
        .await;
      assert_eq!(res.unwrap(), 7);
      let res: mogh_error::Result<u64> = async { Ok(7) }
        .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
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
      let err = failing(&executions)
        .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
        .await
        .unwrap_err();
      assert_ne!(err.status, StatusCode::TOO_MANY_REQUESTS);
    }
    assert_eq!(executions.load(Ordering::SeqCst), 10);
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
    let err = failing(&executions)
      .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
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
    let err = failing(&executions)
      .with_strict_failure_rate_limit_using_headers(
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
      .with_strict_failure_rate_limit_using_headers(
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

  /// Sends `count` slow failing attempts from [IP] at once,
  /// returning how many ran, how many were refused with 429,
  /// and the attempts remaining noted on the others.
  async fn failing_burst(
    limiter: &Arc<RateLimiter>,
    count: usize,
    strict: bool,
  ) -> (usize, usize, Vec<usize>) {
    let executions = Arc::new(AtomicUsize::new(0));
    // Best effort attempts wait for each other, so all of them are
    // past their check before any failure is recorded. The strict
    // ones don't all run.
    let running = Arc::new(tokio::sync::Barrier::new(if strict {
      1
    } else {
      count
    }));
    let attempts = (0..count)
      .map(|_| {
        let limiter = limiter.clone();
        let executions = executions.clone();
        let running = running.clone();
        tokio::spawn(async move {
          let attempt = async {
            executions.fetch_add(1, Ordering::SeqCst);
            running.wait().await;
            failing_slowly().await
          };
          if strict {
            attempt
              .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
              .await
              .unwrap_err()
          } else {
            attempt
              .with_failure_rate_limit_using_ip(&limiter, &IP)
              .await
              .unwrap_err()
          }
        })
      })
      .collect::<Vec<_>>();
    let mut refused = 0;
    let mut remaining = Vec::new();
    for attempt in attempts {
      let err = attempt.await.unwrap();
      if err.status == StatusCode::TOO_MANY_REQUESTS {
        refused += 1;
      } else {
        remaining.push(
          err
            .error
            .downcast_ref::<FailedAttempt>()
            .unwrap()
            .remaining_attempts(),
        );
      }
    }
    remaining.sort();
    (executions.load(Ordering::SeqCst), refused, remaining)
  }

  #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
  async fn strict_limit_holds_for_concurrent_attempts() {
    let limiter = RateLimiter::new(false, 3, Duration::from_secs(60));
    let (executions, refused, remaining) =
      failing_burst(&limiter, 100, true).await;
    assert_eq!(executions, 3);
    assert_eq!(refused, 97);
    assert_eq!(remaining, [0, 1, 2]);
  }

  #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
  async fn concurrent_failures_note_the_attempts_remaining() {
    // Not strict: the whole burst runs (the documented trade-off),
    // but each failure still notes what is actually left.
    let limiter = RateLimiter::new(false, 3, Duration::from_secs(60));
    let (executions, refused, remaining) =
      failing_burst(&limiter, 10, false).await;
    assert_eq!(executions, 10);
    assert_eq!(refused, 0);
    assert_eq!(remaining, [0, 0, 0, 0, 0, 0, 0, 0, 1, 2]);
    // And the client is refused afterwards.
    let executions = AtomicUsize::new(0);
    let err = failing(&executions)
      .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(executions.load(Ordering::SeqCst), 0);
  }

  #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
  async fn strict_concurrent_successes_are_held_back_not_refused() {
    let limiter = RateLimiter::new(false, 3, Duration::from_secs(60));
    let running = Arc::new(AtomicUsize::new(0));
    let most_running = Arc::new(AtomicUsize::new(0));
    let attempts = (0..20)
      .map(|i| {
        let limiter = limiter.clone();
        let running = running.clone();
        let most_running = most_running.clone();
        tokio::spawn(async move {
          async {
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
            most_running.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(20)).await;
            running.fetch_sub(1, Ordering::SeqCst);
            Ok(i)
          }
          .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
          .await
        })
      })
      .collect::<Vec<_>>();
    for (i, attempt) in attempts.into_iter().enumerate() {
      assert_eq!(attempt.await.unwrap().unwrap(), i);
    }
    assert!(most_running.load(Ordering::SeqCst) <= 3);
    // Nothing was used up.
    let err = failing_slowly()
      .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(remaining(&err), "2 attempts remaining");
  }

  #[tokio::test]
  async fn strict_attempt_waits_for_the_budget_in_flight() {
    let limiter = RateLimiter::new(false, 1, Duration::from_secs(60));
    let started = Arc::new(Notify::new());
    let in_flight = tokio::spawn({
      let limiter = limiter.clone();
      let started = started.clone();
      async move {
        async {
          started.notify_one();
          failing_slowly().await
        }
        .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
        .await
        .unwrap_err()
      }
    });
    started.notified().await;
    // Waits for the attempt in flight, which uses up the budget.
    let executions = AtomicUsize::new(0);
    let err = failing(&executions)
      .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(executions.load(Ordering::SeqCst), 0);
    assert_eq!(
      remaining(&in_flight.await.unwrap()),
      "0 attempts remaining"
    );
  }

  #[tokio::test]
  async fn strict_attempt_waits_for_a_failure_to_leave_the_window() {
    let limiter =
      RateLimiter::new(false, 2, Duration::from_millis(200));
    let executions = AtomicUsize::new(0);
    failing(&executions)
      .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    // Holds the other attempt for much longer than the window.
    let started = Arc::new(Notify::new());
    let in_flight = tokio::spawn({
      let limiter = limiter.clone();
      let started = started.clone();
      async move {
        async {
          started.notify_one();
          tokio::time::sleep(Duration::from_secs(3600)).await;
          Ok(())
        }
        .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
        .await
      }
    });
    started.notified().await;
    // Runs once the first failure leaves the window.
    let err = tokio::time::timeout(
      Duration::from_secs(5),
      failing(&executions)
        .with_strict_failure_rate_limit_using_ip(&limiter, &IP),
    )
    .await
    .expect("the expired failure did not free an attempt")
    .unwrap_err();
    assert_eq!(remaining(&err), "1 attempts remaining");
    assert_eq!(executions.load(Ordering::SeqCst), 2);
    in_flight.abort();
  }

  #[tokio::test]
  async fn cancelled_strict_attempt_gives_back_its_reservation() {
    let limiter = RateLimiter::new(false, 1, Duration::from_secs(60));
    let started = Arc::new(Notify::new());
    let in_flight = tokio::spawn({
      let limiter = limiter.clone();
      let started = started.clone();
      async move {
        async {
          started.notify_one();
          tokio::time::sleep(Duration::from_secs(3600)).await;
          Ok(())
        }
        .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
        .await
      }
    });
    started.notified().await;
    // Like a client which disconnects.
    in_flight.abort();
    assert!(in_flight.await.unwrap_err().is_cancelled());

    let executions = AtomicUsize::new(0);
    let err = tokio::time::timeout(
      Duration::from_secs(5),
      failing(&executions)
        .with_strict_failure_rate_limit_using_ip(&limiter, &IP),
    )
    .await
    .expect("the reservation was not given back")
    .unwrap_err();
    assert_eq!(remaining(&err), "0 attempts remaining");
    assert_eq!(executions.load(Ordering::SeqCst), 1);
  }

  #[tokio::test]
  async fn strict_and_best_effort_attempts_share_the_budget() {
    let limiter = RateLimiter::new(false, 2, Duration::from_secs(60));
    let executions = AtomicUsize::new(0);
    failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    let err = failing(&executions)
      .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(remaining(&err), "0 attempts remaining");
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(executions.load(Ordering::SeqCst), 2);
  }

  fn ip(ip: &str) -> IpAddr {
    ip.parse().unwrap()
  }

  #[tokio::test]
  async fn ipv6_clients_share_a_budget_per_64() {
    let limiter = RateLimiter::new(false, 1, Duration::from_secs(60));
    let executions = AtomicUsize::new(0);
    failing(&executions)
      .with_failure_rate_limit_using_ip(
        &limiter,
        &ip("2001:db8:1:2::1"),
      )
      .await
      .unwrap_err();
    // Another address in the same /64.
    let err = failing(&executions)
      .with_strict_failure_rate_limit_using_ip(
        &limiter,
        &ip("2001:db8:1:2:ffff:ffff:ffff:ffff"),
      )
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    // The next /64 has its own budget.
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(
        &limiter,
        &ip("2001:db8:1:3::1"),
      )
      .await
      .unwrap_err();
    assert_ne!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(executions.load(Ordering::SeqCst), 2);
  }

  #[tokio::test]
  async fn ipv4_mapped_addresses_count_as_ipv4() {
    let limiter = RateLimiter::new(false, 1, Duration::from_secs(60));
    let executions = AtomicUsize::new(0);
    failing(&executions)
      .with_failure_rate_limit_using_ip(
        &limiter,
        &ip("::ffff:1.2.3.4"),
      )
      .await
      .unwrap_err();
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    // Not collapsed into the `::/64` of the mapped range.
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(
        &limiter,
        &ip("::ffff:5.6.7.8"),
      )
      .await
      .unwrap_err();
    assert_ne!(err.status, StatusCode::TOO_MANY_REQUESTS);
  }

  #[tokio::test]
  async fn ipv6_prefix_len_is_configurable() {
    let key = |len: u8, addr: &str| {
      RateLimiter::builder(1, Duration::from_secs(60))
        .disabled(true)
        .ipv6_prefix_len(len)
        .build()
        .key(&ip(addr))
    };
    let addr = "2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff";
    assert_eq!(key(64, addr), ip("2001:db8:aaaa:bbbb::"));
    assert_eq!(key(56, addr), ip("2001:db8:aaaa:bb00::"));
    assert_eq!(key(48, addr), ip("2001:db8:aaaa::"));
    assert_eq!(key(128, addr), ip(addr));
    assert_eq!(key(200, addr), ip(addr));
    assert_eq!(key(0, addr), ip("::"));
    assert_eq!(key(0, "1.2.3.4"), IP);
    assert_eq!(key(64, "::ffff:1.2.3.4"), IP);

    // One budget per address.
    let limiter = RateLimiter::builder(1, Duration::from_secs(60))
      .ipv6_prefix_len(128)
      .build();
    let executions = AtomicUsize::new(0);
    failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &ip("2001:db8::1"))
      .await
      .unwrap_err();
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &ip("2001:db8::2"))
      .await
      .unwrap_err();
    assert_ne!(err.status, StatusCode::TOO_MANY_REQUESTS);
  }

  #[tokio::test]
  async fn cleanup_keeps_failures_within_a_long_window() {
    let limiter =
      RateLimiter::new(false, 1, Duration::from_secs(60 * 60));
    let executions = AtomicUsize::new(0);
    failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    // Long after the 15 minutes entries used to be kept for.
    limiter
      .cleanup_at(Instant::now() + Duration::from_secs(16 * 60))
      .await;
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(executions.load(Ordering::SeqCst), 1);
    // Removed once the failure leaves the window.
    limiter
      .cleanup_at(Instant::now() + Duration::from_secs(60 * 60))
      .await;
    assert_eq!(map_len(&limiter).await, 0);
  }

  #[tokio::test]
  async fn cleanup_removes_short_windows_sooner() {
    let limiter = RateLimiter::new(false, 1, Duration::from_secs(15));
    let executions = AtomicUsize::new(0);
    failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    limiter
      .cleanup_at(Instant::now() + Duration::from_secs(10))
      .await;
    assert_eq!(map_len(&limiter).await, 1);
    limiter
      .cleanup_at(Instant::now() + Duration::from_secs(16))
      .await;
    assert_eq!(map_len(&limiter).await, 0);
  }

  #[tokio::test]
  async fn clients_tracked_are_bounded() {
    let limiter = RateLimiter::builder(1, Duration::from_secs(60))
      .max_entries(10)
      .build();
    let executions = AtomicUsize::new(0);
    let client = |i: u32| IpAddr::V4(std::net::Ipv4Addr::from(i));
    for i in 0..25 {
      failing(&executions)
        .with_failure_rate_limit_using_ip(&limiter, &client(i))
        .await
        .unwrap_err();
      assert!(map_len(&limiter).await <= 10);
    }
    assert_eq!(executions.load(Ordering::SeqCst), 25);
    // The latest failures are kept.
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &client(24))
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    // The oldest were removed to make room.
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &client(0))
      .await
      .unwrap_err();
    assert_ne!(err.status, StatusCode::TOO_MANY_REQUESTS);
  }

  #[tokio::test]
  async fn clients_in_flight_are_not_removed_to_make_room() {
    let limiter = RateLimiter::builder(1, Duration::from_secs(60))
      .max_entries(2)
      .build();
    let started = Arc::new(Notify::new());
    let in_flight = tokio::spawn({
      let limiter = limiter.clone();
      let started = started.clone();
      async move {
        async {
          started.notify_one();
          failing_slowly().await
        }
        .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
        .await
        .unwrap_err()
      }
    });
    started.notified().await;
    let executions = AtomicUsize::new(0);
    for i in 0..5 {
      let other = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, i));
      failing(&executions)
        .with_failure_rate_limit_using_ip(&limiter, &other)
        .await
        .unwrap_err();
    }
    in_flight.await.unwrap();
    let err = failing(&executions)
      .with_failure_rate_limit_using_ip(&limiter, &IP)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
  }

  #[tokio::test]
  async fn retry_time_waits_for_every_failure_above_the_budget() {
    let window = Duration::from_secs(60);
    let limiter = RateLimiter::new(true, 2, window);
    let now = Instant::now();
    let failures = [
      now,
      now + Duration::from_secs(10),
      now + Duration::from_secs(20),
    ];
    let later = now + Duration::from_secs(20);
    let msg = |failures: &[Instant]| {
      limiter.too_many_attempts(failures, later).error.to_string()
    };
    // The second failure has to leave the window too.
    assert_eq!(
      msg(&failures),
      "Too many attempts | Try again in 50s"
    );
    assert_eq!(
      msg(&failures[..2]),
      "Too many attempts | Try again in 40s"
    );
    assert_eq!(msg(&[]), "Too many attempts | Try again in 60s");
  }

  #[tokio::test]
  async fn cleanup_task_does_not_keep_the_limiter_alive() {
    let limiter = RateLimiter::new(false, 1, Duration::from_secs(60));
    let weak = Arc::downgrade(&limiter);
    drop(limiter);
    assert!(weak.upgrade().is_none());
  }

  #[test]
  fn limiter_can_be_created_outside_a_runtime() {
    let limiter = RateLimiter::new(false, 1, Duration::from_secs(60));
    let runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();
    let executions = AtomicUsize::new(0);
    runtime.block_on(async {
      failing(&executions)
        .with_failure_rate_limit_using_ip(&limiter, &IP)
        .await
        .unwrap_err();
      let err = failing(&executions)
        .with_strict_failure_rate_limit_using_ip(&limiter, &IP)
        .await
        .unwrap_err();
      assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    });
  }

  #[test]
  fn limited_futures_are_send() {
    fn assert_send(_: impl Send) {}
    let limiter = RateLimiter::new(true, 1, Duration::from_secs(60));
    let headers = HeaderMap::new();
    let ok = || async { mogh_error::Result::Ok(()) };
    assert_send(ok().with_failure_rate_limit_using_ip(&limiter, &IP));
    assert_send(
      ok().with_strict_failure_rate_limit_using_ip(&limiter, &IP),
    );
    assert_send(ok().with_failure_rate_limit_using_headers(
      &limiter,
      &headers,
      None,
      &TrustedProxies::None,
    ));
    assert_send(ok().with_strict_failure_rate_limit_using_headers(
      &limiter,
      &headers,
      None,
      &TrustedProxies::None,
    ));
  }
}
