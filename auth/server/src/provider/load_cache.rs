//! A cache for values which are slow to load over the network
//! (provider clients from discovery, signing keys of trusted issuers),
//! loaded on demand by requests to unauthenticated endpoints.
//!
//! - Concurrent requests share one load instead of each starting their own.
//! - A load is bounded in time, so a hanging server can't block the key.
//! - After a failed load the source is left alone for a while,
//!   instead of being tried again by every request.
//! - While the source can't be reached, the last loaded value stays in
//!   use for a limited time, so a short outage doesn't stop everything.

use std::{
  collections::HashMap,
  sync::{Arc, Mutex, RwLock},
  time::{Duration, Instant},
};

use anyhow::anyhow;

/// A load taking longer than this has failed. Callers wait
/// on each other, so a load must not be able to hang.
const LOAD_TIMEOUT: Duration = Duration::from_secs(15);
/// After a failed load the source is left alone this long.
const RETRY_FAILED_LOAD_AFTER: Duration = Duration::from_secs(30);
/// While loading fails, the last loaded value stays in use this long.
const MAX_STALE_AGE: Duration = Duration::from_secs(60 * 60);

/// The error of a load which wasn't attempted, because it failed too
/// recently. The failure itself was returned (and can be logged) by the
/// caller which attempted it, so this one is not worth another log line:
/// it is what every request gets for as long as the source is down.
#[derive(Debug)]
pub struct LoadFailedRecently;

impl std::fmt::Display for LoadFailedRecently {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "Loading failed less than {} seconds ago, not trying again yet",
      RETRY_FAILED_LOAD_AFTER.as_secs()
    )
  }
}

impl std::error::Error for LoadFailedRecently {}

impl LoadFailedRecently {
  /// Whether the error only repeats a failure which was already reported.
  pub fn is(e: &anyhow::Error) -> bool {
    e.downcast_ref::<LoadFailedRecently>().is_some()
  }
}

struct Entry<T> {
  /// Identifies the configuration the value was loaded from.
  /// A value of another configuration is of no use.
  fingerprint: u64,
  /// The last value which loaded, and when.
  value: Option<(Instant, Arc<T>)>,
  /// When loading last failed.
  failed_at: Option<Instant>,
}

#[derive(Debug, PartialEq)]
enum State {
  /// The cached value is current.
  Fresh,
  /// Loading failed recently, but the value from before is still usable.
  Stale,
  /// Loading failed recently, and there is no usable value.
  FailedRecently,
  Load,
}

/// `valid_for` of None never goes out of date.
fn state(
  valid_for: Option<Duration>,
  value_age: Option<Duration>,
  failed_ago: Option<Duration>,
) -> State {
  if value_age.is_some_and(|age| {
    valid_for.is_none_or(|valid_for| age < valid_for)
  }) {
    return State::Fresh;
  }
  if failed_ago.is_some_and(|ago| ago < RETRY_FAILED_LOAD_AFTER) {
    return if value_age.is_some_and(|age| age < MAX_STALE_AGE) {
      State::Stale
    } else {
      State::FailedRecently
    };
  }
  State::Load
}

pub struct LoadCache<T> {
  entries: RwLock<HashMap<String, Entry<T>>>,
  /// One lock per key, held while loading it.
  loading: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl<T> Default for LoadCache<T> {
  fn default() -> Self {
    Self {
      entries: Default::default(),
      loading: Default::default(),
    }
  }
}

impl<T> LoadCache<T> {
  /// The cached value, if it can be used without loading.
  /// `Err` if loading failed too recently to try again.
  fn cached(
    &self,
    key: &str,
    fingerprint: u64,
    valid_for: Option<Duration>,
  ) -> anyhow::Result<Option<Arc<T>>> {
    let entries =
      self.entries.read().unwrap_or_else(|e| e.into_inner());
    let entry = entries
      .get(key)
      .filter(|entry| entry.fingerprint == fingerprint);
    let value = entry.and_then(|entry| entry.value.as_ref());
    match state(
      valid_for,
      value.map(|(loaded_at, _)| loaded_at.elapsed()),
      entry
        .and_then(|entry| entry.failed_at)
        .map(|failed_at| failed_at.elapsed()),
    ) {
      State::Fresh | State::Stale => {
        Ok(value.map(|(_, value)| value.clone()))
      }
      State::FailedRecently => {
        Err(anyhow::Error::new(LoadFailedRecently))
      }
      State::Load => Ok(None),
    }
  }

  /// Returns the cached value for `key`, loading it if there is none,
  /// it was loaded from another configuration (`fingerprint`), or it is
  /// older than `valid_for` (None never goes out of date).
  pub async fn load<F, Fut>(
    &self,
    key: &str,
    fingerprint: u64,
    valid_for: Option<Duration>,
    load: F,
  ) -> anyhow::Result<Arc<T>>
  where
    F: FnOnce() -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
  {
    self
      .load_with_timeout(
        key,
        fingerprint,
        valid_for,
        LOAD_TIMEOUT,
        load,
      )
      .await
  }

  async fn load_with_timeout<F, Fut>(
    &self,
    key: &str,
    fingerprint: u64,
    valid_for: Option<Duration>,
    timeout: Duration,
    load: F,
  ) -> anyhow::Result<Arc<T>>
  where
    F: FnOnce() -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
  {
    if let Some(value) = self.cached(key, fingerprint, valid_for)? {
      return Ok(value);
    }

    // Only one caller loads, the others wait for its result.
    let loading = self
      .loading
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .entry(key.to_string())
      .or_default()
      .clone();
    let _loading = loading.lock().await;

    // Which may be there by now.
    if let Some(value) = self.cached(key, fingerprint, valid_for)? {
      return Ok(value);
    }

    let loaded = match tokio::time::timeout(timeout, load()).await {
      Ok(loaded) => loaded,
      Err(_) => Err(anyhow!(
        "Loading took longer than {} seconds",
        timeout.as_secs()
      )),
    };

    let mut entries =
      self.entries.write().unwrap_or_else(|e| e.into_inner());
    // The value loaded before, if it is of the same configuration.
    let previous = entries
      .remove(key)
      .filter(|entry| entry.fingerprint == fingerprint)
      .and_then(|entry| entry.value);

    match loaded {
      Ok(value) => {
        let value = Arc::new(value);
        entries.insert(
          key.to_string(),
          Entry {
            fingerprint,
            value: Some((Instant::now(), value.clone())),
            failed_at: None,
          },
        );
        Ok(value)
      }
      Err(e) => {
        let stale = previous
          .as_ref()
          .filter(|(loaded_at, _)| {
            loaded_at.elapsed() < MAX_STALE_AGE
          })
          .map(|(_, value)| value.clone());
        entries.insert(
          key.to_string(),
          Entry {
            fingerprint,
            value: previous,
            failed_at: Some(Instant::now()),
          },
        );
        match stale {
          Some(value) => {
            tracing::warn!(
              key,
              "Failed to reload, using the previous value | {e:#}"
            );
            Ok(value)
          }
          None => Err(e),
        }
      }
    }
  }

  pub fn evict(&self, key: &str) {
    self
      .entries
      .write()
      .unwrap_or_else(|e| e.into_inner())
      .remove(key);
    self
      .loading
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .remove(key);
  }

  /// Drops everything `keep` doesn't hold for.
  pub fn retain(&self, keep: impl Fn(&str) -> bool) {
    // This runs often, only take the
    // write lock if there is something to drop.
    if self
      .entries
      .read()
      .unwrap_or_else(|e| e.into_inner())
      .keys()
      .all(|key| keep(key))
    {
      return;
    }
    self
      .entries
      .write()
      .unwrap_or_else(|e| e.into_inner())
      .retain(|key, _| keep(key));
    self
      .loading
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .retain(|key, _| keep(key));
  }

  #[cfg(test)]
  pub fn keys(&self) -> Vec<String> {
    let mut keys = self
      .entries
      .read()
      .unwrap()
      .keys()
      .cloned()
      .collect::<Vec<_>>();
    keys.sort();
    keys
  }
}

#[cfg(test)]
mod tests {
  use std::sync::atomic::{AtomicUsize, Ordering};

  use super::*;

  const MINUTE: Option<Duration> = Some(Duration::from_secs(60));

  #[test]
  fn test_state() {
    let secs = Duration::from_secs;
    assert_eq!(state(MINUTE, None, None), State::Load);
    assert_eq!(state(MINUTE, Some(secs(30)), None), State::Fresh);
    // Outdated values are reloaded
    assert_eq!(state(MINUTE, Some(secs(600)), None), State::Load);
    // A recent failure isn't retried, the value from before stays in use
    assert_eq!(
      state(MINUTE, Some(secs(600)), Some(secs(5))),
      State::Stale
    );
    assert_eq!(
      state(MINUTE, Some(secs(600)), Some(secs(60))),
      State::Load
    );
    // But not forever, and not without any value
    assert_eq!(
      state(MINUTE, Some(secs(2 * 60 * 60)), Some(secs(5))),
      State::FailedRecently
    );
    assert_eq!(
      state(MINUTE, None, Some(secs(5))),
      State::FailedRecently
    );
    assert_eq!(state(MINUTE, None, Some(secs(60))), State::Load);
    // A failure doesn't take a fresh value out of use
    assert_eq!(
      state(MINUTE, Some(secs(30)), Some(secs(5))),
      State::Fresh
    );
    // Without a lifetime the value never goes out of date
    assert_eq!(
      state(None, Some(secs(24 * 60 * 60)), None),
      State::Fresh
    );
  }

  #[tokio::test]
  async fn test_value_is_cached_until_fingerprint_changes() {
    let cache = LoadCache::<u32>::default();
    let loads = AtomicUsize::new(0);
    let load = |fingerprint| {
      cache.load("key", fingerprint, MINUTE, || async {
        Ok(loads.fetch_add(1, Ordering::SeqCst) as u32)
      })
    };
    let first = load(1).await.unwrap();
    assert!(Arc::ptr_eq(&first, &load(1).await.unwrap()));
    assert_eq!(*load(2).await.unwrap(), 1);
    cache.evict("key");
    assert_eq!(*load(2).await.unwrap(), 2);
  }

  /// A burst of requests for a cold key loads once.
  #[tokio::test]
  async fn test_concurrent_callers_share_one_load() {
    let cache = Arc::new(LoadCache::<u32>::default());
    let loads = Arc::new(AtomicUsize::new(0));
    let callers = (0..50)
      .map(|_| {
        let (cache, loads) = (cache.clone(), loads.clone());
        tokio::spawn(async move {
          cache
            .load("key", 1, MINUTE, || async move {
              loads.fetch_add(1, Ordering::SeqCst);
              // Long enough for every caller to arrive
              tokio::time::sleep(Duration::from_millis(100)).await;
              Ok(7)
            })
            .await
        })
      })
      .collect::<Vec<_>>();
    for caller in callers {
      assert_eq!(*caller.await.unwrap().unwrap(), 7);
    }
    assert_eq!(loads.load(Ordering::SeqCst), 1);
  }

  /// Neither does a burst during an outage load one after another.
  #[tokio::test]
  async fn test_concurrent_callers_share_one_failure() {
    let cache = Arc::new(LoadCache::<u32>::default());
    let loads = Arc::new(AtomicUsize::new(0));
    let callers = (0..50)
      .map(|_| {
        let (cache, loads) = (cache.clone(), loads.clone());
        tokio::spawn(async move {
          cache
            .load("key", 1, MINUTE, || async move {
              loads.fetch_add(1, Ordering::SeqCst);
              tokio::time::sleep(Duration::from_millis(100)).await;
              Err(anyhow!("unreachable"))
            })
            .await
        })
      })
      .collect::<Vec<_>>();
    // Only the caller which attempted the load has a failure
    // to report, the rest are told it failed recently.
    let mut reported = 0;
    for caller in callers {
      let err = caller.await.unwrap().unwrap_err();
      if !LoadFailedRecently::is(&err) {
        assert!(err.to_string().contains("unreachable"));
        reported += 1;
      }
    }
    assert_eq!(reported, 1);
    assert_eq!(loads.load(Ordering::SeqCst), 1);

    // As is everyone asking during the retry delay
    let err = cache
      .load("key", 1, MINUTE, || async { Ok(1) })
      .await
      .unwrap_err();
    assert!(LoadFailedRecently::is(&err));

    // A changed configuration is tried right away
    assert!(
      cache
        .load("key", 2, MINUTE, || async { Ok(1) })
        .await
        .is_ok()
    );
    // Other keys are not affected
    assert!(
      cache
        .load("other", 1, MINUTE, || async { Ok(1) })
        .await
        .is_ok()
    );
  }

  /// Callers wait on each other, so a server which
  /// never answers must not be able to block the key.
  #[tokio::test]
  async fn test_hanging_load_times_out() {
    let cache = LoadCache::<u32>::default();
    let err = cache
      .load_with_timeout(
        "key",
        1,
        MINUTE,
        Duration::from_millis(50),
        std::future::pending,
      )
      .await
      .unwrap_err();
    assert!(err.to_string().contains("longer than"), "{err:#}");
    // The key is usable again, and remembers the failure
    assert!(
      cache
        .load("key", 1, MINUTE, || async { Ok(1) })
        .await
        .is_err()
    );
    assert!(
      cache
        .load("key", 2, MINUTE, || async { Ok(1) })
        .await
        .is_ok()
    );
  }

  /// The source going away doesn't take down a value
  /// which loaded before, as long as it isn't too old.
  #[tokio::test]
  async fn test_previous_value_is_used_when_reload_fails() {
    let cache = LoadCache::<u32>::default();
    // Outdated right away
    let expired = Some(Duration::ZERO);
    let first = cache
      .load("key", 1, expired, || async { Ok(7) })
      .await
      .unwrap();
    let second = cache
      .load("key", 1, expired, || async {
        Err(anyhow!("unreachable"))
      })
      .await
      .unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    // And without another attempt for a while
    let third = cache
      .load("key", 1, expired, || async { panic!("must not load") })
      .await
      .unwrap();
    assert!(Arc::ptr_eq(&first, &third));

    // The value of another configuration is no substitute
    assert!(
      cache
        .load("key", 2, expired, || async {
          Err(anyhow!("unreachable"))
        })
        .await
        .is_err()
    );
  }

  #[tokio::test]
  async fn test_retain() {
    let cache = LoadCache::<u32>::default();
    for key in ["a", "b", "c"] {
      cache
        .load(key, 1, MINUTE, || async { Ok(1) })
        .await
        .unwrap();
    }
    cache.retain(|key| key != "b");
    assert_eq!(cache.keys(), ["a", "c"]);
    cache.retain(|_| true);
    assert_eq!(cache.keys(), ["a", "c"]);
  }
}
