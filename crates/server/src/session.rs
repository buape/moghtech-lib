use std::{
  collections::HashMap,
  sync::{Arc, Mutex, MutexGuard, PoisonError},
  time::{Duration as StdDuration, Instant},
};

use async_trait::async_trait;
use tower_sessions::{
  Expiry,
  cookie::time::{Duration, OffsetDateTime},
  session::{Id, Record},
  session_store,
};
use tracing::{info, warn};

pub use tower_sessions::{
  ExpiredDeletion, Session, SessionManagerLayer, SessionStore,
  cookie::SameSite,
};

/// The default [SessionConfig::max_sessions].
pub const DEFAULT_MAX_SESSIONS: usize = 10_000;

/// The session cookie name on https hosts without a
/// [SessionConfig::cookie_domain]. The `__Host-` prefix makes
/// browsers only accept the cookie from this host, over https,
/// without a `Domain` attribute, so other subdomains can't set or
/// shadow it.
const HOST_COOKIE_NAME: &str = "__Host-id";

/// How often [MemorySessionStore] sweeps expired sessions
/// when sessions are saved.
const SWEEP_INTERVAL: StdDuration = StdDuration::from_secs(60);

pub trait SessionConfig {
  fn host(&self) -> &str;
  fn host_env_field(&self) -> &str {
    "HOST"
  }
  /// How long session stays valid
  fn expiry_seconds(&self) -> i64 {
    60 * 3
  }
  /// Enable in UI development context for login
  /// to work.
  ///
  /// Sets `SameSite=None`, which browsers only accept together
  /// with `Secure`, so the cookie is then always `Secure`. This
  /// works on https hosts and on `localhost` / loopback ips, but
  /// not on other plain http hosts.
  fn allow_cross_site(&self) -> bool {
    false
  }
  /// Sets the session cookie `Domain` attribute, which makes
  /// browsers send the session to this domain **and all of its
  /// subdomains**. Only set it when the app is really reached
  /// under several subdomains sharing one session.
  ///
  /// Default: `None`, the cookie is host-only (sent only to the
  /// host which set it). On https hosts it is then also named
  /// with the `__Host-` prefix, so subdomains can't set it either.
  fn cookie_domain(&self) -> Option<&str> {
    None
  }
  /// The maximum number of sessions held by [memory_session_layer].
  /// When full, the sessions closest to expiry are evicted, see
  /// [MemorySessionStore]. Keep it well above the number of
  /// sessions active within one [expiry][Self::expiry_seconds].
  ///
  /// Default: [DEFAULT_MAX_SESSIONS].
  fn max_sessions(&self) -> usize {
    DEFAULT_MAX_SESSIONS
  }
}

/// Adds an in memory session manager layer,
/// backed by a [MemorySessionStore] holding at most
/// [SessionConfig::max_sessions].
///
/// Use [Session] to extract
/// the client session in axum request handlers.
pub fn memory_session_layer(
  config: impl SessionConfig,
) -> SessionManagerLayer<MemorySessionStore> {
  let store = MemorySessionStore::new(config.max_sessions());
  session_layer(store, config)
}

/// Adds a session manager layer backed by the given store,
/// with the session cookie configured from the [SessionConfig].
/// [SessionConfig::max_sessions] is not used, the store
/// decides how many sessions it holds.
///
/// With the `__Host-` cookie name (https hosts without a
/// [SessionConfig::cookie_domain]), the removal cookie
/// tower-sessions sends for a dead session (flushed, expired or
/// evicted) lacks `Secure`, so browsers ignore the removal. The
/// dead session's cookie then lingers until its `Max-Age`, which
/// is harmless: its id no longer resolves to a session.
pub fn session_layer<S: SessionStore>(
  store: S,
  config: impl SessionConfig,
) -> SessionManagerLayer<S> {
  let host = config.host();
  let host_url = url::Url::parse(host)
    .inspect_err(|e| {
      warn!(
        "Invalid {}: not URL. Passkeys won't work. | {e:?}",
        config.host_env_field(),
      )
    })
    .ok();
  let https = match &host_url {
    Some(url) => url.scheme() == "https",
    None => host
      .get(..8)
      .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://")),
  };
  let cross_site = config.allow_cross_site();
  if cross_site {
    info!("Session allowing cross site usage (SameSite=None).");
    if !https && !host_url.as_ref().is_some_and(is_loopback) {
      warn!(
        "{} is not https: browsers reject the SameSite=None session cookie, login flows using the session will fail.",
        config.host_env_field()
      );
    }
  }
  let mut layer = SessionManagerLayer::new(store)
    .with_expiry(Expiry::OnInactivity(Duration::seconds(
      config.expiry_seconds(),
    )))
    // Browsers reject SameSite=None cookies without Secure,
    // and accept Secure cookies from localhost over http.
    .with_secure(https || cross_site)
    // Needs Lax in order for sessions to work
    // accross oauth redirects.
    .with_same_site(if cross_site {
      SameSite::None
    } else {
      SameSite::Lax
    });
  match config.cookie_domain().filter(|domain| !domain.is_empty()) {
    Some(domain) => {
      info!("Session cookie shared with subdomains of {domain}");
      layer = layer.with_domain(domain.to_string());
    }
    // Host-only cookie. `__Host-` needs Secure, Path=/ (the
    // tower-sessions default) and no Domain.
    None if https => layer = layer.with_name(HOST_COOKIE_NAME),
    None => {}
  }
  layer
}

fn is_loopback(url: &url::Url) -> bool {
  match url.host() {
    Some(url::Host::Domain(domain)) => {
      domain.eq_ignore_ascii_case("localhost")
    }
    Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
    Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
    None => false,
  }
}

/// An in memory [SessionStore]. Unlike `tower_sessions::MemoryStore`,
/// it frees expired sessions and holds a bounded number of them, so
/// clients starting sessions (eg unauthenticated login flows) can't
/// grow the process memory without limit.
///
/// - Expired sessions are removed when loaded, and swept from the
///   store (at most once a minute) when sessions are saved, so no
///   background task is needed. [ExpiredDeletion::delete_expired]
///   sweeps on demand.
/// - When the store is full after the sweep, the sessions closest to
///   expiry (the least recently active) are evicted, a tenth of the
///   store at a time. Their clients have to start over, eg the login
///   flow in progress.
///
/// Clones share the same sessions.
#[derive(Clone)]
pub struct MemorySessionStore {
  inner: Arc<Mutex<MemoryStoreInner>>,
}

struct MemoryStoreInner {
  records: HashMap<Id, Record>,
  max_sessions: usize,
  sweep_interval: StdDuration,
  last_sweep: Instant,
}

impl Default for MemorySessionStore {
  /// Holds at most [DEFAULT_MAX_SESSIONS].
  fn default() -> Self {
    Self::new(DEFAULT_MAX_SESSIONS)
  }
}

// Not derived, the records hold login state.
impl std::fmt::Debug for MemorySessionStore {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let inner = self.lock();
    f.debug_struct("MemorySessionStore")
      .field("sessions", &inner.records.len())
      .field("max_sessions", &inner.max_sessions)
      .finish()
  }
}

impl MemorySessionStore {
  /// A store holding at most `max_sessions` (at least 1).
  pub fn new(max_sessions: usize) -> Self {
    Self::with_sweep_interval(max_sessions, SWEEP_INTERVAL)
  }

  fn with_sweep_interval(
    max_sessions: usize,
    sweep_interval: StdDuration,
  ) -> Self {
    Self {
      inner: Arc::new(Mutex::new(MemoryStoreInner {
        records: HashMap::new(),
        max_sessions: max_sessions.max(1),
        sweep_interval,
        last_sweep: Instant::now(),
      })),
    }
  }

  /// The number of sessions held, including expired
  /// sessions which haven't been swept yet.
  pub fn len(&self) -> usize {
    self.lock().records.len()
  }

  pub fn is_empty(&self) -> bool {
    self.len() == 0
  }

  fn lock(&self) -> MutexGuard<'_, MemoryStoreInner> {
    // No invariant spans the lock, a panic
    // elsewhere leaves the map usable.
    self.inner.lock().unwrap_or_else(PoisonError::into_inner)
  }
}

impl MemoryStoreInner {
  fn sweep(&mut self, now: OffsetDateTime) {
    self.records.retain(|_, record| is_active(record, now));
    self.last_sweep = Instant::now();
  }

  fn maybe_sweep(&mut self, now: OffsetDateTime) {
    if self.last_sweep.elapsed() >= self.sweep_interval {
      self.sweep(now);
    }
  }

  /// Makes room for one more session: sweeps expired sessions,
  /// then evicts the sessions closest to expiry if still full.
  /// Evicting a tenth of the store at a time keeps a flood of new
  /// sessions from scanning the whole store on every insert.
  fn make_room(&mut self, now: OffsetDateTime) {
    if self.records.len() < self.max_sessions {
      return;
    }
    self.sweep(now);
    let excess =
      (self.records.len() + 1).saturating_sub(self.max_sessions);
    if excess == 0 {
      return;
    }
    let count =
      excess.max(self.max_sessions / 10).min(self.records.len());
    warn!(
      "Session store is full ({} sessions), evicting the {count} closest to expiry.",
      self.records.len()
    );
    let mut by_expiry = self
      .records
      .iter()
      .map(|(id, record)| (record.expiry_date, *id))
      .collect::<Vec<_>>();
    if count < by_expiry.len() {
      // Moves the `count` soonest to expire to the front.
      by_expiry
        .select_nth_unstable_by_key(count, |(expiry, _)| *expiry);
    }
    for (_, id) in &by_expiry[..count] {
      self.records.remove(id);
    }
  }
}

fn is_active(record: &Record, now: OffsetDateTime) -> bool {
  record.expiry_date > now
}

#[async_trait]
impl SessionStore for MemorySessionStore {
  async fn create(
    &self,
    record: &mut Record,
  ) -> session_store::Result<()> {
    let now = OffsetDateTime::now_utc();
    let mut inner = self.lock();
    inner.maybe_sweep(now);
    inner.make_room(now);
    while inner.records.contains_key(&record.id) {
      // Session ID collision mitigation.
      record.id = Id::default();
    }
    inner.records.insert(record.id, record.clone());
    Ok(())
  }

  async fn save(&self, record: &Record) -> session_store::Result<()> {
    let now = OffsetDateTime::now_utc();
    let mut inner = self.lock();
    inner.maybe_sweep(now);
    if !inner.records.contains_key(&record.id) {
      // Swept or evicted while the request was handled.
      inner.make_room(now);
    }
    inner.records.insert(record.id, record.clone());
    Ok(())
  }

  async fn load(
    &self,
    session_id: &Id,
  ) -> session_store::Result<Option<Record>> {
    let now = OffsetDateTime::now_utc();
    let mut inner = self.lock();
    match inner.records.get(session_id) {
      Some(record) if is_active(record, now) => {
        Ok(Some(record.clone()))
      }
      Some(_) => {
        inner.records.remove(session_id);
        Ok(None)
      }
      None => Ok(None),
    }
  }

  async fn delete(
    &self,
    session_id: &Id,
  ) -> session_store::Result<()> {
    self.lock().records.remove(session_id);
    Ok(())
  }
}

#[async_trait]
impl ExpiredDeletion for MemorySessionStore {
  async fn delete_expired(&self) -> session_store::Result<()> {
    self.lock().sweep(OffsetDateTime::now_utc());
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn record(expires_in_seconds: i64) -> Record {
    Record {
      id: Id::default(),
      data: Default::default(),
      expiry_date: OffsetDateTime::now_utc()
        + Duration::seconds(expires_in_seconds),
    }
  }

  #[tokio::test]
  async fn load_removes_expired_sessions() {
    let store = MemorySessionStore::default();
    let mut expired = record(-10);
    let mut active = record(60);
    store.create(&mut expired).await.unwrap();
    store.create(&mut active).await.unwrap();
    assert_eq!(store.len(), 2);
    assert_eq!(store.load(&expired.id).await.unwrap(), None);
    assert_eq!(store.len(), 1);
    assert_eq!(store.load(&active.id).await.unwrap(), Some(active));
  }

  #[tokio::test]
  async fn delete_expired_sweeps_the_store() {
    let store = MemorySessionStore::default();
    for _ in 0..5 {
      store.create(&mut record(-10)).await.unwrap();
    }
    let mut active = record(60);
    store.create(&mut active).await.unwrap();
    assert_eq!(store.len(), 6);
    store.delete_expired().await.unwrap();
    assert_eq!(store.len(), 1);
    assert!(store.load(&active.id).await.unwrap().is_some());
  }

  #[tokio::test]
  async fn saving_sweeps_expired_sessions_periodically() {
    let store =
      MemorySessionStore::with_sweep_interval(100, StdDuration::ZERO);
    for _ in 0..5 {
      store.save(&record(-10)).await.unwrap();
    }
    // Every save swept the ones saved before.
    assert_eq!(store.len(), 1);
    let mut active = record(60);
    store.create(&mut active).await.unwrap();
    assert_eq!(store.len(), 1);
    assert!(store.load(&active.id).await.unwrap().is_some());

    // Without the interval passing, nothing is swept.
    let store = MemorySessionStore::new(100);
    for _ in 0..5 {
      store.save(&record(-10)).await.unwrap();
    }
    assert_eq!(store.len(), 5);
  }

  #[tokio::test]
  async fn full_store_evicts_the_sessions_closest_to_expiry() {
    let store = MemorySessionStore::new(20);
    let mut oldest = record(10);
    store.create(&mut oldest).await.unwrap();
    for i in 0..19 {
      store.create(&mut record(100 + i)).await.unwrap();
    }
    assert_eq!(store.len(), 20);
    // Full: the tenth closest to expiry makes room.
    let mut newest = record(1000);
    store.create(&mut newest).await.unwrap();
    assert_eq!(store.len(), 19);
    assert_eq!(store.load(&oldest.id).await.unwrap(), None);
    assert!(store.load(&newest.id).await.unwrap().is_some());
    // Stays bounded under a flood.
    for _ in 0..1000 {
      store.create(&mut record(2000)).await.unwrap();
      assert!(store.len() <= 20);
    }
  }

  #[tokio::test]
  async fn full_store_sweeps_expired_sessions_before_evicting() {
    let store = MemorySessionStore::new(10);
    for _ in 0..5 {
      store.create(&mut record(-10)).await.unwrap();
    }
    let mut active = Vec::new();
    for _ in 0..5 {
      let mut active_record = record(60);
      store.create(&mut active_record).await.unwrap();
      active.push(active_record);
    }
    assert_eq!(store.len(), 10);
    store.create(&mut record(60)).await.unwrap();
    assert_eq!(store.len(), 6);
    for record in active {
      assert!(store.load(&record.id).await.unwrap().is_some());
    }
  }

  #[tokio::test]
  async fn create_avoids_id_collisions() {
    let store = MemorySessionStore::default();
    let mut first = record(60);
    store.create(&mut first).await.unwrap();
    let mut second = record(60);
    second.id = first.id;
    store.create(&mut second).await.unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(store.len(), 2);
  }

  #[test]
  fn debug_does_not_print_session_data() {
    let store = MemorySessionStore::new(5);
    assert_eq!(
      format!("{store:?}"),
      "MemorySessionStore { sessions: 0, max_sessions: 5 }"
    );
  }
}
