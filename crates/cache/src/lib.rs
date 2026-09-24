use std::{
  collections::{HashMap, HashSet},
  hash::Hash,
  sync::Arc,
};

use tokio::sync::{Mutex, RwLock};

/// Prevents simultaneous / rapid fire access to an action,
/// returning the cached result instead in these situations.
///
/// A caller takes the entry for its key with
/// [get_lock](TimeoutCache::get_lock), locks it for the length of
/// the action, and reuses [CacheEntry::res] while
/// [CacheEntry::last_ts] is recent enough.
///
/// Entries stay until removed. When keys come from request input
/// (eg an image name), call [prune](TimeoutCache::prune) from a
/// periodic task to keep the map bounded. An entry a caller still
/// holds is never removed, so eviction cannot let a second caller
/// run the same action at the same time.
#[derive(Default)]
pub struct TimeoutCache<K, Res>(
  Mutex<HashMap<K, Arc<Mutex<CacheEntry<Res>>>>>,
);

impl<K: Eq + Hash, Res: Default> TimeoutCache<K, Res> {
  pub async fn get_lock(
    &self,
    key: K,
  ) -> Arc<Mutex<CacheEntry<Res>>> {
    let mut lock = self.0.lock().await;
    lock.entry(key).or_default().clone()
  }
}

impl<K: Eq + Hash, Res> TimeoutCache<K, Res> {
  /// The number of cached keys.
  pub async fn len(&self) -> usize {
    self.0.lock().await.len()
  }

  pub async fn is_empty(&self) -> bool {
    self.0.lock().await.is_empty()
  }

  /// Removes the entry for `key`, unless a caller still holds it
  /// (between [get_lock](TimeoutCache::get_lock) and dropping the
  /// handle). Returns whether an entry was removed.
  pub async fn remove(&self, key: &K) -> bool {
    let mut map = self.0.lock().await;
    match map.get(key) {
      Some(entry) if !is_held(entry) => {
        map.remove(key);
        true
      }
      _ => false,
    }
  }

  /// Keeps only the entries `keep` returns true for. Entries a
  /// caller still holds are always kept, without calling `keep`.
  pub async fn retain(
    &self,
    mut keep: impl FnMut(&K, &CacheEntry<Res>) -> bool,
  ) {
    self.0.lock().await.retain(|key, entry| {
      if is_held(entry) {
        return true;
      }
      // Nobody else can reach an unheld entry, the lock is free.
      match entry.try_lock() {
        Ok(entry) => keep(key, &entry),
        Err(_) => true,
      }
    });
  }

  /// Removes the entries no caller holds whose
  /// [last_ts](CacheEntry::last_ts) is before `older_than` (same
  /// unit, eg `now - timeout` in unix ms). Returns how many were
  /// removed.
  pub async fn prune(&self, older_than: i64) -> usize {
    let mut removed = 0;
    self
      .retain(|_, entry| {
        let keep = entry.last_ts >= older_than;
        if !keep {
          removed += 1;
        }
        keep
      })
      .await;
    removed
  }
}

/// Whether a caller holds a handle to the entry. Only called under
/// the map lock, where no new handle can be taken, so a count that
/// reads as unheld stays unheld.
fn is_held<Res>(entry: &Arc<Mutex<CacheEntry<Res>>>) -> bool {
  Arc::strong_count(entry) > 1 || Arc::weak_count(entry) > 0
}

pub struct CacheEntry<Res> {
  /// The last cached ts, in the unit the caller passes to
  /// [set](CacheEntry::set) (0 until the first set).
  pub last_ts: i64,
  /// The last cached result
  pub res: anyhow::Result<Res>,
}

impl<Res: Default> Default for CacheEntry<Res> {
  fn default() -> Self {
    CacheEntry {
      last_ts: 0,
      res: Ok(Res::default()),
    }
  }
}

impl<Res: Clone> CacheEntry<Res> {
  pub fn set(&mut self, res: &anyhow::Result<Res>, timestamp: i64) {
    self.res = res.as_ref().map_err(clone_anyhow_error).cloned();
    self.last_ts = timestamp;
  }

  pub fn clone_res(&self) -> anyhow::Result<Res> {
    self.res.as_ref().map_err(clone_anyhow_error).cloned()
  }
}

fn clone_anyhow_error(e: &anyhow::Error) -> anyhow::Error {
  let mut reasons =
    e.chain().map(|e| e.to_string()).collect::<Vec<_>>();
  // Always guaranteed to be at least one reason
  // Need to start the chain with the last reason
  let mut e = anyhow::Error::msg(reasons.pop().unwrap());
  // Need to reverse reason application from lowest context to highest context.
  for reason in reasons.into_iter().rev() {
    e = e.context(reason)
  }
  e
}

#[derive(Debug)]
pub struct CloneCache<K: PartialEq + Eq + Hash, T: Clone>(
  RwLock<HashMap<K, T>>,
);

impl<K: PartialEq + Eq + Hash, T: Clone> Default
  for CloneCache<K, T>
{
  fn default() -> Self {
    Self(RwLock::new(HashMap::new()))
  }
}

// Note. No `Debug` bounds: cached values are often
// secrets (tokens, provider configs) without a `Debug` impl.
impl<K: PartialEq + Eq + Hash + Clone, T: Clone> CloneCache<K, T> {
  pub async fn get(&self, key: &K) -> Option<T> {
    self.0.read().await.get(key).cloned()
  }

  pub async fn get_keys(&self) -> Vec<K> {
    let cache = self.0.read().await;
    cache.keys().cloned().collect()
  }

  pub async fn get_values(&self) -> Vec<T> {
    let cache = self.0.read().await;
    cache.values().cloned().collect()
  }

  pub async fn get_entries(&self) -> Vec<(K, T)> {
    let cache = self.0.read().await;
    cache.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
  }

  pub async fn insert<Key>(&self, key: Key, val: T) -> Option<T>
  where
    Key: Into<K>,
  {
    self.0.write().await.insert(key.into(), val)
  }

  pub async fn remove(&self, key: &K) -> Option<T> {
    self.0.write().await.remove(key)
  }

  ///Retains only the elements specified by the predicate.
  ///
  /// In other words, remove all pairs (k, v) for which f(&k, &mut v) returns false. The elements are visited in unsorted (and unspecified) order.
  pub async fn retain(&self, retain: impl FnMut(&K, &mut T) -> bool) {
    self.0.write().await.retain(retain);
  }

  pub async fn get_or_insert_with(
    &self,
    key: &K,
    default: impl FnOnce() -> T,
  ) -> T {
    let mut lock = self.0.write().await;
    match lock.get(key).cloned() {
      Some(item) => item,
      None => {
        let item: T = default();
        lock.insert(key.clone(), item.clone());
        item
      }
    }
  }
}

impl<K: PartialEq + Eq + Hash + Clone, T: Clone + Default>
  CloneCache<K, T>
{
  pub async fn get_or_insert_default(&self, key: &K) -> T {
    self.get_or_insert_with(key, T::default).await
  }
}

pub struct CloneVecCache<T: Clone>(RwLock<Vec<T>>);

impl<T: Clone> Default for CloneVecCache<T> {
  fn default() -> Self {
    Self(RwLock::new(Vec::new()))
  }
}

impl<T: Clone> CloneVecCache<T> {
  pub async fn find(
    &self,
    find: impl FnMut(&&T) -> bool,
  ) -> Option<T> {
    self.0.read().await.iter().find(find).cloned()
  }

  pub async fn list(&self) -> Vec<T> {
    self.0.read().await.clone()
  }

  pub async fn insert(
    &self,
    find: impl FnMut(&T) -> bool,
    mut val: T,
  ) -> Option<T> {
    let mut cache = self.0.write().await;
    let index = cache.iter().position(find);
    if let Some(index) = index {
      std::mem::swap(&mut cache[index], &mut val);
      Some(val)
    } else {
      cache.push(val);
      None
    }
  }

  pub async fn remove(
    &self,
    find: impl FnMut(&T) -> bool,
  ) -> Option<T> {
    let mut cache = self.0.write().await;
    let index = cache.iter().position(find)?;
    Some(cache.swap_remove(index))
  }

  pub async fn retain(&self, keep: impl FnMut(&T) -> bool) {
    self.0.write().await.retain(keep);
  }

  /// Returns the first item matching `find`, or inserts and returns
  /// `make()` when none does. Both happen under one write lock, so
  /// concurrent callers insert at most once.
  ///
  /// `make` must build an item `find` matches (eg one carrying the
  /// id `find` compares), otherwise the next call misses again and
  /// inserts another item. Debug builds assert this.
  pub async fn find_or_insert_with(
    &self,
    mut find: impl FnMut(&T) -> bool,
    make: impl FnOnce() -> T,
  ) -> T {
    let mut cache = self.0.write().await;
    if let Some(item) = cache.iter().find(|item| find(item)) {
      return item.clone();
    }
    let item = make();
    debug_assert!(
      find(&item),
      "CloneVecCache::find_or_insert_with: the inserted item does not match 'find'"
    );
    cache.push(item.clone());
    item
  }
}

impl<T: Clone + Default> CloneVecCache<T> {
  /// Returns the first item matching `find`, or inserts and returns
  /// `T::default()` when none does.
  ///
  /// Only idempotent when `T::default()` itself matches `find`.
  /// A keyed `find` (eg `|t| t.id == id`) never matches the default,
  /// so every call inserts another default and returns it instead
  /// of an item with that key.
  #[deprecated(
    note = "T::default() rarely matches a keyed 'find', so every miss inserts another default: use 'find_or_insert_with'"
  )]
  pub async fn find_or_insert_default(
    &self,
    find: impl FnMut(&&T) -> bool,
  ) -> T {
    let mut cache = self.0.write().await;
    match cache.iter().find(find).cloned() {
      Some(item) => item,
      None => {
        let item: T = Default::default();
        cache.push(item.clone());
        item
      }
    }
  }
}

pub struct SetCache<K>(Mutex<HashSet<K>>);

impl<K> Default for SetCache<K> {
  fn default() -> Self {
    Self(Default::default())
  }
}

impl<K: Eq + Hash> SetCache<K> {
  pub async fn contains(&self, key: &K) -> bool {
    self.0.lock().await.contains(key)
  }

  pub async fn insert(&self, key: K) -> bool {
    self.0.lock().await.insert(key)
  }

  pub async fn remove(&self, key: &K) -> bool {
    self.0.lock().await.remove(key)
  }

  pub async fn retain(&self, retain: impl FnMut(&K) -> bool) {
    self.0.lock().await.retain(retain);
  }
}

#[cfg(test)]
mod tests {
  use std::sync::atomic::{AtomicUsize, Ordering};

  use super::*;

  #[tokio::test]
  async fn clone_cache_does_not_need_debug() {
    // Eg. a secret, which deliberately has no Debug impl.
    #[derive(Clone, PartialEq, Eq, Hash)]
    struct NoDebugKey(u8);
    #[derive(Clone)]
    struct NoDebugValue(&'static str);

    let cache = CloneCache::<NoDebugKey, NoDebugValue>::default();
    assert!(
      cache
        .insert(NoDebugKey(1), NoDebugValue("a"))
        .await
        .is_none()
    );
    assert_eq!(cache.get(&NoDebugKey(1)).await.unwrap().0, "a");
    let value = cache
      .get_or_insert_with(&NoDebugKey(2), || NoDebugValue("b"))
      .await;
    assert_eq!(value.0, "b");
    assert_eq!(cache.get_keys().await.len(), 2);
    assert_eq!(cache.remove(&NoDebugKey(1)).await.unwrap().0, "a");
  }

  #[test]
  fn clone_anyhow_error_preserves_context_chain() {
    let e = anyhow::anyhow!("root cause")
      .context("middle context")
      .context("top context");
    let cloned = clone_anyhow_error(&e);
    let original =
      e.chain().map(|e| e.to_string()).collect::<Vec<_>>();
    let clone =
      cloned.chain().map(|e| e.to_string()).collect::<Vec<_>>();
    assert_eq!(
      original,
      vec!["top context", "middle context", "root cause"]
    );
    assert_eq!(original, clone);
    assert_eq!(format!("{e:#}"), format!("{cloned:#}"));
  }

  #[test]
  fn clone_anyhow_error_single_message() {
    let e = anyhow::anyhow!("only reason");
    let cloned = clone_anyhow_error(&e);
    assert_eq!(cloned.chain().count(), 1);
    assert_eq!(cloned.to_string(), "only reason");
  }

  #[tokio::test]
  async fn timeout_cache_returns_same_entry_for_same_key() {
    let cache = TimeoutCache::<&str, u64>::default();
    let a = cache.get_lock("key").await;
    let b = cache.get_lock("key").await;
    assert!(Arc::ptr_eq(&a, &b));
    let c = cache.get_lock("other").await;
    assert!(!Arc::ptr_eq(&a, &c));
  }

  #[tokio::test]
  async fn timeout_cache_entry_set_and_clone_res() {
    let cache = TimeoutCache::<&str, u64>::default();
    let entry = cache.get_lock("key").await;
    {
      let mut entry = entry.lock().await;
      assert_eq!(entry.last_ts, 0);
      assert_eq!(entry.clone_res().unwrap(), 0);
      entry.set(&Ok(42), 100);
    }
    // The cached result is visible through another handle.
    let entry = cache.get_lock("key").await;
    let mut entry = entry.lock().await;
    assert_eq!(entry.last_ts, 100);
    assert_eq!(entry.clone_res().unwrap(), 42);
    // Errors are cloned with context intact.
    let err: anyhow::Result<u64> =
      Err(anyhow::anyhow!("inner").context("outer"));
    entry.set(&err, 200);
    let cloned = entry.clone_res().unwrap_err();
    assert_eq!(format!("{cloned:#}"), "outer: inner");
  }

  /// Sets the entry for `key` to a result cached at `ts`.
  async fn set_at(
    cache: &TimeoutCache<&str, u64>,
    key: &'static str,
    ts: i64,
  ) {
    cache.get_lock(key).await.lock().await.set(&Ok(1), ts);
  }

  #[tokio::test]
  async fn timeout_cache_prune_drops_stale_unheld_entries() {
    let cache = TimeoutCache::<&str, u64>::default();
    set_at(&cache, "stale", 100).await;
    set_at(&cache, "fresh", 300).await;
    set_at(&cache, "held", 100).await;
    set_at(&cache, "locked", 100).await;
    // A caller between get_lock and dropping the handle.
    let held = cache.get_lock("held").await;
    // A caller mid action, holding the entry lock.
    let locked = cache.get_lock("locked").await;
    let guard = locked.lock().await;
    assert_eq!(cache.len().await, 4);

    assert_eq!(cache.prune(200).await, 1);
    assert_eq!(cache.len().await, 3);
    // The stale entry is gone: the next caller starts over.
    let entry = cache.get_lock("stale").await;
    assert_eq!(entry.lock().await.last_ts, 0);
    drop(entry);
    // Held entries survive, so a second caller still waits on the
    // same one instead of running the action alongside.
    assert!(Arc::ptr_eq(&held, &cache.get_lock("held").await));
    assert!(Arc::ptr_eq(&locked, &cache.get_lock("locked").await));

    drop(guard);
    drop(locked);
    drop(held);
    // "stale" (recreated at 0) + "held" + "locked".
    assert_eq!(cache.prune(200).await, 3);
    assert_eq!(cache.len().await, 1);
    assert!(!cache.is_empty().await);
  }

  #[tokio::test]
  async fn timeout_cache_remove_skips_held_entry() {
    let cache = TimeoutCache::<&str, u64>::default();
    assert!(!cache.remove(&"missing").await);
    let held = cache.get_lock("key").await;
    held.lock().await.set(&Ok(7), 100);
    assert!(!cache.remove(&"key").await);
    assert!(Arc::ptr_eq(&held, &cache.get_lock("key").await));
    // A weak handle can come back, it counts as held too.
    let weak = Arc::downgrade(&held);
    drop(held);
    assert!(!cache.remove(&"key").await);
    drop(weak);
    assert!(cache.remove(&"key").await);
    assert!(cache.is_empty().await);
    assert_eq!(cache.get_lock("key").await.lock().await.last_ts, 0);
  }

  #[tokio::test]
  async fn timeout_cache_retain() {
    let cache = TimeoutCache::<&str, u64>::default();
    set_at(&cache, "a", 1).await;
    set_at(&cache, "b", 2).await;
    let held = cache.get_lock("c").await;
    let mut seen = Vec::new();
    cache
      .retain(|key, entry| {
        seen.push(*key);
        entry.last_ts == 2
      })
      .await;
    seen.sort();
    // The held entry isn't offered to 'keep', and stays.
    assert_eq!(seen, vec!["a", "b"]);
    assert_eq!(cache.len().await, 2);
    assert!(Arc::ptr_eq(&held, &cache.get_lock("c").await));
  }

  #[tokio::test]
  async fn clone_cache_insert_get_remove() {
    let cache = CloneCache::<String, u64>::default();
    assert_eq!(cache.get(&"a".to_string()).await, None);
    assert_eq!(cache.insert("a", 1).await, None);
    // Insert returns previous value
    assert_eq!(cache.insert("a", 2).await, Some(1));
    assert_eq!(cache.get(&"a".to_string()).await, Some(2));
    assert_eq!(cache.remove(&"a".to_string()).await, Some(2));
    assert_eq!(cache.get(&"a".to_string()).await, None);
  }

  #[tokio::test]
  async fn clone_cache_entries_and_retain() {
    let cache = CloneCache::<u64, u64>::default();
    for i in 0..5 {
      cache.insert(i, i * 10).await;
    }
    assert_eq!(cache.get_keys().await.len(), 5);
    assert_eq!(cache.get_values().await.len(), 5);
    cache.retain(|k, _| *k % 2 == 0).await;
    let mut entries = cache.get_entries().await;
    entries.sort();
    assert_eq!(entries, vec![(0, 0), (2, 20), (4, 40)]);
  }

  #[tokio::test]
  async fn clone_cache_get_or_insert_with_only_inserts_once() {
    let cache =
      Arc::new(CloneCache::<String, Arc<AtomicUsize>>::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..32 {
      let cache = cache.clone();
      let calls = calls.clone();
      handles.push(tokio::spawn(async move {
        cache
          .get_or_insert_with(&"key".to_string(), || {
            calls.fetch_add(1, Ordering::SeqCst);
            Arc::new(AtomicUsize::new(0))
          })
          .await
      }));
    }
    let mut entries = Vec::new();
    for handle in handles {
      entries.push(handle.await.unwrap());
    }
    // Exactly one default was inserted, and everyone got it.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let first = &entries[0];
    assert!(entries.iter().all(|e| Arc::ptr_eq(first, e)));
  }

  #[tokio::test]
  async fn clone_cache_get_or_insert_default() {
    let cache = CloneCache::<u8, u64>::default();
    assert_eq!(cache.get_or_insert_default(&1).await, 0);
    cache.insert(2u8, 7).await;
    assert_eq!(cache.get_or_insert_default(&2).await, 7);
  }

  #[tokio::test]
  async fn clone_vec_cache_insert_replaces_matching() {
    let cache = CloneVecCache::<(u8, &str)>::default();
    assert_eq!(
      cache.insert(|(id, _)| *id == 1, (1, "a")).await,
      None
    );
    assert_eq!(
      cache.insert(|(id, _)| *id == 2, (2, "b")).await,
      None
    );
    // Replacing returns the previous value.
    assert_eq!(
      cache.insert(|(id, _)| *id == 1, (1, "c")).await,
      Some((1, "a"))
    );
    assert_eq!(cache.list().await.len(), 2);
    assert_eq!(cache.find(|(id, _)| *id == 1).await, Some((1, "c")));
  }

  #[tokio::test]
  async fn clone_vec_cache_remove_and_retain() {
    let cache = CloneVecCache::<u64>::default();
    for i in 0..5 {
      cache.insert(|v| *v == i, i).await;
    }
    assert_eq!(cache.remove(|v| *v == 3).await, Some(3));
    assert_eq!(cache.remove(|v| *v == 3).await, None);
    cache.retain(|v| *v < 2).await;
    let mut list = cache.list().await;
    list.sort();
    assert_eq!(list, vec![0, 1]);
  }

  #[tokio::test]
  #[allow(deprecated)]
  async fn clone_vec_cache_find_or_insert_default() {
    let cache = CloneVecCache::<u64>::default();
    assert_eq!(cache.find_or_insert_default(|&&v| v == 0).await, 0);
    // Did not insert twice
    assert_eq!(cache.list().await, vec![0]);
    cache.insert(|&v| v == 9, 9).await;
    assert_eq!(cache.find_or_insert_default(|&&v| v == 9).await, 9);
    assert_eq!(cache.list().await.len(), 2);
  }

  #[derive(Clone, Debug, Default, PartialEq)]
  struct Named {
    name: &'static str,
    hits: u64,
  }

  /// With a keyed `find`, the item `make` builds carries the key,
  /// so repeat calls find it rather than inserting again (unlike
  /// `find_or_insert_default`, whose default has no name).
  #[tokio::test]
  async fn clone_vec_cache_find_or_insert_with_keyed() {
    let cache = CloneVecCache::<Named>::default();
    let make = || Named { name: "a", hits: 0 };
    for _ in 0..3 {
      let item =
        cache.find_or_insert_with(|t| t.name == "a", make).await;
      assert_eq!(item.name, "a");
    }
    assert_eq!(cache.list().await.len(), 1);
    // An existing match is returned as is, make isn't called.
    cache
      .insert(|t| t.name == "a", Named { name: "a", hits: 5 })
      .await;
    let item = cache
      .find_or_insert_with(
        |t| t.name == "a",
        || unreachable!("the item exists"),
      )
      .await;
    assert_eq!(item.hits, 5);
    // Another key inserts its own item.
    let item = cache
      .find_or_insert_with(
        |t| t.name == "b",
        || Named { name: "b", hits: 1 },
      )
      .await;
    assert_eq!(item, Named { name: "b", hits: 1 });
    assert_eq!(cache.list().await.len(), 2);
  }

  #[tokio::test]
  async fn clone_vec_cache_find_or_insert_with_only_inserts_once() {
    let cache = Arc::new(CloneVecCache::<Named>::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..32 {
      let cache = cache.clone();
      let calls = calls.clone();
      handles.push(tokio::spawn(async move {
        cache
          .find_or_insert_with(
            |t| t.name == "a",
            || {
              calls.fetch_add(1, Ordering::SeqCst);
              Named { name: "a", hits: 0 }
            },
          )
          .await
      }));
    }
    for handle in handles {
      assert_eq!(handle.await.unwrap().name, "a");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(cache.list().await.len(), 1);
  }

  #[cfg(debug_assertions)]
  #[tokio::test]
  #[should_panic(expected = "does not match 'find'")]
  async fn clone_vec_cache_find_or_insert_with_asserts_match() {
    let cache = CloneVecCache::<Named>::default();
    cache
      .find_or_insert_with(|t| t.name == "a", Named::default)
      .await;
  }

  #[tokio::test]
  async fn set_cache_behavior() {
    let cache = SetCache::<u64>::default();
    assert!(!cache.contains(&1).await);
    assert!(cache.insert(1).await);
    // Second insert of same key returns false
    assert!(!cache.insert(1).await);
    assert!(cache.contains(&1).await);
    cache.insert(2).await;
    cache.retain(|&k| k == 2).await;
    assert!(!cache.contains(&1).await);
    assert!(cache.remove(&2).await);
    assert!(!cache.remove(&2).await);
  }
}
