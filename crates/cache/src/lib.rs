use std::{
  collections::{HashMap, HashSet},
  hash::Hash,
  sync::Arc,
};

use tokio::sync::{Mutex, RwLock};

/// Prevents simultaneous / rapid fire access to an action,
/// returning the cached result instead in these situations.
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

pub struct CacheEntry<Res> {
  /// The last cached ts
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

impl<K: PartialEq + Eq + Hash + std::fmt::Debug + Clone, T: Clone>
  CloneCache<K, T>
{
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
    T: std::fmt::Debug,
    Key: Into<K> + std::fmt::Debug,
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

impl<
  K: PartialEq + Eq + Hash + std::fmt::Debug + Clone,
  T: Clone + Default,
> CloneCache<K, T>
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
}

impl<T: Clone + Default> CloneVecCache<T> {
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
  async fn clone_vec_cache_find_or_insert_default() {
    let cache = CloneVecCache::<u64>::default();
    assert_eq!(cache.find_or_insert_default(|&&v| v == 0).await, 0);
    // Did not insert twice
    assert_eq!(cache.list().await, vec![0]);
    cache.insert(|&v| v == 9, 9).await;
    assert_eq!(cache.find_or_insert_default(|&&v| v == 9).await, 9);
    assert_eq!(cache.list().await.len(), 2);
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
