# Mogh Cache

```rust
use std::sync::OnceLock;
use mogh_cache::CloneCache;

type Cache = CloneCache<i64, i64>;

pub fn cache() -> &'static Cache {
  static CACHE: OnceLock<Cache> = OnceLock::new();
  CACHE.get_or_init(Default::default)
}

let entry: Option<i64> = cache().get(&0).await;
```

## TimeoutCache

Lets concurrent / rapid fire calls of an action share one run and
its result:

```rust
let lock = pull_cache().get_lock(image.clone()).await;
// Concurrent callers for the same key wait here.
let mut entry = lock.lock().await;
let now = unix_timestamp_ms();
if entry.last_ts + TIMEOUT_MS > now {
  return entry.clone_res();
}
let res = pull(&image).await;
entry.set(&res, now);
res
```

Entries stay until removed. When the keys come from request input
(an image name, a repo path), prune the stale ones from a periodic
task so the map stays bounded. Entries a caller still holds are
never removed, so pruning can't let two callers run the action at
the same time:

```rust
pull_cache().prune(unix_timestamp_ms() - TIMEOUT_MS).await;
```

## CloneVecCache

`find_or_insert_with` returns the first item matching `find`, or
inserts the one `make` builds. `make` must build an item `find`
matches, otherwise every call inserts another one:

```rust
let terminal = terminals
  .find_or_insert_with(|t| t.name == name, || Terminal::new(&name))
  .await;
```

`find_or_insert_default` is deprecated: `T::default()` rarely
matches a keyed `find`, so each call pushed another default.
