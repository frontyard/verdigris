//! HTTP response cache, per named store (`[cache.<name>]`, routes opt in
//! via `route.cache.store`).
//!
//! Tiers: RAM (bounded `Bytes` objects), disk (`objects/` files with
//! self-describing heads; index rebuilt by scan at open), and hybrid
//! (RAM in front of disk, disk hits promoted into RAM). Eviction policy
//! is shared (`policy::Order`): LRU, LFU, or FIFO over whole buckets.
//!
//! Request flow lives in `server::service`: this facade owns lookup,
//! insertion, request coalescing, freshening (304 → renewed metadata),
//! and admin purge.

mod disk;
pub mod entry;
pub mod key;
mod policy;
mod ram;
pub mod semantics;
pub mod stage;
mod tee;

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;

use crate::cache::disk::Disk;
use crate::cache::entry::Meta;
use crate::cache::key::Key;
use crate::cache::ram::Ram;
pub use crate::cache::ram::Stored;
use crate::cache::semantics::vary_matches;
use crate::config::model as cfg;

/// A named cache store (`[cache.<name>]`).
pub struct Cache {
    /// Store name for admin surfaces.
    pub name: String,
    store: Store,
    /// Responses larger than this are never stored.
    max_object: u64,
    /// In-flight fetches by key hash — followers wait on the slot's
    /// notify and re-lookup once the leader commits.
    inflight: Arc<DashMap<u64, Arc<FetchSlot>>>,
    /// Serialized store config for reload-diff reuse.
    serialized: Option<String>,
    /// Resolved metric handles (`store` label bound once).
    pub meters: crate::observe::metrics::CacheMeters,
}

/// Backing tiers.
enum Store {
    /// `tier = "ram"`.
    Ram(Ram),
    /// `tier = "disk"`.
    Disk(Disk),
    /// `tier = "hybrid"`: RAM read-through, disk authoritative.
    Hybrid { ram: Ram, disk: Disk },
}

/// Coalescing slot for one in-flight fetch.
pub struct FetchSlot {
    done: tokio::sync::Notify,
    finished: std::sync::atomic::AtomicBool,
}

impl FetchSlot {
    /// Wait for the leader to finish. Registered before the flag check so
    /// a wakeup between the two can't be missed.
    pub async fn wait(&self) {
        let notified = self.done.notified();
        tokio::pin!(notified);
        let _ = notified.as_mut().enable();
        if !self.finished.load(std::sync::atomic::Ordering::Acquire) {
            notified.await;
        }
    }
}

/// Leadership over an in-flight fetch — `Drop` wakes followers.
pub struct FetchGuard {
    hash: u64,
    slots: Arc<DashMap<u64, Arc<FetchSlot>>>,
}

impl Drop for FetchGuard {
    fn drop(&mut self) {
        if let Some((_, slot)) = self.slots.remove(&self.hash) {
            slot.finished
                .store(true, std::sync::atomic::Ordering::Release);
            slot.done.notify_waiters();
        }
    }
}

/// Claim a fetch slot: first caller leads; followers get a notify handle.
pub enum Leadership {
    /// This caller fetches from the handler and commits.
    Leader(FetchGuard),
    /// Another fetch is in flight — wait then re-lookup.
    Follower(Arc<FetchSlot>),
}

/// A variant-matched lookup result.
pub enum Lookup {
    /// Entry for this key (freshness decided by the caller via `meta`).
    Found(Arc<Stored>),
    /// Nothing usable.
    Miss,
}

impl Cache {
    /// Whether `c` describes this store exactly (serialized TOML compare —
    /// the model intentionally has no PartialEq).
    fn same_config(&self, c: &cfg::CacheStore) -> bool {
        self.serialized.as_deref() == toml::to_string(c).ok().as_deref()
    }

    /// Build every named store in the config (`Runtime::build` context —
    /// disk rebuild is sync std::fs; it's a one-shot boot cost). `prior`
    /// carries the previous generation's stores: a store whose config is
    /// unchanged is reused whole — RAM contents, open disk index and all.
    pub fn build_all(
        config: &cfg::Config,
        prior: Option<&HashMap<String, Arc<Cache>>>,
    ) -> Result<HashMap<String, Arc<Cache>>, String> {
        let mut out = HashMap::new();
        for (name, c) in &config.cache {
            if let Some(old) = prior.and_then(|p| p.get(name))
                && old.same_config(c)
            {
                out.insert(name.clone(), old.clone());
                continue;
            }
            let store = match c.tier {
                cfg::CacheTier::Ram => Store::Ram(Ram::new(c)),
                cfg::CacheTier::Disk => Store::Disk(Disk::open_sync(c)?),
                cfg::CacheTier::Hybrid => Store::Hybrid {
                    ram: Ram::new(c),
                    disk: Disk::open_sync(c)?,
                },
            };
            out.insert(
                name.clone(),
                Arc::new(Self {
                    name: name.clone(),
                    store,
                    max_object: c.max_object_bytes.0,
                    inflight: Arc::new(DashMap::new()),
                    serialized: toml::to_string(c).ok(),
                    meters: crate::observe::metrics::CacheMeters::new(name),
                }),
            );
        }
        Ok(out)
    }

    /// Variant-matched lookup: variants under `key.hash` are filtered by
    /// canonical-key equality and stored `Vary` values vs this request.
    pub async fn lookup(&self, key: &Key, headers: &http::HeaderMap) -> Lookup {
        let pick = |variants: Vec<Arc<Stored>>| {
            variants
                .into_iter()
                .find(|s| s.meta.key == key.raw && vary_matches(&s.meta.vary, headers))
                .map(Lookup::Found)
                .unwrap_or(Lookup::Miss)
        };
        match &self.store {
            Store::Ram(ram) => pick(ram.get(key.hash)),
            Store::Disk(disk) => disk
                .load_file(key.hash, &|m| {
                    m.key == key.raw && vary_matches(&m.vary, headers)
                })
                .await
                .map(|s| Lookup::Found(Arc::new(s)))
                .unwrap_or(Lookup::Miss),
            Store::Hybrid { ram, disk } => {
                match pick(ram.get(key.hash)) {
                    f @ Lookup::Found(_) => f,
                    Lookup::Miss => {
                        let metas = disk.variants(key.hash);
                        let Some(meta) = metas
                            .into_iter()
                            .find(|m| m.key == key.raw && vary_matches(&m.vary, headers))
                        else {
                            return Lookup::Miss;
                        };
                        match disk.load_for(&meta).await {
                            Some(s) => {
                                // promote on hit: RAM copy for next time
                                let s = Arc::new(s);
                                if s.meta.body_len <= self.max_object {
                                    ram.insert(s.clone());
                                }
                                Lookup::Found(s)
                            }
                            None => Lookup::Miss,
                        }
                    }
                }
            }
        }
    }

    /// Persist a fully-collected response.
    pub async fn record(&self, meta: Meta, body: Bytes) {
        if body.len() as u64 > self.max_object {
            return;
        }
        let stored = Arc::new(Stored {
            meta,
            body: ram::StoredBody::Mem(body),
        });
        match &self.store {
            Store::Ram(ram) => ram.insert(stored),
            Store::Disk(disk) => {
                if let Err(e) = disk.insert(stored).await {
                    tracing::warn!(error = %e, "cache: disk insert failed");
                }
            }
            Store::Hybrid { ram, disk } => {
                if let Err(e) = disk.insert(stored.clone()).await {
                    tracing::warn!(error = %e, "cache: disk insert failed");
                }
                ram.insert(stored);
            }
        }
    }

    /// Freshen a stored entry after a 304 revalidation — updates
    /// `stored_at` and the freshness windows in place.
    pub async fn freshen(
        &self,
        key: &Key,
        headers: &http::HeaderMap,
        mutate: &(dyn Fn(&mut Meta) + Sync),
    ) {
        let pred = |m: &Meta| m.key == key.raw && vary_matches(&m.vary, headers);
        match &self.store {
            Store::Ram(ram) => ram.freshen(key.hash, &pred, mutate),
            Store::Disk(disk) => {
                let _ = disk.freshen(key.hash, &pred, mutate).await;
            }
            Store::Hybrid { ram, disk } => {
                let _ = disk.freshen(key.hash, &pred, mutate).await;
                ram.freshen(key.hash, &pred, mutate);
            }
        }
    }

    /// Request coalescing: leader fetches, followers wait for the
    /// notify then re-lookup.
    pub fn begin_fetch(&self, key: &Key) -> Leadership {
        match self.inflight.entry(key.hash) {
            dashmap::Entry::Occupied(e) => Leadership::Follower(e.get().clone()),
            dashmap::Entry::Vacant(e) => {
                let slot = Arc::new(FetchSlot {
                    done: tokio::sync::Notify::new(),
                    finished: std::sync::atomic::AtomicBool::new(false),
                });
                e.insert(slot.clone());
                Leadership::Leader(FetchGuard {
                    hash: key.hash,
                    slots: self.inflight.clone(),
                })
            }
        }
    }

    /// Remove exactly one key's variants.
    pub async fn purge_key(&self, key: &str) -> bool {
        match &self.store {
            Store::Ram(r) => r.remove_key(key),
            Store::Disk(d) => d.remove_key(key).await,
            Store::Hybrid { ram, disk } => {
                let d = disk.remove_key(key).await;
                ram.remove_key(key) || d
            }
        }
    }

    /// Remove every entry whose path starts with `prefix`.
    pub async fn purge_prefix(&self, prefix: &str) -> usize {
        match &self.store {
            Store::Ram(r) => r.remove_prefix(prefix),
            Store::Disk(d) => d.remove_prefix(prefix).await,
            Store::Hybrid { ram, disk } => {
                let d = disk.remove_prefix(prefix).await;
                ram.remove_prefix(prefix).max(d)
            }
        }
    }

    /// Empty the store.
    pub async fn purge_all(&self) {
        match &self.store {
            Store::Ram(r) => r.clear(),
            Store::Disk(d) => d.clear().await,
            Store::Hybrid { ram, disk } => {
                disk.clear().await;
                ram.clear();
            }
        }
    }

    /// Largest response we'll store — the tee uses it as its cap.
    pub fn max_object(&self) -> u64 {
        self.max_object
    }

    /// `(bytes, items)` currently held — RAM tier counts for hybrid.
    pub fn stats(&self) -> (u64, u64) {
        match &self.store {
            Store::Ram(r) => r.stats(),
            Store::Disk(d) => d.stats(),
            Store::Hybrid { ram, .. } => ram.stats(),
        }
    }
}

/// Freshness classification passthrough for the service layer.
pub use entry::Freshness;

/// Compose a response from a stored entry (HEAD → headers only).
pub fn respond(stored: &Stored, head_only: bool) -> http::Response<crate::body::BoxBody> {
    let body = if head_only {
        crate::body::empty()
    } else {
        match &stored.body {
            ram::StoredBody::Mem(b) => crate::body::full(b.clone()),
            ram::StoredBody::Mapped { map, off, len } => crate::body::mapped(map, *off, *len),
            ram::StoredBody::File { file, off, len } => {
                crate::body::file_shared(file.clone(), *off, *len)
            }
        }
    };
    let mut resp = http::Response::new(body);
    *resp.status_mut() =
        http::StatusCode::from_u16(stored.meta.status).unwrap_or(http::StatusCode::OK);
    *resp.headers_mut() = stored.meta.header_map();
    resp
}
