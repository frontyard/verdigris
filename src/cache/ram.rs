//! RAM tier: `hash → variant bucket` map with bounded bytes/items and
//! policy-driven whole-bucket eviction.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use dashmap::DashMap;

use crate::cache::entry::{Meta, accounted_size};
use crate::cache::policy::Order;
use crate::config::model::{CacheStore, EvictionPolicy};

/// A fully materialized cached response — the universal representation
/// both tiers hand back on lookup.
#[derive(Debug)]
pub struct Stored {
    /// Response metadata (status, headers, validity, vary).
    pub meta: Meta,
    /// Response body.
    pub body: StoredBody,
}

/// Where a stored response body lives. RAM entries hold `Bytes`; disk
/// entries keep the body in the object file and hand out the open fd +
/// region — a hit streams it with positioned reads instead of pulling a
/// multi-MiB blob through the blocking pool and `copy_from_slice`.
#[derive(Debug, Clone)]
pub enum StoredBody {
    /// In-memory body.
    Mem(Bytes),
    /// Body region `off..off+len` inside an open object file.
    File {
        /// Open fd on the object file (survives eviction unlinks).
        file: std::sync::Arc<std::fs::File>,
        /// Byte offset of the body inside the file.
        off: u64,
        /// Body length.
        len: u64,
    },
    /// Body region `off..off+len` of an `mmap`'d object — the zero-copy
    /// hit path: no fd, no `read(2)`, just `Bytes` views of the map.
    Mapped {
        /// Shared read-only map of the whole object file.
        map: crate::body::FileMap,
        /// Byte offset of the body inside the mapped file.
        off: u64,
        /// Body length.
        len: u64,
    },
}

impl StoredBody {
    /// `Some(bytes)` when the body is memory-resident — disk writes and
    /// tests need this; `None` for file-backed bodies.
    pub fn as_mem(&self) -> Option<&[u8]> {
        match self {
            StoredBody::Mem(b) => Some(b.as_ref()),
            StoredBody::File { .. } | StoredBody::Mapped { .. } => None,
        }
    }
}

/// In-memory cache store.
pub struct Ram {
    buckets: DashMap<u64, Vec<std::sync::Arc<Stored>>>,
    order: Mutex<Order>,
    policy: EvictionPolicy,
    bytes: AtomicU64,
    items: AtomicU64,
    max_bytes: u64,
    max_items: u64,
}

impl Ram {
    /// New store honoring the configured budgets.
    pub fn new(cfg: &CacheStore) -> Self {
        Self {
            buckets: DashMap::new(),
            order: Mutex::new(Order::new(cfg.policy)),
            policy: cfg.policy,
            bytes: AtomicU64::new(0),
            items: AtomicU64::new(0),
            max_bytes: cfg.ram_bytes.0,
            max_items: cfg.max_items,
        }
    }

    /// Variants stored under `hash` (and a policy access).
    pub fn get(&self, hash: u64) -> Vec<std::sync::Arc<Stored>> {
        let out = self
            .buckets
            .get(&hash)
            .map(|b| b.value().clone())
            .unwrap_or_default();
        if !out.is_empty() {
            self.order
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .touch(hash);
        }
        out
    }

    /// Insert or replace the matching variant, then evict to budget.
    pub fn insert(&self, stored: std::sync::Arc<Stored>) {
        let hash = crate::cache::key::fnv1a(&stored.meta.key);
        let size = accounted_size(&stored.meta);
        {
            let mut entry = self.buckets.entry(hash).or_default();
            if let Some(old) = entry
                .iter()
                .position(|s| same_variant(&s.meta, &stored.meta))
            {
                let old = entry.swap_remove(old);
                self.sub(&old.meta);
            }
            entry.push(stored);
        }
        self.bytes.fetch_add(size, Ordering::Relaxed);
        self.items.fetch_add(1, Ordering::Relaxed);
        self.order
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(hash, 0);
        self.evict();
    }

    /// Two metas describe the same variant when their vary sets match.
    fn sub(&self, m: &Meta) {
        self.bytes.fetch_sub(accounted_size(m), Ordering::Relaxed);
        self.items.fetch_sub(1, Ordering::Relaxed);
    }

    /// Evict whole buckets until under both budgets.
    fn evict(&self) {
        loop {
            let over = self.bytes.load(Ordering::Relaxed) > self.max_bytes
                || self.items.load(Ordering::Relaxed) > self.max_items;
            if !over {
                return;
            }
            let victim = self
                .order
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .victim();
            let Some(victim) = victim else { return };
            self.remove_bucket(victim);
        }
    }

    /// Drop a whole variant bucket, correcting the accounting.
    fn remove_bucket(&self, hash: u64) {
        self.order
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(hash);
        if let Some((_, bucket)) = self.buckets.remove(&hash) {
            for s in &bucket {
                self.sub(&s.meta);
            }
        }
    }

    /// Mutate the matching variant's metadata in place (304 freshen —
    /// body untouched).
    pub fn freshen(&self, hash: u64, pred: &dyn Fn(&Meta) -> bool, mutate: &dyn Fn(&mut Meta)) {
        if let Some(mut bucket) = self.buckets.get_mut(&hash) {
            for s in bucket.iter_mut() {
                if pred(&s.meta) {
                    let mut meta = s.meta.clone();
                    mutate(&mut meta);
                    *s = std::sync::Arc::new(Stored {
                        meta,
                        body: s.body.clone(),
                    });
                }
            }
        }
    }

    /// Remove the variant(s) exactly matching `key` (purge by full key).
    pub fn remove_key(&self, key: &str) -> bool {
        let hash = crate::cache::key::fnv1a(key);
        self.remove_matching(hash, |m| m.key == key)
    }

    /// Remove variants whose path starts with `prefix`; `None` removes
    /// the whole bucket.
    pub fn remove_prefix(&self, prefix: &str) -> usize {
        let mut n = 0;
        let hashes: Vec<u64> = self.buckets.iter().map(|e| *e.key()).collect();
        for hash in hashes {
            n += self.remove_matching(hash, |m| m.path.starts_with(prefix)) as usize;
        }
        n
    }

    /// Shared remove primitive: filter a bucket by `pred`.
    fn remove_matching(&self, hash: u64, pred: impl Fn(&Meta) -> bool) -> bool {
        let mut removed_sizes = Vec::new();
        let mut empty = false;
        if let Some(mut bucket) = self.buckets.get_mut(&hash) {
            bucket.retain(|s| {
                if pred(&s.meta) {
                    removed_sizes.push(accounted_size(&s.meta));
                    false
                } else {
                    true
                }
            });
            empty = bucket.is_empty();
        }
        if empty {
            self.buckets.remove(&hash);
            self.order
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(hash);
        }
        for sz in &removed_sizes {
            self.bytes.fetch_sub(*sz, Ordering::Relaxed);
            self.items.fetch_sub(1, Ordering::Relaxed);
        }
        !removed_sizes.is_empty()
    }

    /// Drop everything.
    pub fn clear(&self) {
        self.buckets.clear();
        *self.order.lock().unwrap_or_else(|e| e.into_inner()) = Order::new(self.policy);
        self.bytes.store(0, Ordering::Relaxed);
        self.items.store(0, Ordering::Relaxed);
    }

    /// `(bytes, items)` currently held.
    pub fn stats(&self) -> (u64, u64) {
        (
            self.bytes.load(Ordering::Relaxed),
            self.items.load(Ordering::Relaxed),
        )
    }
}

/// Two entries are the same variant when their recorded vary pairs match.
pub fn same_variant(a: &Meta, b: &Meta) -> bool {
    a.key == b.key && a.vary == b.vary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::entry::Meta;
    use crate::cache::ram::StoredBody;
    use crate::config::ByteSize;
    use crate::config::model::{CacheStore, CacheTier, EvictionPolicy};
    use std::sync::Arc;

    fn store(policy: EvictionPolicy, bytes: u64, items: u64) -> Ram {
        Ram::new(&CacheStore {
            tier: CacheTier::Ram,
            policy,
            ram_bytes: ByteSize(bytes),
            disk_bytes: ByteSize(0),
            disk_path: None,
            max_items: items,
            max_object_bytes: ByteSize(1 << 30),
        })
    }

    fn meta(key: &str) -> Meta {
        Meta {
            key: key.to_string(),
            path: "/p".into(),
            status: 200,
            headers: vec![],
            stored_at: crate::cache::entry::now_secs(),
            fresh_for: 60,
            swr_for: 0,
            sie_for: 0,
            etag: None,
            last_modified: None,
            vary: vec![],
            negative: false,
            body_len: 4,
        }
    }

    fn put(r: &Ram, key: &str, body: &str) {
        r.insert(Arc::new(Stored {
            meta: meta(key),
            body: StoredBody::Mem(bytes::Bytes::from(body.to_string())),
        }));
    }

    #[test]
    fn insert_lookup_and_variant_replace() {
        let r = store(EvictionPolicy::Lru, 1 << 20, 100);
        put(&r, "k1", "aaaa");
        let v = r.get(crate::cache::key::fnv1a("k1"));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].body.as_mem().unwrap(), b"aaaa");
        // replace same variant: item count stays 1
        put(&r, "k1", "bbbb");
        let v = r.get(crate::cache::key::fnv1a("k1"));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].body.as_mem().unwrap(), b"bbbb");
        assert_eq!(r.stats().1, 1);
    }

    #[test]
    fn lru_evicts_least_recently_touched() {
        // room for ~2 entries
        let r = store(EvictionPolicy::Lru, 2100, 100);
        let h = |k: &str| crate::cache::key::fnv1a(k);
        put(&r, "k1", "aa");
        put(&r, "k2", "bb");
        // touch k1 so k2 is oldest
        let _ = r.get(h("k1"));
        put(&r, "k3", "cc");
        assert!(r.get(h("k2")).is_empty(), "k2 evicted");
        assert_eq!(r.get(h("k1")).len(), 1);
        assert_eq!(r.get(h("k3")).len(), 1);
    }

    #[test]
    fn lfu_evicts_least_frequently_used() {
        let r = store(EvictionPolicy::Lfu, 2100, 100);
        let h = |k: &str| crate::cache::key::fnv1a(k);
        put(&r, "k1", "aa");
        put(&r, "k2", "bb");
        // k1 hot, k2 cold
        for _ in 0..4 {
            let _ = r.get(h("k1"));
        }
        put(&r, "k3", "cc");
        assert!(r.get(h("k2")).is_empty(), "k2 (coldest) evicted");
        assert_eq!(r.get(h("k1")).len(), 1);
    }

    #[test]
    fn fifo_evicts_insertion_order() {
        let r = store(EvictionPolicy::Fifo, 2100, 100);
        let h = |k: &str| crate::cache::key::fnv1a(k);
        put(&r, "k1", "aa");
        put(&r, "k2", "bb");
        // touching k1 must NOT save it under FIFO
        let _ = r.get(h("k1"));
        put(&r, "k3", "cc");
        assert!(r.get(h("k1")).is_empty(), "k1 (oldest) evicted");
        assert_eq!(r.get(h("k3")).len(), 1);
    }

    #[test]
    fn item_limit_and_purges() {
        let r = store(EvictionPolicy::Lru, 1 << 20, 2);
        put(&r, "k1", "aa");
        put(&r, "k2", "bb");
        put(&r, "k3", "cc");
        assert_eq!(r.stats().1, 2, "item cap enforced");

        assert!(r.remove_key("k2"));
        put(&r, "k2", "bb");
        // prefix purge by path
        let n = r.remove_prefix("/p");
        assert!(n >= 1);
        r.clear();
        assert_eq!(r.stats(), (0, 0));
    }
}
