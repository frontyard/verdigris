//! Disk tier: one object file per cached variant under `objects/`, with a
//! self-describing header (`magic | u32 meta-len | meta JSON | body`).
//!
//! The index is rebuilt by scanning `objects/` at open — the files *are*
//! the durable state, so a crash can only leave a complete object or a
//! `.tmp` partial (deleted on sight). Corrupt headers are skipped and
//! removed. Writes go through tmp+rename so readers never see a
//! half-written object.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-process hasher for object filenames (see `object_path`).
static NAME_HASH: std::sync::LazyLock<ahash::RandomState> =
    std::sync::LazyLock::new(ahash::RandomState::new);

use bytes::Bytes;
use dashmap::DashMap;

use crate::cache::entry::{Meta, accounted_size};
use crate::cache::policy::Order;
use crate::cache::ram::{Stored, same_variant};
use crate::config::model::CacheStore;

/// Object-file magic + format version.
const MAGIC: &[u8; 8] = b"CRDCOBJ1";

/// One indexed variant: metadata plus its object file.
#[derive(Debug)]
struct Slot {
    meta: Meta,
    file: PathBuf,
    /// Lazily-established `mmap` of the object — the `OnceCell` makes
    /// hits after the first pay zero syscalls. `Some(None)` means the
    /// object couldn't be mapped; fall back to the fd path. Reset
    /// whenever the object file is replaced (`freshen`, re-store).
    /// tokio's `OnceCell`, not `OnceLock`: the prefaulted map is built
    /// on the blocking pool — sync `get_or_init` would park a reactor
    /// worker for the whole fault sweep on a cold hit.
    map: std::sync::Arc<tokio::sync::OnceCell<Option<MappedSlot>>>,
}

/// A validated `mmap` of a disk object plus its body offset.
#[derive(Debug)]
struct MappedSlot {
    map: crate::body::FileMap,
    off: u64,
}

impl Clone for Slot {
    fn clone(&self) -> Self {
        Self {
            meta: self.meta.clone(),
            file: self.file.clone(),
            map: self.map.clone(),
        }
    }
}

/// Disk-backed cache store. The in-RAM index maps key-hash → variant
/// slots; bodies stay on disk until read.
pub struct Disk {
    dir: PathBuf,
    index: DashMap<u64, Vec<Slot>>,
    order: Mutex<Order>,
    policy: crate::config::model::EvictionPolicy,
    bytes: AtomicU64,
    items: AtomicU64,
    max_bytes: u64,
    max_items: u64,
}

impl Disk {
    /// Open (and create) the store directory, rebuilding the index from
    /// whatever objects survived — corrupt files are removed. Sync:
    /// called once per generation from `Runtime::build`.
    pub fn open_sync(cfg: &CacheStore) -> Result<Self, String> {
        let Some(dir) = cfg.disk_path.clone() else {
            return Err("disk tier requires disk_path".into());
        };
        let objects = dir.join("objects");
        std::fs::create_dir_all(&objects)
            .map_err(|e| format!("cache dir {}: {e}", dir.display()))?;
        // cached bodies may carry response data not meant for other
        // local users — keep the store owner-only
        crate::fsperm::private_dir(&dir);
        crate::fsperm::private_dir(&objects);
        let store = Self {
            dir,
            index: DashMap::new(),
            order: Mutex::new(Order::new(cfg.policy)),
            policy: cfg.policy,
            bytes: AtomicU64::new(0),
            items: AtomicU64::new(0),
            max_bytes: cfg.disk_bytes.0,
            max_items: cfg.max_items,
        };
        store.rebuild();
        Ok(store)
    }

    /// Scan `objects/`, parsing each header into the index.
    fn rebuild(&self) {
        let objects = self.dir.join("objects");
        let rd = match std::fs::read_dir(&objects) {
            Ok(rd) => rd,
            Err(e) => {
                tracing::warn!(?objects, error = %e, "cache: cannot scan objects dir");
                return;
            }
        };
        let (mut kept, mut dropped) = (0usize, 0usize);
        for e in rd.flatten() {
            let path = e.path();
            let is_tmp = path.extension().is_some_and(|x| x == "tmp");
            if is_tmp || !path.is_file() {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            match read_object_head(&path) {
                Ok(meta) => {
                    let hash = crate::cache::key::fnv1a(&meta.key);
                    self.bytes
                        .fetch_add(accounted_size(&meta), Ordering::Relaxed);
                    self.items.fetch_add(1, Ordering::Relaxed);
                    self.index.entry(hash).or_default().push(Slot {
                        meta,
                        file: path,
                        map: std::sync::Arc::new(tokio::sync::OnceCell::new()),
                    });
                    self.order
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(hash, 0);
                    kept += 1;
                }
                Err(e) => {
                    tracing::warn!(?path, error = %e, "cache: dropping corrupt object");
                    let _ = std::fs::remove_file(&path);
                    dropped += 1;
                }
            }
        }
        if kept + dropped > 0 {
            tracing::info!(kept, dropped, "cache: disk index rebuilt");
        }
    }

    /// Find the slot file for a key+meta pair (vary-matched by caller).
    fn file_for(
        &self,
        hash: u64,
        pred: &(dyn Fn(&Meta) -> bool + Sync),
    ) -> Option<(Meta, PathBuf)> {
        let (meta, file) = {
            let bucket = self.index.get(&hash)?;
            let slot = bucket.iter().find(|s| pred(&s.meta))?;
            (slot.meta.clone(), slot.file.clone())
        };
        Some((meta, file))
    }

    /// Load the object for a previously-indexed meta — the path is
    /// deterministic so no index round-trip is needed. `None` when the
    /// file was evicted or corrupted between index and read.
    pub async fn load_for(&self, meta: &Meta) -> Option<Stored> {
        read_object(&self.object_path(meta)).await.ok()
    }

    /// Disk hit *without* a body copy: the variant's `OnceCell` map is
    /// opened+validated+prefaulted on the blocking pool at first hit,
    /// then every hit serves `Bytes` views straight off the shared
    /// `mmap` — no `open`, `pread`, or `memcpy` in the hot loop. Objects
    /// are immutable once renamed into place, so a stale map can only
    /// outlive an eviction by the duration of one in-flight response —
    /// correct either way. Falls back to an fd+`pread` body when the
    /// object can't be mapped.
    pub async fn load_file(
        &self,
        hash: u64,
        pred: &(dyn Fn(&Meta) -> bool + Sync),
    ) -> Option<Stored> {
        let slot = {
            let bucket = self.index.get(&hash)?;
            bucket.iter().find(|s| pred(&s.meta))?.clone()
        };
        let meta = slot.meta;
        let len = meta.body_len;
        let file = slot.file.clone();
        let body = match slot
            .map
            .get_or_init(move || async move {
                // first-hit mapping prefaults up to `max_object` bytes —
                // keep that fault sweep off the reactor
                tokio::task::spawn_blocking(move || map_object(&file, len))
                    .await
                    .unwrap_or(None)
            })
            .await
            .as_ref()
        {
            Some(m) => crate::cache::ram::StoredBody::Mapped {
                map: m.map.clone(),
                off: m.off,
                len,
            },
            None => {
                // un-mappable object: same hit path via positioned reads
                let file = std::fs::File::open(&slot.file).ok()?;
                let mut head = [0u8; 12];
                std::os::unix::fs::FileExt::read_exact_at(&file, &mut head, 0).ok()?;
                if &head[..8] != MAGIC {
                    return None;
                }
                let off = 12 + u32::from_be_bytes(head[8..12].try_into().unwrap()) as u64;
                if file.metadata().ok()?.len() < off + len {
                    return None;
                }
                crate::cache::ram::StoredBody::File {
                    file: std::sync::Arc::new(file),
                    off,
                    len,
                }
            }
        };
        Some(Stored { meta, body })
    }

    /// Freshen a stored entry after a 304 — rewrite its meta head and
    /// update the index copy.
    pub async fn freshen(
        &self,
        hash: u64,
        pred: &(dyn Fn(&Meta) -> bool + Sync),
        mutate: &(dyn Fn(&mut Meta) + Sync),
    ) -> std::io::Result<()> {
        let Some((mut meta, file)) = self.file_for(hash, pred) else {
            return Ok(());
        };
        mutate(&mut meta);
        let mut stored = read_object(&file)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        stored.meta = meta.clone();
        write_object(&file, &stored).await?;
        if let Some(mut bucket) = self.index.get_mut(&hash)
            && let Some(slot) = bucket.iter_mut().find(|s| same_variant(&s.meta, &meta))
        {
            // the rewrite may shift the body offset — drop any cached map
            slot.meta = meta;
            slot.map = std::sync::Arc::new(tokio::sync::OnceCell::new());
        }
        Ok(())
    }

    /// Variant metas under `hash` (facade does the vary matching).
    pub fn variants(&self, hash: u64) -> Vec<Meta> {
        let out: Vec<Meta> = self
            .index
            .get(&hash)
            .map(|b| b.iter().map(|s| s.meta.clone()).collect())
            .unwrap_or_default();
        if !out.is_empty() {
            self.order
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .touch(hash);
        }
        out
    }

    /// Persist a stored object (tmp+rename), index it, evict to budget.
    pub async fn insert(&self, stored: std::sync::Arc<Stored>) -> std::io::Result<()> {
        let hash = crate::cache::key::fnv1a(&stored.meta.key);
        let file = self.object_path(&stored.meta);
        write_object(&file, stored.as_ref()).await?;

        // index swap under the entry lock
        {
            let mut entry = self.index.entry(hash).or_default();
            if let Some(pos) = entry
                .iter()
                .position(|s| same_variant(&s.meta, &stored.meta))
            {
                let old = entry.swap_remove(pos);
                self.bytes
                    .fetch_sub(accounted_size(&old.meta), Ordering::Relaxed);
                self.items.fetch_sub(1, Ordering::Relaxed);
                if old.file != file {
                    let _ = tokio::fs::remove_file(&old.file).await;
                }
            }
            entry.push(Slot {
                meta: stored.meta.clone(),
                file,
                map: std::sync::Arc::new(tokio::sync::OnceCell::new()),
            });
        }
        self.bytes
            .fetch_add(accounted_size(&stored.meta), Ordering::Relaxed);
        self.items.fetch_add(1, Ordering::Relaxed);
        self.order
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(hash, 0);
        self.evict().await;
        Ok(())
    }

    /// Object path for a meta — deterministic from key + vary within this
    /// process so a re-store overwrites the same file. Hashed with a
    /// per-process random state: a plain FNV filename is a ~2^32-work
    /// collision target, and two (key, vary) pairs sharing one file
    /// overwrite each other forever (still not a content leak — the
    /// embedded `meta.key` is verified against the request on every load).
    fn object_path(&self, meta: &Meta) -> PathBuf {
        let vary = serde_json::to_string(&meta.vary).unwrap_or_default();
        let name = format!("{:016x}", NAME_HASH.hash_one((&meta.key, &vary)));
        self.dir.join("objects").join(name)
    }

    /// Evict buckets until under both budgets.
    async fn evict(&self) {
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
            self.remove_bucket(victim).await;
        }
    }

    async fn remove_bucket(&self, hash: u64) {
        self.order
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(hash);
        if let Some((_, slots)) = self.index.remove(&hash) {
            for s in slots {
                self.bytes
                    .fetch_sub(accounted_size(&s.meta), Ordering::Relaxed);
                self.items.fetch_sub(1, Ordering::Relaxed);
                let _ = tokio::fs::remove_file(&s.file).await;
            }
        }
    }

    /// Remove variant(s) whose meta matches `pred` under `hash`.
    async fn remove_matching(&self, hash: u64, pred: impl Fn(&Meta) -> bool) -> usize {
        let mut removed = Vec::new();
        let mut empty = false;
        if let Some(mut bucket) = self.index.get_mut(&hash) {
            let mut kept = Vec::with_capacity(bucket.len());
            for slot in bucket.drain(..) {
                if pred(&slot.meta) {
                    removed.push(slot);
                } else {
                    kept.push(slot);
                }
            }
            *bucket = kept;
            empty = bucket.is_empty();
        }
        if empty {
            self.index.remove(&hash);
            self.order
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(hash);
        }
        let n = removed.len();
        for s in removed {
            self.bytes
                .fetch_sub(accounted_size(&s.meta), Ordering::Relaxed);
            self.items.fetch_sub(1, Ordering::Relaxed);
            let _ = tokio::fs::remove_file(&s.file).await;
        }
        n
    }

    /// Purge one exact key.
    pub async fn remove_key(&self, key: &str) -> bool {
        self.remove_matching(crate::cache::key::fnv1a(key), |m| m.key == key)
            .await
            > 0
    }

    /// Purge all variants whose path starts with `prefix`.
    pub async fn remove_prefix(&self, prefix: &str) -> usize {
        let mut n = 0;
        let hashes: Vec<u64> = self.index.iter().map(|e| *e.key()).collect();
        for hash in hashes {
            n += self
                .remove_matching(hash, |m| m.path.starts_with(prefix))
                .await;
        }
        n
    }

    /// Drop the index and delete every object.
    pub async fn clear(&self) {
        self.index.clear();
        *self.order.lock().unwrap_or_else(|e| e.into_inner()) = Order::new(self.policy);
        self.bytes.store(0, Ordering::Relaxed);
        self.items.store(0, Ordering::Relaxed);
        let objects = self.dir.join("objects");
        if let Ok(mut rd) = tokio::fs::read_dir(&objects).await {
            while let Ok(Some(e)) = rd.next_entry().await {
                let _ = tokio::fs::remove_file(e.path()).await;
            }
        }
    }

    /// `(bytes, items)` currently held.
    pub fn stats(&self) -> (u64, u64) {
        (
            self.bytes.load(Ordering::Relaxed),
            self.items.load(Ordering::Relaxed),
        )
    }
}

/// Open + validate + map `path` — one-time work behind a slot's
/// `OnceCell`, run on the blocking pool. `None` when the object is
/// unreadable, malformed, or torn.
fn map_object(path: &std::path::Path, body_len: u64) -> Option<MappedSlot> {
    let file = std::fs::File::open(path).ok()?;
    let mut head = [0u8; 12];
    std::os::unix::fs::FileExt::read_exact_at(&file, &mut head, 0).ok()?;
    if &head[..8] != MAGIC {
        return None;
    }
    let off = 12 + u32::from_be_bytes(head[8..12].try_into().unwrap()) as u64;
    let map = match crate::body::FileMap::new(&file) {
        Ok(m) => m,
        Err(e) => {
            // most likely vm.max_map_count (65k default) vs a larger
            // `max_items` — hits silently degrade to the fd path
            static WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                tracing::warn!(error = %e,
                    "cache: object mmap failed; hits fall back to the fd path \
                     (check vm.max_map_count vs max_items)");
            }
            return None;
        }
    };
    // torn or truncated object → treat as a miss, not a short body
    if map.len() < off + body_len {
        return None;
    }
    Some(MappedSlot { map, off })
}

/// Serialize `[magic][len][meta json][body]` to `path` via tmp+rename.
async fn write_object(path: &Path, s: &Stored) -> std::io::Result<()> {
    let Some(body) = s.body.as_mem() else {
        return Err(std::io::Error::other("disk write needs a memory body"));
    };
    let meta = serde_json::to_vec(&s.meta).map_err(std::io::Error::other)?;
    // Unique tmp name per write: two writers to the same key share `path`,
    // and a shared `<hash>.tmp` lets one rename the other's truncated
    // partial. The `*.tmp` suffix still matches boot-time cleanup.
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!("{}.tmp", SEQ.fetch_add(1, Ordering::Relaxed)));
    let mut buf = Vec::with_capacity(meta.len() + body.len() + 12);
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&(meta.len() as u32).to_be_bytes());
    buf.extend_from_slice(&meta);
    buf.extend_from_slice(body);
    tokio::fs::write(&tmp, &buf).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

/// Parse an object file into a `Stored`.
fn parse_object(data: &[u8]) -> Result<Stored, String> {
    if data.len() < 12 || &data[..8] != MAGIC {
        return Err("bad magic".into());
    }
    let mlen = u32::from_be_bytes(data[8..12].try_into().unwrap()) as usize;
    if data.len() < 12 + mlen {
        return Err("truncated meta".into());
    }
    let meta: Meta =
        serde_json::from_slice(&data[12..12 + mlen]).map_err(|e| format!("meta json: {e}"))?;
    Ok(Stored {
        meta,
        body: crate::cache::ram::StoredBody::Mem(Bytes::copy_from_slice(&data[12 + mlen..])),
    })
}

/// Async parse-and-read used on the request path.
async fn read_object(path: &Path) -> Result<Stored, String> {
    let data = tokio::fs::read(path)
        .await
        .map_err(|e| format!("read: {e}"))?;
    parse_object(&data)
}

/// Header-only object read for the boot-time rebuild: parses just the
/// meta — pulling multi-GB bodies through `std::fs::read` (plus their
/// allocations) per object made cold starts quadratic in cache size.
fn read_object_head(path: &Path) -> Result<Meta, String> {
    use std::io::Read as _;
    let mut f = std::fs::File::open(path).map_err(|e| format!("open: {e}"))?;
    let mut head = [0u8; 12];
    f.read_exact(&mut head).map_err(|e| format!("head: {e}"))?;
    if &head[..8] != MAGIC {
        return Err("bad magic".into());
    }
    let mlen = u32::from_be_bytes(head[8..12].try_into().unwrap()) as usize;
    if mlen > 1024 * 1024 {
        return Err("absurd meta length".into());
    }
    let mut m = vec![0u8; mlen];
    f.read_exact(&mut m).map_err(|e| format!("meta: {e}"))?;
    serde_json::from_slice(&m).map_err(|e| format!("meta json: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::cache::entry::{Meta, now_secs};
    use crate::cache::ram::StoredBody;
    use crate::config::ByteSize;
    use crate::config::model::{CacheTier, EvictionPolicy};

    fn cfg(dir: &Path, bytes: u64, items: u64) -> CacheStore {
        CacheStore {
            tier: CacheTier::Disk,
            policy: EvictionPolicy::Lru,
            ram_bytes: ByteSize(0),
            disk_bytes: ByteSize(bytes),
            disk_path: Some(dir.to_path_buf()),
            max_items: items,
            max_object_bytes: ByteSize(1 << 30),
        }
    }

    fn meta(key: &str) -> Meta {
        Meta {
            key: key.to_string(),
            path: "/p".into(),
            status: 200,
            headers: vec![("cache-control".into(), "max-age=60".into())],
            stored_at: now_secs(),
            fresh_for: 60,
            swr_for: 0,
            sie_for: 0,
            etag: Some("\"e1\"".into()),
            last_modified: None,
            vary: vec![],
            negative: false,
            body_len: 4,
        }
    }

    fn stored(key: &str, body: &str) -> Arc<Stored> {
        let mut m = meta(key);
        m.body_len = body.len() as u64;
        Arc::new(Stored {
            meta: m,
            body: StoredBody::Mem(Bytes::from(body.to_string())),
        })
    }

    #[tokio::test]
    async fn write_read_rebuild_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        {
            let d = Disk::open_sync(&cfg(dir.path(), 1 << 20, 100)).unwrap();
            d.insert(stored("k1", "aaaa")).await.unwrap();
            d.insert(stored("k2", "bbbb")).await.unwrap();
        }
        // fresh open rebuilds the index from the object files
        let d = Disk::open_sync(&cfg(dir.path(), 1 << 20, 100)).unwrap();
        assert_eq!(d.stats().1, 2);
        let metas = d.variants(crate::cache::key::fnv1a("k1"));
        assert_eq!(metas.len(), 1);
        let s = d.load_for(&metas[0]).await.unwrap();
        assert_eq!(s.body.as_mem().unwrap(), b"aaaa");
        assert_eq!(s.meta.etag.as_deref(), Some("\"e1\""));
    }

    #[tokio::test]
    async fn rebuild_drops_corrupt_and_tmp() {
        let dir = tempfile::tempdir().unwrap();
        {
            let d = Disk::open_sync(&cfg(dir.path(), 1 << 20, 100)).unwrap();
            d.insert(stored("good", "gg")).await.unwrap();
        }
        let objects = dir.path().join("objects");
        let mut files: Vec<PathBuf> = std::fs::read_dir(&objects)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        // corrupt the good object: garbage mid-file
        let target = files.pop().unwrap();
        let mut b = std::fs::read(&target).unwrap();
        let mid = b.len() / 2;
        b[mid] = b[mid].wrapping_add(0x5a);
        std::fs::write(&target, &b).unwrap();
        // a leftover .tmp partial must be deleted on sight
        std::fs::write(objects.join("orphan.tmp"), b"junk").unwrap();

        let d = Disk::open_sync(&cfg(dir.path(), 1 << 20, 100)).unwrap();
        assert_eq!(d.stats().1, 0, "corrupt object dropped");
        assert!(!objects.join("orphan.tmp").exists(), "tmp removed");
        assert!(!target.exists(), "corrupt object removed");
    }

    #[tokio::test]
    async fn freshen_rewrites_meta_and_purges() {
        let dir = tempfile::tempdir().unwrap();
        let d = Disk::open_sync(&cfg(dir.path(), 1 << 20, 100)).unwrap();
        d.insert(stored("k1", "aaaa")).await.unwrap();
        let hash = crate::cache::key::fnv1a("k1");

        let pred = |m: &Meta| m.key == "k1";
        let mutate = |m: &mut Meta| {
            m.stored_at = now_secs() + 999;
            m.fresh_for = 5;
        };
        d.freshen(hash, &pred, &mutate).await.unwrap();
        let metas = d.variants(hash);
        assert_eq!(metas[0].fresh_for, 5);
        // the file itself was rewritten, not just the index
        let s = d.load_for(&metas[0]).await.unwrap();
        assert_eq!(s.meta.fresh_for, 5);
        assert_eq!(s.body.as_mem().unwrap(), b"aaaa");

        assert!(d.remove_key("k1").await);
        assert_eq!(d.stats().1, 0);
    }

    #[tokio::test]
    async fn disk_budget_evicts_and_removes_files() {
        let dir = tempfile::tempdir().unwrap();
        // ~2 entries of ~1030 bytes
        let d = Disk::open_sync(&cfg(dir.path(), 2150, 100)).unwrap();
        d.insert(stored("k1", "aa")).await.unwrap();
        d.insert(stored("k2", "bb")).await.unwrap();
        d.insert(stored("k3", "cc")).await.unwrap();
        let objects = dir.path().join("objects");
        let n_files = std::fs::read_dir(&objects).unwrap().count();
        assert_eq!(d.stats().1, 2);
        assert_eq!(n_files, 2, "evicted object file removed");
        // LRU: k1 was the victim
        assert!(d.variants(crate::cache::key::fnv1a("k1")).is_empty());
    }

    #[tokio::test]
    async fn open_requires_disk_path() {
        let mut c = cfg(Path::new("/tmp"), 1 << 20, 100);
        c.disk_path = None;
        assert!(Disk::open_sync(&c).is_err());
    }

    #[tokio::test]
    async fn rebuild_missing_objects_dir_warns_and_returns() {
        let dir = tempfile::tempdir().unwrap();
        let d = Disk::open_sync(&cfg(dir.path(), 1 << 20, 100)).unwrap();
        std::fs::remove_dir_all(dir.path().join("objects")).unwrap();
        d.rebuild(); // must not panic — warns and keeps an empty index
        assert_eq!(d.stats().1, 0);
    }

    #[tokio::test]
    async fn load_file_maps_and_serves_body() {
        let dir = tempfile::tempdir().unwrap();
        let d = Disk::open_sync(&cfg(dir.path(), 1 << 20, 100)).unwrap();
        d.insert(stored("k1", "body-data")).await.unwrap();
        let hash = crate::cache::key::fnv1a("k1");
        let s = d.load_file(hash, &|m| m.key == "k1").await.unwrap();
        assert!(matches!(s.body, StoredBody::Mapped { .. }));
        // mapped body serves through cache::respond → Bytes view of the map
        let resp = crate::cache::respond(&s, false);
        let got = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&got[..], b"body-data");
        // second hit reuses the cached map
        let s2 = d.load_file(hash, &|m| m.key == "k1").await.unwrap();
        let resp = crate::cache::respond(&s2, false);
        let got = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&got[..], b"body-data");
        // unknown hash / non-matching pred → miss
        assert!(d.load_file(hash, &|m| m.key == "other").await.is_none());
        assert!(d.load_file(0xdead, &|_| true).await.is_none());
    }

    #[tokio::test]
    async fn load_file_torn_or_corrupt_falls_back_and_misses() {
        let dir = tempfile::tempdir().unwrap();
        let d = Disk::open_sync(&cfg(dir.path(), 1 << 20, 100)).unwrap();
        d.insert(stored("k1", "body-data")).await.unwrap();
        let hash = crate::cache::key::fnv1a("k1");
        let metas = d.variants(hash);
        let file = d.object_path(&metas[0]);

        // corrupt the magic: mmap init fails, fd fallback rejects too
        let mut b = std::fs::read(&file).unwrap();
        b[0] ^= 0xff;
        std::fs::write(&file, &b).unwrap();
        assert!(d.load_file(hash, &|m| m.key == "k1").await.is_none());
    }

    #[tokio::test]
    async fn freshen_missing_or_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let d = Disk::open_sync(&cfg(dir.path(), 1 << 20, 100)).unwrap();
        // nothing under this hash → Ok(()) no-op
        d.freshen(42, &|_| true, &|_| {}).await.unwrap();

        d.insert(stored("k1", "aaaa")).await.unwrap();
        let hash = crate::cache::key::fnv1a("k1");
        let metas = d.variants(hash);
        let file = d.object_path(&metas[0]);
        // corrupt the object → freshen surfaces InvalidData
        std::fs::write(&file, b"junk").unwrap();
        assert!(d.freshen(hash, &|m| m.key == "k1", &|_| {}).await.is_err());
    }

    #[tokio::test]
    async fn variant_replace_reindexes() {
        let dir = tempfile::tempdir().unwrap();
        let d = Disk::open_sync(&cfg(dir.path(), 1 << 20, 100)).unwrap();
        d.insert(stored("k1", "aaaa")).await.unwrap();
        d.insert(stored("k1", "bbbb")).await.unwrap(); // same key+vary → replace
        let hash = crate::cache::key::fnv1a("k1");
        assert_eq!(d.variants(hash).len(), 1);
        let s = d.load_for(&d.variants(hash)[0]).await.unwrap();
        assert_eq!(s.body.as_mem().unwrap(), b"bbbb");
    }

    #[tokio::test]
    async fn remove_prefix_and_clear() {
        let dir = tempfile::tempdir().unwrap();
        let d = Disk::open_sync(&cfg(dir.path(), 1 << 20, 100)).unwrap();
        let mut a = meta("k-a");
        a.path = "/keep/x".into();
        let mut b = meta("k-b");
        b.path = "/drop/y".into();
        let mut c = meta("k-c");
        c.path = "/drop/z".into();
        for (m, body) in [(a, "1"), (b, "2"), (c, "3")] {
            let mut m = m;
            m.body_len = body.len() as u64;
            d.insert(Arc::new(Stored {
                meta: m,
                body: StoredBody::Mem(Bytes::from(body)),
            }))
            .await
            .unwrap();
        }
        assert_eq!(d.remove_prefix("/drop/").await, 2);
        assert_eq!(d.stats().1, 1);

        d.clear().await;
        assert_eq!(d.stats(), (0, 0));
        assert!(
            std::fs::read_dir(dir.path().join("objects"))
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[tokio::test]
    async fn variants_of_one_key_keep_bucket_on_partial_purge() {
        let dir = tempfile::tempdir().unwrap();
        let d = Disk::open_sync(&cfg(dir.path(), 1 << 20, 100)).unwrap();
        let mut m2 = meta("k1");
        m2.vary = vec![("accept".into(), Some("a".into()))];
        m2.body_len = 4;
        d.insert(stored("k1", "aaaa")).await.unwrap();
        d.insert(Arc::new(Stored {
            meta: m2,
            body: StoredBody::Mem(Bytes::from_static(b"bbbb")),
        }))
        .await
        .unwrap();
        let hash = crate::cache::key::fnv1a("k1");
        assert_eq!(d.variants(hash).len(), 2);
        // exact-key purge removes both variants (they share the key)
        assert!(d.remove_key("k1").await);
        assert_eq!(d.stats().1, 0);
    }

    #[tokio::test]
    async fn write_object_rejects_non_memory_body() {
        let dir = tempfile::tempdir().unwrap();
        let f = tempfile::tempfile().unwrap();
        let s = Stored {
            meta: meta("k1"),
            body: StoredBody::File {
                file: Arc::new(f),
                off: 0,
                len: 4,
            },
        };
        assert!(write_object(&dir.path().join("o"), &s).await.is_err());
    }

    #[tokio::test]
    async fn parse_and_head_errors() {
        // bad magic / truncated meta
        assert!(parse_object(b"short").is_err());
        assert!(parse_object(b"notmagic!!1234junkjunk").is_err());
        let mut good = Vec::new();
        good.extend_from_slice(MAGIC);
        good.extend_from_slice(&10u32.to_be_bytes());
        good.extend_from_slice(b"{}");
        assert!(parse_object(&good).is_err()); // truncated meta
        // valid magic + absurd meta length
        let mut absurd = Vec::new();
        absurd.extend_from_slice(MAGIC);
        absurd.extend_from_slice(&(u32::MAX).to_be_bytes());
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o");
        std::fs::write(&p, &absurd).unwrap();
        assert!(read_object_head(&p).is_err());
        // valid meta length but garbage json
        let mut bad = Vec::new();
        bad.extend_from_slice(MAGIC);
        bad.extend_from_slice(&4u32.to_be_bytes());
        bad.extend_from_slice(b"junk");
        std::fs::write(&p, &bad).unwrap();
        assert!(read_object_head(&p).is_err());
        // nonexistent path
        assert!(read_object_head(&dir.path().join("ghost")).is_err());
        assert!(read_object(&p).await.is_err());
    }
}
