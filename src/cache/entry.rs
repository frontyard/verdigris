//! A cached response: metadata shared by both tiers plus the freshness
//! math (TTL, stale-while-revalidate, stale-if-error windows).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Everything needed to serve and revalidate a cached response; the body
/// itself lives alongside (RAM `Bytes` / disk object tail).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    /// Canonical key string — verified on lookup (hash collisions can't
    /// serve the wrong object) and scanned by prefix purge.
    pub key: String,
    /// Request path only — prefix purge matches on this.
    pub path: String,
    /// Response status.
    pub status: u16,
    /// Response headers as stored (name, value pairs).
    pub headers: Vec<(String, String)>,
    /// When the response entered the cache (unix seconds).
    pub stored_at: u64,
    /// Seconds the object stays fresh from `stored_at`.
    pub fresh_for: u64,
    /// Extra seconds past freshness where stale may be served while a
    /// background revalidation runs.
    pub swr_for: u64,
    /// Extra seconds past freshness where stale may be served on error.
    pub sie_for: u64,
    /// ETag for conditional revalidation.
    pub etag: Option<String>,
    /// Last-Modified for conditional revalidation.
    pub last_modified: Option<String>,
    /// `Vary` header names resolved against the original request
    /// (name, value-or-absent) — a new request must match all of these
    /// to be served this variant.
    pub vary: Vec<(String, Option<String>)>,
    /// True when stored via negative caching (error status).
    pub negative: bool,
    /// Body size in bytes (also the size accounting unit plus ~1KiB meta).
    pub body_len: u64,
}

/// Freshness state of an entry at `now`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// `Age` limit not reached — serve directly.
    Fresh,
    /// Past freshness but inside the SWR window — serve + revalidate.
    Swr,
    /// Past freshness, outside SWR but inside the SIE window — serve
    /// only when the fetch fails.
    Sie,
    /// No stale allowance left — revalidate or refetch.
    Dead,
}

impl Meta {
    /// Freshness at the current time.
    pub fn freshness(&self) -> Freshness {
        self.freshness_at(now_secs())
    }

    /// Freshness at `now` (unix seconds).
    pub fn freshness_at(&self, now: u64) -> Freshness {
        let age = now.saturating_sub(self.stored_at);
        if age < self.fresh_for {
            Freshness::Fresh
        } else if age < self.fresh_for + self.swr_for {
            Freshness::Swr
        } else if age < self.fresh_for + self.sie_for {
            Freshness::Sie
        } else {
            Freshness::Dead
        }
    }

    /// Whole-second Age for the `Age` response header.
    pub fn age(&self) -> u64 {
        now_secs().saturating_sub(self.stored_at)
    }

    /// Rebuild the response header map; `Age` is recomputed and
    /// `Content-Length` pinned to the stored body length.
    pub fn header_map(&self) -> http::HeaderMap {
        let mut map = http::HeaderMap::with_capacity(self.headers.len() + 2);
        for (k, v) in &self.headers {
            if let (Ok(name), Ok(value)) = (
                http::header::HeaderName::from_bytes(k.as_bytes()),
                http::HeaderValue::from_str(v),
            ) {
                map.append(name, value);
            }
        }
        map.insert(
            http::header::AGE,
            http::HeaderValue::from(self.age().min(u32::MAX as u64) as u32),
        );
        map.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from(self.body_len.min(usize::MAX as u64) as usize),
        );
        map
    }

    /// Apply a successful (304) revalidation: new `stored_at`, optionally
    /// refreshed freshness parameters when the 304 carried its own
    /// `Cache-Control`/`Expires`.
    pub fn freshen(&mut self, fresh_for: Option<u64>, swr_for: Option<u64>, sie_for: Option<u64>) {
        self.stored_at = now_secs();
        if let Some(f) = fresh_for {
            self.fresh_for = f;
        }
        if let Some(s) = swr_for {
            self.swr_for = s;
        }
        if let Some(s) = sie_for {
            self.sie_for = s;
        }
        // A 304 may rotate validators — take new ones when present.
    }
}

/// Unix seconds now; `0` before the epoch (never in practice).
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Estimated per-entry overhead added to `body_len` for limit accounting.
pub const META_OVERHEAD: u64 = 1024;

/// Total accounted size of an entry.
pub fn accounted_size(m: &Meta) -> u64 {
    m.body_len + META_OVERHEAD
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(fresh: u64, swr: u64, sie: u64) -> Meta {
        Meta {
            key: "k".into(),
            path: "/p".into(),
            status: 200,
            headers: vec![],
            stored_at: now_secs(),
            fresh_for: fresh,
            swr_for: swr,
            sie_for: sie,
            etag: None,
            last_modified: None,
            vary: vec![],
            negative: false,
            body_len: 10,
        }
    }

    #[test]
    fn freshness_windows() {
        let mut m = meta(10, 20, 60);
        let t0 = m.stored_at;
        assert_eq!(m.freshness_at(t0 + 5), Freshness::Fresh);
        assert_eq!(m.freshness_at(t0 + 10), Freshness::Swr);
        assert_eq!(m.freshness_at(t0 + 31), Freshness::Sie);
        assert_eq!(m.freshness_at(t0 + 71), Freshness::Dead);
        m.fresh_for = 0;
        assert_eq!(m.freshness_at(t0), Freshness::Swr);
    }
}
