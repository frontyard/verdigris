//! Token-bucket rate limiting. Each route's limiter keeps a
//! [`DashMap`]-sharded bucket map keyed by client IP, authenticated
//! identity, the route itself, or a header value. Emits IETF
//! `RateLimit-*` headers on every response and `Retry-After` + `429`
//! when the bucket is empty. `dry_run` never rejects but reports what
//! would have happened.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use http::{HeaderValue, StatusCode};

use crate::config::model as cfg;

/// What the bucket key is derived from.
#[derive(Debug)]
pub enum KeyKind {
    /// Client IP address.
    Ip,
    /// Authenticated identity (falls back to IP when unauthenticated).
    Identity,
    /// One shared bucket per route.
    Route,
    /// Value of a request header.
    Header(http::HeaderName),
}

/// Upper bound on live buckets — attacker-influenced keys (e.g.
/// `header:` kinds) can't grow the map without bound.
const MAX_BUCKETS: usize = 65_536;

/// A token bucket cell.
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Outcome of a rate-limit check.
pub struct Decision {
    /// Whether the request may proceed (always true in dry-run).
    pub allowed: bool,
    /// Whether the bucket was empty (dry-run still reports this).
    pub would_deny: bool,
    /// Remaining whole tokens after this request.
    pub remaining: u64,
    /// Configured limit (`permits` per `period`) for the Limit header.
    pub limit: u64,
    /// Seconds until at least one more token is available (for 429s and
    /// the Reset header's worst case).
    pub retry_after: u64,
}

/// A compiled rate limiter for one route.
pub struct RateLimiter {
    kind: KeyKind,
    rate: f64,
    burst: u32,
    permits: u64,
    period: Duration,
    exempt: Vec<ipnet::IpNet>,
    dry_run: bool,
    buckets: DashMap<String, Bucket>,
    /// Flag set when a dry-run denial was logged at least once per sweep
    /// interval, to keep the log readable.
    dry_run_noted: AtomicBool,
}

impl RateLimiter {
    /// Compile from config.
    pub fn build(c: &cfg::RateLimitConfig) -> Result<Self, String> {
        let kind = match c.key.as_str() {
            "ip" => KeyKind::Ip,
            "identity" => KeyKind::Identity,
            "route" => KeyKind::Route,
            other => {
                let name = other
                    .strip_prefix("header:")
                    .ok_or_else(|| format!("invalid rate_limit key {other:?}"))?;
                KeyKind::Header(
                    http::HeaderName::from_bytes(name.as_bytes())
                        .map_err(|_| format!("invalid rate_limit header name {name:?}"))?,
                )
            }
        };
        let spec = c
            .rate
            .ok_or_else(|| "rate_limit.rate is required when enabled".to_string())?;
        let rate = spec.per_second();
        if !(rate.is_finite() && rate > 0.0) {
            return Err(format!("rate_limit rate must be positive, got {spec}"));
        }
        let burst = c.burst.unwrap_or_else(|| {
            // default burst = one second of rate, at least 1
            rate.ceil().clamp(1.0, u32::MAX as f64) as u32
        });
        Ok(Self {
            kind,
            rate,
            burst,
            permits: spec.permits,
            period: spec.period,
            exempt: c.exempt.clone(),
            dry_run: c.dry_run,
            buckets: DashMap::new(),
            dry_run_noted: AtomicBool::new(false),
        })
    }

    /// True when buckets are keyed on authenticated identity (IP
    /// fallback) — the only kind that benefits from a post-auth second
    /// pass in the pipeline.
    pub fn identity_keyed(&self) -> bool {
        matches!(self.kind, KeyKind::Identity)
    }

    /// The bucket key for this request. Returns `None` when the request is
    /// exempt or the key material is absent (e.g. missing header).
    fn key_for(
        &self,
        ip: IpAddr,
        identity: Option<&str>,
        parts: &http::request::Parts,
        route_id: &str,
    ) -> Option<String> {
        if self.exempt.iter().any(|n| n.contains(&ip)) {
            return None;
        }
        match &self.kind {
            KeyKind::Ip => Some(format!("ip:{ip}")),
            // namespaced: the pre-auth IP fallback and the post-auth
            // identity bucket must not collide on names that look like
            // IPs ("10.0.0.1" as a username)
            KeyKind::Identity => Some(
                identity
                    .map(|id| format!("id:{id}"))
                    .unwrap_or_else(|| format!("ip:{ip}")),
            ),
            KeyKind::Route => Some(format!("route:{route_id}")),
            // A missing/invalid header must not skip the limiter —
            // otherwise omitting it bypasses the rule entirely. Fall
            // back to the client IP so the request is still bounded.
            // The value is hashed, not stored: unique oversized header
            // values would otherwise inflate bucket memory (header cap
            // × bucket cap is GiB-scale).
            KeyKind::Header(name) => Some(
                parts
                    .headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| format!("hdr:{:016x}", crate::cache::key::fnv1a(s)))
                    .unwrap_or_else(|| format!("ip:{ip}")),
            ),
        }
    }

    /// Check and consume one token if available.
    pub fn check(
        &self,
        ip: IpAddr,
        identity: Option<&str>,
        parts: &http::request::Parts,
        route_id: &str,
    ) -> Option<Decision> {
        let key = self.key_for(ip, identity, parts, route_id)?;
        // bucket-table DoS guard: header-keyed (or otherwise attacker-
        // influenced) keys can mint a bucket per request. Cap the table;
        // on overflow evict the stalest entry — a real client refills
        // harmlessly, an attacker just rotates memory bounded.
        if !self.buckets.contains_key(&key)
            && self.buckets.len() >= MAX_BUCKETS
            && let Some(oldest) = self
                .buckets
                .iter()
                .min_by_key(|e| e.value().last)
                .map(|e| e.key().clone())
        {
            self.buckets.remove(&oldest);
        }
        let now = Instant::now();
        let mut b = self.buckets.entry(key).or_insert(Bucket {
            tokens: self.burst as f64,
            last: now,
        });
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.last = now;
        b.tokens = (b.tokens + elapsed * self.rate).min(self.burst as f64);
        let allowed = b.tokens >= 1.0;
        if allowed {
            b.tokens -= 1.0;
        }
        let remaining = b.tokens.floor().max(0.0) as u64;
        let retry_after = if allowed {
            0
        } else {
            ((1.0 - b.tokens) / self.rate).ceil().max(1.0) as u64
        };
        let would_deny = !allowed;
        if would_deny && self.dry_run && !self.dry_run_noted.swap(true, Ordering::Relaxed) {
            tracing::info!(
                permits = self.permits,
                "rate_limit dry_run: bucket empty — request would have been denied"
            );
        }
        Some(Decision {
            allowed: allowed || self.dry_run,
            would_deny,
            remaining,
            limit: self.permits,
            retry_after,
        })
    }

    /// Emit `RateLimit-*` headers for a decision.
    pub fn headers(&self, d: &Decision, headers: &mut http::HeaderMap) {
        let put = |h: &mut http::HeaderMap, name: &'static str, v: String| {
            if let Ok(v) = HeaderValue::from_str(&v) {
                h.insert(http::HeaderName::from_static(name), v);
            }
        };
        put(headers, "ratelimit-limit", self.permits.to_string());
        put(headers, "ratelimit-remaining", d.remaining.to_string());
        put(headers, "ratelimit-reset", d.retry_after.max(1).to_string());
    }

    /// Idle time after which a bucket is evicted by the sweeper.
    pub fn idle_ttl(&self) -> Duration {
        // keep at least 4 full periods or 5 minutes, whichever is longer
        self.period.saturating_mul(4).max(Duration::from_secs(300))
    }

    /// Periodic janitor: drop buckets idle longer than `max_idle` to bound
    /// memory. Called by the runtime sweep task.
    pub fn sweep(&self, max_idle: Duration) {
        let now = Instant::now();
        self.buckets
            .retain(|_, b| now.duration_since(b.last) <= max_idle);
        self.dry_run_noted.store(false, Ordering::Relaxed);
    }

    /// Number of live buckets (for metrics/admin).
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }
}

/// Build the `429` response with `Retry-After`.
pub fn too_many(d: &Decision) -> http::Response<crate::body::BoxBody> {
    let mut resp = http::Response::new(crate::body::full("429 rate limit exceeded\n".to_string()));
    *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    if let Ok(v) = HeaderValue::from_str(&d.retry_after.to_string()) {
        resp.headers_mut().insert(http::header::RETRY_AFTER, v);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn cfg_key(key: &str, rate: &str) -> cfg::RateLimitConfig {
        cfg::RateLimitConfig {
            enabled: true,
            key: key.into(),
            rate: Some(crate::config::RateSpec::parse(rate).unwrap()),
            burst: None,
            exempt: Vec::new(),
            dry_run: false,
        }
    }

    fn parts() -> http::request::Parts {
        http::Request::builder()
            .uri("http://x/")
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    #[test]
    fn bucket_allows_burst_then_denies() {
        let rl = RateLimiter::build(&cfg_key("ip", "2/s")).unwrap();
        // default burst = 2
        let ip = IpAddr::from_str("10.0.0.1").unwrap();
        let p = parts();
        assert!(rl.check(ip, None, &p, "r1").unwrap().allowed);
        assert!(rl.check(ip, None, &p, "r1").unwrap().allowed);
        let d = rl.check(ip, None, &p, "r1").unwrap();
        assert!(!d.allowed);
        assert!(d.retry_after >= 1);
    }

    #[test]
    fn exempt_cidr_skips() {
        let mut c = cfg_key("ip", "1/s");
        c.exempt = vec!["10.0.0.0/8".parse().unwrap()];
        let rl = RateLimiter::build(&c).unwrap();
        let ip = IpAddr::from_str("10.1.2.3").unwrap();
        assert!(rl.check(ip, None, &parts(), "r1").is_none());
    }

    #[test]
    fn identity_falls_back_to_ip() {
        let rl = RateLimiter::build(&cfg_key("identity", "1/s")).unwrap();
        let ip = IpAddr::from_str("10.0.0.1").unwrap();
        let p = parts();
        assert!(rl.check(ip, Some("alice"), &p, "r1").unwrap().allowed);
        // same identity → same bucket even from a different IP
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();
        assert!(!rl.check(ip2, Some("alice"), &p, "r1").unwrap().allowed);
    }

    #[test]
    fn header_key() {
        let rl = RateLimiter::build(&cfg_key("header:X-Tenant", "1/s")).unwrap();
        let ip = IpAddr::from_str("10.0.0.1").unwrap();
        let mut p = parts();
        p.headers.insert("x-tenant", HeaderValue::from_static("t1"));
        assert!(rl.check(ip, None, &p, "r1").unwrap().allowed);
        assert!(!rl.check(ip, None, &p, "r1").unwrap().allowed);
        let mut p2 = parts();
        p2.headers
            .insert("x-tenant", HeaderValue::from_static("t2"));
        assert!(rl.check(ip, None, &p2, "r1").unwrap().allowed);
    }

    #[test]
    fn header_key_material_is_bounded() {
        // bucket keys hold a hash of the header value, not the value —
        // unique oversized values must not inflate the bucket map
        let rl = RateLimiter::build(&cfg_key("header:X-Trace", "1000/s")).unwrap();
        let ip = IpAddr::from_str("10.0.0.1").unwrap();
        for i in 0..64 {
            let mut p = parts();
            let big = format!("{}{i}", "x".repeat(16 * 1024));
            p.headers
                .insert("x-trace", HeaderValue::from_str(&big).unwrap());
            rl.check(ip, None, &p, "r1");
        }
        assert_eq!(rl.buckets.len(), 64);
        for e in rl.buckets.iter() {
            assert!(
                e.key().len() <= 24,
                "unbounded key material: {}",
                e.key().len()
            );
            assert!(e.key().starts_with("hdr:"));
        }
    }

    #[test]
    fn dry_run_never_denies() {
        let mut c = cfg_key("ip", "1/s");
        c.dry_run = true;
        let rl = RateLimiter::build(&c).unwrap();
        let ip = IpAddr::from_str("10.0.0.1").unwrap();
        let p = parts();
        rl.check(ip, None, &p, "r1");
        let d = rl.check(ip, None, &p, "r1").unwrap();
        assert!(d.allowed && d.would_deny);
    }

    #[test]
    fn sweep_evicts_idle() {
        let rl = RateLimiter::build(&cfg_key("ip", "1/s")).unwrap();
        let ip = IpAddr::from_str("10.0.0.1").unwrap();
        rl.check(ip, None, &parts(), "r1");
        assert_eq!(rl.bucket_count(), 1);
        rl.sweep(Duration::ZERO);
        assert_eq!(rl.bucket_count(), 0);
    }
}
