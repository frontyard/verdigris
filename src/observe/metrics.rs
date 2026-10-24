//! Metrics: a `metrics`-facade emitter surface plus the Prometheus
//! recorder/exporter, process stats, and the periodic gauge sweep.
//!
//! Label cardinality is deliberately bounded: route ids come from the
//! config, store/cluster/member names from the config, `status` is the
//! exact three-digit code (the set this server emits is itself small),
//! `method` folds anything non-standard into `OTHER`, and cache `result`
//! is a fixed enum — never raw hosts/paths/headers.
//!
//! Hot-path cost: every `metrics::counter!`/`histogram!` call builds a
//! key and resolves it through the recorder's registry (label
//! allocations, a hash, a locked shard lookup). Emit sites therefore
//! resolve handles once per owning object — [`RouteMeters`] on a
//! `router::Route`, [`MemberMeters`]/[`ClusterMeters`] on the upstream
//! side, [`CacheMeters`] on a store — into `OnceLock`/`DashMap` slots
//! gated by [`installed`]. A steady-state request then costs a handful
//! of atomic ops, not a registry traversal or an allocation.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::Ordering;
use std::time::Instant;

/// Global Prometheus render handle; installed once per process.
static HANDLE: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();

/// Whether a metrics recorder is bound for this process. Handle slots
/// are only filled while this is true — a `metrics::*!` macro evaluated
/// without a recorder yields a permanently no-op handle, which must not
/// be cached (unit tests emit without ever calling [`install`]).
#[inline]
fn installed() -> bool {
    HANDLE.get().is_some()
}

/// Resolve a lazily-bound metric handle. Once a recorder is installed the
/// registration runs once per slot and the `Arc`-backed handle is cheap
/// to clone; before that, `f` yields an ephemeral (no-op) handle that is
/// deliberately not retained — emission self-heals after [`install`].
#[inline]
fn resolve<T: Clone>(slot: &OnceLock<T>, f: impl FnOnce() -> T) -> T {
    if installed() {
        slot.get_or_init(f).clone()
    } else {
        f()
    }
}

/// Histogram buckets (seconds) for request and upstream latencies.
/// Fixed buckets beat the default rolling quantile summary on both ends:
/// recording is a bucket scan of atomic increments instead of a locked
/// reservoir insert, and `le` series aggregate across instances via
/// `histogram_quantile` where client-side `quantile` values cannot.
const DURATION_BUCKETS: &[f64] = &[
    0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

fn builder() -> metrics_exporter_prometheus::PrometheusBuilder {
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .set_buckets(DURATION_BUCKETS)
        .unwrap_or_else(|_| metrics_exporter_prometheus::PrometheusBuilder::new())
}

/// Install the global recorder (idempotent — later runtimes in the same
/// process share the recorder). Returns the render handle.
pub fn install() -> metrics_exporter_prometheus::PrometheusHandle {
    let handle = HANDLE
        .get_or_init(|| {
            builder().install_recorder().unwrap_or_else(|_| {
                // a recorder was already installed (tests); a plain
                // builder handle still renders its registry — but the
                // global facade may be bound elsewhere. Keep this
                // handle for exposition; metric emission is unaffected.
                builder().build_recorder().handle()
            })
        })
        .clone();
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(describe);
    handle
}

/// Install HELP text for every family and pin `verd_build_info`.
fn describe() {
    metrics::describe_counter!("verd_requests_total", "completed requests");
    metrics::describe_histogram!(
        "verd_request_duration_seconds",
        "request wall-clock duration (headers to end of body stream)"
    );
    metrics::describe_counter!(
        "verd_response_bytes_total",
        "response body bytes sent to clients"
    );
    metrics::describe_counter!(
        "verd_request_bytes_total",
        "request body bytes received from clients"
    );
    metrics::describe_counter!("verd_cache_requests_total", "cache lookup outcomes");
    metrics::describe_counter!(
        "verd_upstream_requests_total",
        "upstream fetch attempts by result"
    );
    metrics::describe_gauge!(
        "verd_upstream_healthy",
        "upstream member health, 1 = healthy"
    );
    metrics::describe_gauge!(
        "verd_upstream_inflight",
        "requests currently in flight to an upstream member"
    );
    metrics::describe_histogram!(
        "verd_upstream_duration_seconds",
        "upstream fetch attempt duration"
    );
    metrics::describe_gauge!("verd_active_connections", "open client connections");
    metrics::describe_counter!("verd_connections_total", "accepted client connections");
    metrics::describe_counter!(
        "verd_connections_rejected_total",
        "connections dropped by admission limits"
    );
    metrics::describe_gauge!("verd_active_requests", "requests currently in flight");
    metrics::describe_counter!(
        "verd_tls_handshake_errors_total",
        "failed or timed-out TLS handshakes"
    );
    metrics::describe_counter!(
        "verd_ratelimit_rejected_total",
        "requests rejected with 429"
    );
    metrics::describe_counter!("verd_acme_issuance_total", "ACME issuance attempts");
    metrics::describe_gauge!(
        "verd_cert_expiry_seconds",
        "seconds until certificate not_after"
    );
    metrics::describe_gauge!("verd_cache_bytes", "cache store occupancy in bytes");
    metrics::describe_gauge!("verd_cache_items", "cache store entry count");
    metrics::describe_counter!(
        "verd_tunnels_total",
        "upgraded (WebSocket/CONNECT) tunnels opened"
    );
    metrics::describe_gauge!("verd_tunnels_active", "upgraded tunnels currently open");
    metrics::describe_counter!(
        "verd_tunnel_bytes_total",
        "payload bytes moved by upgraded tunnels"
    );
    metrics::describe_counter!(
        "verd_config_reloads_total",
        "config reload attempts by result"
    );
    metrics::describe_gauge!("verd_build_info", "build information (always 1)");
    metrics::describe_gauge!("verd_process_resident_bytes", "resident set size");
    metrics::describe_counter!("verd_process_cpu_seconds_total", "user+system CPU consumed");
    metrics::describe_gauge!("verd_process_open_fds", "open file descriptors");
    metrics::describe_gauge!("verd_process_threads", "thread count");
    metrics::describe_gauge!("verd_uptime_seconds", "process uptime");
    metrics::gauge!(
        "verd_build_info",
        "version" => env!("CARGO_PKG_VERSION"),
        "commit" => option_env!("VERD_GIT_SHA").unwrap_or("unknown")
    )
    .set(1.0);
}

/// Rendered `/metrics` body (empty when no recorder is installed).
pub fn render() -> String {
    HANDLE.get().map(|h| h.render()).unwrap_or_default()
}

/// The process start instant (uptime gauge).
pub fn started() -> &'static Instant {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now)
}

// ---------- per-object handle caches ----------

/// Method label values; index order matches [`method_idx`].
const METHODS: [&str; 10] = [
    "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS", "CONNECT", "TRACE", "OTHER",
];

/// Bucket the request method into a bounded label index.
fn method_idx(m: &str) -> usize {
    match m {
        "GET" => 0,
        "POST" => 1,
        "PUT" => 2,
        "DELETE" => 3,
        "HEAD" => 4,
        "PATCH" => 5,
        "OPTIONS" => 6,
        "CONNECT" => 7,
        "TRACE" => 8,
        _ => 9,
    }
}

/// Per-route metric handles: resolved on first use, then a `DashMap`
/// read or atomic load per request. Lives on `router::Route`, so every
/// metric stays scoped to the owning config object.
#[derive(Debug)]
pub struct RouteMeters {
    route: metrics::SharedString,
    /// (method index, status code) → requests_total handle.
    requests: dashmap::DashMap<(usize, u16), metrics::Counter>,
    duration: OnceLock<metrics::Histogram>,
    out_bytes: OnceLock<metrics::Counter>,
    in_bytes: OnceLock<metrics::Counter>,
    ratelimit: OnceLock<metrics::Counter>,
}

impl RouteMeters {
    /// Create the slot set for `route` (the config route id).
    pub fn new(route: &str) -> Self {
        Self {
            route: metrics::SharedString::from(route.to_string()),
            requests: dashmap::DashMap::new(),
            duration: OnceLock::new(),
            out_bytes: OnceLock::new(),
            in_bytes: OnceLock::new(),
            ratelimit: OnceLock::new(),
        }
    }

    /// `verd_requests_total{method,status,route}` += 1.
    pub fn request(&self, method: usize, status: u16) {
        let key = (method, status);
        if let Some(c) = self.requests.get(&key) {
            c.increment(1);
            return;
        }
        let method_label = METHODS[key.0.min(METHODS.len() - 1)];
        let mk = || {
            metrics::counter!(
                "verd_requests_total",
                "method" => method_label,
                "status" => status.to_string(),
                "route" => self.route.clone()
            )
        };
        let c = if installed() {
            self.requests.entry(key).or_insert_with(mk).clone()
        } else {
            mk()
        };
        c.increment(1);
    }

    /// `verd_request_duration_seconds{route}` observe.
    pub fn duration(&self, secs: f64) {
        resolve(
            &self.duration,
            || metrics::histogram!("verd_request_duration_seconds", "route" => self.route.clone()),
        )
        .record(secs);
    }

    /// `verd_response_bytes_total{route}` += `n`.
    pub fn out_bytes(&self, n: u64) {
        resolve(
            &self.out_bytes,
            || metrics::counter!("verd_response_bytes_total", "route" => self.route.clone()),
        )
        .increment(n);
    }

    /// `verd_request_bytes_total{route}` += `n`.
    pub fn in_bytes(&self, n: u64) {
        resolve(
            &self.in_bytes,
            || metrics::counter!("verd_request_bytes_total", "route" => self.route.clone()),
        )
        .increment(n);
    }

    /// `verd_ratelimit_rejected_total{route}` += 1.
    pub fn ratelimit(&self) {
        resolve(
            &self.ratelimit,
            || metrics::counter!("verd_ratelimit_rejected_total", "route" => self.route.clone()),
        )
        .increment(1);
    }
}

/// Shared meters for requests that never matched a route (`route="-"`).
fn unmatched() -> &'static RouteMeters {
    static M: OnceLock<RouteMeters> = OnceLock::new();
    M.get_or_init(|| RouteMeters::new("-"))
}

/// Per-upstream-member handles (`cluster`/`member` labels bound once).
pub struct MemberMeters {
    cluster: metrics::SharedString,
    member: metrics::SharedString,
    ok: OnceLock<metrics::Counter>,
    err: OnceLock<metrics::Counter>,
    healthy: OnceLock<metrics::Gauge>,
    inflight: OnceLock<metrics::Gauge>,
}

impl MemberMeters {
    /// Create for one member: `cluster` is shared with the owning
    /// [`ClusterMeters`], `member` is the member's `url.authority()`.
    pub fn new(cluster: metrics::SharedString, member: String) -> Self {
        Self {
            cluster,
            member: metrics::SharedString::from(member),
            ok: OnceLock::new(),
            err: OnceLock::new(),
            healthy: OnceLock::new(),
            inflight: OnceLock::new(),
        }
    }

    /// `verd_upstream_requests_total{cluster,member,result}` += 1.
    pub fn attempt(&self, ok: bool) {
        let (slot, result) = if ok {
            (&self.ok, "ok")
        } else {
            (&self.err, "error")
        };
        resolve(slot, || {
            metrics::counter!(
                "verd_upstream_requests_total",
                "cluster" => self.cluster.clone(),
                "member" => self.member.clone(),
                "result" => result
            )
        })
        .increment(1);
    }

    /// `verd_upstream_healthy{cluster,member}` = 0/1.
    pub fn set_healthy(&self, healthy: bool) {
        resolve(&self.healthy, || {
            metrics::gauge!(
                "verd_upstream_healthy",
                "cluster" => self.cluster.clone(),
                "member" => self.member.clone()
            )
        })
        .set(if healthy { 1.0 } else { 0.0 });
    }

    /// `verd_upstream_inflight{cluster,member}` = `n` — updated on
    /// every fetch checkout/return and refreshed by the gauge sweep.
    pub fn set_inflight(&self, n: usize) {
        resolve(&self.inflight, || {
            metrics::gauge!(
                "verd_upstream_inflight",
                "cluster" => self.cluster.clone(),
                "member" => self.member.clone()
            )
        })
        .set(n as f64);
    }
}

/// Per-cluster handles.
pub struct ClusterMeters {
    cluster: metrics::SharedString,
    duration: OnceLock<metrics::Histogram>,
}

impl ClusterMeters {
    /// Create for cluster `name`.
    pub fn new(name: &str) -> Self {
        Self {
            cluster: metrics::SharedString::from(name.to_string()),
            duration: OnceLock::new(),
        }
    }

    /// The shared `cluster` label for member meters.
    pub fn label(&self) -> metrics::SharedString {
        self.cluster.clone()
    }

    /// `verd_upstream_duration_seconds{cluster}` observe.
    pub fn duration(&self, secs: f64) {
        resolve(&self.duration, || {
            metrics::histogram!("verd_upstream_duration_seconds", "cluster" => self.cluster.clone())
        })
        .record(secs);
    }
}

/// Per-cache-store handles (`store` label bound once). The store name is
/// config-derived; the `result` label is the fixed hit/miss/stale/bypass
/// set.
pub struct CacheMeters {
    store: metrics::SharedString,
    results: dashmap::DashMap<&'static str, metrics::Counter>,
}

impl CacheMeters {
    /// Create for store `name`.
    pub fn new(name: &str) -> Self {
        Self {
            store: metrics::SharedString::from(name.to_string()),
            results: dashmap::DashMap::new(),
        }
    }

    /// `verd_cache_requests_total{store,result}` += 1. `result` is the
    /// static tag string ("HIT"/"MISS"/"STALE"/"BYPASS").
    pub fn result(&self, result: &'static str) {
        if let Some(c) = self.results.get(&result) {
            c.increment(1);
            return;
        }
        let mk = || {
            metrics::counter!(
                "verd_cache_requests_total",
                "store" => self.store.clone(),
                "result" => result.to_ascii_lowercase()
            )
        };
        let c = if installed() {
            self.results.entry(result).or_insert_with(mk).clone()
        } else {
            mk()
        };
        c.increment(1);
    }
}

// ---------- data-plane emit points ----------

/// One completed request (also fired for aborted bodies as 499).
pub fn request_done(rec: &crate::observe::LogRecord) {
    let f = rec.fields();
    let m = f.meters.unwrap_or_else(|| unmatched());
    m.request(method_idx(f.method), f.status);
    m.duration(f.duration_ms as f64 / 1000.0);
    if f.bytes > 0 {
        m.out_bytes(f.bytes);
    }
    if f.req_bytes > 0 {
        m.in_bytes(f.req_bytes);
    }
}

/// Connection opened/closed.
pub fn conn_active(delta: f64) {
    static G: OnceLock<metrics::Gauge> = OnceLock::new();
    resolve(&G, || metrics::gauge!("verd_active_connections")).increment(delta);
}

/// One accepted connection (admitted).
pub fn conn_accepted() {
    static C: OnceLock<metrics::Counter> = OnceLock::new();
    resolve(&C, || metrics::counter!("verd_connections_total")).increment(1);
}

/// A connection dropped by the admission limits.
pub fn conn_rejected() {
    static C: OnceLock<metrics::Counter> = OnceLock::new();
    resolve(&C, || metrics::counter!("verd_connections_rejected_total")).increment(1);
}

/// In-flight request count delta.
pub fn requests_inflight(delta: f64) {
    static G: OnceLock<metrics::Gauge> = OnceLock::new();
    resolve(&G, || metrics::gauge!("verd_active_requests")).increment(delta);
}

/// TLS handshake failure.
pub fn tls_handshake_error() {
    static C: OnceLock<metrics::Counter> = OnceLock::new();
    resolve(&C, || metrics::counter!("verd_tls_handshake_errors_total")).increment(1);
}

/// ACME issuance attempt result.
pub fn acme_issuance(ok: bool) {
    metrics::counter!(
        "verd_acme_issuance_total",
        "result" => if ok { "ok" } else { "error" }
    )
    .increment(1);
}

/// Config reload attempt result.
pub fn config_reload(ok: bool) {
    static OK: OnceLock<metrics::Counter> = OnceLock::new();
    static ERR: OnceLock<metrics::Counter> = OnceLock::new();
    resolve(if ok { &OK } else { &ERR }, || {
        metrics::counter!(
            "verd_config_reloads_total",
            "result" => if ok { "ok" } else { "error" }
        )
    })
    .increment(1);
}

/// An upgraded tunnel opened (counts toward `verd_tunnels_total` and
/// the active gauge).
pub fn tunnel_open() {
    static T: OnceLock<metrics::Counter> = OnceLock::new();
    static A: OnceLock<metrics::Gauge> = OnceLock::new();
    resolve(&T, || metrics::counter!("verd_tunnels_total")).increment(1);
    resolve(&A, || metrics::gauge!("verd_tunnels_active")).increment(1.0);
}

/// A tunnel closed; `up`/`down` are payload bytes client→upstream and
/// upstream→client moved during its life.
pub fn tunnel_close(up: u64, down: u64) {
    static A: OnceLock<metrics::Gauge> = OnceLock::new();
    static UP: OnceLock<metrics::Counter> = OnceLock::new();
    static DOWN: OnceLock<metrics::Counter> = OnceLock::new();
    resolve(&A, || metrics::gauge!("verd_tunnels_active")).decrement(1.0);
    if up > 0 {
        resolve(
            &UP,
            || metrics::counter!("verd_tunnel_bytes_total", "direction" => "up"),
        )
        .increment(up);
    }
    if down > 0 {
        resolve(
            &DOWN,
            || metrics::counter!("verd_tunnel_bytes_total", "direction" => "down"),
        )
        .increment(down);
    }
}

/// Certificate expiry gauge (seconds until not_after) — sweep-cadence.
pub fn cert_expiry(host: &str, secs: f64) {
    metrics::gauge!(
        "verd_cert_expiry_seconds",
        "host" => host.to_string()
    )
    .set(secs.max(0.0));
}

/// Current cache store occupancy gauges — sweep-cadence.
pub fn cache_stats(store: &str, bytes: u64, items: u64) {
    metrics::gauge!(
        "verd_cache_bytes",
        "store" => store.to_string()
    )
    .set(bytes as f64);
    metrics::gauge!(
        "verd_cache_items",
        "store" => store.to_string()
    )
    .set(items as f64);
}

// ---------- process stats (linux /proc) ----------

/// Refresh process-level gauges from `/proc/self`.
pub fn update_process() {
    if let Some(rss) = rss_bytes() {
        metrics::gauge!("verd_process_resident_bytes").set(rss as f64);
    }
    if let Some((cpu, threads)) = cpu_threads() {
        // cpu seconds is monotonic — a real counter (`_total` suffix),
        // not a gauge; absolute() replays the /proc reading as-is.
        metrics::counter!("verd_process_cpu_seconds_total").absolute(cpu as u64);
        metrics::gauge!("verd_process_threads").set(threads as f64);
    }
    if let Some(fds) = open_fds() {
        metrics::gauge!("verd_process_open_fds").set(fds as f64);
    }
    metrics::gauge!("verd_uptime_seconds").set(started().elapsed().as_secs_f64());
}

/// RSS in bytes via `/proc/self/statm` (resident pages × page size).
fn rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * 4096)
}

/// (utime + stime in seconds, thread count) via `/proc/self/stat`.
fn cpu_threads() -> Option<(f64, u64)> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    // fields 14/15/20 (1-based) are utime/stime/num_threads; the comm
    // field may contain spaces — parse past the last ')'
    let after = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = after.split_whitespace().collect();
    // after the comm field, index 0 = state (field 3), so utime is 11,
    // stime 12, num_threads 17
    let ticks_per_sec = 100.0_f64; // CLK_TCK on linux is universally 100
    let utime: f64 = fields.get(11)?.parse().ok()?;
    let stime: f64 = fields.get(12)?.parse().ok()?;
    let threads: u64 = fields.get(17)?.parse().ok()?;
    Some(((utime + stime) / ticks_per_sec, threads))
}

/// Count of open fds via `/proc/self/fd`.
fn open_fds() -> Option<usize> {
    std::fs::read_dir("/proc/self/fd").ok().map(|d| d.count())
}

/// Periodic gauge sweep: process stats + per-store cache occupancy +
/// upstream inflight + cert expiry. Spawned once per serve() generation.
pub async fn sweep(rt: Arc<crate::server::Runtime>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        tick.tick().await;
        update_process();
        for (name, c) in rt.mw_factory.caches() {
            let (bytes, items) = c.stats();
            cache_stats(name, bytes, items);
        }
        for cluster in rt.hosts.clusters.iter() {
            for m in &cluster.members {
                m.meters.set_inflight(m.inflight.load(Ordering::Relaxed));
            }
        }
        if let Some(tls) = &rt.tls {
            for (host, exp) in tls.resolver.cert_expiries() {
                cert_expiry(&host, exp);
            }
        }
    }
}
