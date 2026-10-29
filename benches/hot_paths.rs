//! Per-request hot-path benchmarks, tracked in CI by CodSpeed
//! (`.github/workflows/codspeed.yml`). These cover the work done once
//! or more *per request* — path normalization, host/route matching,
//! client-IP resolution, upstream selection, cache key + lookup,
//! forwarded-header rewrite, response decoration — where a perf
//! regression is user-visible. Config parsing is included as a
//! control: cold path, representative of "real" deserialization work.
//!
//! Deliberately not covered: `within_header_limit`, `check_ip`,
//! `peer_trusted` (trivial loops over small collections), auth +
//! rate-limit middleware (conditional; token bucket + constant-time
//! compare are atomics-dominated), access-log formatting (stream end,
//! not request hot path), and the streaming body pipeline —
//! throughput-bound, measured by `bench/` wrk suites, not here.
//!
//! Simulation caveat: `upstream_pick` and `cache_lookup_hit` include
//! clock-reading syscalls (health-check `Instant::elapsed`, moka
//! timestamps) that CodSpeed's CPU-simulation can't price — their
//! reported times understate real cost. Regression detection is
//! unaffected: the instruction-count delta still tracks code changes.
//!
//! `divan` here is the CodSpeed compat shim — `cargo bench` runs
//! these locally exactly like upstream divan.

use std::net::IpAddr;

use bytes::Bytes;
use divan::{Bencher, black_box};
use http::HeaderValue;
use verd::cache::{self, entry::Meta, key};
use verd::config::model::{self as cfg, Config, LoadBalancing};
use verd::middleware::{Factory, Security, compress::Compress};
use verd::observe::RequestId;
use verd::proxy::{self, lb};
use verd::router::{self, HostIndex};
use verd::server::service;

fn main() {
    divan::main();
}

/// A multi-site config exercising exact + wildcard host lookups, a
/// realistic matchit prefix tree, method/query route conditions, a
/// regex fallback route, a named least-conn upstream cluster, and a
/// RAM cache store.
const CONFIG_TOML: &str = r#"
[upstream.backend]
servers = [
    "http://127.0.0.1:9001",
    "http://127.0.0.1:9002",
    "http://127.0.0.1:9003",
    "http://127.0.0.1:9004",
]
lb = "least-conn"

[cache.main]
tier = "ram"

[[site]]
hosts = ["example.com", "www.example.com"]

[[site.route]]
prefix = "/api/v1/users"
proxy = { upstream = "backend" }
cache = { store = "main" }

[[site.route]]
prefix = "/api/v1/search"
match = { query = { q = "re:^[a-z0-9-]+$" } }
respond = { body = "search" }

[[site.route]]
prefix = "/api/v1/admin"
match = { methods = ["DELETE"] }
respond = { body = "admin" }

[[site.route]]
regex = "^/app/.*\\.php$"
respond = { body = "php" }

[[site.route]]
prefix = "/api/v1"
proxy = { upstream = ["http://127.0.0.1:9000"] }

[[site.route]]
prefix = "/static"
respond = { body = "ok" }

[[site.route]]
prefix = "/health"
respond = { body = "ok" }

[[site]]
hosts = ["*.example.com"]

[[site.route]]
prefix = "/"
respond = { body = "wild" }

[[site]]
default = true

[[site.route]]
prefix = "/"
respond = { body = "default" }
"#;

fn build_index() -> HostIndex {
    let cfg: Config = toml::from_str(CONFIG_TOML).unwrap();
    let mw = Factory::new(&cfg, None, verd::BuildMode::Live).unwrap();
    router::build(&cfg, &mw).unwrap()
}

fn req_parts(uri: &str) -> http::request::Parts {
    http::Request::builder()
        .method("GET")
        .uri(uri)
        .body(())
        .unwrap()
        .into_parts()
        .0
}

/// Cold-path control: real deserialization work.
#[divan::bench]
fn parse_config(bencher: Bencher) {
    bencher.bench(|| black_box(toml::from_str::<Config>(black_box(CONFIG_TOML))));
}

/// Path normalization — first thing every request pays.
#[divan::bench]
fn normalize_request_path(bencher: Bencher) {
    bencher.bench(|| {
        // real callers pass parts.uri.path() — query strings never
        // reach the normalizer, so including one measures work that
        // production never performs
        black_box(verd::router::normalize::normalize_path(black_box(
            "/api//v1/./users/../users/42",
        )))
    });
}

#[divan::bench]
fn host_lookup_exact(bencher: Bencher) {
    let idx = build_index();
    bencher.bench(|| black_box(idx.lookup(black_box("www.example.com"))));
}

#[divan::bench]
fn host_lookup_wildcard(bencher: Bencher) {
    let idx = build_index();
    bencher.bench(|| black_box(idx.lookup(black_box("cdn.assets.example.com"))));
}

/// First-try hit: matchit resolves the full path on the first `at()`.
#[divan::bench]
fn match_route(bencher: Bencher) {
    let idx = build_index();
    let site = idx.lookup("example.com").unwrap();
    let parts = req_parts("http://example.com/api/v1/users/42?expand=profile");
    bencher.bench(|| black_box(site.match_route(black_box(&parts), black_box("/api/v1/users/42"))));
}

/// The shape that makes `parent_prefix` matter in production: the
/// deepest prefix's routes all fail conditions, so matching climbs
/// parent by parent until a shorter prefix accepts the request.
#[divan::bench]
fn match_route_fallback(bencher: Bencher) {
    let idx = build_index();
    let site = idx.lookup("example.com").unwrap();
    // GET — the DELETE-only /api/v1/admin routes reject, matching
    // climbs /api/v1/admin/panel → /api/v1/admin → /api/v1
    let parts = req_parts("http://example.com/api/v1/admin/panel/7");
    bencher.bench(|| {
        black_box(site.match_route_idx(black_box(&parts), black_box("/api/v1/admin/panel/7")))
    });
}

/// No prefix covers the path — the matchit lookup misses and the
/// linear regex-route scan decides.
#[divan::bench]
fn match_route_regex(bencher: Bencher) {
    let idx = build_index();
    let site = idx.lookup("example.com").unwrap();
    let parts = req_parts("http://example.com/app/x/y/index.php");
    bencher
        .bench(|| black_box(site.match_route(black_box(&parts), black_box("/app/x/y/index.php"))));
}

/// Query-param conditions: the request's query string is parsed and
/// allocated per evaluated candidate.
#[divan::bench]
fn route_conditions_query(bencher: Bencher) {
    let idx = build_index();
    let site = idx.lookup("example.com").unwrap();
    let parts = req_parts("http://example.com/api/v1/search?q=test-123&page=2");
    bencher.bench(|| black_box(site.match_route(black_box(&parts), black_box("/api/v1/search"))));
}

/// Trusted peer + X-Forwarded-For chain: parse each hop, walk
/// right-to-left past trusted CIDRs — per request behind a CDN or LB.
#[divan::bench]
fn real_ip(bencher: Bencher) {
    let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
    let peer: IpAddr = "10.0.0.9".parse().unwrap();
    let mut parts = req_parts("http://example.com/");
    parts.headers.insert(
        "x-forwarded-for",
        HeaderValue::from_static("203.0.113.10, 203.0.113.20, 10.8.0.5"),
    );
    bencher.bench(|| {
        black_box(service::real_ip(
            black_box(peer),
            black_box(&parts),
            black_box(&trusted),
        ))
    });
}

/// Client-supplied `X-Request-Id` present → validate + propagate.
/// (The absent-header path is `uuid` crate's `getrandom` + format —
/// dependency internals we can't regress, and syscall-dominated under
/// simulation, so it's not worth a slot here.)
#[divan::bench]
fn request_id(bencher: Bencher) {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "x-request-id",
        HeaderValue::from_static("7f8a9b2c-3d4e-5f60-9a8b-7c6d5e4f3a2b"),
    );
    bencher.bench(|| black_box(RequestId::extract(black_box(&headers))));
}

/// Least-conn member selection: health-check + in-flight atomic read
/// per member, per proxied request.
#[divan::bench]
fn upstream_pick(bencher: Bencher) {
    let idx = build_index();
    let cluster = idx
        .clusters
        .iter()
        .find(|c| matches!(c.lb, LoadBalancing::LeastConn))
        .unwrap();
    let ip: IpAddr = "203.0.113.7".parse().unwrap();
    bencher.bench(|| {
        black_box(lb::pick(
            black_box(cluster.as_ref()),
            black_box(ip),
            black_box(&[]),
        ))
    });
}

/// `X-Forwarded-*`/`Forwarded` rewrite applied to every proxied
/// request: join-or-set across four header fields.
#[divan::bench]
fn forwarded_headers(bencher: Bencher) {
    bencher
        .with_inputs(|| {
            let mut h = http::HeaderMap::new();
            h.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.7"));
            h
        })
        .bench_local_refs(|h| {
            proxy::headers::set_forwarded(
                black_box(h),
                black_box("10.0.0.9".parse().unwrap()),
                black_box(true),
                black_box("203.0.113.10".parse().unwrap()),
                black_box("https"),
                black_box("example.com"),
            )
        });
}

/// Re-encode the path for the upstream request-target — runs per
/// proxied request on routes with `rewrite` configured (routes
/// without a rewrite forward the original target verbatim; the
/// rewrite result is decoded, so it must be re-encoded upstream).
/// Percent-encoding scan over every byte.
#[divan::bench]
fn encode_path(bencher: Bencher) {
    bencher.bench(|| {
        black_box(proxy::headers::encode_path(black_box(
            "/api/v1/users/björk/42",
        )))
    });
}

#[divan::bench]
fn cache_key_primary(bencher: Bencher) {
    let vary = [
        ("accept-encoding".to_owned(), Some("br".to_owned())),
        ("accept".to_owned(), None),
    ];
    bencher.bench(|| {
        black_box(key::primary(
            black_box(&http::Method::GET),
            black_box("https"),
            black_box("example.com"),
            black_box("/api/v1/users/42?expand=profile&page=2"),
            black_box(&vary),
        ))
    });
}

#[divan::bench]
fn cache_key_authority(bencher: Bencher) {
    bencher.bench(|| black_box(key::key_authority(black_box("Example.COM:8443"))));
}

#[divan::bench]
fn strip_utm_param(bencher: Bencher) {
    bencher.bench(|| {
        black_box(key::strip_query_param(
            black_box("/docs/guide?utm_source=x&utm_medium=y&utm_campaign=z&id=42"),
            black_box("utm_source"),
        ))
    });
}

/// RAM hit: dashmap bucket get + canonical-key verify + vary match —
/// the hot path for every cacheable request.
#[divan::bench]
fn cache_lookup_hit(bencher: Bencher) {
    let cfg: Config = toml::from_str(CONFIG_TOML).unwrap();
    let mw = Factory::new(&cfg, None, verd::BuildMode::Live).unwrap();
    let cache = mw.caches()["main"].clone();
    let key = key::primary(
        &http::Method::GET,
        "https",
        "example.com",
        "/api/v1/users/42?expand=profile&page=2",
        &[],
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(cache.record(
        Meta {
            key: key.raw.clone(),
            path: "/api/v1/users/42".into(),
            status: 200,
            headers: vec![("content-type".into(), "text/plain".into())],
            stored_at: 0,
            fresh_for: 3600,
            swr_for: 0,
            sie_for: 0,
            etag: None,
            last_modified: None,
            vary: vec![],
            negative: false,
            body_len: 5,
        },
        Bytes::from_static(b"hello"),
    ));
    let headers = http::HeaderMap::new();
    assert!(matches!(
        rt.block_on(cache.lookup(&key, &headers)),
        cache::Lookup::Found(_)
    ));
    bencher.bench(|| black_box(rt.block_on(cache.lookup(black_box(&key), black_box(&headers)))));
}

/// Response decoration: insert-if-absent + HSTS `format!` + header-map
/// inserts — every response when security headers are enabled.
#[divan::bench]
fn security_headers(bencher: Bencher) {
    let sec = Security::build(
        &cfg::SecurityConfig {
            enabled: true,
            hsts: true,
            hsts_max_age: std::time::Duration::from_secs(31_536_000),
            hsts_subdomains: true,
            content_type_options: true,
            frame_options: "DENY".into(),
            referrer_policy: "no-referrer".into(),
            csp: Some("default-src 'self'".into()),
            cross_domain_policy: "none".into(),
        },
        None,
        None,
    )
    .unwrap();
    bencher
        .with_inputs(http::HeaderMap::new)
        .bench_local_refs(|h| sec.apply(black_box(h), black_box(true)));
}

/// Per-response compression decision + Accept-Encoding negotiation +
/// body wrap — the middleware cost when compression is enabled.
#[divan::bench]
fn compress_apply(bencher: Bencher) {
    let compress = Compress::build(&cfg::CompressConfig::default()).unwrap();
    let ctx = verd::middleware::compress::ReqCtx {
        method_is_head: false,
        has_range: false,
        accept_encoding: Some("gzip, deflate, br, zstd;q=0.8".into()),
    };
    bencher
        .with_inputs(|| {
            http::Response::builder()
                .header("content-type", "text/html; charset=utf-8")
                .header("content-length", "2048")
                .body(verd::body::full(vec![0u8; 2048]))
                .unwrap()
        })
        .bench_local_refs(|resp| compress.apply(black_box(resp), black_box(&ctx)));
}
