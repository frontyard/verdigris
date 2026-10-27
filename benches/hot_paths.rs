//! Per-request hot-path benchmarks, tracked in CI by CodSpeed
//! (`.github/workflows/codspeed.yml`). These cover the work done once
//! or more *per request* — path normalization, host/route matching,
//! cache-key construction — where a perf regression is user-visible.
//! Config parsing is included as a control: cold path, representative
//! of "real" deserialization work.
//!
//! `divan` here is the CodSpeed compat shim — `cargo bench` runs
//! these locally exactly like upstream divan.

use divan::{Bencher, black_box};
use verd::cache::key;
use verd::config::model::Config;
use verd::middleware::Factory;
use verd::router::{self, HostIndex, normalize::normalize_path};

fn main() {
    divan::main();
}

/// A multi-site config exercising exact + wildcard host lookups and a
/// realistic matchit prefix tree.
const CONFIG_TOML: &str = r#"
[[site]]
hosts = ["example.com", "www.example.com"]

[[site.route]]
prefix = "/api/v1/users"
proxy = { upstream = ["http://127.0.0.1:9001"] }

[[site.route]]
prefix = "/api/v1"
proxy = { upstream = ["http://127.0.0.1:9000"] }

[[site.route]]
prefix = "/static"
respond = { body = "ok" }

[[site.route]]
path = "/health"
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
    let mw = Factory::new(&cfg, None).unwrap();
    router::build(&cfg, &mw).unwrap()
}

fn parts() -> http::request::Parts {
    http::Request::builder()
        .method("GET")
        .uri("http://example.com/api/v1/users/42?expand=profile")
        .body(())
        .unwrap()
        .into_parts()
        .0
}

#[divan::bench]
fn parse_config(bencher: Bencher) {
    bencher.bench(|| black_box(toml::from_str::<Config>(black_box(CONFIG_TOML))));
}

#[divan::bench]
fn normalize_request_path(bencher: Bencher) {
    bencher.bench(|| {
        // real callers pass parts.uri.path() — query strings never
        // reach the normalizer, so including one measures work that
        // production never performs
        black_box(normalize_path(black_box("/api//v1/./users/../users/42")))
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

#[divan::bench]
fn match_route(bencher: Bencher) {
    let idx = build_index();
    let site = idx.lookup("example.com").unwrap();
    let parts = parts();
    bencher.bench(|| black_box(site.match_route(black_box(&parts), black_box("/api/v1/users/42"))));
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

#[divan::bench]
fn parent_prefix(bencher: Bencher) {
    bencher.bench(|| {
        black_box(verd::router::normalize::parent_prefix(black_box(
            "/api/v1/users/42/posts/7/comments/3",
        )))
    });
}
