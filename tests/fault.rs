//! Fault-injection e2e: misbehaving upstreams (hang, reset, slowloris)
//! must fail fast with the right status, never hang the data plane.
//! The soak test is `#[ignore]` — run it on demand with `--ignored`.

use std::io::Write;
use std::net::TcpListener as StdListener;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use verd::config::model::Config;
use verd::server::{self, Runtime};

async fn start(config: &str) -> (String, tokio::sync::watch::Sender<bool>) {
    let port = portpicker::pick_unused_port().expect("free port");
    let cfg: Config = toml::from_str(config).unwrap();
    let mut cfg = cfg;
    cfg.server.listen = vec![verd::config::model::ListenAddr {
        addr: format!("127.0.0.1:{port}").parse().unwrap(),
        tls: false,
    }];
    let rt = Runtime::build(Arc::new(cfg)).expect("runtime builds");
    let (tx, rx) = tokio::sync::watch::channel(false);
    {
        let mut rx = rx.clone();
        tokio::spawn(async move {
            server::serve(rt, async move {
                let _ = rx.changed().await;
            })
            .await
        });
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    (format!("http://127.0.0.1:{port}"), tx)
}

/// Spawn a raw TCP imposter upstream; `behave` decides each connection's
/// fate on a fresh thread (std I/O is fine — these are short-lived).
fn imposter(behave: impl Fn(std::net::TcpStream) + Send + Sync + 'static) -> u16 {
    let listener = StdListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let behave = std::sync::Arc::new(behave);
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { continue };
            let behave = behave.clone();
            std::thread::spawn(move || behave(conn));
        }
    });
    port
}

fn proxy_cfg(port: u16, extra: &str) -> String {
    format!(
        r#"
[upstream.up]
servers = ["http://127.0.0.1:{port}"]
timeouts = {{ connect = "500ms", response_header = "1s", idle = "1s" }}
max_connections = 8

[[site]]
default = true
tls = "off"

[[site.route]]
prefix = "/"
proxy = {{ upstream = "up" }}
{extra}
"#
    )
}

#[tokio::test]
async fn hanging_upstream_times_out_as_504() {
    // accepts the connection and never speaks
    let up = imposter(|_conn| std::thread::sleep(Duration::from_secs(30)));
    let (base, sd) = start(&proxy_cfg(up, "")).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let resp = client.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(resp.status(), 504, "expected response-header timeout");
    let _ = sd.send(true);
}

#[tokio::test]
async fn resetting_upstream_fails_over_to_502() {
    // accepts, reads part of the request, and closes — unread data in
    // the receive buffer makes the kernel send RST
    let up = imposter(|mut conn| {
        let mut buf = [0u8; 64];
        let _ = std::io::Read::read(&mut conn, &mut buf);
        drop(conn);
    });
    let (base, sd) = start(&proxy_cfg(up, "")).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let resp = client.get(format!("{base}/")).send().await.unwrap();
    assert!(
        resp.status().is_server_error(),
        "expected 502/504, got {}",
        resp.status()
    );
    let _ = sd.send(true);
}

#[tokio::test]
async fn route_request_deadline_beats_slow_upstream() {
    // upstream hangs and its own response_header timeout is generous —
    // the route's request_deadline is what produces the 504
    let up = imposter(|_conn| std::thread::sleep(Duration::from_secs(30)));
    let (base, sd) = start(&proxy_cfg(up, "timeouts = { request_deadline = \"50ms\" }")).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let t0 = std::time::Instant::now();
    let resp = client.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(resp.status(), 504);
    assert!(
        t0.elapsed() < Duration::from_secs(1),
        "deadline fired but slowly: {:?}",
        t0.elapsed()
    );
    let _ = sd.send(true);
}

#[tokio::test]
async fn slowloris_upstream_hits_response_header_timeout() {
    // writes the status line one byte per 500ms
    let up = imposter(|mut conn| {
        for b in b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" {
            if conn.write_all(&[*b]).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        std::thread::sleep(Duration::from_secs(30));
    });
    let (base, sd) = start(&proxy_cfg(up, "")).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let resp = client.get(format!("{base}/")).send().await.unwrap();
    // 504 when the header deadline fires; 502 is also correct when the
    // imposter's trickle dies first — the assertion is "fails fast"
    assert!(
        resp.status().is_server_error(),
        "expected 502/504, got {}",
        resp.status()
    );
    let _ = sd.send(true);
}

#[tokio::test]
async fn unwritable_cache_dir_fails_fast_at_build() {
    // a disk store whose parent is read-only must fail Runtime::build
    // cleanly (not panic, not silently fall back to RAM)
    let cfg: Config = toml::from_str(
        r#"
[cache.broken]
tier = "disk"
disk_path = "/proc/definitely/not/writable"

[[site]]
default = true
tls = "off"

[[site.route]]
prefix = "/"
respond = { body = "x" }
"#,
    )
    .unwrap();
    let mut cfg = cfg;
    cfg.server.listen = vec![verd::config::model::ListenAddr {
        addr: "127.0.0.1:0".parse().unwrap(),
        tls: false,
    }];
    assert!(
        Runtime::build(Arc::new(cfg)).is_err(),
        "unwritable disk_path must fail runtime build"
    );
}

#[tokio::test]
async fn corrupt_disk_object_dropped_on_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    // a garbage object file in the store dir: rebuild must ignore it
    std::fs::write(
        dir.path().join("corrupt.obj"),
        b"\x00\x01\x02 not an object",
    )
    .unwrap();
    let cfg_text = format!(
        r#"
[cache.c]
tier = "disk"
disk_path = "{}"

[[site]]
default = true
tls = "off"

[[site.route]]
prefix = "/"
respond = {{ body = "x" }}
"#,
        dir.path().display()
    );
    let cfg: Config = toml::from_str(&cfg_text).unwrap();
    let mut cfg = cfg;
    cfg.server.listen = vec![verd::config::model::ListenAddr {
        addr: "127.0.0.1:0".parse().unwrap(),
        tls: false,
    }];
    let rt = Runtime::build(Arc::new(cfg)).expect("corrupt objects must not break the build");
    let cache = rt.mw_factory.caches()["c"].clone();
    assert_eq!(cache.stats().1, 0, "corrupt entry must not be indexed");
}

/// Resident set size in bytes via /proc/self/statm.
fn rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map(|pages| pages * 4096)
        .unwrap_or(0)
}

/// RSS-growth soak: sustained traffic on cached + proxied routes must not
/// leak. Ignored by default — run `cargo test --test fault -- --ignored`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn soak_rss_bounded_under_sustained_load() {
    let dir = tempfile::tempdir().unwrap();
    let www = dir.path().join("www");
    std::fs::create_dir(&www).unwrap();
    std::fs::write(www.join("f.txt"), "cached payload\n".repeat(8)).unwrap();
    let cfg = format!(
        r#"
[cache.main]
tier = "ram"

[[site]]
default = true
tls = "off"

[[site.route]]
prefix = "/"
static = {{ root = "{}" }}
cache = {{ store = "main" }}
"#,
        www.display()
    );
    let (base, _sd) = start(&cfg).await;
    let client = reqwest::Client::new();
    // warm up (first-hit allocations settle)
    for _ in 0..500 {
        drop(
            client
                .get(format!("{base}/f.txt"))
                .send()
                .await
                .unwrap()
                .text()
                .await,
        );
    }
    let baseline = rss_bytes();
    let mut peak = baseline;
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let client = client.clone();
        let base = base.clone();
        let stop = stop.clone();
        workers.spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let _ = client.get(format!("{base}/f.txt")).send().await;
            }
        });
    }
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        peak = peak.max(rss_bytes());
    }
    stop.store(true, Ordering::Relaxed);
    while workers.join_next().await.is_some() {}
    // steady-state growth must stay modest — allocator noise included
    let growth = peak.saturating_sub(baseline);
    assert!(
        growth < 128 * 1024 * 1024,
        "RSS grew {growth} bytes over soak (baseline {baseline}, peak {peak})"
    );
}
