//! P10 observability e2e: access-log golden fields + filters, 499 on
//! client abort, Prometheus scrape, and readiness gating.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use verd::config::model::Config;
use verd::server::{self, Runtime};

/// Start a server on an ephemeral port; returns base URL, admin URL,
/// runtime handle and a shutdown sender.
async fn start(
    config: &str,
) -> (
    String,
    String,
    Arc<Runtime>,
    tokio::sync::watch::Sender<bool>,
) {
    let port = portpicker::pick_unused_port().expect("free port");
    let admin_port = portpicker::pick_unused_port().expect("free admin port");
    let cfg: Config = toml::from_str(config).unwrap();
    let mut cfg = cfg;
    cfg.server.listen = vec![verd::config::model::ListenAddr {
        addr: format!("127.0.0.1:{port}").parse().unwrap(),
        tls: false,
    }];
    cfg.admin.listen = format!("127.0.0.1:{admin_port}").parse().unwrap();

    let rt = Runtime::build(Arc::new(cfg)).expect("runtime builds");
    // readiness gate: config valid + runtime built, but listeners are not
    // bound yet — /ready must still refuse traffic
    assert!(
        !rt.ready.load(Ordering::Relaxed),
        "ready before listeners bound"
    );

    let (tx, rx) = tokio::sync::watch::channel(false);
    {
        let rt = rt.clone();
        let mut rx = rx.clone();
        tokio::spawn(async move {
            server::serve(rt, async move {
                let _ = rx.changed().await;
            })
            .await
        });
    }
    {
        let shared = verd::server::Shared::new(rt.clone());
        let (reload_tx, _reload_rx) = tokio::sync::mpsc::channel(1);
        let rx = rx.clone();
        tokio::spawn(async move { verd::admin::serve(shared, reload_tx, rx).await });
    }
    for _ in 0..100 {
        if rt.ready.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        rt.ready.load(Ordering::Relaxed),
        "server never became ready"
    );
    (
        format!("http://127.0.0.1:{port}"),
        format!("http://127.0.0.1:{admin_port}"),
        rt,
        tx,
    )
}

/// Read the log file once it contains at least `want` lines.
async fn read_log(path: &std::path::Path, want: usize) -> Vec<String> {
    for _ in 0..100 {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        if lines.len() >= want {
            return lines;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("log {} never reached {want} lines", path.display());
}

#[tokio::test]
async fn access_log_json_fields_and_filter() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("access.log");
    let cfg = format!(
        r#"
[log.access]
output = "{log}"
filter = 'path != "/skip"'

[[site]]
default = true
tls = "off"

[[site.route]]
path = "/"
respond = {{ status = 200, body = "hi\n" }}

[[site.route]]
path = "/skip"
respond = {{ status = 200, body = "skip\n" }}
"#,
        log = log.display()
    );
    let (base, _admin, _rt, sd) = start(&cfg).await;
    let client = reqwest::Client::new();

    let r = client
        .get(format!("{base}/"))
        .header("host", "h.test")
        .header("user-agent", "observe-test/1.0")
        .header("referer", "https://ref.example/")
        .header("x-request-id", "obs-1")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "hi\n");

    // filtered out — must never appear in the file
    let r = client.get(format!("{base}/skip")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    drop(r);

    let lines = read_log(&log, 1).await;
    assert_eq!(lines.len(), 1, "filtered request leaked into the log");
    let rec: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();

    // the golden field set the mission requires
    assert_eq!(rec["req_id"], "obs-1");
    assert_eq!(rec["method"], "GET");
    assert_eq!(rec["path"], "/");
    assert_eq!(rec["host"], "h.test");
    assert_eq!(rec["status"], 200);
    assert_eq!(rec["bytes"], 3);
    assert_eq!(rec["user_agent"], "observe-test/1.0");
    assert_eq!(rec["referer"], "https://ref.example/");
    assert_eq!(rec["proto"], "HTTP/1.1");
    assert!(rec["tls"].is_null());
    assert!(
        rec["client_ip"]
            .as_str()
            .unwrap()
            .parse::<std::net::IpAddr>()
            .is_ok()
    );
    assert!(rec["duration_ms"].is_number());
    assert!(rec["route"].is_string());
    // RFC 3339 timestamp
    let ts = rec["ts"].as_str().unwrap();
    assert!(ts.contains('T') && ts.ends_with('Z'), "{ts}");
    let _ = sd.send(true);
}

#[tokio::test]
async fn client_abort_mid_body_logs_499() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("access.log");
    // an 8 MiB static file: the streaming body cannot complete after the
    // client closes, so the record must come out as 499
    let www = dir.path().join("www");
    std::fs::create_dir(&www).unwrap();
    std::fs::write(www.join("big.bin"), vec![0xabu8; 8 * 1024 * 1024]).unwrap();
    let cfg = format!(
        r#"
[log.access]
output = "{log}"

[[site]]
default = true
tls = "off"

[[site.route]]
path = "/"
static = {{ root = "{www}" }}
"#,
        log = log.display(),
        www = www.display()
    );
    let (base, _admin, _rt, sd) = start(&cfg).await;
    let port: u16 = base.rsplit(':').next().unwrap().parse().unwrap();

    // raw client: read the response headers, then close without draining
    // the body. The FIN+RST on the unread data fails the server's writes.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut conn = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        conn.write_all(b"GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n"),
    )
    .await
    .unwrap()
    .unwrap();
    let mut head = vec![0u8; 1024];
    let _ = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut head))
        .await
        .unwrap()
        .unwrap();
    drop(conn);

    let lines = read_log(&log, 1).await;
    let rec: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(rec["status"], 499, "abort should log 499: {rec}");
    assert!(rec["bytes"].as_u64().unwrap() < 8 * 1024 * 1024);
    let _ = sd.send(true);
}

#[tokio::test]
async fn full_body_response_does_not_log_499() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("access.log");
    let cfg = format!(
        r#"
[log.access]
output = "{log}"

[[site]]
default = true
tls = "off"

[[site.route]]
path = "/"
respond = {{ status = 200, body = "complete\n" }}
"#,
        log = log.display()
    );
    let (base, _admin, _rt, sd) = start(&cfg).await;
    let r = reqwest::get(format!("{base}/")).await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "complete\n");

    let lines = read_log(&log, 1).await;
    let rec: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(rec["status"], 200);
    assert_eq!(rec["bytes"], 9);
    let _ = sd.send(true);
}

/// Minimal upstream: answers 200 to everything after draining the body.
async fn start_upstream() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(|req| async move {
                    let _ = http_body_util::BodyExt::collect(req.into_body()).await;
                    Ok::<_, std::convert::Infallible>(http::Response::new(
                        http_body_util::Full::new(bytes::Bytes::from("up\n")),
                    ))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    port
}

#[tokio::test]
async fn metrics_scrape_names_and_labels() {
    let up_port = start_upstream().await;
    let cfg = format!(
        r#"
[[site]]
default = true
tls = "off"

[[site.route]]
path = "/"
respond = {{ status = 200, body = "m\n" }}

[[site.route]]
path = "/proxy"
proxy = {{ upstream = ["http://127.0.0.1:{up_port}"] }}
"#
    );
    let (base, admin, _rt, sd) = start(&cfg).await;
    let client = reqwest::Client::new();
    let resp = client.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    drop(resp);
    // a body-carrying request so request_bytes_total has a series
    // (the proxy consumes the request body; `respond` never reads it)
    let resp = client
        .post(format!("{base}/proxy"))
        .body("ping")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    drop(resp);

    // /ready + /health live on the admin listener
    let ready = reqwest::get(format!("{admin}/ready")).await.unwrap();
    assert_eq!(ready.status(), 200);
    let health = reqwest::get(format!("{admin}/health")).await.unwrap();
    assert_eq!(health.status(), 200);

    let text = reqwest::get(format!("{admin}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    // request counter with bounded route label + status
    assert!(
        text.contains("verd_requests_total{") && text.contains("status=\"200\""),
        "missing requests_total: {text}"
    );
    assert!(text.contains("route="), "missing route label: {text}");
    assert!(
        text.contains("method=\"GET\""),
        "missing method label: {text}"
    );
    assert!(
        text.contains("verd_request_duration_seconds_bucket{route=") && text.contains("le="),
        "missing bucketed duration histogram: {text}"
    );
    assert!(text.contains("verd_response_bytes_total{route="));
    assert!(
        text.contains("verd_request_bytes_total{route="),
        "missing request_bytes_total: {text}"
    );
    assert!(
        text.contains("verd_upstream_requests_total{cluster=") && text.contains("result=\"ok\""),
        "missing upstream_requests_total: {text}"
    );
    assert!(text.contains("verd_upstream_healthy{cluster="));
    assert!(text.contains("verd_upstream_inflight{cluster="));
    assert!(text.contains("verd_upstream_duration_seconds_bucket{cluster="));
    assert!(text.contains("verd_active_connections"));
    assert!(text.contains("verd_connections_total"));
    assert!(text.contains("verd_process_resident_bytes"));
    assert!(text.contains("verd_process_open_fds"));
    assert!(text.contains("verd_process_threads"));
    assert!(text.contains("verd_uptime_seconds"));
    assert!(
        text.contains("verd_build_info{version="),
        "missing build_info: {text}"
    );
    let _ = sd.send(true);
}
