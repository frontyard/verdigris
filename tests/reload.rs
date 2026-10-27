//! P11 lifecycle e2e: atomic config reload under load, listener diffing,
//! and the admin management API (reload, purge, drain, config, upstreams).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use verd::server::{self, Runtime, Shared};

const BASE_CFG: &str = r#"
[[site]]
default = true
tls = "off"

[[site.route]]
prefix = "/"
respond = { status = 200, body = "v1\n" }
"#;

/// Write a config file with the harness-injected listener + admin port
/// so the on-disk file and the in-memory runtime always agree (a reload
/// re-reads the file verbatim).
fn write_cfg(path: &std::path::Path, port: u16, admin_port: u16, body: &str) {
    write_cfg_ex(path, port, admin_port, "", body);
}

/// `admin_extra` lines land inside the single `[admin]` table (e.g.
/// `token = "…"`); `body` must not declare `[admin]` itself.
fn write_cfg_ex(path: &std::path::Path, port: u16, admin_port: u16, admin_extra: &str, body: &str) {
    let text = format!(
        "[[server.listen]]\naddr = \"127.0.0.1:{port}\"\n\n[admin]\nlisten = \"127.0.0.1:{admin_port}\"\n{admin_extra}\n\n{body}"
    );
    std::fs::write(path, text).unwrap();
}

/// Start a reloadable server: returns base URL, admin URL, the shared
/// handle, the reload channel, and the shutdown sender. The config file
/// at `config_path` is (re)written with bound ports embedded — tests must
/// pass the ports through `ports()` when rewriting the file.
async fn start(
    config_path: &std::path::Path,
) -> (
    String,
    String,
    Arc<Shared>,
    tokio::sync::mpsc::Sender<server::Reload>,
    tokio::sync::watch::Sender<bool>,
) {
    let loaded = verd::config::load(config_path).expect("config loads");
    assert!(loaded.is_valid(), "{:?}", loaded.diagnostics);
    let cfg = loaded.config;
    let port = cfg.server.listen[0].addr.port();
    let admin_port = cfg.admin.listen.port();

    let rt = Runtime::build(Arc::new(cfg)).expect("runtime builds");
    let shared = Shared::new(rt);
    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel(4);
    let (tx, rx) = tokio::sync::watch::channel(false);
    {
        let shared = shared.clone();
        let mut rx = rx.clone();
        let path = config_path.to_path_buf();
        tokio::spawn(async move {
            server::serve_shared(shared, reload_rx, Some(path), async move {
                let _ = rx.changed().await;
            })
            .await
        });
    }
    {
        let shared = shared.clone();
        let rx = rx.clone();
        let tx = reload_tx.clone();
        tokio::spawn(async move { verd::admin::serve(shared, tx, rx).await });
    }
    for _ in 0..100 {
        if shared.load().ready.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (
        format!("http://127.0.0.1:{port}"),
        format!("http://127.0.0.1:{admin_port}"),
        shared,
        reload_tx,
        tx,
    )
}

/// Trigger a reload through the channel and wait for the result.
async fn reload_via_channel(tx: &tokio::sync::mpsc::Sender<server::Reload>) -> Result<(), String> {
    let (done, rx) = tokio::sync::oneshot::channel();
    tx.send(server::Reload {
        cause: "test",
        done: Some(done),
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), rx)
        .await
        .expect("reload reply timed out")
        .expect("reload channel dropped")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reload_swaps_config_under_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("verd.toml");
    let port = portpicker::pick_unused_port().unwrap();
    let admin_port = portpicker::pick_unused_port().unwrap();
    write_cfg(&path, port, admin_port, BASE_CFG);
    let (base, _admin, shared, tx, sd) = start(&path).await;
    let gen0 = shared.load();

    // steady request load while the config file and reload flip
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut load = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let base = base.clone();
        let stop = stop.clone();
        load.spawn(async move {
            let client = reqwest::Client::new();
            while !stop.load(Ordering::Relaxed) {
                let r = client.get(format!("{base}/")).send().await;
                assert!(r.is_ok(), "request failed during reload: {r:?}");
                assert_eq!(r.unwrap().status(), 200);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    // v2 config: different body
    write_cfg(
        &path,
        port,
        admin_port,
        r#"
[[site]]
default = true
tls = "off"

[[site.route]]
prefix = "/"
respond = { status = 200, body = "v2\n" }
"#,
    );
    reload_via_channel(&tx).await.expect("reload succeeds");

    let gen1 = shared.load();
    assert!(
        !Arc::ptr_eq(&gen0, &gen1),
        "reload must swap the runtime generation"
    );
    assert!(gen1.ready.load(Ordering::Relaxed));

    // new generation serves the new body
    let r = reqwest::get(format!("{base}/")).await.unwrap();
    assert_eq!(r.text().await.unwrap(), "v2\n");

    stop.store(true, Ordering::Relaxed);
    while load.join_next().await.is_some() {}
    let _ = sd.send(true);
}

#[tokio::test]
async fn reload_listener_diff_adds_and_removes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("verd.toml");
    let old_port = portpicker::pick_unused_port().unwrap();
    let admin_port = portpicker::pick_unused_port().unwrap();
    write_cfg(&path, old_port, admin_port, BASE_CFG);
    let (_base, _admin, shared, tx, sd) = start(&path).await;
    let new_port = portpicker::pick_unused_port().unwrap();

    // add a second listener: both serve the same generation
    let both = format!(
        "[[server.listen]]\naddr = \"127.0.0.1:{new_port}\"\n\n[admin]\nlisten = \"127.0.0.1:{admin_port}\"\n\n[[server.listen]]\naddr = \"127.0.0.1:{old_port}\"\n\n{BASE_CFG}"
    );
    std::fs::write(&path, both).unwrap();
    reload_via_channel(&tx).await.expect("reload adds listener");

    // both ports serve the new generation
    for port in [old_port, new_port] {
        let r = reqwest::get(format!("http://127.0.0.1:{port}/"))
            .await
            .unwrap();
        assert_eq!(r.text().await.unwrap(), "v1\n");
    }

    // drop the old port entirely: its socket drains and refuses new conns
    write_cfg(&path, new_port, admin_port, BASE_CFG);
    reload_via_channel(&tx)
        .await
        .expect("reload removes listener");

    let r = reqwest::get(format!("http://127.0.0.1:{new_port}/"))
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // old socket closed → TCP connect fails outright
    let conn = std::net::TcpStream::connect(format!("127.0.0.1:{old_port}"));
    assert!(conn.is_err(), "drained listener still accepts");

    let _ = (shared, sd);
}

#[tokio::test]
async fn reload_invalid_config_keeps_old_generation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("verd.toml");
    let port = portpicker::pick_unused_port().unwrap();
    let admin_port = portpicker::pick_unused_port().unwrap();
    write_cfg(&path, port, admin_port, BASE_CFG);
    let (base, _admin, shared, tx, sd) = start(&path).await;
    let gen0 = shared.load();

    std::fs::write(&path, "this is not toml [[[").unwrap();
    let err = reload_via_channel(&tx).await;
    assert!(err.is_err(), "invalid config must fail the reload");
    assert!(Arc::ptr_eq(&gen0, &shared.load()));

    let r = reqwest::get(format!("{base}/")).await.unwrap();
    assert_eq!(r.text().await.unwrap(), "v1\n");
    let _ = sd.send(true);
}

#[tokio::test]
async fn admin_endpoints_config_upstreams_purge_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("verd.toml");
    let port = portpicker::pick_unused_port().unwrap();
    let admin_port = portpicker::pick_unused_port().unwrap();
    write_cfg_ex(
        &path,
        port,
        admin_port,
        r#"token = "s3cret-admin-token""#,
        r#"
[[site]]
default = true
tls = "off"

[[site.route]]
prefix = "/"
respond = { status = 200, body = "v1\n" }

[upstream.app]
servers = ["http://127.0.0.1:1"]

[[site.route]]
prefix = "/app"
proxy = { upstream = "app" }

[cache.main]
tier = "ram"
"#,
    );
    let (base, admin, _shared, tx, sd) = start(&path).await;
    let client = reqwest::Client::new();
    let auth = || {
        client
            .get(format!("{admin}/upstreams"))
            .bearer_auth("s3cret-admin-token")
    };

    // bearer gate: unauthenticated → 401, wrong token → 401
    assert_eq!(
        client
            .get(format!("{admin}/upstreams"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .get(format!("{admin}/upstreams"))
            .bearer_auth("wrong")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );

    // /upstreams lists the cluster + member
    let ups: serde_json::Value = auth().send().await.unwrap().json().await.unwrap();
    let member = &ups["clusters"][0]["members"][0];
    assert_eq!(member["url"], "127.0.0.1:1");
    assert_eq!(member["healthy"], true);
    assert_eq!(member["draining"], false);

    // drain → member leaves rotation; undrain → back
    let r = client
        .post(format!("{admin}/upstreams/app/0/drain"))
        .bearer_auth("s3cret-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let ups: serde_json::Value = auth().send().await.unwrap().json().await.unwrap();
    assert_eq!(ups["clusters"][0]["members"][0]["draining"], true);
    let r = client
        .post(format!("{admin}/upstreams/app/0/undrain"))
        .bearer_auth("s3cret-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // /config is redacted: admin token must not appear
    let cfg: serde_json::Value = client
        .get(format!("{admin}/config"))
        .bearer_auth("s3cret-admin-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let raw = cfg.to_string();
    assert!(!raw.contains("s3cret"), "token leaked: {raw}");
    assert!(raw.contains("***"));

    // /purge all stores
    let r = client
        .post(format!("{admin}/purge"))
        .bearer_auth("s3cret-admin-token")
        .json(&serde_json::json!({ "all": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["purged"]["main"], "all");

    // /reload via the API swaps generations (v2 body)
    write_cfg_ex(
        &path,
        port,
        admin_port,
        r#"token = "s3cret-admin-token""#,
        r#"
[[site]]
default = true
tls = "off"

[[site.route]]
prefix = "/"
respond = { status = 200, body = "v2\n" }
"#,
    );
    let r = client
        .post(format!("{admin}/reload"))
        .bearer_auth("s3cret-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = reqwest::get(format!("{base}/")).await.unwrap();
    assert_eq!(r.text().await.unwrap(), "v2\n");

    let _ = tx;
    let _ = sd.send(true);
}
