//! ACME end-to-end tests against [Pebble](https://github.com/letsencrypt/pebble)
//! running in Docker. The test orchestrates a private docker network:
//!
//! ```text
//! ┌────────────┐  ACME dir HTTPS :14000   ┌──────────────────────────┐
//! │  pebble    │ ◄──────────────────────  │  verd (this test)     │
//! │  (CA+VA)   │ ── http-01 GET ─────────►│  0.0.0.0:5002 (plain)    │
//! │            │ ── tls-alpn-01 hello ───►│  0.0.0.0:5001 (TLS)      │
//! └────┬───────┘                          └──────────────────────────┘
//!      │ DNS lookup verd.test ──►  gateway IP (host)
//! ┌────┴───────┐
//! │ challtestsrv│  all names → gateway IP, so the VA reaches the host
//! └────────────┘
//! ```
//!
//! The test skips cleanly when docker or the images are unavailable —
//! CI pulls them beforehand (see the release/CI workflow).
//!
//! Ports 5001/5002/14000/8053 must be free on the host.

use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use verd::config::model as cfg;
use verd::server::{self, Runtime};

const HTTP01_PORT: u16 = 5002;
const TLSALPN_PORT: u16 = 5001;
const CTS_DNS_PORT: u16 = 8053;
const CTS_MGMT_PORT: u16 = 8055;
const PEBBLE_DIR: &str = "https://localhost:14000/dir";
const PEBBLE_IMG: &str = "ghcr.io/letsencrypt/pebble:latest";
const CTS_IMG: &str = "ghcr.io/letsencrypt/pebble-challtestsrv:latest";

/// One docker command; returns trimmed stdout.
fn docker(args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new("docker")
        .args(args)
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("docker: {e}"))?;
    if !out.status.success() {
        return Err(format!("docker {args:?} failed"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// `docker` available and daemon reachable.
fn docker_ok() -> bool {
    std::process::Command::new("docker")
        .args(["info"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn image_present(img: &str) -> bool {
    docker(&["image", "inspect", img]).is_ok()
}

/// Pull the pebble images if missing; `false` when unobtainable.
fn ensure_images() -> bool {
    for img in [PEBBLE_IMG, CTS_IMG] {
        if image_present(img) {
            continue;
        }
        let ok = std::process::Command::new("docker")
            .args(["pull", img])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            return false;
        }
    }
    true
}

/// A TCP port check before binding the stack.
fn port_free(port: u16) -> bool {
    std::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).is_ok()
}

/// Cleanup guard: `docker rm -f` the containers and remove the network.
struct Stack {
    name: String,
    containers: Vec<String>,
}

impl Stack {
    /// Bring up network + challtestsrv + pebble; returns the gateway IP
    /// (what `verd.test` resolves to — it must reach the host).
    fn up() -> Result<Self, String> {
        let name = format!("verd-acme-{}", std::process::id());
        docker(&["network", "create", &name])?;
        let mut stack = Stack {
            name: name.clone(),
            containers: vec![],
        };
        let r = stack.up_inner();
        if r.is_err() {
            stack.teardown();
        }
        r.map(|_| stack)
    }

    fn up_inner(&mut self) -> Result<(), String> {
        let cts = format!("{}-cts", self.name);
        let pebble = format!("{}-pebble", self.name);
        self.containers = vec![cts.clone(), pebble.clone()];

        // gateway first — DNS answers must point at the host
        let gateway = docker(&[
            "network",
            "inspect",
            &self.name,
            "--format",
            "{{range .IPAM.Config}}{{.Gateway}}{{end}}",
        ])?;
        // challtestsrv: DNS inside the network, answers = gateway IP;
        // empty AAAA or the VA prefers ::1 and fails (pebble's own
        // compose sets -defaultIPv6 "" for the same reason). The DNS and
        // management ports are published for the dns-01 test: verd's
        // propagation check queries 8053, the mock Cloudflare API pushes
        // TXT records through 8055.
        docker(&[
            "run",
            "-d",
            "--name",
            &cts,
            "--network",
            &self.name,
            "-p",
            &format!("127.0.0.1:{CTS_DNS_PORT}:8053"),
            "-p",
            &format!("127.0.0.1:{CTS_DNS_PORT}:8053/udp"),
            "-p",
            &format!("127.0.0.1:{CTS_MGMT_PORT}:8055"),
            CTS_IMG,
            "-defaultIPv6",
            "",
            "-defaultIPv4",
            &gateway,
        ])?;
        let cts_ip = docker(&[
            "inspect",
            &cts,
            "--format",
            &format!(
                "{{{{(index .NetworkSettings.Networks \"{}\").IPAddress}}}}",
                self.name
            ),
        ])?;
        // pebble: dir on host :14000, DNS via challtestsrv, no VA sleep
        docker(&[
            "run",
            "-d",
            "--name",
            &pebble,
            "--network",
            &self.name,
            "-p",
            "14000:14000",
            "-p",
            "15000:15000",
            "-e",
            "PEBBLE_VA_NOSLEEP=1",
            PEBBLE_IMG,
            "-dnsserver",
            &format!("{cts_ip}:8053"),
            "-strict",
        ])?;
        Ok(())
    }

    /// Wait until pebble's ACME port is bound (TLS comes last in startup).
    async fn wait_ready(&self) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if tokio::net::TcpStream::connect("127.0.0.1:14000")
                .await
                .is_ok()
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        Err("pebble directory never became ready".into())
    }

    /// The static minica root that signs pebble's API TLS cert — our
    /// `acme.ca_roots` for talking to the directory. The image is
    /// distroless, so extract via `docker cp` into `dir`.
    fn copy_minica(&self, dir: &std::path::Path) -> Result<(), String> {
        docker(&[
            "cp",
            &format!("{}-pebble:/test/certs/pebble.minica.pem", self.name),
            &dir.join("pebble.minica.pem").display().to_string(),
        ])
        .map(|_| ())
    }

    fn teardown(&mut self) {
        for c in &self.containers {
            let _ = docker(&["rm", "-f", c]);
        }
        let _ = docker(&["network", "rm", &self.name]);
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Start a verd Runtime with `hosts` on 0.0.0.0:5002 (plain) and
/// optionally 0.0.0.0:5001 (TLS), ACME pointing at pebble. `extra_acme`
/// lands inside the `[acme]` table (for `[acme.dns.*]` fragments).
async fn start_acme(
    challenge: &str,
    ca_pem_path: &std::path::Path,
    http: bool,
    tls: bool,
    hosts: &str,
    extra_acme: &str,
) -> (Arc<Runtime>, tokio::sync::watch::Sender<bool>) {
    let storage = tempfile::tempdir().expect("storage dir");
    let config = format!(
        r#"
[acme]
email = "dev@verd.test"
directory = "{dir}"
ca_roots = "{ca}"
challenge = "{challenge}"
storage = "{storage}"
{extra_acme}

[[site]]
hosts = [{hosts}]
default = true
tls = "auto"

[[site.route]]
prefix = "/"
respond = {{ body = "acme-ok\n" }}
"#,
        dir = PEBBLE_DIR,
        ca = ca_pem_path.display(),
        challenge = challenge,
        storage = storage.path().display(),
        extra_acme = extra_acme,
        hosts = hosts,
    );
    let mut config: cfg::Config = toml::from_str(&config).unwrap();
    config.server.listen.clear();
    if http {
        config.server.listen.push(cfg::ListenAddr {
            addr: SocketAddr::from(([0, 0, 0, 0], HTTP01_PORT)),
            tls: false,
        });
    }
    if tls {
        config.server.listen.push(cfg::ListenAddr {
            addr: SocketAddr::from(([0, 0, 0, 0], TLSALPN_PORT)),
            tls: true,
        });
    }
    config.admin.listen = SocketAddr::from(([127, 0, 0, 1], 0));

    let rt = Runtime::build(Arc::new(config)).expect("runtime builds");
    assert!(rt.acme.is_some(), "acme manager present for tls=auto site");
    let (tx, mut rx) = tokio::sync::watch::channel(false);
    let rt2 = rt.clone();
    tokio::spawn(async move {
        server::serve(rt2, async move {
            let _ = rx.changed().await;
        })
        .await
    });
    for _ in 0..100 {
        if rt.ready.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // keep tempdir alive for the test duration
    std::mem::forget(storage);
    (rt, tx)
}

/// Poll the resolver until a cert for `host` exists (or timeout).
async fn cert_for(rt: &Arc<Runtime>, host: &str) -> Option<Arc<rustls::sign::CertifiedKey>> {
    let resolver = rt.tls.as_ref()?.resolver.clone();
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if let Some(ck) = resolver.lookup(host) {
            return Some(ck);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    None
}

/// Leaf certificate SANs of a `CertifiedKey`.
fn cert_sans(ck: &rustls::sign::CertifiedKey) -> Vec<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(ck.cert[0].as_ref()).expect("parse leaf");
    cert.subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    x509_parser::extensions::GeneralName::DNSName(s) => Some(s.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The whole suite in one test: pebble/challtestsrv startup dominates the
/// cost, and http-01 + tls-alpn-01 can share the stack.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acme_issuance_against_pebble() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "verd=debug".into()),
        )
        .with_test_writer()
        .try_init();
    if !docker_ok() || !ensure_images() {
        eprintln!("SKIP: docker or pebble images unavailable");
        return;
    }
    for p in [
        HTTP01_PORT,
        TLSALPN_PORT,
        14000,
        15000,
        CTS_DNS_PORT,
        CTS_MGMT_PORT,
    ] {
        if !port_free(p) {
            eprintln!("SKIP: port {p} is in use");
            return;
        }
    }
    let stack = Stack::up().expect("pebble stack up");
    stack.wait_ready().await.expect("pebble ready");

    // trust root for the directory API: the static minica cert
    let roots_dir = tempfile::tempdir().unwrap();
    let ca_path = roots_dir.path().join("pebble.minica.pem");
    stack.copy_minica(roots_dir.path()).expect("minica.pem");
    assert!(
        std::fs::read_to_string(&ca_path)
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );

    // ---- http-01 ----
    {
        let (rt, sd) = start_acme("http-01", &ca_path, true, true, "\"verd.test\"", "").await;
        let ck = cert_for(&rt, "verd.test")
            .await
            .expect("cert issued via http-01 within 90s");
        assert_eq!(cert_sans(&ck), vec!["verd.test"]);
        // serving end-to-end: HTTPS request with the issued cert
        let out = tokio::process::Command::new("curl")
            .args([
                "-skS",
                "--connect-timeout",
                "5",
                "--resolve",
                &format!("verd.test:{TLSALPN_PORT}:127.0.0.1"),
                &format!("https://verd.test:{TLSALPN_PORT}/"),
            ])
            .output()
            .await
            .unwrap();
        assert!(
            out.status.success(),
            "curl failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout), "acme-ok\n");
        shutdown_and_free(sd, &[HTTP01_PORT, TLSALPN_PORT]).await;
    }

    // ---- tls-alpn-01 ----
    {
        let (rt, sd) = start_acme("tls-alpn-01", &ca_path, false, true, "\"verd.test\"", "").await;
        let ck = cert_for(&rt, "verd.test")
            .await
            .expect("cert issued via tls-alpn-01 within 90s");
        assert_eq!(cert_sans(&ck), vec!["verd.test"]);
        shutdown_and_free(sd, &[TLSALPN_PORT]).await;
    }

    // ---- dns-01 (mock Cloudflare API → challtestsrv TXT records) ----
    {
        let cf_base = mock_cloudflare().await;
        let dns_cfg = format!(
            r#"
[acme.dns.cloudflare]
api_token = "test-token"
api_base = "{cf_base}/client/v4"
resolver = "127.0.0.1:{CTS_DNS_PORT}"
propagation_timeout = "30s"
"#
        );
        let (rt, sd) = start_acme(
            "dns-01",
            &ca_path,
            false,
            true,
            "\"verd.test\", \"*.verd.test\"",
            &dns_cfg,
        )
        .await;
        let ck = cert_for(&rt, "verd.test")
            .await
            .expect("cert issued via dns-01 within 90s");
        let mut sans = cert_sans(&ck);
        sans.sort();
        // one order, two authzs — base + wildcard share the same
        // `_acme-challenge.verd.test` name with distinct TXT values
        assert_eq!(sans, vec!["*.verd.test", "verd.test"]);
        let resolver = rt.tls.as_ref().unwrap().resolver.clone();
        assert!(resolver.lookup("a.verd.test").is_some());
        shutdown_and_free(sd, &[TLSALPN_PORT]).await;
    }
}

/// Mock Cloudflare v4 API on 127.0.0.1: translates DNS record writes
/// into challtestsrv `set-txt`/`clear-txt` calls, so pebble's VA sees
/// the TXT records in DNS exactly as it would with real Cloudflare.
struct MockCf {
    /// record id → record name (for DELETE → `clear-txt`).
    records: std::sync::Mutex<std::collections::HashMap<String, String>>,
    next: std::sync::atomic::AtomicU64,
    /// challtestsrv management base (`http://127.0.0.1:8055`).
    cts: String,
    http: reqwest::Client,
}

type Json = hyper::Response<http_body_util::Full<bytes::Bytes>>;

fn cf_json(v: serde_json::Value) -> Json {
    hyper::Response::builder()
        .header("content-type", "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::from(v.to_string())))
        .unwrap()
}

async fn cf_handle(req: hyper::Request<hyper::body::Incoming>, st: Arc<MockCf>) -> Json {
    // token plumbing is part of the contract — reject wrong/missing auth
    if req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        != Some("Bearer test-token")
    {
        return cf_json(serde_json::json!({
            "success": false,
            "errors": [{"message": "bad credentials"}],
        }));
    }
    let path = req.uri().path().to_string();
    match (req.method().clone(), path.as_str()) {
        (hyper::Method::GET, "/client/v4/zones") => {
            let name = form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
                .find(|(k, _)| k == "name")
                .map(|(_, v)| v.into_owned());
            let result = match name.as_deref() {
                Some("verd.test") => serde_json::json!([{ "id": "z1", "name": "verd.test" }]),
                _ => serde_json::json!([]),
            };
            cf_json(serde_json::json!({ "success": true, "result": result }))
        }
        (hyper::Method::POST, p) if p.ends_with("/dns_records") => {
            use http_body_util::BodyExt;
            let body = req.into_body().collect().await.unwrap().to_bytes();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let name = v["name"].as_str().unwrap().to_string();
            st.http
                .post(format!("{}/set-txt", st.cts))
                .json(&serde_json::json!({
                    "host": format!("{name}."),
                    "value": v["content"].as_str().unwrap(),
                }))
                .send()
                .await
                .expect("challtestsrv set-txt");
            let id = format!("r{}", st.next.fetch_add(1, Ordering::Relaxed));
            st.records.lock().unwrap().insert(id.clone(), name);
            cf_json(serde_json::json!({ "success": true, "result": { "id": id } }))
        }
        (hyper::Method::DELETE, p) if p.contains("/dns_records/") => {
            let id = p.rsplit('/').next().unwrap_or_default().to_string();
            let name = st.records.lock().unwrap().remove(&id);
            if let Some(name) = name {
                let _ = st
                    .http
                    .post(format!("{}/clear-txt", st.cts))
                    .json(&serde_json::json!({ "host": format!("{name}.") }))
                    .send()
                    .await;
            }
            cf_json(serde_json::json!({ "success": true, "result": { "id": id } }))
        }
        _ => cf_json(serde_json::json!({
            "success": false,
            "errors": [{"message": "no route"}],
        })),
    }
}

/// Spawn the mock; returns its `http://127.0.0.1:PORT` base.
async fn mock_cloudflare() -> String {
    let st = Arc::new(MockCf {
        records: std::sync::Mutex::new(std::collections::HashMap::new()),
        next: std::sync::atomic::AtomicU64::new(1),
        cts: format!("http://127.0.0.1:{CTS_MGMT_PORT}"),
        http: reqwest::Client::new(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let st = st.clone();
            tokio::spawn(async move {
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(
                    hyper_util::rt::TokioIo::new(sock),
                    hyper::service::service_fn(move |r| {
                        let st = st.clone();
                        async move { Ok::<_, std::convert::Infallible>(cf_handle(r, st).await) }
                    }),
                )
                .await;
            });
        }
    });
    base
}

/// Signal shutdown and wait until `ports` are re-bindable — graceful
/// drain can outlive a fixed sleep, and a second verd must not race
/// the first one's sockets.
async fn shutdown_and_free(sd: tokio::sync::watch::Sender<bool>, ports: &[u16]) {
    sd.send(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if ports.iter().all(|p| port_free(*p)) {
            return;
        }
        assert!(Instant::now() < deadline, "ports {ports:?} never released");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
