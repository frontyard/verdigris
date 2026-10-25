//! The control plane: an axum app on a dedicated listener carrying the
//! probe endpoints (`/health`, `/ready`, `/metrics`, `/version`) plus the
//! management API — `/config` (secrets redacted), `/upstreams`,
//! `/reload`, `/purge`, and member drain/undrain. Bearer auth is enforced
//! whenever `admin.token` is configured (mandatory off-loopback).

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Json;
use axum::routing::{get, post};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::server::{Reload, Runtime, Shared};

/// Router state: the swap point plus the reload request channel.
pub struct AdminState {
    shared: Arc<Shared>,
    reload_tx: tokio::sync::mpsc::Sender<Reload>,
}

impl AdminState {
    fn rt(&self) -> Arc<Runtime> {
        self.shared.load()
    }
}

/// Build the admin router.
pub fn router(state: Arc<AdminState>) -> axum::Router {
    axum::Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(prom_metrics))
        .route("/version", get(version))
        .route("/config", get(show_config))
        .route("/upstreams", get(upstreams))
        .route("/reload", post(reload))
        .route("/purge", post(purge))
        .route("/upstreams/{cluster}/{member}/drain", post(drain))
        .route("/upstreams/{cluster}/{member}/undrain", post(undrain))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            bearer_auth,
        ))
        .with_state(state)
}

/// Bearer-token gate. When `admin.token` is unset the listener is
/// loopback-only — but "loopback" doesn't stop a browser or any local
/// process from reaching it, so the unauthenticated surface is still
/// gated by [`local_only`].
async fn bearer_auth(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let Some(expected) = &state.rt().config.admin.token else {
        return local_only(&headers, req, next).await;
    };
    let ok = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|got| {
            use subtle::ConstantTimeEq;
            got.as_bytes().ct_eq(expected.as_bytes()).into()
        });
    if ok {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Gate for the token-less (loopback) admin surface: require a loopback
/// `Host` (rejects DNS rebinding), and for mutating methods reject
/// cross-origin browser markers (`Origin`/`Sec-Fetch-Site`) — a web page
/// can POST to `127.0.0.1` but must send those headers. Local tools
/// (curl, scripts) send neither.
async fn local_only(
    headers: &HeaderMap,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    use axum::http::header::{HOST, ORIGIN};
    let host_ok = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .is_some_and(host_is_loopback);
    if !host_ok {
        return Err(StatusCode::FORBIDDEN);
    }
    let mutating = !matches!(
        *req.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );
    if mutating {
        if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok())
            && !matches!(site, "same-origin" | "none")
        {
            return Err(StatusCode::FORBIDDEN);
        }
        if let Some(origin) = headers.get(ORIGIN).and_then(|v| v.to_str().ok()) {
            let host = origin
                .split_once("://")
                .map(|(_, r)| r)
                .unwrap_or(origin)
                .split('/')
                .next()
                .unwrap_or("");
            if !host_is_loopback(host) {
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }
    Ok(next.run(req).await)
}

/// Whether an authority (`Host` header or `Origin` host part) names a
/// loopback interface: `localhost`, `*.localhost`, `127.0.0.0/8`, `[::1]`
/// — an optional `:port` is ignored.
fn host_is_loopback(authority: &str) -> bool {
    let h = authority.trim().trim_end_matches('.');
    let bare = if let Some(rest) = h.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        match h.rsplit_once(':') {
            Some((name, port)) if port.parse::<u16>().is_ok() => name,
            _ => h,
        }
    };
    let b = bare.to_ascii_lowercase();
    b == "localhost"
        || b.ends_with(".localhost")
        || b == "::1"
        || (b.starts_with("127.") && b.parse::<std::net::Ipv4Addr>().is_ok())
}

async fn health() -> &'static str {
    "ok\n"
}

async fn ready(State(state): State<Arc<AdminState>>) -> (StatusCode, &'static str) {
    if state.rt().ready.load(Ordering::Relaxed) {
        (StatusCode::OK, "ready\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
    }
}

async fn prom_metrics() -> ([(&'static str, &'static str); 1], String) {
    (
        [("content-type", "text/plain; version=0.0.4")],
        crate::observe::metrics::render(),
    )
}

async fn version() -> Json<Value> {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "commit": option_env!("VERD_GIT_SHA"),
    }))
}

/// The live config, serialized, with secret-bearing keys blanked out.
async fn show_config(State(state): State<Arc<AdminState>>) -> Json<Value> {
    let mut v = serde_json::to_value(&*state.rt().config).unwrap_or_else(|_| json!({}));
    redact(&mut v);
    Json(v)
}

/// Recursively replace values whose key name suggests a secret.
fn redact(v: &mut Value) {
    const SECRET_KEYS: [&str; 6] = ["password", "token", "secret", "key", "key_file", "api_key"];
    match v {
        Value::Object(m) => {
            for (k, val) in m.iter_mut() {
                if SECRET_KEYS
                    .iter()
                    .any(|s| k.to_ascii_lowercase().contains(s))
                {
                    // blank the whole value — an array of api keys or a map
                    // of secrets under a secret-named key is still secret
                    *val = json!("***");
                } else {
                    redact(val);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(redact),
        Value::String(s) => {
            // credentials embedded in URL userinfo: `scheme://user:pass@host`
            // — the `url` key doesn't smell secret but the value is
            if let Some(scheme_end) = s.find("://") {
                let rest = &s[scheme_end + 3..];
                let authority_end = rest.find('/').unwrap_or(rest.len());
                let authority = &rest[..authority_end];
                if let Some(at) = authority.rfind('@')
                    && at > 0
                {
                    *s = format!("{}://***@{}", &s[..scheme_end], &authority[at + 1..]);
                }
            }
        }
        _ => {}
    }
}

/// Cluster/member status snapshot.
async fn upstreams(State(state): State<Arc<AdminState>>) -> Json<Value> {
    let rt = state.rt();
    let clusters: Vec<Value> = rt
        .hosts
        .clusters
        .iter()
        .map(|c| {
            json!({
                "name": c.name,
                "members": c.members.iter().enumerate().map(|(i, m)| json!({
                    "index": i,
                    "url": m.url.authority(),
                    "healthy": m.healthy(),
                    "draining": m.draining(),
                    "inflight": m.inflight.load(Ordering::Relaxed),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    Json(json!({ "clusters": clusters }))
}

/// Resolve `{member}` as an index or URL authority.
fn find_member(
    rt: &Runtime,
    cluster: &str,
    member: &str,
) -> Result<Arc<crate::proxy::cluster::Member>, StatusCode> {
    let c = rt
        .hosts
        .clusters
        .iter()
        .find(|c| c.name == cluster)
        .ok_or(StatusCode::NOT_FOUND)?;
    if let Ok(i) = member.parse::<usize>() {
        return c.members.get(i).cloned().ok_or(StatusCode::NOT_FOUND);
    }
    c.members
        .iter()
        .find(|m| m.url.authority() == member)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)
}

async fn set_drain(
    state: &AdminState,
    cluster: &str,
    member: &str,
    on: bool,
) -> Result<Json<Value>, StatusCode> {
    let m = find_member(&state.rt(), cluster, member)?;
    m.set_draining(on);
    Ok(Json(json!({ "member": m.url.authority(), "draining": on })))
}

async fn drain(
    State(state): State<Arc<AdminState>>,
    Path((cluster, member)): Path<(String, String)>,
) -> Result<Json<Value>, StatusCode> {
    set_drain(&state, &cluster, &member, true).await
}

async fn undrain(
    State(state): State<Arc<AdminState>>,
    Path((cluster, member)): Path<(String, String)>,
) -> Result<Json<Value>, StatusCode> {
    set_drain(&state, &cluster, &member, false).await
}

/// Kick a config reload; reports the outcome once the swap resolves.
async fn reload(State(state): State<Arc<AdminState>>) -> (StatusCode, Json<Value>) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    if state
        .reload_tx
        .send(Reload {
            cause: "admin api",
            done: Some(tx),
        })
        .await
        .is_err()
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "reload channel closed" })),
        );
    }
    match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
        Ok(Ok(Ok(()))) => (StatusCode::OK, Json(json!({ "reloaded": true }))),
        Ok(Ok(Err(e))) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
        Ok(Err(_)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "reload aborted" })),
        ),
        Err(_) => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(json!({ "error": "reload timed out" })),
        ),
    }
}

/// Purge request body: `{ "store"?, "key"? | "prefix"? | "all"? }`.
/// Without `store`, every named store is purged.
#[derive(serde::Deserialize)]
struct PurgeBody {
    store: Option<String>,
    key: Option<String>,
    prefix: Option<String>,
    all: Option<bool>,
}

async fn purge(
    State(state): State<Arc<AdminState>>,
    body: Option<Json<PurgeBody>>,
) -> (StatusCode, Json<Value>) {
    let body = body.map(|b| b.0).unwrap_or(PurgeBody {
        store: None,
        key: None,
        prefix: None,
        all: Some(true),
    });
    let rt = state.rt();
    let caches = rt.mw_factory.caches();
    let stores: Vec<(&String, &Arc<crate::cache::Cache>)> = match &body.store {
        Some(name) => match caches.get_key_value(name) {
            Some((n, c)) => vec![(n, c)],
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": format!("no cache store {name:?}") })),
                );
            }
        },
        None => caches.iter().collect(),
    };
    let mut removed = serde_json::Map::new();
    for (name, cache) in stores {
        let n = if body.all == Some(true) {
            cache.purge_all().await;
            -1
        } else if let Some(p) = &body.prefix {
            cache.purge_prefix(p).await as i64
        } else if let Some(k) = &body.key {
            i64::from(cache.purge_key(k).await)
        } else {
            0
        };
        removed.insert(name.clone(), if n < 0 { json!("all") } else { json!(n) });
    }
    (StatusCode::OK, Json(json!({ "purged": removed })))
}

/// Serve the admin listener until `shutdown` flips true. The listen
/// address and its TLS pair are boot-fixed (they don't hot-reload); the
/// bearer token follows the current config generation.
pub async fn serve(
    shared: Arc<Shared>,
    reload_tx: tokio::sync::mpsc::Sender<Reload>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    let rt = shared.load();
    let addr = rt.config.admin.listen;
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        std::io::Error::new(e.kind(), format!("cannot bind admin listener {addr}: {e}"))
    })?;

    let acceptor = match &rt.config.admin.tls {
        Some(m) => {
            let ck = crate::tls::manual::load_pair(m)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let resolver = Arc::new(crate::tls::resolver::CertResolver::default());
            resolver.set_default(ck);
            let mut sc = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(resolver);
            sc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Some(tokio_rustls::TlsAcceptor::from(Arc::new(sc)))
        }
        None => None,
    };

    let state = Arc::new(AdminState { shared, reload_tx });
    tracing::info!(%addr, tls = acceptor.is_some(), "admin listener bound");
    if rt.config.admin.token.is_none() {
        tracing::warn!(
            %addr,
            "admin listener has no token — restricted to loopback-originated requests; \
             set admin.token to enable remote management"
        );
    }
    match acceptor {
        None => {
            axum::serve(listener, router(state))
                .with_graceful_shutdown(async move {
                    let _ = shutdown.changed().await;
                })
                .await
        }
        Some(acc) => serve_tls(listener, acc, router(state), shutdown).await,
    }
}

/// Minimal TLS accept loop for the admin app: one `hyper` connection per
/// accepted socket, protocol chosen by ALPN (the acceptor advertises
/// `h2` + `http/1.1`). Admin traffic is low-volume control plane, so
/// per-connection tasks are fine here.
async fn serve_tls(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    app: axum::Router,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tower_service::Service as _;

    let mut conns = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            // reap finished connection tasks — otherwise their results
            // accumulate in the JoinSet for the lifetime of the listener
            _ = conns.join_next(), if !conns.is_empty() => {}
            r = listener.accept() => {
                let Ok((stream, peer)) = r else { continue };
                let acc = acceptor.clone();
                let app = app.clone();
                conns.spawn(async move {
                    // bound the handshake — a peer that connects and stalls
                    // would otherwise hold a task (and an fd) forever
                    let tls = match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        acc.accept(stream),
                    )
                    .await
                    {
                        Ok(Ok(tls)) => tls,
                        Ok(Err(_)) => {
                            tracing::debug!(%peer, "admin TLS handshake failed");
                            return;
                        }
                        Err(_) => {
                            tracing::debug!(%peer, "admin TLS handshake timed out");
                            return;
                        }
                    };
                    let svc = service_fn(move |req| {
                        let mut app = app.clone();
                        async move { app.call(req).await }
                    });
                    // `auto` honours the negotiated ALPN: clients that
                    // picked h2 get a real h2 conn, http/1.1 otherwise
                    let builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );
                    let conn = builder.serve_connection(TokioIo::new(tls), svc);
                    if let Err(e) = conn.await {
                        tracing::debug!(%peer, error = %e, "admin connection error");
                    }
                });
            }
        }
    }
    while conns.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_host_detection() {
        for ok in [
            "localhost",
            "localhost:2019",
            "sub.localhost",
            "127.0.0.1",
            "127.0.0.1:2019",
            "127.99.0.1:9999",
            "[::1]",
            "[::1]:2019",
            "LOCALHOST",
        ] {
            assert!(host_is_loopback(ok), "{ok} should be loopback");
        }
        for bad in [
            "",
            "example.com",
            "localhost.evil.com",
            "127.0.0.1.attacker.com",
            "0x7f000001",
            "::1",
            "attacker.com:127",
        ] {
            assert!(!host_is_loopback(bad), "{bad} must not be loopback");
        }
    }
}

#[cfg(test)]
mod api_tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;

    fn state(cfg_toml: &str) -> (axum::Router, tokio::sync::mpsc::Receiver<Reload>) {
        let cfg = crate::config::validate::parse_test_config(cfg_toml);
        let rt = crate::server::Runtime::build(Arc::new(cfg)).unwrap();
        let (reload_tx, reload_rx) = tokio::sync::mpsc::channel(1);
        let shared = crate::server::Shared::new(rt);
        (
            router(Arc::new(AdminState { shared, reload_tx })),
            reload_rx,
        )
    }

    fn req(method: &str, uri: &str) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "127.0.0.1:9777")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn read_endpoints_and_auth_gate() {
        // token configured → everything needs the bearer
        let (app, _rx) = state("[admin]\ntoken = \"sekrit\"\n");
        for uri in [
            "/health",
            "/ready",
            "/metrics",
            "/version",
            "/config",
            "/upstreams",
        ] {
            let r = app.clone().oneshot(req("GET", uri)).await.unwrap();
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
        let auth_req = axum::http::Request::builder()
            .method("GET")
            .uri("/health")
            .header("host", "127.0.0.1:9777")
            .header("authorization", "Bearer sekrit")
            .body(Body::empty())
            .unwrap();
        let r = app.clone().oneshot(auth_req).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn local_only_reads_and_write_guards() {
        let (app, _rx) = state("");
        // loopback host → reads allowed (not yet ready → 503 on /ready)
        for uri in ["/health", "/metrics", "/version", "/config", "/upstreams"] {
            let r = app.clone().oneshot(req("GET", uri)).await.unwrap();
            assert_eq!(r.status(), StatusCode::OK, "{uri}");
        }
        let r = app.clone().oneshot(req("GET", "/ready")).await.unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        // non-loopback Host → 403 (DNS rebinding guard)
        let r = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .header("host", "evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        // mutating + cross-site marker → 403
        let r = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/purge")
                    .header("host", "127.0.0.1")
                    .header("content-type", "application/json")
                    .header("sec-fetch-site", "cross-site")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        // mutating + foreign origin → 403
        let r = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/purge")
                    .header("host", "127.0.0.1")
                    .header("content-type", "application/json")
                    .header("origin", "https://evil.example")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        // mutating, clean headers → allowed
        let r = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/purge")
                    .header("host", "127.0.0.1")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn purge_variants() {
        let cfg = "[cache.c]\ntier = \"ram\"\n";
        let (app, _rx) = state(cfg);
        let post = |body: &str| {
            axum::http::Request::builder()
                .method("POST")
                .uri("/purge")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        // unknown store → 404
        let r = app
            .clone()
            .oneshot(post(r#"{"store":"nope","all":true}"#))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        // key purge
        let r = app
            .clone()
            .oneshot(post(r#"{"store":"c","key":"k"}"#))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        // prefix purge
        let r = app
            .clone()
            .oneshot(post(r#"{"prefix":"/x"}"#))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        // no body at all → purge all stores
        let r = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/purge")
                    .header("host", "127.0.0.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn drain_undrain_and_reload() {
        let cfg = "[upstream.u]\nservers = [\"http://127.0.0.1:9\"]\n";
        let (app, mut rx) = state(cfg);
        let post = |uri: String| {
            axum::http::Request::builder()
                .method("POST")
                .uri(uri)
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap()
        };
        // drain by index then by authority
        for uri in [
            "/upstreams/u/0/drain",
            "/upstreams/u/127.0.0.1:9/undrain",
            "/upstreams/u/127.0.0.1:9/drain",
        ] {
            let r = app.clone().oneshot(post(uri.into())).await.unwrap();
            assert_eq!(r.status(), StatusCode::OK, "{uri}");
        }
        // unknown cluster / member index / member authority → 404
        for uri in [
            "/upstreams/nope/0/drain",
            "/upstreams/u/9/drain",
            "/upstreams/u/9.9.9.9:9/drain",
        ] {
            let r = app.clone().oneshot(post(uri.into())).await.unwrap();
            assert_eq!(r.status(), StatusCode::NOT_FOUND, "{uri}");
        }
        // reload: answer the channel with success
        let app2 = app.clone();
        let h = tokio::spawn(async move { app2.oneshot(post("/reload".into())).await.unwrap() });
        let reload = rx.recv().await.unwrap();
        reload.done.unwrap().send(Ok(())).unwrap();
        let r = h.await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        // closed channel → 503
        drop(rx);
        let r = app.clone().oneshot(post("/reload".into())).await.unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn redact_scrubs_secrets_and_urls() {
        let mut v = json!({
            "password": "x",
            "api_key": ["a", "b"],
            "nested": { "secret": "y", "safe": "keep" },
            "url": "https://user:pass@host/path",
            "urls": ["http://u:p@h/x"],
            "plain": "value",
        });
        redact(&mut v);
        assert_eq!(v["password"], "***");
        assert_eq!(v["api_key"], "***");
        assert_eq!(v["nested"]["secret"], "***");
        assert_eq!(v["nested"]["safe"], "keep");
        assert_eq!(v["url"], "https://***@host");
        assert_eq!(v["urls"][0], "http://***@h");
        assert_eq!(v["plain"], "value");
    }
}
