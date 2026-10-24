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

/// Bearer-token gate. Skipped entirely when `admin.token` is unset —
/// config validation only permits that on loopback listeners.
async fn bearer_auth(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let Some(expected) = &state.rt().config.admin.token else {
        return Ok(next.run(req).await);
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
