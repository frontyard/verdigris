//! The data plane: listeners, per-connection handling, and the request
//! pipeline. [`Runtime`] is an immutable snapshot of everything a request
//! needs; it is swapped atomically on reload.

pub mod conn;
pub mod service;
pub mod timeout;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use dashmap::DashMap;
use thiserror::Error;
use tokio::net::TcpListener;

use crate::config::model as cfg;
use crate::middleware;
use crate::observe;
use crate::router::{self, HostIndex};
use crate::tls::TlsRuntime;

/// The immutable runtime state behind every request: routing, middleware,
/// limits and logging, built once per config generation.
pub struct Runtime {
    /// The parsed config this runtime was built from.
    pub config: Arc<cfg::Config>,
    /// Host → site index.
    pub hosts: HostIndex,
    /// Compiled middleware factory products are inside routes; the factory
    /// is kept for future reload-diff reuse.
    pub mw_factory: middleware::Factory,
    /// `Server` response header value; `None` when disabled.
    pub server_header: Option<http::HeaderValue>,
    /// Access logger.
    pub access: observe::AccessLogger,
    /// Readiness flag — set once all listeners are bound.
    pub ready: AtomicBool,
    /// Per-generation connection admission limits.
    pub limits: Arc<ConnLimits>,
    /// Whether any listener in this generation serves TLS.
    pub has_tls: bool,
    /// Inbound TLS: acceptor + cert resolver; `None` when no listener
    /// terminates TLS.
    pub tls: Option<Arc<TlsRuntime>>,
    /// ACME manager: `Some` when sites use `tls = "auto"` or on-demand
    /// issuance is enabled. Serves `/.well-known/acme-challenge/` tokens.
    pub acme: Option<Arc<crate::acme::AcmeManager>>,
}

impl Runtime {
    /// Build a runtime from a validated config.
    pub fn build(config: Arc<cfg::Config>) -> Result<Arc<Self>, BuildError> {
        Self::build_with(config, None)
    }

    /// Build a runtime, optionally reusing unchanged pieces (cache stores)
    /// from `prior` — the reload path.
    pub fn build_with(
        config: Arc<cfg::Config>,
        prior: Option<&Runtime>,
    ) -> Result<Arc<Self>, BuildError> {
        let mw_factory = middleware::Factory::new(&config, prior.map(|p| &p.mw_factory))
            .map_err(|e| BuildError::Router(format!("middleware: {e}")))?;
        let hosts =
            router::build(&config, &mw_factory).map_err(|e| BuildError::Router(e.to_string()))?;
        let server_header = match config.server.server_header.as_str() {
            "off" | "" => None,
            v => http::HeaderValue::from_str(v).ok(),
        };
        let access = observe::AccessLogger::build(&config.log.access)
            .map_err(|e| BuildError::Access(e.to_string()))?;
        let has_tls = config.server.listen.iter().any(|l| l.tls);
        let tls = TlsRuntime::build(&config)
            .map_err(BuildError::Tls)?
            .map(Arc::new);
        let acme = match &tls {
            Some(t) => crate::acme::build(&config, &t.resolver).map_err(BuildError::Tls)?,
            None => None,
        };
        let limits = Arc::new(ConnLimits::new(&config.server));
        Ok(Arc::new(Self {
            config,
            hosts,
            mw_factory,
            server_header,
            access,
            ready: AtomicBool::new(false),
            limits,
            has_tls,
            tls,
            acme,
        }))
    }
}

/// Errors while building a [`Runtime`].
#[derive(Debug, Error)]
pub enum BuildError {
    /// Route compilation failed.
    #[error("{0}")]
    Router(String),
    /// Access log setup failed.
    #[error("access log: {0}")]
    Access(String),
    /// TLS setup failed.
    #[error("tls: {0}")]
    Tls(String),
}

/// Shared connection accounting.
pub struct ConnLimits {
    /// Maximum concurrent connections.
    max_global: usize,
    /// Maximum per client IP.
    max_per_ip: usize,
    global: AtomicUsize,
    per_ip: DashMap<std::net::IpAddr, usize>,
}

impl ConnLimits {
    /// Construct from config.
    pub fn new(cfg: &cfg::ServerConfig) -> Self {
        Self {
            max_global: cfg.max_connections,
            max_per_ip: cfg.max_connections_per_ip,
            global: AtomicUsize::new(0),
            per_ip: DashMap::new(),
        }
    }

    /// Try to admit a connection from `ip`. Returns a guard that releases
    /// the slot on drop, or `None` when a limit is exceeded.
    // fetch_update is deprecated on newer toolchains, but its replacement
    // (try_update) is still unstable on the MSRV toolchain — allow until
    // MSRV >= the stabilizing version.
    #[allow(deprecated)]
    pub fn admit(self: &Arc<Self>, ip: std::net::IpAddr) -> Option<ConnGuard> {
        // global first — the common rejection
        if self
            .global
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < self.max_global).then_some(n + 1)
            })
            .is_err()
        {
            return None;
        }
        let mut entry = self.per_ip.entry(ip).or_insert(0);
        if *entry >= self.max_per_ip {
            self.global.fetch_sub(1, Ordering::Relaxed);
            if *entry == 0 {
                drop(entry);
                self.per_ip.remove(&ip);
            }
            return None;
        }
        *entry += 1;
        drop(entry);
        Some(ConnGuard {
            limits: self.clone(),
            ip,
        })
    }

    /// Current global connection count.
    pub fn active(&self) -> usize {
        self.global.load(Ordering::Relaxed)
    }
}

/// Releases a connection slot on drop.
pub struct ConnGuard {
    limits: Arc<ConnLimits>,
    ip: std::net::IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.limits.global.fetch_sub(1, Ordering::Relaxed);
        if let Some(mut n) = self.limits.per_ip.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                drop(n);
                self.limits.per_ip.remove(&self.ip);
            }
        }
    }
}

/// The atomic swap point between config generations: every accepted
/// connection resolves `shared.load()` so new connections always see the
/// current runtime while in-flight ones keep theirs.
pub struct Shared {
    rt: arc_swap::ArcSwap<Runtime>,
}

impl Shared {
    /// Wrap the first-generation runtime.
    pub fn new(rt: Arc<Runtime>) -> Arc<Self> {
        Arc::new(Self {
            rt: arc_swap::ArcSwap::from(rt),
        })
    }

    /// The current generation.
    pub fn load(&self) -> Arc<Runtime> {
        self.rt.load_full()
    }
}

/// A reload request: reload the config file, rebuild the runtime, swap it
/// in, and diff listeners. `done` reports the outcome to API callers.
pub struct Reload {
    /// What triggered this reload (for the log line).
    pub cause: &'static str,
    /// Completion report channel.
    pub done: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
}

/// Start every accept loop until `shutdown`, serving the first-generation
/// runtime. Test/simple entry point — no reload channel, no config path.
pub async fn serve(
    rt: Arc<Runtime>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    serve_shared(Shared::new(rt), rx, None, shutdown).await
}

/// Like [`serve`] but with reload plumbing: `reload_rx` triggers a config
/// re-read of `config_path`, an atomic runtime swap, and listener diffing.
pub async fn serve_shared(
    shared: Arc<Shared>,
    mut reload_rx: tokio::sync::mpsc::Receiver<Reload>,
    config_path: Option<std::path::PathBuf>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    // before any listener can accept: emitted metric handles are
    // cached per-object, so the recorder must exist before traffic
    crate::observe::metrics::install();
    let rt = shared.load();
    // bound listeners keyed by (addr, tls); the watch sender drains that
    // listener's accept loop when the entry is removed or the server stops
    let mut bound: std::collections::HashMap<(SocketAddr, bool), tokio::sync::watch::Sender<bool>> =
        std::collections::HashMap::new();
    let mut tasks = tokio::task::JoinSet::new();
    for l in &rt.config.server.listen {
        let socket = TcpListener::bind(l.addr)
            .await
            .map_err(|e| std::io::Error::new(e.kind(), format!("cannot bind {}: {e}", l.addr)))?;
        spawn_listener(&mut tasks, &mut bound, socket, l.addr, l.tls, &shared);
    }

    // per-generation background tasks stop when their token is cancelled
    let mut bg_stop = tokio_util::sync::CancellationToken::new();
    spawn_generation_tasks(&rt, &mut bg_stop);

    rt.ready.store(true, Ordering::Relaxed);
    tracing::info!(listeners = rt.config.server.listen.len(), "verd listening");

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            req = reload_rx.recv() => {
                let Some(req) = req else { continue };
                let result = do_reload(&shared, config_path.as_deref(), req.cause, &mut bound, &mut tasks, &mut bg_stop)
                    .await;
                if let Some(done) = req.done {
                    let _ = done.send(result);
                }
            }
            () = &mut shutdown => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
        }
    }

    tracing::info!("shutdown signal received; draining connections");
    shared.load().ready.store(false, Ordering::Relaxed);
    for (_, tx) in bound.drain() {
        let _ = tx.send(true);
    }
    bg_stop.cancel();

    let graceful = shared.load().config.server.graceful_timeout;
    let drain = async {
        while tasks.join_next().await.is_some() {}
        // upgraded tunnels outlive their connections — drain them under
        // the same deadline
        crate::proxy::drain_tunnels().await;
    };
    if tokio::time::timeout(graceful, drain).await.is_err() {
        tracing::warn!(?graceful, "drain timeout exceeded; aborting connections");
        tasks.abort_all();
        crate::proxy::abort_tunnels();
        while tasks.join_next().await.is_some() {}
        crate::proxy::drain_tunnels().await;
    }
    Ok(())
}

/// Bind + spawn the accept loop for one listener.
fn spawn_listener(
    tasks: &mut tokio::task::JoinSet<()>,
    bound: &mut std::collections::HashMap<(SocketAddr, bool), tokio::sync::watch::Sender<bool>>,
    socket: TcpListener,
    addr: SocketAddr,
    tls: bool,
    shared: &Arc<Shared>,
) {
    let (tx, rx) = tokio::sync::watch::channel(false);
    bound.insert((addr, tls), tx);
    tracing::info!(%addr, tls, "listener bound");
    tasks.spawn(conn::accept_loop(socket, tls, shared.clone(), rx));
}

/// The per-generation background suite: upstream probes, cert hot reload,
/// ACME, idle-bucket and metrics sweeps.
fn spawn_generation_tasks(rt: &Arc<Runtime>, stop: &mut tokio_util::sync::CancellationToken) {
    *stop = tokio_util::sync::CancellationToken::new();
    rt.hosts.clusters.spawn_background(stop.clone());
    if let Some(tls_rt) = &rt.tls {
        tls_rt.spawn_watcher(stop.clone());
    }
    if let Some(acme) = &rt.acme {
        let acme = acme.clone();
        let t = stop.clone();
        tokio::spawn(async move { acme.run(t).await });
    }
    {
        let limiters = rt.mw_factory.limiters();
        if !limiters.is_empty() {
            let t = stop.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    tokio::select! {
                        _ = t.cancelled() => return,
                        _ = tick.tick() => {
                            for l in &limiters {
                                l.sweep(l.idle_ttl());
                            }
                        }
                    }
                }
            });
        }
    }
    {
        let rt = rt.clone();
        let t = stop.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = t.cancelled() => {},
                _ = crate::observe::metrics::sweep(rt) => {},
            }
        });
    }
}

/// Re-read the config, rebuild the runtime, swap it atomically, and diff
/// listeners: sockets that match the new config keep running (their accept
/// loops pick up the new runtime per connection), removed ones drain,
/// added ones bind — any bind failure aborts the whole reload.
async fn do_reload(
    shared: &Arc<Shared>,
    config_path: Option<&std::path::Path>,
    cause: &str,
    bound: &mut std::collections::HashMap<(SocketAddr, bool), tokio::sync::watch::Sender<bool>>,
    tasks: &mut tokio::task::JoinSet<()>,
    bg_stop: &mut tokio_util::sync::CancellationToken,
) -> Result<(), String> {
    match reload_inner(shared, config_path, bound, tasks).await {
        Ok(()) => {
            bg_stop.cancel();
            spawn_generation_tasks(&shared.load(), bg_stop);
            crate::observe::metrics::config_reload(true);
            tracing::info!(cause, "config reloaded");
            Ok(())
        }
        Err(e) => {
            crate::observe::metrics::config_reload(false);
            tracing::error!(cause, error = %e, "config reload failed; keeping previous generation");
            Err(e)
        }
    }
}

async fn reload_inner(
    shared: &Arc<Shared>,
    config_path: Option<&std::path::Path>,
    bound: &mut std::collections::HashMap<(SocketAddr, bool), tokio::sync::watch::Sender<bool>>,
    tasks: &mut tokio::task::JoinSet<()>,
) -> Result<(), String> {
    let path = config_path.ok_or_else(|| "no configuration file path".to_string())?;
    let loaded = crate::config::load(path).map_err(|e| e.to_string())?;
    for d in &loaded.diagnostics {
        tracing::warn!(severity = ?d.severity, path = %d.path, "{}", d.message);
    }
    if !loaded.is_valid() {
        return Err("configuration is invalid".to_string());
    }
    let old = shared.load();
    let new_rt =
        Runtime::build_with(Arc::new(loaded.config), Some(&old)).map_err(|e| e.to_string())?;

    // listener diff: bind all newly-required sockets before committing
    let desired: std::collections::HashSet<(SocketAddr, bool)> = new_rt
        .config
        .server
        .listen
        .iter()
        .map(|l| (l.addr, l.tls))
        .collect();
    let mut pending = Vec::new();
    for &(addr, tls) in &desired {
        if bound.contains_key(&(addr, tls)) {
            continue;
        }
        // same addr but flipped tls flag counts as new — the old socket
        // is removed below, and the bind happens after removal
        if bound.contains_key(&(addr, !tls)) {
            continue;
        }
        let socket = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("cannot bind {addr}: {e}"))?;
        pending.push((socket, addr, tls));
    }
    // sockets whose addr survives with a flipped tls flag: drop first,
    // then re-bind
    let mut flipped = Vec::new();
    for &(addr, tls) in &desired {
        if bound.contains_key(&(addr, tls)) || !bound.contains_key(&(addr, !tls)) {
            continue;
        }
        if let Some(tx) = bound.remove(&(addr, !tls)) {
            let _ = tx.send(true);
        }
        let socket = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("cannot rebind {addr}: {e}"))?;
        flipped.push((socket, addr, tls));
    }

    // commit: swap the runtime first so kept listeners serve the new
    // generation on their next accepted connection
    shared.rt.store(new_rt.clone());
    new_rt.ready.store(true, Ordering::Relaxed);
    old.ready.store(false, Ordering::Relaxed);

    for (socket, addr, tls) in pending.into_iter().chain(flipped) {
        spawn_listener(tasks, bound, socket, addr, tls, shared);
    }
    // removed listeners drain: their accept loops shut down gracefully
    let gone: Vec<(SocketAddr, bool)> = bound
        .keys()
        .filter(|k| !desired.contains(k))
        .copied()
        .collect();
    for key in gone {
        if let Some(tx) = bound.remove(&key) {
            let _ = tx.send(true);
        }
    }
    Ok(())
}
