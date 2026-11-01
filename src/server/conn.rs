//! Accept loop and per-connection handling: admission limits, header/idle
//! read deadlines, HTTP/1.1+HTTP/2 auto-negotiation, graceful drain.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use crate::proxy::cluster::IoT;
use crate::server::service::{self, ConnCtx};
use crate::server::timeout::{DeadlineGate, TimeoutIo};
use crate::server::{Runtime, Shared};

/// Accept connections on `listener` until `shutdown` flips true; in-flight
/// connections are handed to a [`hyper_util::server::graceful::GracefulShutdown`]
/// tracker so they can finish their current request.
pub async fn accept_loop(
    listener: TcpListener,
    tls: bool,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) {
    let graceful = GracefulShutdown::new();
    let mut conns = tokio::task::JoinSet::new();

    loop {
        let accept = tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
                continue;
            }
            r = listener.accept() => r,
            _ = conns.join_next(), if !conns.is_empty() => continue,
        };
        let (stream, peer) = match accept {
            Ok(v) => v,
            Err(e) => {
                // EMFILE/ENFILE: retrying immediately is a hot spin —
                // back off briefly so the loop can't starve the runtime
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                continue;
            }
        };
        // resolve the current generation per connection — kept listeners
        // serve a reloaded config immediately
        let rt = shared.load();
        let Some(guard) = rt.limits.admit(peer.ip()) else {
            crate::observe::metrics::conn_rejected();
            tracing::debug!(%peer, "connection rejected: limit exceeded");
            drop(stream);
            continue;
        };
        crate::observe::metrics::conn_accepted();
        let acceptor = if tls {
            rt.tls.as_ref().map(|t| t.acceptor.clone())
        } else {
            None
        };
        let watcher = graceful.watcher();
        conns.spawn(async move {
            serve_conn(stream, peer, acceptor, rt, watcher, guard).await;
        });
    }

    // stop accepting; let in-flight connections finish within the
    // remaining drain budget (outer layer enforces the deadline).
    graceful.shutdown().await;
    while conns.join_next().await.is_some() {}
}

/// hyper's HTTP/1 write-buffer high-water mark. hyper keeps pulling body
/// frames until this much is queued before it flushes; its default
/// (~400KiB) means six 64KiB file frames are read, allocated and held
/// before the first byte hits the socket. Two frames' worth keeps the
/// read→encrypt→write pipeline tight: measured +8-24% raw static
/// throughput (TLS and plaintext, 1-32 MiB) vs the default; 256KiB is
/// already ~10% worse than this (see PERFORMANCE.md). It also bounds the
/// *read* buffer, so it is raised to fit the configured header limit.
const HTTP1_MAX_BUF: usize = 128 * 1024;

async fn serve_conn(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: Option<TlsAcceptor>,
    rt: Arc<Runtime>,
    watcher: Watcher,
    conn_guard: crate::server::ConnGuard,
) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(%peer, error = %e, "set_nodelay failed");
    }
    let timeouts = &rt.config.timeouts;
    let first_request_done = Arc::new(AtomicBool::new(false));
    let read_gate = DeadlineGate::default();
    let tls = acceptor.is_some();
    // a second fd handle for the read-deadline watchdog — must be taken
    // before the TLS acceptor consumes `stream`
    let watchdog_tcp = std::os::fd::AsFd::as_fd(&stream)
        .try_clone_to_owned()
        .ok()
        .map(std::net::TcpStream::from)
        .map(std::sync::Arc::new);

    let mut tls_version = None;

    let io: Box<dyn IoT> = match acceptor {
        Some(acc) => {
            let hs = timeouts.tls_handshake;
            match tokio::time::timeout(hs, acc.accept(stream)).await {
                Ok(Ok(tls_stream)) => {
                    tls_version = tls_stream
                        .get_ref()
                        .1
                        .protocol_version()
                        .map(|v| format!("{v:?}"));
                    Box::new(TokioIo::new(TimeoutIo::new(
                        tls_stream,
                        timeouts.header_read,
                        timeouts.idle,
                        timeouts.send,
                        first_request_done.clone(),
                        read_gate.clone(),
                        watchdog_tcp.clone(),
                    )))
                }
                Ok(Err(e)) => {
                    crate::observe::metrics::tls_handshake_error();
                    tracing::debug!(%peer, error = %e, "TLS handshake failed");
                    return;
                }
                Err(_) => {
                    crate::observe::metrics::tls_handshake_error();
                    tracing::debug!(%peer, "TLS handshake timed out");
                    return;
                }
            }
        }
        None => Box::new(TokioIo::new(TimeoutIo::new(
            stream,
            timeouts.header_read,
            timeouts.idle,
            timeouts.send,
            first_request_done.clone(),
            read_gate.clone(),
            watchdog_tcp.clone(),
        ))),
    };

    let ctx = ConnCtx {
        remote: peer,
        tls,
        tls_version,
        request_counter: Arc::new(AtomicUsize::new(0)),
        first_request_done: first_request_done.clone(),
        read_gate,
        conn_guard,
    };
    crate::observe::metrics::conn_active(1.0);
    let svc = service_fn(|req| {
        let ctx = ctx.clone();
        let rt = rt.clone();
        async move {
            crate::observe::metrics::requests_inflight(1.0);
            let r = service::handle(req, ctx, rt).await;
            crate::observe::metrics::requests_inflight(-1.0);
            r
        }
    });

    let mut builder = auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    let header_limit = usize::try_from(rt.config.limits.header_bytes.0).unwrap_or(usize::MAX);
    builder
        .http1()
        .max_buf_size(HTTP1_MAX_BUF.max(header_limit.saturating_add(8 * 1024)));
    // h2 hardening — don't rely on library defaults: bound concurrent
    // streams, cap the decoded header list at our own header limit, and
    // keep-alive pings evict dead/hoarded connections (ping floods are
    // rate-limited inside h2 itself).
    builder
        .http2()
        .timer(hyper_util::rt::TokioTimer::new())
        .max_concurrent_streams(200)
        .max_header_list_size(u32::try_from(rt.config.limits.header_bytes.0).unwrap_or(u32::MAX))
        .keep_alive_interval(Some(std::time::Duration::from_secs(20)))
        .keep_alive_timeout(std::time::Duration::from_secs(10));
    // `serve_connection_with_upgrades` so WebSocket-style requests can
    // detach into the proxy tunnel; `UpgradeableConnection` still
    // implements `GracefulConnection` for draining.
    let conn = watcher.watch(builder.serve_connection_with_upgrades(io, svc));
    if let Err(e) = conn.await {
        tracing::debug!(%peer, error = %e, "connection error");
    }
    crate::observe::metrics::conn_active(-1.0);
}
