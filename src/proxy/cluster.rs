//! Upstream clusters: parsed server URLs, member health and DNS state,
//! connection pooling and the dial path (plain TCP, TLS with ALPN, h2c).
//!
//! A [`Cluster`] is built once per config generation; its [`Member`]s hold
//! all mutable runtime state (idle pools, shared h2 connections, health
//! atomics) behind interior mutability so routes can share them freely.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use http::uri::Scheme;
use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::body::BoxBody;
use crate::config::model as cfg;

/// How the wire protocol to a member is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WantProto {
    /// HTTP/1.1 cleartext (`http://`).
    H1,
    /// HTTP/2 prior knowledge cleartext (`h2c://`).
    H2,
    /// TLS with ALPN negotiation between h2 and HTTP/1.1 (`https://`).
    Alpn,
}

/// A parsed upstream server URL.
#[derive(Debug, Clone)]
pub struct UpstreamUrl {
    /// Protocol selection.
    pub want: WantProto,
    /// Whether the connection uses TLS.
    pub tls: bool,
    /// Hostname or IP literal — IPv6 stored without the RFC 3986
    /// brackets so it parses as `IpAddr`; `authority()` restores them.
    pub host: String,
    /// Port (scheme default applied when omitted).
    pub port: u16,
}

impl UpstreamUrl {
    /// Parse `http://`, `https://` or `h2c://` URLs. Paths are rejected —
    /// upstreams are authorities, not resources.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let uri =
            http::Uri::from_str(raw).map_err(|e| format!("invalid upstream URL {raw:?}: {e}"))?;
        let scheme = uri
            .scheme()
            .ok_or_else(|| format!("upstream URL {raw:?} has no scheme"))?;
        let (want, tls, default_port) = if *scheme == Scheme::HTTP {
            (WantProto::H1, false, 80)
        } else if *scheme == Scheme::HTTPS {
            (WantProto::Alpn, true, 443)
        } else if scheme.as_str() == "h2c" {
            (WantProto::H2, false, 80)
        } else {
            return Err(format!(
                "upstream URL {raw:?} must have scheme http, https, or h2c"
            ));
        };
        let authority = uri
            .authority()
            .ok_or_else(|| format!("upstream URL {raw:?} has no host"))?;
        if uri.path() != "/" && !uri.path().is_empty() || uri.query().is_some() {
            return Err(format!(
                "upstream URL {raw:?} must not contain a path or query"
            ));
        }
        if authority.as_str().contains('@') {
            return Err(format!("upstream URL {raw:?} must not contain userinfo"));
        }
        // `Authority::host()` keeps the RFC 3986 brackets on IPv6
        // literals; store the bare address so `host` parses as `IpAddr`
        // for literal dialing and SNI.
        let host = authority.host();
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        Ok(Self {
            want,
            tls,
            host: host.to_string(),
            port: authority.port_u16().unwrap_or(default_port),
        })
    }

    /// `host:port` for the `Host` header / authority, omitting the default
    /// port and restoring IPv6 brackets.
    pub fn authority(&self) -> String {
        let default = match self.want {
            WantProto::Alpn => 443,
            _ => 80,
        };
        let host = if self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6()) {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// An upstream connection checked out for one request.
pub enum Checkout {
    /// HTTP/1.1: exclusive connection; the permit returns to the pool with it.
    H1 {
        /// Sender half of the client connection.
        sr: hyper::client::conn::http1::SendRequest<BoxBody>,
        /// Open-connection permit, held by the connection across the pool.
        permit: OwnedSemaphorePermit,
    },
    /// HTTP/2: a stream on the shared member connection; the permit caps
    /// concurrent streams against `max_connections`.
    H2 {
        /// Sender half of the shared h2 connection.
        sr: hyper::client::conn::http2::SendRequest<BoxBody>,
        /// In-flight stream permit, released when the response body ends.
        permit: OwnedSemaphorePermit,
    },
}

impl Checkout {
    /// Send the request, returning the response and the token that decides
    /// the connection's fate when the response body ends.
    pub async fn send(
        self,
        req: http::Request<BoxBody>,
    ) -> Result<(http::Response<hyper::body::Incoming>, Return), hyper::Error> {
        match self {
            Self::H1 { mut sr, permit } => {
                sr.ready().await?;
                let resp = sr.send_request(req).await?;
                Ok((resp, Return::H1 { sr, permit }))
            }
            Self::H2 { mut sr, permit } => {
                let resp = sr.send_request(req).await?;
                Ok((resp, Return::H2 { permit }))
            }
        }
    }
}

/// What becomes of an upstream connection once a response body completes.
pub enum Return {
    /// Re-pool for reuse.
    H1 {
        /// The connection sender.
        sr: hyper::client::conn::http1::SendRequest<BoxBody>,
        /// Its connection permit.
        permit: OwnedSemaphorePermit,
    },
    /// Just release the stream slot.
    H2 {
        /// Its stream permit.
        permit: OwnedSemaphorePermit,
    },
}

/// A pooled idle h1 connection.
struct PooledH1 {
    sr: hyper::client::conn::http1::SendRequest<BoxBody>,
    permit: OwnedSemaphorePermit,
    since: Instant,
}

/// DNS cache state for hostname members.
#[derive(Default)]
struct DnsState {
    /// Last-known-good addresses.
    addrs: Vec<SocketAddr>,
    /// When the cached addresses expire.
    expires_at: Option<Instant>,
    /// First consecutive resolution failure (grace-period bookkeeping).
    failing_since: Option<Instant>,
}

/// A single upstream server and its runtime state.
pub struct Member {
    /// Index within the cluster.
    pub id: usize,
    /// The parsed server URL.
    pub url: UpstreamUrl,
    /// Selection weight relative to the other primaries.
    pub weight: u32,
    /// Standby member — only picked when no primary is healthy.
    pub backup: bool,
    /// Smooth-weighted-round-robin running weight.
    pub(crate) ew: AtomicI64,
    /// Instant the member was built — epoch for `sick_until` millis.
    epoch: Instant,
    /// Millis since `epoch` until which the member is out of rotation.
    sick_until: AtomicU64,
    /// Consecutive failures for passive health tracking.
    fails: AtomicU32,
    /// Administratively drained via the admin API — out of rotation until
    /// undrained, independent of health state.
    draining: AtomicBool,
    /// In-flight requests (least-conn).
    pub inflight: AtomicUsize,
    /// Idle pooled h1 connections.
    pool: Mutex<VecDeque<PooledH1>>,
    /// Shared h2 connection (h2c or negotiated via ALPN).
    h2: Mutex<Option<hyper::client::conn::http2::SendRequest<BoxBody>>>,
    /// DNS state; tokio mutex because lookups are async.
    dns: tokio::sync::Mutex<DnsState>,
    /// `host` is an IP literal — no DNS needed.
    literal: bool,
    /// Open-connection cap (h1: conns in use + idle; h2: streams).
    sem: Arc<Semaphore>,
    /// Resolved metric handles (`cluster`/`member` labels bound once).
    pub meters: crate::observe::metrics::MemberMeters,
}

impl Member {
    fn build(
        id: usize,
        url: UpstreamUrl,
        weight: u32,
        backup: bool,
        max_connections: usize,
        cluster: metrics::SharedString,
    ) -> Arc<Self> {
        let literal = url.host.parse::<IpAddr>().is_ok();
        let meters = crate::observe::metrics::MemberMeters::new(cluster, url.authority());
        Arc::new(Self {
            id,
            url,
            weight,
            backup,
            ew: AtomicI64::new(0),
            epoch: Instant::now(),
            sick_until: AtomicU64::new(0),
            fails: AtomicU32::new(0),
            draining: AtomicBool::new(false),
            inflight: AtomicUsize::new(0),
            pool: Mutex::new(VecDeque::new()),
            h2: Mutex::new(None),
            dns: tokio::sync::Mutex::new(DnsState::default()),
            literal,
            sem: Arc::new(Semaphore::new(max_connections)),
            meters,
        })
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Whether the member is eligible for traffic right now. Members that
    /// were marked sick re-enter automatically once the cooldown lapses.
    pub fn healthy(&self) -> bool {
        self.healthy_at(Instant::now())
    }

    /// `healthy` judged against a caller-supplied instant — `lb::pick`
    /// snapshots one clock read so every member is evaluated at the same
    /// time (and pays one `Instant::now()` per pick instead of per member).
    pub(crate) fn healthy_at(&self, now: Instant) -> bool {
        !self.draining.load(Ordering::Relaxed)
            && now.saturating_duration_since(self.epoch).as_millis() as u64
                >= self.sick_until.load(Ordering::Relaxed)
    }

    /// Administrative drain/undrain (admin API). Draining members finish
    /// in-flight requests but receive no new ones.
    pub fn set_draining(&self, on: bool) {
        self.draining.store(on, Ordering::Relaxed);
    }

    /// Whether the member is administratively drained.
    pub fn draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// Mark the member sick for `cooldown`.
    pub fn mark_sick(&self, cooldown: Duration) {
        self.sick_until.store(
            self.now_ms() + cooldown.as_millis() as u64,
            Ordering::Relaxed,
        );
    }

    /// Record a request failure; passive health kicks in past `failures`.
    pub fn report_failure(&self, passive: Option<&cfg::PassiveHealth>) {
        let n = self.fails.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(p) = passive
            && n >= p.failures
        {
            self.mark_sick(p.cooldown);
        }
    }

    /// Record a success: reset the failure counter and re-admit the member.
    pub fn report_success(&self) {
        self.fails.store(0, Ordering::Relaxed);
        self.sick_until.store(0, Ordering::Relaxed);
    }

    /// Force re-resolution on next use (e.g. after a connect failure).
    fn invalidate_dns(&self, st: &mut DnsState) {
        st.expires_at = None;
    }

    /// Resolved dial addresses, honouring TTL and last-known-good grace.
    async fn addrs(&self, cluster: &Cluster) -> Result<Vec<SocketAddr>, UpError> {
        if self.literal {
            let ip: IpAddr = self.url.host.parse().map_err(|_| UpError::Resolve)?;
            return Ok(vec![SocketAddr::new(ip, self.url.port)]);
        }
        let mut st = self.dns.lock().await;
        if !st.addrs.is_empty()
            && let Some(exp) = st.expires_at
            && exp > Instant::now()
        {
            return Ok(st.addrs.clone());
        }
        let lookup = cluster.resolver()?.lookup_ip(&self.url.host).await;
        match lookup {
            Ok(lookup) => {
                let addrs: Vec<SocketAddr> = lookup
                    .iter()
                    .map(|ip| SocketAddr::new(ip, self.url.port))
                    .collect();
                if addrs.is_empty() {
                    self.dns_failed(&mut st, cluster, Instant::now());
                    return self.last_known_good(&st, cluster);
                }
                st.addrs = addrs.clone();
                st.expires_at = Some(lookup.valid_until());
                st.failing_since = None;
                Ok(addrs)
            }
            Err(e) => {
                tracing::debug!(host = %self.url.host, error = %e, "upstream DNS lookup failed");
                self.dns_failed(&mut st, cluster, Instant::now());
                self.last_known_good(&st, cluster)
            }
        }
    }

    /// `now` is a parameter so tests can pin the grace boundary exactly.
    fn dns_failed(&self, st: &mut DnsState, cluster: &Cluster, now: Instant) {
        let since = st.failing_since.get_or_insert(now);
        if now.duration_since(*since) > cluster.dns.grace {
            st.addrs.clear();
        } else {
            // retry soon rather than waiting out the old TTL
            st.expires_at = Some(now + Duration::from_secs(2));
        }
    }

    fn last_known_good(
        &self,
        st: &DnsState,
        _cluster: &Cluster,
    ) -> Result<Vec<SocketAddr>, UpError> {
        if st.addrs.is_empty() {
            Err(UpError::Resolve)
        } else {
            Ok(st.addrs.clone())
        }
    }

    /// Live shared h2 sender, if one exists and hasn't been closed.
    fn h2_live(&self) -> Option<hyper::client::conn::http2::SendRequest<BoxBody>> {
        self.h2
            .lock()
            .ok()
            .and_then(|g| g.as_ref().filter(|s| !s.is_closed()).cloned())
    }

    /// Checkout a connection: reuse a pooled h1 conn or the shared h2 conn,
    /// else dial. Permits enforce `max_connections` per member.
    pub async fn checkout(self: &Arc<Self>, cluster: &Cluster) -> Result<Checkout, UpError> {
        // h2 path: explicit h2c, or an https conn that negotiated h2 earlier
        if self.url.want != WantProto::H1
            && let Some(sr) = self.h2_live()
        {
            let permit = self.stream_permit(cluster).await?;
            return Ok(Checkout::H2 { sr, permit });
        }
        match self.url.want {
            WantProto::H2 => {
                let permit = self.stream_permit(cluster).await?;
                let sr = match self.dial(cluster, WantProto::H2).await? {
                    Dialed::H2(sr) => sr,
                    Dialed::H1(_) => {
                        return Err(UpError::Connect);
                    }
                };
                Ok(Checkout::H2 { sr, permit })
            }
            WantProto::H1 | WantProto::Alpn => {
                while let Some(p) = self.pool.lock().ok().and_then(|mut q| q.pop_front()) {
                    if !p.sr.is_closed() && p.since.elapsed() <= cluster.limits.idle {
                        return Ok(Checkout::H1 {
                            sr: p.sr,
                            permit: p.permit,
                        });
                    }
                    // stale/dead pooled conn: drop releases the permit
                }
                match self.dial(cluster, self.url.want).await? {
                    Dialed::H2(sr) => {
                        let permit = self.stream_permit(cluster).await?;
                        Ok(Checkout::H2 { sr, permit })
                    }
                    Dialed::H1(sr) => Ok(sr),
                }
            }
        }
    }

    /// Wait for an h2 stream slot (bounded by the connect timeout).
    async fn stream_permit(&self, cluster: &Cluster) -> Result<OwnedSemaphorePermit, UpError> {
        tokio::time::timeout(cluster.limits.connect, self.sem.clone().acquire_owned())
            .await
            .map_err(|_| UpError::Busy)?
            .map_err(|_| UpError::Busy)
    }

    /// Dial: resolve → TCP → optional TLS (+ALPN) → HTTP handshake. The h1
    /// permit is acquired inside; h2 callers take a stream permit instead.
    async fn dial(self: &Arc<Self>, cluster: &Cluster, want: WantProto) -> Result<Dialed, UpError> {
        let addrs = self.addrs(cluster).await?;
        let mut last_err = UpError::Connect;
        let mut stream = None;
        for addr in &addrs {
            match tokio::time::timeout(cluster.limits.connect, TcpStream::connect(addr)).await {
                Ok(Ok(s)) => {
                    stream = Some(s);
                    break;
                }
                Ok(Err(e)) => {
                    tracing::debug!(%addr, error = %e, "upstream connect failed");
                    last_err = UpError::Connect;
                }
                Err(_) => {
                    tracing::debug!(%addr, "upstream connect timed out");
                    last_err = UpError::ConnectTimeout;
                }
            }
        }
        let Some(tcp) = stream else {
            // maybe the addresses went stale — re-resolve on next request
            if let Ok(mut st) = self.dns.try_lock() {
                self.invalidate_dns(&mut st);
            }
            return Err(last_err);
        };
        let _ = tcp.set_nodelay(true);

        let io: Box<dyn IoT> = if self.url.tls {
            let connector = TlsConnector::from(cluster.tls_client()?);
            let name = cluster
                .tls
                .sni
                .clone()
                .unwrap_or_else(|| self.url.host.clone());
            let server_name =
                ServerName::try_from(name.clone()).map_err(|_| UpError::Tls(name.clone()))?;
            let tls =
                tokio::time::timeout(cluster.limits.connect, connector.connect(server_name, tcp))
                    .await
                    .map_err(|_| UpError::ConnectTimeout)?
                    .map_err(|e| {
                        tracing::debug!(%name, error = %e, "upstream TLS handshake failed");
                        UpError::Tls(name)
                    })?;
            let alpn = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
            let negotiated_h2 = alpn.as_deref() == Some(b"h2");
            if want == WantProto::Alpn && negotiated_h2 {
                return Ok(Dialed::H2(
                    self.h2_handshake(Box::new(hyper_util::rt::TokioIo::new(tls)))
                        .await?,
                ));
            }
            Box::new(hyper_util::rt::TokioIo::new(tls))
        } else {
            Box::new(hyper_util::rt::TokioIo::new(tcp))
        };

        match want {
            // h2 callers hold a stream permit; h1 conns hold an
            // open-connection permit acquired here, inside the dial.
            WantProto::H2 => Ok(Dialed::H2(self.h2_handshake(io).await?)),
            _ => {
                let conn_permit = self.stream_permit(cluster).await?;
                Ok(Dialed::H1(self.h1_handshake(io, conn_permit).await?))
            }
        }
    }

    async fn h1_handshake(
        &self,
        io: Box<dyn IoT>,
        permit: OwnedSemaphorePermit,
    ) -> Result<Checkout, UpError> {
        let (sr, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| {
                tracing::debug!(error = %e, "upstream h1 handshake failed");
                UpError::Connect
            })?;
        // `with_upgrades` lets the conn fulfill `hyper::upgrade` futures on
        // 101 responses — plain `Connection` abandons them.
        let conn = conn.with_upgrades();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(Checkout::H1 { sr, permit })
    }

    async fn h2_handshake(
        self: &Arc<Self>,
        io: Box<dyn IoT>,
    ) -> Result<hyper::client::conn::http2::SendRequest<BoxBody>, UpError> {
        let exec = hyper_util::rt::TokioExecutor::new();
        let (sr, conn) = hyper::client::conn::http2::handshake(exec, io)
            .await
            .map_err(|e| {
                tracing::debug!(error = %e, "upstream h2 handshake failed");
                UpError::Connect
            })?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        // last-writer-wins on concurrent dials: unlike hyper-util's pooled
        // client there is no "connecting" lock, so cold-start bursts (or
        // the window after the shared conn dies/GOAWAYs) each complete a
        // full handshake before this store — loser conns serve one request
        // then close. Bounded by `sem`, self-cleaning; a per-member dial
        // mutex re-checking `h2_live()` would dedup if it ever matters.
        if let Ok(mut g) = self.h2.lock() {
            *g = Some(sr.clone());
        }
        Ok(sr)
    }

    /// Return a finished h1 connection to the idle pool.
    pub fn repool(&self, ret: Return) {
        let Return::H1 { sr, permit } = ret else {
            return;
        };
        if sr.is_closed() {
            return;
        }
        if let Ok(mut q) = self.pool.lock() {
            q.push_back(PooledH1 {
                sr,
                permit,
                since: Instant::now(),
            });
        }
    }

    /// Health-probe this member once with a fresh, unpooled connection.
    async fn probe(&self, cluster: &Cluster, active: &cfg::ActiveHealth) -> bool {
        let result = async {
            let addrs = self.addrs(cluster).await.ok()?;
            let addr = *addrs.first()?;
            let tcp = TcpStream::connect(addr).await.ok()?;
            let _ = tcp.set_nodelay(true);
            let io: Box<dyn IoT> = if self.url.tls {
                let connector = TlsConnector::from(cluster.tls_client().ok()?);
                let name = cluster
                    .tls
                    .sni
                    .clone()
                    .unwrap_or_else(|| self.url.host.clone());
                let sn = ServerName::try_from(name).ok()?;
                let tls = connector.connect(sn, tcp).await.ok()?;
                let h2 = tls
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .map(|p| p.to_vec())
                    .as_deref()
                    == Some(b"h2");
                if h2 || self.url.want == WantProto::H2 {
                    return self.probe_h2(tls, active).await;
                }
                Box::new(hyper_util::rt::TokioIo::new(tls))
            } else if self.url.want == WantProto::H2 {
                return self.probe_h2(tcp, active).await;
            } else {
                Box::new(hyper_util::rt::TokioIo::new(tcp))
            };
            let (mut sr, conn) = hyper::client::conn::http1::handshake(io).await.ok()?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let req = http::Request::builder()
                .method(http::Method::GET)
                .uri(&active.path)
                .header(http::header::HOST, self.url.authority())
                .header(http::header::CONNECTION, "close")
                .body(crate::body::empty())
                .ok()?;
            let resp = sr.send_request(req).await.ok()?;
            Some(resp.status().as_u16() == active.expect)
        };
        tokio::time::timeout(active.timeout, result)
            .await
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    async fn probe_h2<I>(&self, io: I, active: &cfg::ActiveHealth) -> Option<bool>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let exec = hyper_util::rt::TokioExecutor::new();
        let io = hyper_util::rt::TokioIo::new(io);
        let (mut sr, conn) = hyper::client::conn::http2::handshake(exec, io).await.ok()?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        // absolute-form: h2 requires `:scheme` + `:authority` — a
        // path-only URI is rejected by the codec before it ever ships
        let uri = format!(
            "{}://{}{}",
            if self.url.tls { "https" } else { "http" },
            self.url.authority(),
            active.path,
        );
        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri(&uri)
            .header(http::header::HOST, self.url.authority())
            .version(http::Version::HTTP_2)
            .body(crate::body::empty())
            .ok()?;
        let resp = sr.send_request(req).await.ok()?;
        Some(resp.status().as_u16() == active.expect)
    }
}

/// Result of a dial: a fresh h1 checkout, or a stored shared h2 sender.
enum Dialed {
    H1(Checkout),
    H2(hyper::client::conn::http2::SendRequest<BoxBody>),
}

/// Boxed upstream IO so plain and TLS streams share the handshake path.
/// Boxable hyper-rt IO object — the concrete stream differs between
/// plaintext and TLS connections.
pub(crate) trait IoT: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static {}
impl<T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static> IoT for T {}

/// Why an upstream attempt failed.
#[derive(Debug, Clone)]
pub enum UpError {
    /// No resolved addresses / DNS grace expired.
    Resolve,
    /// TCP connect failed.
    Connect,
    /// TCP or TLS connect exceeded `limits.connect`.
    ConnectTimeout,
    /// Waiting for response headers exceeded `limits.response_header`.
    HeaderTimeout,
    /// TLS setup failed for the named server.
    Tls(String),
    /// `max_connections` exhausted within the connect timeout.
    Busy,
    /// The send itself errored.
    Send(String),
}

impl std::fmt::Display for UpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resolve => write!(f, "upstream DNS resolution failed"),
            Self::Connect => write!(f, "upstream connect failed"),
            Self::ConnectTimeout => write!(f, "upstream connect timed out"),
            Self::HeaderTimeout => write!(f, "upstream response headers timed out"),
            Self::Tls(name) => write!(f, "upstream TLS handshake failed for {name}"),
            Self::Busy => write!(f, "upstream connection limit reached"),
            Self::Send(e) => write!(f, "upstream send failed: {e}"),
        }
    }
}

impl std::error::Error for UpError {}

/// A group of upstream servers with shared LB, health and TLS state.
pub struct Cluster {
    /// Name (config key or `@route` for anonymous clusters).
    pub name: String,
    /// Upstream members.
    pub members: Vec<Arc<Member>>,
    /// Load-balancing algorithm.
    pub lb: cfg::LoadBalancing,
    /// Round-robin cursor.
    pub rr: AtomicUsize,
    /// Timeout/limit config.
    pub limits: cfg::UpstreamTimeouts,
    /// DNS grace config.
    pub dns: cfg::UpstreamDns,
    /// Upstream TLS config.
    pub tls: cfg::UpstreamTls,
    /// Health-check config.
    pub health: cfg::HealthCheck,
    /// Response when no member is healthy.
    pub unavailable: cfg::UnavailableResponse,
    /// Requests seen (retry-budget denominator).
    pub requests: AtomicU64,
    /// Retries currently in flight (retry-budget numerator).
    pub retries_inflight: AtomicU64,
    tls_cfg: OnceLock<Result<Arc<ClientConfig>, String>>,
    resolver: OnceLock<Result<hickory_resolver::TokioResolver, UpError>>,
    /// Resolved metric handles (`cluster` label bound once).
    pub meters: crate::observe::metrics::ClusterMeters,
}

impl Cluster {
    /// Build a cluster from upstream config.
    pub fn build(name: &str, c: &cfg::UpstreamConfig) -> Result<Self, String> {
        let meters = crate::observe::metrics::ClusterMeters::new(name);
        let cluster_lbl = meters.label();
        let members = c
            .servers
            .iter()
            .enumerate()
            .map(|(i, raw)| {
                if raw.weight == 0 {
                    return Err(format!(
                        "upstream.{name}.servers[{i}]: weight must be at least 1"
                    ));
                }
                UpstreamUrl::parse(&raw.url)
                    .map(|url| {
                        Member::build(
                            i,
                            url,
                            raw.weight,
                            raw.backup,
                            c.max_connections,
                            cluster_lbl.clone(),
                        )
                    })
                    .map_err(|e| format!("upstream.{name}.servers[{i}]: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if members.is_empty() {
            return Err(format!("upstream.{name} has no servers"));
        }
        Ok(Self {
            name: name.to_string(),
            members,
            lb: c.lb,
            rr: AtomicUsize::new(0),
            limits: c.timeouts.clone(),
            dns: c.dns.clone(),
            tls: c.tls.clone(),
            health: c.health.clone(),
            unavailable: c.unavailable.clone(),
            requests: AtomicU64::new(0),
            retries_inflight: AtomicU64::new(0),
            tls_cfg: OnceLock::new(),
            resolver: OnceLock::new(),
            meters,
        })
    }

    /// Lazily build the shared TLS client config.
    fn tls_client(&self) -> Result<Arc<ClientConfig>, UpError> {
        self.tls_cfg
            .get_or_init(|| build_tls_client(&self.tls))
            .clone()
            .map_err(UpError::Tls)
    }

    /// `BuildMode::Check` extra: force the TLS client build now — it is
    /// lazy in `Live` so an https upstream with a bad `tls` block would
    /// only fail on first request, after `verd validate` said OK.
    pub fn check(&self) -> Result<(), String> {
        if self.members.iter().any(|m| m.url.tls) {
            self.tls_client().map(|_| ()).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Lazily build the DNS resolver (needs a Tokio context, so not built
    /// at `Cluster::build` time).
    fn resolver(&self) -> Result<&hickory_resolver::TokioResolver, UpError> {
        self.resolver
            .get_or_init(|| {
                hickory_resolver::TokioResolver::builder_tokio()
                    .and_then(|b| b.build())
                    .map_err(|_| UpError::Resolve)
            })
            .as_ref()
            .map_err(|e| e.clone())
    }

    /// Spawn active health probes; tasks hold `Weak` refs and stop when the
    /// runtime generation is dropped.
    pub fn spawn_probes(self: &Arc<Self>, shutdown: CancellationToken) {
        let Some(active) = self.health.active.clone() else {
            return;
        };
        for member in &self.members {
            let member = member.clone();
            let cluster = Arc::downgrade(self);
            let active = active.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(active.interval);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = tick.tick() => {},
                    }
                    let Some(cluster) = cluster.upgrade() else {
                        break;
                    };
                    let ok = member.probe(&cluster, &active).await;
                    if ok {
                        member.report_success();
                    } else {
                        member.mark_sick(
                            cluster
                                .health
                                .passive
                                .as_ref()
                                .map(|p| p.cooldown)
                                .unwrap_or(active.interval),
                        );
                    }
                    member.meters.set_healthy(ok);
                }
            });
        }
    }
}

/// Build the shared rustls client config for a cluster.
fn build_tls_client(tls: &cfg::UpstreamTls) -> Result<Arc<ClientConfig>, String> {
    let builder = ClientConfig::builder();
    let mut config = if tls.verify {
        let mut roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(ca) = &tls.ca {
            let data = std::fs::read(ca)
                .map_err(|e| format!("cannot read upstream CA {}: {e}", ca.display()))?;
            let certs = CertificateDer::pem_reader_iter(data.as_slice())
                .collect::<Result<Vec<CertificateDer>, _>>()
                .map_err(|e| format!("cannot parse upstream CA {}: {e}", ca.display()))?;
            let (_, ignored) = roots.add_parsable_certificates(certs);
            if let 1.. = ignored {
                tracing::warn!(ca = %ca.display(), ignored, "unparsable CA certificates ignored");
            }
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify::new()))
            .with_no_client_auth()
    };
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Certificate verifier that accepts anything (used when `tls.verify = false`).
#[derive(Debug)]
struct NoVerify {
    algos: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl NoVerify {
    fn new() -> Self {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        Self {
            algos: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algos)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algos)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algos.supported_schemes()
    }
}

/// In-flight counter decrementer; dropped when a request finishes.
pub struct InflightGuard {
    member: Arc<Member>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.member
            .meters
            .set_inflight(self.member.inflight.fetch_sub(1, Ordering::Relaxed) - 1);
    }
}

/// Guard accounting for one in-flight request on a member.
pub fn track_inflight(member: &Arc<Member>) -> InflightGuard {
    member
        .meters
        .set_inflight(member.inflight.fetch_add(1, Ordering::Relaxed) + 1);
    InflightGuard {
        member: member.clone(),
    }
}

/// Guard for one in-flight retry against the cluster budget.
pub struct RetryGuard {
    pub(crate) cluster: Arc<Cluster>,
}

impl Drop for RetryGuard {
    fn drop(&mut self) {
        self.cluster
            .retries_inflight
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_url_parsing() {
        let u = UpstreamUrl::parse("http://example.com").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.tls, u.want),
            ("example.com", 80, false, WantProto::H1)
        );
        let u = UpstreamUrl::parse("https://example.com:8443").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.tls, u.want),
            ("example.com", 8443, true, WantProto::Alpn)
        );
        let u = UpstreamUrl::parse("h2c://10.0.0.1:50051").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.want),
            ("10.0.0.1", 50051, WantProto::H2)
        );
        assert!(UpstreamUrl::parse("http://x/path").is_err());
        assert!(UpstreamUrl::parse("ftp://x").is_err());
        assert!(UpstreamUrl::parse("http://user@x").is_err());
    }

    #[test]
    fn authority_formatting() {
        assert_eq!(UpstreamUrl::parse("http://a").unwrap().authority(), "a");
        assert_eq!(
            UpstreamUrl::parse("http://a:8080").unwrap().authority(),
            "a:8080"
        );
        assert_eq!(
            UpstreamUrl::parse("http://[::1]:8080").unwrap().authority(),
            "[::1]:8080"
        );
        // brackets come off at parse so `host` is a usable IpAddr, and
        // authority() puts them back — including at the default port,
        // where a bare `::1` is not a valid authority.
        let v6 = UpstreamUrl::parse("h2c://[::1]").unwrap();
        assert_eq!(v6.host, "::1");
        assert_eq!(v6.authority(), "[::1]");
        assert_eq!(
            UpstreamUrl::parse("https://[::1]").unwrap().authority(),
            "[::1]"
        );
    }

    #[test]
    fn member_health_cycle() {
        let m = Member::build(
            0,
            UpstreamUrl::parse("http://x").unwrap(),
            1,
            false,
            4,
            "test".into(),
        );
        assert!(m.healthy());
        let p = cfg::PassiveHealth {
            failures: 2,
            cooldown: Duration::from_millis(50),
        };
        m.report_failure(Some(&p));
        assert!(m.healthy());
        m.report_failure(Some(&p));
        assert!(!m.healthy());
        std::thread::sleep(Duration::from_millis(60));
        assert!(m.healthy());
        m.mark_sick(Duration::from_secs(60));
        assert!(!m.healthy());
        m.report_success();
        assert!(m.healthy());
    }

    fn test_cluster(servers: Vec<String>, max_conn: usize, idle: Duration) -> Cluster {
        Cluster::build(
            "t",
            &cfg::UpstreamConfig {
                servers: servers.into_iter().map(Into::into).collect(),
                lb: cfg::LoadBalancing::default(),
                health: cfg::HealthCheck::default(),
                timeouts: cfg::UpstreamTimeouts {
                    connect: Duration::from_millis(300),
                    idle,
                    ..Default::default()
                },
                max_connections: max_conn,
                dns: cfg::UpstreamDns::default(),
                tls: cfg::UpstreamTls::default(),
                unavailable: cfg::UnavailableResponse::default(),
            },
        )
        .unwrap()
    }

    /// Fake h1 upstream: serves `status` for every request, keeps the
    /// connection alive; counts accepted TCP connections.
    async fn fake_upstream(status: u16) -> (SocketAddr, Arc<AtomicUsize>) {
        let lis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = lis.local_addr().unwrap();
        let conns = Arc::new(AtomicUsize::new(0));
        let c = conns.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = lis.accept().await {
                c.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 8192];
                    let mut used = 0;
                    loop {
                        match s.read(&mut buf[used..]).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => used += n,
                        }
                        if buf[..used].windows(4).any(|w| w == b"\r\n\r\n") {
                            let reason = if status == 200 { "OK" } else { "X" };
                            let resp =
                                format!("HTTP/1.1 {status} {reason}\r\ncontent-length: 0\r\n\r\n");
                            if s.write_all(resp.as_bytes()).await.is_err() {
                                return;
                            }
                            used = 0;
                        }
                    }
                });
            }
        });
        (addr, conns)
    }

    fn get_req() -> http::Request<BoxBody> {
        http::Request::builder()
            .uri("/")
            .body(crate::body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn checkout_send_repool_reuses_h1_conn() {
        let (addr, conns) = fake_upstream(200).await;
        let cluster = test_cluster(vec![format!("http://{addr}")], 8, Duration::from_secs(60));
        let member = cluster.members[0].clone();
        for _ in 0..2 {
            let co = member.checkout(&cluster).await.unwrap();
            let (resp, ret) = co.send(get_req()).await.unwrap();
            assert_eq!(resp.status().as_u16(), 200);
            drop(resp);
            member.repool(ret);
        }
        // give the conn-count a beat to settle — second request must have
        // ridden the pooled conn, not a fresh dial
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(conns.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn stale_pool_entry_is_dropped() {
        let (addr, conns) = fake_upstream(200).await;
        // idle = 0 → any pooled conn is immediately stale
        let cluster = test_cluster(vec![format!("http://{addr}")], 8, Duration::ZERO);
        let member = cluster.members[0].clone();
        for _ in 0..2 {
            let co = member.checkout(&cluster).await.unwrap();
            let (resp, ret) = co.send(get_req()).await.unwrap();
            drop(resp);
            member.repool(ret);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(conns.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn connect_refused_surfaces_as_error() {
        // nothing listens here
        let cluster = test_cluster(
            vec!["http://127.0.0.1:1".into()],
            4,
            Duration::from_secs(60),
        );
        let member = cluster.members[0].clone();
        let err = member.checkout(&cluster).await.err().unwrap();
        assert!(matches!(err, UpError::Connect | UpError::ConnectTimeout));
    }

    #[tokio::test]
    async fn connection_cap_reports_busy() {
        let (addr, _) = fake_upstream(200).await;
        let cluster = test_cluster(vec![format!("http://{addr}")], 1, Duration::from_secs(60));
        let member = cluster.members[0].clone();
        // hold the single open-connection permit; the next checkout must
        // time out on the semaphore and report Busy
        let _hold = member.sem.clone().acquire_owned().await.unwrap();
        let err = member.checkout(&cluster).await.err().unwrap();
        assert!(matches!(err, UpError::Busy));
    }

    #[tokio::test]
    async fn probe_matches_expected_status() {
        let (addr, _) = fake_upstream(200).await;
        let cluster = test_cluster(vec![format!("http://{addr}")], 4, Duration::from_secs(60));
        let member = cluster.members[0].clone();
        let mut active = cfg::ActiveHealth {
            timeout: Duration::from_secs(2),
            ..Default::default()
        };
        assert!(member.probe(&cluster, &active).await);
        active.expect = 204;
        assert!(!member.probe(&cluster, &active).await);
    }

    #[tokio::test]
    async fn probe_refused_is_unhealthy() {
        let cluster = test_cluster(
            vec!["http://127.0.0.1:1".into()],
            4,
            Duration::from_secs(60),
        );
        let member = cluster.members[0].clone();
        let active = cfg::ActiveHealth {
            timeout: Duration::from_millis(500),
            ..Default::default()
        };
        assert!(!member.probe(&cluster, &active).await);
    }

    #[tokio::test]
    async fn dns_grace_keeps_then_drops_last_known_good() {
        // hostname member → non-literal DNS path
        let cluster = test_cluster(
            vec!["http://upstream.invalid".into()],
            4,
            Duration::from_secs(60),
        );
        let member = cluster.members[0].clone();
        assert!(!member.literal);
        let mut st = member.dns.lock().await;
        st.addrs = vec!["10.1.2.3:80".parse().unwrap()];
        // first failure inside the grace window: addrs survive
        member.dns_failed(&mut st, &cluster, Instant::now());
        assert!(!st.addrs.is_empty());
        // still failing at exactly the grace boundary: still kept —
        // the drop needs strictly more
        let now = Instant::now();
        st.failing_since = Some(now - cluster.dns.grace);
        member.dns_failed(&mut st, &cluster, now);
        assert!(!st.addrs.is_empty());
        // still failing past the grace window: addrs are dropped
        st.failing_since = Some(Instant::now() - cluster.dns.grace - Duration::from_secs(1));
        member.dns_failed(&mut st, &cluster, Instant::now());
        assert!(st.addrs.is_empty());
        assert!(matches!(
            member.last_known_good(&st, &cluster),
            Err(UpError::Resolve)
        ));
    }

    #[tokio::test]
    async fn literal_member_skips_dns() {
        let cluster = test_cluster(
            vec!["http://127.0.0.1:9".into()],
            4,
            Duration::from_secs(60),
        );
        let member = cluster.members[0].clone();
        assert!(member.literal);
        let addrs = member.addrs(&cluster).await.unwrap();
        assert_eq!(addrs, vec!["127.0.0.1:9".parse().unwrap()]);
    }

    #[tokio::test]
    async fn guards_decrement_counters_on_drop() {
        let cluster = test_cluster(
            vec!["http://127.0.0.1:9".into()],
            4,
            Duration::from_secs(60),
        );
        let member = cluster.members[0].clone();
        {
            let _g = track_inflight(&member);
            assert_eq!(member.inflight.load(Ordering::Relaxed), 1);
        }
        assert_eq!(member.inflight.load(Ordering::Relaxed), 0);
        let cluster = Arc::new(cluster);
        cluster.retries_inflight.fetch_add(1, Ordering::Relaxed);
        {
            let _g = RetryGuard {
                cluster: cluster.clone(),
            };
            assert_eq!(cluster.retries_inflight.load(Ordering::Relaxed), 1);
        }
        assert_eq!(cluster.retries_inflight.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn h2c_checkouts_share_one_connection() {
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;
        let lis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = lis.local_addr().unwrap();
        let conns = Arc::new(AtomicUsize::new(0));
        let c = conns.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = lis.accept().await {
                c.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let svc = service_fn(|_req| async {
                        Ok::<_, std::convert::Infallible>(http::Response::new(crate::body::full(
                            "ok",
                        )))
                    });
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(TokioIo::new(s), svc)
                    .await;
                });
            }
        });
        let cluster = test_cluster(vec![format!("h2c://{addr}")], 8, Duration::from_secs(60));
        let member = cluster.members[0].clone();
        for _ in 0..2 {
            let co = member.checkout(&cluster).await.unwrap();
            let (resp, ret) = co.send(get_req()).await.unwrap();
            assert_eq!(resp.status().as_u16(), 200);
            drop(resp);
            member.repool(ret);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        // both requests multiplexed over a single h2 conn
        assert_eq!(conns.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn cluster_build_errors() {
        assert!(
            Cluster::build(
                "t",
                &cfg::UpstreamConfig {
                    servers: vec![],
                    ..Default::default()
                },
            )
            .is_err()
        );
        let bad = Cluster::build(
            "t",
            &cfg::UpstreamConfig {
                servers: vec!["gopher://x".into()],
                ..Default::default()
            },
        );
        match bad {
            Err(e) => assert!(e.contains("servers[0]"), "{e}"),
            Ok(_) => panic!("expected build error"),
        }
    }

    #[test]
    fn tls_client_variants() {
        assert!(
            build_tls_client(&cfg::UpstreamTls {
                verify: false,
                ca: None,
                sni: None,
            })
            .is_ok()
        );
        match build_tls_client(&cfg::UpstreamTls {
            verify: true,
            ca: Some("/nonexistent/ca.pem".into()),
            sni: None,
        }) {
            Err(e) => assert!(e.contains("cannot read"), "{e}"),
            Ok(_) => panic!("expected tls build error"),
        }
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("ca.pem");
        std::fs::write(
            &bad,
            "-----BEGIN CERTIFICATE-----\n!!!bad\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(
            build_tls_client(&cfg::UpstreamTls {
                verify: true,
                ca: Some(bad),
                sni: None,
            })
            .is_err()
        );
    }

    #[test]
    fn no_verify_accepts_anything() {
        let v = NoVerify::new();
        assert!(!v.supported_verify_schemes().is_empty());
    }

    #[tokio::test]
    async fn probe_reports_status_match() {
        let (addr, _) = fake_upstream(200).await;
        let cluster = test_cluster(vec![format!("http://{addr}")], 4, Duration::from_secs(60));
        let active = cfg::ActiveHealth {
            path: "/healthz".into(),
            timeout: Duration::from_secs(2),
            ..Default::default()
        };
        assert!(cluster.members[0].probe(&cluster, &active).await);
        let active = cfg::ActiveHealth {
            expect: 500,
            ..active
        };
        assert!(!cluster.members[0].probe(&cluster, &active).await);
        let dead = test_cluster(
            vec!["http://127.0.0.1:1".into()],
            4,
            Duration::from_secs(60),
        );
        assert!(!dead.members[0].probe(&dead, &active).await);
    }

    #[tokio::test]
    async fn dns_state_transitions() {
        let cluster = test_cluster(
            vec!["http://127.0.0.1:9".into()],
            4,
            Duration::from_secs(60),
        );
        let m = &cluster.members[0];
        let addrs = m.addrs(&cluster).await.unwrap();
        assert_eq!(addrs[0].port(), 9);

        let host_cluster = test_cluster(
            vec!["http://x.invalid:9".into()],
            4,
            Duration::from_secs(60),
        );
        let hm = &host_cluster.members[0];
        let mut st = DnsState::default();
        assert!(hm.last_known_good(&st, &host_cluster).is_err());
        st.addrs = vec!["10.1.2.3:9".parse().unwrap()];
        assert_eq!(hm.last_known_good(&st, &host_cluster).unwrap().len(), 1);
        hm.dns_failed(&mut st, &host_cluster, Instant::now());
        assert!(!st.addrs.is_empty());
        let mut st2 = DnsState {
            addrs: vec!["10.1.2.3:9".parse().unwrap()],
            expires_at: None,
            failing_since: Some(Instant::now() - Duration::from_secs(3600)),
        };
        hm.dns_failed(&mut st2, &host_cluster, Instant::now());
        assert!(st2.addrs.is_empty());
        hm.invalidate_dns(&mut st2);
        assert!(st2.expires_at.is_none());
    }

    #[tokio::test]
    async fn probe_h2_reports_status_match() {
        // in-memory h2 peer: handshake + GET exercise the probe for
        // real without TLS or a socket
        let h2_peer = |status: u16| {
            let (client_io, server_io) = tokio::io::duplex(8192);
            tokio::spawn(async move {
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(
                    hyper_util::rt::TokioIo::new(server_io),
                    hyper::service::service_fn(move |_req| async move {
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(status)
                                .body(crate::body::full("ok"))
                                .unwrap(),
                        )
                    }),
                )
                .await;
            });
            client_io
        };
        let active = cfg::ActiveHealth {
            path: "/healthz".into(),
            expect: 200,
            ..Default::default()
        };
        let cluster = test_cluster(
            vec!["http://127.0.0.1:1".into()],
            4,
            Duration::from_secs(60),
        );
        let m = &cluster.members[0];
        // status match → Some(true); mismatch → Some(false); a `-> None`
        // stub answers neither
        assert_eq!(m.probe_h2(h2_peer(200), &active).await, Some(true));
        assert_eq!(m.probe_h2(h2_peer(500), &active).await, Some(false));
    }

    #[tokio::test]
    async fn spawn_probes_marks_sick_and_stops() {
        let (addr, _) = fake_upstream(200).await;
        let shutdown = tokio_util::sync::CancellationToken::new();
        let hc = cfg::HealthCheck {
            active: Some(cfg::ActiveHealth {
                interval: Duration::from_millis(10),
                timeout: Duration::from_millis(100),
                ..Default::default()
            }),
            passive: Some(cfg::PassiveHealth {
                cooldown: Duration::from_secs(60),
                ..Default::default()
            }),
        };
        let rebuild = |servers: Vec<String>| {
            let mut c = cfg::UpstreamConfig {
                servers: servers.into_iter().map(Into::into).collect(),
                health: hc.clone(),
                ..Default::default()
            };
            c.timeouts.connect = Duration::from_millis(200);
            Arc::new(Cluster::build("t", &c).unwrap())
        };
        let dead = rebuild(vec!["http://127.0.0.1:1".into()]);
        let ok = rebuild(vec![format!("http://{addr}")]);
        dead.clone().spawn_probes(shutdown.clone());
        ok.clone().spawn_probes(shutdown.clone());
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(!dead.members[0].healthy(), "failing probe marks sick");
        assert!(ok.members[0].healthy(), "passing probe stays healthy");
        shutdown.cancel();
        let none = Arc::new(test_cluster(
            vec!["http://127.0.0.1:1".into()],
            4,
            Duration::from_secs(60),
        ));
        none.spawn_probes(shutdown.clone());
    }

    #[tokio::test]
    async fn inflight_guard_accounting() {
        let cluster = test_cluster(
            vec!["http://127.0.0.1:9".into()],
            4,
            Duration::from_secs(60),
        );
        let m = &cluster.members[0];
        {
            let _g = track_inflight(m);
            assert_eq!(m.inflight.load(Ordering::Relaxed), 1);
        }
        assert_eq!(m.inflight.load(Ordering::Relaxed), 0);
    }
}
