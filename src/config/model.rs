//! The configuration model: every type here is a `serde` target, the source
//! of truth for validation, and (via `schemars`) the source of truth for the
//! published JSON Schema. Doc comments become schema descriptions.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::config::values::{ByteSize, RateSpec};

fn default_true() -> bool {
    true
}

/// Root configuration for a verdigris instance.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Additional files or directories of `*.toml` fragments merged into this
    /// configuration, relative to the directory containing this file.
    /// Fragment files are loaded in sorted order; scalar conflicts between
    /// fragments and the main file are errors.
    pub include: Vec<String>,
    /// Server-wide settings: listeners, connection limits, shutdown.
    pub server: ServerConfig,
    /// Default timeouts; individual routes may override.
    pub timeouts: Timeouts,
    /// Default request limits; individual routes may override.
    pub limits: Limits,
    /// Server and access logging.
    pub log: LogConfig,
    /// Admin API listener (metrics, health, reload, purge, inspection).
    pub admin: AdminConfig,
    /// ACME account settings used by sites with `tls = "auto"`.
    pub acme: AcmeConfig,
    /// Named upstream clusters for reverse proxy routes.
    pub upstream: BTreeMap<String, UpstreamConfig>,
    /// Named cache stores for routes with `cache` enabled.
    pub cache: BTreeMap<String, CacheStore>,
    /// Virtual sites. Requests are routed by the Host header.
    pub site: Vec<SiteConfig>,
}

/// Server-wide settings.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Addresses to listen on. Defaults to a single plaintext listener on
    /// port 80. Mark a listener `tls = true` to terminate TLS on it.
    pub listen: Vec<ListenAddr>,
    /// Time to wait for in-flight requests during shutdown or reload before
    /// connections are closed.
    pub graceful_timeout: Duration,
    /// CIDRs whose `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`,
    /// `X-Real-IP` and `Forwarded` headers are trusted. Empty: trust none.
    #[schemars(with = "Vec<String>")]
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Value of the `Server` response header, or `"off"` to omit it.
    pub server_header: String,
    /// Maximum concurrent connections across all listeners.
    pub max_connections: usize,
    /// Maximum concurrent connections per client IP address.
    pub max_connections_per_ip: usize,
    /// Baseline security response headers applied to every route.
    pub security: SecurityConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: vec![ListenAddr::default()],
            graceful_timeout: Duration::from_secs(30),
            trusted_proxies: Vec::new(),
            server_header: "verd".into(),
            max_connections: 65_536,
            max_connections_per_ip: 256,
            security: SecurityConfig::default(),
        }
    }
}

/// Baseline security response headers (OWASP-ish defaults). Each route may
/// override or disable individual headers via `route.security`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    /// Master switch; `false` emits none of these headers.
    pub enabled: bool,
    /// `Strict-Transport-Security`, emitted only on TLS responses.
    pub hsts: bool,
    /// HSTS `max-age` in seconds.
    pub hsts_max_age: u64,
    /// Append `includeSubDomains` to the HSTS header.
    pub hsts_subdomains: bool,
    /// `X-Content-Type-Options: nosniff`.
    pub content_type_options: bool,
    /// `X-Frame-Options` value, e.g. `"DENY"` or `"SAMEORIGIN"`. Empty
    /// string disables the header.
    pub frame_options: String,
    /// `Referrer-Policy` value. Empty string disables the header.
    pub referrer_policy: String,
    /// `Content-Security-Policy` value; unset emits no CSP.
    pub csp: Option<String>,
    /// `X-Permitted-Cross-Domain-Policies` value. Empty disables.
    pub cross_domain_policy: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hsts: true,
            hsts_max_age: 15_552_000, // 180 days
            hsts_subdomains: false,
            content_type_options: true,
            frame_options: "DENY".into(),
            referrer_policy: "strict-origin-when-cross-origin".into(),
            csp: None,
            cross_domain_policy: String::new(),
        }
    }
}

/// Per-route security-header overrides: absent fields inherit the global
/// [`SecurityConfig`]. `enabled = false` suppresses all of them.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RouteSecurity {
    /// Route-level master switch; absent inherits global `enabled`.
    pub enabled: Option<bool>,
    /// Override HSTS on/off for this route.
    pub hsts: Option<bool>,
    /// Override HSTS `max-age`.
    pub hsts_max_age: Option<u64>,
    /// Override `includeSubDomains`.
    pub hsts_subdomains: Option<bool>,
    /// Override `X-Content-Type-Options`.
    pub content_type_options: Option<bool>,
    /// Override `X-Frame-Options` (`""` disables).
    pub frame_options: Option<String>,
    /// Override `Referrer-Policy` (`""` disables).
    pub referrer_policy: Option<String>,
    /// Set a CSP for this route (`""` clears an inherited one).
    pub csp: Option<String>,
    /// Override `X-Permitted-Cross-Domain-Policies` (`""` disables).
    pub cross_domain_policy: Option<String>,
}

/// A single listen socket.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ListenAddr {
    /// `IP:port` to bind, e.g. `0.0.0.0:80` or `[::]:443`.
    #[schemars(with = "String")]
    pub addr: SocketAddr,
    /// Terminate TLS on this listener.
    pub tls: bool,
}

impl Default for ListenAddr {
    fn default() -> Self {
        Self {
            addr: SocketAddr::from(([0, 0, 0, 0], 80)),
            tls: false,
        }
    }
}

/// Timeout settings. `0s` disables a timeout.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Timeouts {
    /// TLS handshake deadline.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub tls_handshake: Duration,
    /// Time allowed to read request headers (slowloris protection).
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub header_read: Duration,
    /// Time allowed to read a request body.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub body_read: Duration,
    /// Keep-alive idle time between requests on one connection.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub idle: Duration,
    /// Overall per-request deadline. Set to `0s` for long-lived routes
    /// (SSE, WebSocket, long-polling).
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub request_deadline: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            tls_handshake: Duration::from_secs(10),
            header_read: Duration::from_secs(20),
            body_read: Duration::from_secs(60),
            idle: Duration::from_secs(75),
            request_deadline: Duration::from_secs(300),
        }
    }
}

impl Timeouts {
    /// Apply a route's overrides to a copy of these defaults.
    pub fn apply_overrides(&mut self, over: &TimeoutOverrides) {
        if let Some(v) = over.header_read {
            self.header_read = v;
        }
        if let Some(v) = over.body_read {
            self.body_read = v;
        }
        if let Some(v) = over.idle {
            self.idle = v;
        }
        if let Some(v) = over.request_deadline {
            self.request_deadline = v;
        }
    }
}

/// Request size limits.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Maximum total size of request headers.
    pub header_bytes: ByteSize,
    /// Maximum size of a request body. The request is rejected with
    /// `413 Payload Too Large` when exceeded.
    pub body_bytes: ByteSize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            header_bytes: ByteSize::kib(16),
            body_bytes: ByteSize::mib(10),
        }
    }
}

impl Limits {
    /// Apply a route's overrides to a copy of these defaults.
    pub fn apply_overrides(&mut self, over: &LimitOverrides) {
        if let Some(v) = over.header_bytes {
            self.header_bytes = v;
        }
        if let Some(v) = over.body_bytes {
            self.body_bytes = v;
        }
    }
}

/// Logging configuration.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// Server (diagnostic) log level: error, warn, info, debug, trace.
    pub level: String,
    /// Server log format: `json` or `pretty`.
    pub format: LogFormat,
    /// Server log destination: `stdout`, `stderr`, or a file path.
    pub output: String,
    /// Access log settings.
    pub access: AccessLog,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: LogFormat::Json,
            output: "stderr".into(),
            access: AccessLog::default(),
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// One JSON object per line — the default, friendly to log collectors.
    #[default]
    Json,
    /// Human-readable single-line format.
    Pretty,
}

/// Access log settings.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AccessLog {
    /// Emit access logs.
    pub enabled: bool,
    /// Format: `json` or `pretty`.
    pub format: LogFormat,
    /// Destination: `stdout` or a file path. File output is reopened on
    /// `SIGUSR1` for logrotate.
    pub output: String,
    /// Optional filter expression evaluated against log fields, e.g.
    /// `path != "/healthz" && status != 404`. Matching requests are logged.
    pub filter: Option<String>,
    /// Fraction of requests to log, 0.0–1.0.
    pub sample: f64,
}

impl Default for AccessLog {
    fn default() -> Self {
        Self {
            enabled: true,
            format: LogFormat::Json,
            output: "stdout".into(),
            filter: None,
            sample: 1.0,
        }
    }
}

/// Admin API configuration. Served on a dedicated listener, separate from
/// the data plane.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    /// `IP:port` to bind. Use loopback unless remote administration is needed.
    #[schemars(with = "String")]
    pub listen: SocketAddr,
    /// Bearer token required on all admin requests. Mandatory when `listen`
    /// is not a loopback address; use `${VAR}` interpolation to keep it out
    /// of the file.
    pub token: Option<String>,
    /// Optional TLS for the admin listener (recommended when bound beyond
    /// localhost).
    pub tls: Option<ManualTls>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 2019)),
            token: None,
            tls: None,
        }
    }
}

/// Certificate + private key file pair.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManualTls {
    /// PEM file with the certificate chain.
    pub cert: PathBuf,
    /// PEM file with the private key.
    pub key: PathBuf,
}

/// ACME account settings (Let's Encrypt or any RFC 8555 directory).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AcmeConfig {
    /// Contact email for the ACME account.
    pub email: Option<String>,
    /// ACME directory URL. Use the Let's Encrypt staging directory
    /// (`https://acme-staging-v02.api.letsencrypt.org/directory`) while
    /// testing to avoid production rate limits.
    pub directory: String,
    /// Directory holding the account key and issued certificates. Must be
    /// writable; persists across restarts.
    pub storage: PathBuf,
    /// External Account Binding for providers that require it.
    pub eab: Option<ExternalAccountBinding>,
    /// Renew certificates this long before expiry.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub renew_before: Duration,
    /// Preferred challenge type: `http-01`, `tls-alpn-01`, or `auto`
    /// (HTTP-01 when a plaintext listener exists, else TLS-ALPN-01).
    pub challenge: AcmeChallenge,
    /// PEM bundle of extra CA roots to trust when talking to the ACME
    /// directory — for private ACME servers (Pebble, step-ca, internal
    /// PKI). The system/WebPKI roots are always included.
    pub ca_roots: Option<PathBuf>,
    /// On-demand issuance for previously unseen hostnames.
    pub on_demand: OnDemandAcme,
}

/// Which ACME challenge type to solve.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum AcmeChallenge {
    /// `http-01` — answer challenges over HTTP on port 80.
    #[serde(rename = "http-01", alias = "http01")]
    Http01,
    /// `tls-alpn-01` — answer challenges inside the TLS handshake.
    #[serde(rename = "tls-alpn-01", alias = "tls-alpn01")]
    TlsAlpn01,
    /// `http-01` when a plaintext listener exists, else `tls-alpn-01`.
    #[serde(rename = "auto")]
    #[default]
    Auto,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            email: None,
            directory: "https://acme-v02.api.letsencrypt.org/directory".into(),
            storage: PathBuf::from("./verd-state/acme"),
            eab: None,
            renew_before: Duration::from_secs(30 * 24 * 3600),
            challenge: AcmeChallenge::Auto,
            ca_roots: None,
            on_demand: OnDemandAcme::default(),
        }
    }
}

/// External Account Binding credentials.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExternalAccountBinding {
    /// EAB key identifier.
    pub key_id: String,
    /// Base64url-encoded HMAC key.
    pub key: String,
}

/// On-demand certificate issuance.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct OnDemandAcme {
    /// Enable issuance for hostnames not present in any site's `hosts` list.
    pub enabled: bool,
    /// Hostnames or `*.suffix` patterns allowed to trigger issuance. Empty
    /// list means on-demand never issues — an explicit allowlist is required.
    pub allowed_hosts: Vec<String>,
    /// Maximum issuance rate, e.g. `5/hour`.
    pub rate: Option<RateSpec>,
}

/// A named cluster of upstream servers.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamConfig {
    /// Server URLs: `http://host:port`, `https://host:port`, or `h2c://` for
    /// cleartext HTTP/2 prior knowledge (typical for gRPC backends).
    pub servers: Vec<String>,
    /// Load balancing algorithm.
    pub lb: LoadBalancing,
    /// Health checking.
    pub health: HealthCheck,
    /// Per-upstream timeouts and limits.
    pub limits: UpstreamLimits,
    /// DNS re-resolution behaviour for hostname upstreams.
    pub dns: UpstreamDns,
    /// TLS options for `https://` upstreams.
    pub tls: UpstreamTls,
    /// Response when no upstream in the cluster is healthy.
    pub unavailable: UnavailableResponse,
}

/// Response served when every upstream in a cluster is unhealthy.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct UnavailableResponse {
    /// Status code returned to clients (typically 502 or 503).
    pub status: u16,
    /// Optional response body; a short default text is used when absent.
    pub body: Option<String>,
}

impl Default for UnavailableResponse {
    fn default() -> Self {
        Self {
            status: 502,
            body: None,
        }
    }
}

/// Load balancing algorithm.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancing {
    /// Rotate through healthy upstreams in order.
    #[default]
    RoundRobin,
    /// Send to the healthy upstream with fewest in-flight requests.
    LeastConn,
    /// Hash the client IP so it consistently reaches the same upstream.
    IpHash,
}

/// Health check configuration: active probes and passive failure tracking.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct HealthCheck {
    /// Periodic probes; absent = no active checking.
    pub active: Option<ActiveHealth>,
    /// Mark upstreams unhealthy after consecutive request failures.
    pub passive: Option<PassiveHealth>,
}

/// Active health probing.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ActiveHealth {
    /// Path to GET on each upstream, e.g. `/healthz`.
    pub path: String,
    /// Probe interval.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub interval: Duration,
    /// Per-probe timeout.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub timeout: Duration,
    /// Expected HTTP status. The upstream is healthy only on an exact match.
    pub expect: u16,
}

impl Default for ActiveHealth {
    fn default() -> Self {
        Self {
            path: "/healthz".into(),
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(3),
            expect: 200,
        }
    }
}

/// Passive health tracking.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PassiveHealth {
    /// Consecutive failures before an upstream is marked unhealthy.
    pub failures: u32,
    /// How long an upstream stays out of rotation before re-admission.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub cooldown: Duration,
}

impl Default for PassiveHealth {
    fn default() -> Self {
        Self {
            failures: 3,
            cooldown: Duration::from_secs(30),
        }
    }
}

/// Per-upstream timeouts and limits.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamLimits {
    /// TCP/TLS connect timeout.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub connect: Duration,
    /// Time waiting for upstream response headers.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub response_header: Duration,
    /// Idle keep-alive time for pooled upstream connections.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub idle: Duration,
    /// Max concurrent connections to a single upstream.
    pub max_connections: usize,
}

impl Default for UpstreamLimits {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            response_header: Duration::from_secs(30),
            idle: Duration::from_secs(90),
            max_connections: 1024,
        }
    }
}

/// DNS re-resolution for hostname upstreams.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamDns {
    /// After DNS records disappear, keep last-known-good addresses for this
    /// long before removing the upstream from rotation.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub grace: Duration,
}

impl Default for UpstreamDns {
    fn default() -> Self {
        Self {
            grace: Duration::from_secs(60),
        }
    }
}

/// TLS verification for `https://` upstreams.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamTls {
    /// Verify the upstream certificate against the web PKI or `ca`.
    pub verify: bool,
    /// Additional CA bundle (PEM) to trust.
    pub ca: Option<PathBuf>,
    /// Override the SNI/verification hostname.
    pub sni: Option<String>,
}

impl Default for UpstreamTls {
    fn default() -> Self {
        Self {
            verify: true,
            ca: None,
            sni: None,
        }
    }
}

/// A named cache store.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CacheStore {
    /// Storage tier: `ram`, `disk`, or `hybrid` (RAM in front of disk with
    /// promotion on hit).
    pub tier: CacheTier,
    /// Eviction policy when limits are exceeded.
    pub policy: EvictionPolicy,
    /// RAM budget. Required for `ram` and `hybrid`.
    pub ram_bytes: ByteSize,
    /// Disk budget. Required for `disk` and `hybrid`.
    pub disk_bytes: ByteSize,
    /// Directory for on-disk objects and index. Required unless `ram`.
    pub disk_path: Option<PathBuf>,
    /// Maximum number of cached items.
    pub max_items: u64,
    /// Maximum size of a single cacheable object.
    pub max_object_bytes: ByteSize,
}

impl Default for CacheStore {
    fn default() -> Self {
        Self {
            tier: CacheTier::default(),
            policy: EvictionPolicy::default(),
            ram_bytes: ByteSize::mib(256),
            disk_bytes: ByteSize::gib(10),
            disk_path: None,
            max_items: 1_000_000,
            max_object_bytes: ByteSize::mib(64),
        }
    }
}

/// Cache storage tier.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CacheTier {
    /// RAM only.
    #[default]
    Ram,
    /// Disk only; persists across restarts.
    Disk,
    /// RAM in front of disk, promoted on hit.
    Hybrid,
}

/// Cache eviction policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum EvictionPolicy {
    /// Least recently used.
    #[default]
    Lru,
    /// Least frequently used.
    Lfu,
    /// First in, first out.
    Fifo,
}

/// TLS mode for a site.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum SiteTls {
    /// A mode keyword.
    Mode(TlsMode),
    /// Explicit certificate files.
    Manual(ManualTls),
}

impl Default for SiteTls {
    fn default() -> Self {
        SiteTls::Mode(TlsMode::Auto)
    }
}

/// TLS mode keyword.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// Obtain and renew certificates automatically via ACME.
    #[default]
    Auto,
    /// No TLS for this site.
    Off,
    /// Generate a self-signed certificate (local development).
    SelfSigned,
}

/// A virtual site: a set of hosts with routes and optional TLS.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SiteConfig {
    /// Optional display name used in logs, metrics and the admin API.
    pub name: Option<String>,
    /// Hostnames served by this site. Exact names and `*.example.com`
    /// wildcards. May be empty only when `default = true`.
    pub hosts: Vec<String>,
    /// Serve requests whose Host matches no site.
    pub default: bool,
    /// TLS mode: `"auto"` (ACME), `{cert, key}`, `"selfsigned"`, or `"off"`.
    pub tls: SiteTls,
    /// Redirect plaintext HTTP to HTTPS when TLS is enabled.
    pub redirect_https: bool,
    /// Host the HTTPS redirect points at; defaults to the request's Host.
    /// Useful for `www → apex` style consolidation across schemes.
    pub redirect_host: Option<String>,
    /// Shorthand for a catch-all static file route rooted here.
    pub root: Option<PathBuf>,
    /// Shorthand for a catch-all reverse proxy route to these upstream URLs.
    pub proxy: Vec<String>,
    /// Routes, evaluated in order of specificity, not declaration order.
    pub route: Vec<RouteConfig>,
    /// Per-site override of the trusted proxy CIDR list.
    #[schemars(with = "Option<Vec<String>>")]
    pub trusted_proxies: Option<Vec<ipnet::IpNet>>,
}

impl Default for SiteConfig {
    fn default() -> Self {
        Self {
            name: None,
            hosts: Vec::new(),
            default: false,
            tls: SiteTls::default(),
            redirect_https: true,
            redirect_host: None,
            root: None,
            proxy: Vec::new(),
            route: Vec::new(),
            trusted_proxies: None,
        }
    }
}

/// One route: a matcher, one handler, and middleware.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RouteConfig {
    /// Shorthand for `prefix`.
    pub path: Option<String>,
    /// Match this exact path only.
    pub exact: Option<String>,
    /// Match paths starting with this prefix.
    pub prefix: Option<String>,
    /// Match paths against this regular expression. Evaluated last; a regex
    /// route never overrides a prefix route.
    pub regex: Option<String>,
    /// Additional match conditions: methods, headers, query parameters.
    #[serde(rename = "match")]
    pub match_: Option<MatchConditions>,
    /// Priority among routes that tie on specificity. Higher wins.
    pub priority: i32,

    /// Serve static files.
    #[serde(rename = "static")]
    pub static_files: Option<StaticHandler>,
    /// Reverse proxy handler.
    pub proxy: Option<ProxyHandler>,
    /// Redirect handler.
    pub redirect: Option<RedirectHandler>,
    /// Fixed response handler.
    pub respond: Option<RespondHandler>,

    /// Client CIDRs allowed; others get 403.
    #[schemars(with = "Vec<String>")]
    pub ip_allow: Vec<ipnet::IpNet>,
    /// Client CIDRs denied; they get 403 before allow rules.
    #[schemars(with = "Vec<String>")]
    pub ip_deny: Vec<ipnet::IpNet>,
    /// Authentication configuration.
    pub auth: Option<AuthConfig>,
    /// Rate limiting.
    pub rate_limit: Option<RateLimitConfig>,
    /// CORS handling.
    pub cors: Option<CorsConfig>,
    /// Response caching.
    pub cache: Option<RouteCache>,
    /// Response compression.
    pub compress: Option<CompressConfig>,
    /// Response header manipulation applied to this route's responses.
    pub headers: Option<HeaderOps>,
    /// Per-route security-header overrides.
    pub security: Option<RouteSecurity>,
    /// Per-route timeout overrides (e.g. `0s` deadline for SSE/WebSocket).
    pub timeouts: Option<TimeoutOverrides>,
    /// Per-route limit overrides.
    pub limits: Option<LimitOverrides>,
}

/// Per-route timeout overrides; each absent field inherits the global value.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TimeoutOverrides {
    /// See [`Timeouts::header_read`].
    #[serde(with = "humantime_serde::option")]
    #[schemars(with = "Option<String>")]
    pub header_read: Option<Duration>,
    /// See [`Timeouts::body_read`].
    #[serde(with = "humantime_serde::option")]
    #[schemars(with = "Option<String>")]
    pub body_read: Option<Duration>,
    /// See [`Timeouts::idle`].
    #[serde(with = "humantime_serde::option")]
    #[schemars(with = "Option<String>")]
    pub idle: Option<Duration>,
    /// See [`Timeouts::request_deadline`]; set `0s` for long-lived streams.
    #[serde(with = "humantime_serde::option")]
    #[schemars(with = "Option<String>")]
    pub request_deadline: Option<Duration>,
}

/// Per-route limit overrides.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct LimitOverrides {
    /// See [`Limits::header_bytes`].
    pub header_bytes: Option<ByteSize>,
    /// See [`Limits::body_bytes`].
    pub body_bytes: Option<ByteSize>,
}

/// Additional match conditions. Conditions filter candidate routes; they do
/// not affect path precedence.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct MatchConditions {
    /// HTTP methods, e.g. `["GET", "HEAD"]`.
    pub methods: Vec<String>,
    /// Required request headers. Values match exactly, or as regex when
    /// prefixed with `re:`.
    pub headers: BTreeMap<String, String>,
    /// Required query parameters (`key` must equal or regex-match the value).
    /// A value of `""` requires only presence.
    pub query: BTreeMap<String, String>,
}

/// Static file handler.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StaticHandler {
    /// Document root on disk.
    pub root: PathBuf,
    /// Index files tried for directory requests, in order.
    #[serde(default = "StaticHandler::default_index")]
    pub index: Vec<String>,
    /// HTML directory listing when no index file exists.
    #[serde(default)]
    pub listing: bool,
    /// SPA mode: serve `index.html` for unknown paths.
    #[serde(default)]
    pub spa: bool,
    /// Extra fallback files tried before the index, e.g. `["/500.html"]`.
    #[serde(default)]
    pub try_files: Vec<String>,
    /// Serve a sibling `.gz`, `.br`, or `.zst` file when the client accepts
    /// that encoding.
    #[serde(default = "default_true")]
    pub precompressed: bool,
    /// `Cache-Control` values applied to paths matching the glob keys.
    #[serde(default)]
    pub cache_control: BTreeMap<String, String>,
    /// Custom error pages: status code → file path, always relative to
    /// `root` (a leading `/` means "from the document root").
    #[serde(default, with = "crate::config::values::status_map")]
    #[schemars(with = "BTreeMap<String, PathBuf>")]
    pub error_pages: BTreeMap<u16, PathBuf>,
    /// MIME type overrides by file extension (without dot).
    #[serde(default)]
    pub mime_types: BTreeMap<String, String>,
}

impl Default for StaticHandler {
    fn default() -> Self {
        Self {
            root: PathBuf::new(),
            index: Self::default_index(),
            listing: false,
            spa: false,
            try_files: Vec::new(),
            precompressed: true,
            cache_control: BTreeMap::new(),
            error_pages: BTreeMap::new(),
            mime_types: BTreeMap::new(),
        }
    }
}

impl StaticHandler {
    fn default_index() -> Vec<String> {
        vec!["index.html".into()]
    }
}

/// Reverse proxy handler.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProxyHandler {
    /// Named upstream (`upstream.name`) or an inline list of upstream URLs.
    pub upstream: UpstreamRef,
    /// Path rewriting before forwarding.
    #[serde(default)]
    pub rewrite: Option<Rewrite>,
    /// Request header manipulation applied before forwarding upstream.
    #[serde(default)]
    pub headers: Option<HeaderOps>,
    /// Retry policy for idempotent requests on connection failure.
    #[serde(default)]
    pub retries: RetryPolicy,
    /// Rewrite the `Host` header to the upstream authority (vs. passing the
    /// original host through).
    #[serde(default = "default_true")]
    pub pass_host: bool,
}

/// Upstream reference: a name or an inline URL list.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum UpstreamRef {
    /// Name of a top-level `[upstream.<name>]` cluster.
    Name(String),
    /// Inline list of upstream URLs forming an anonymous cluster.
    Urls(Vec<String>),
}

/// Path rewriting before forwarding upstream.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Rewrite {
    /// Remove this prefix from the request path.
    pub strip_prefix: Option<String>,
    /// Replace this path prefix with another.
    pub replace_prefix: Option<(String, String)>,
    /// Apply `pattern` regex substitution once to the path.
    pub regex: Option<RegexRewrite>,
}

/// Regex path rewrite: `pattern` → `replace`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegexRewrite {
    /// Regular expression matched against the path.
    pub pattern: String,
    /// Replacement, may contain `$1`-style capture references.
    pub replace: String,
}

/// Retry policy for idempotent requests.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RetryPolicy {
    /// Total retry budget across all requests to the cluster (concurrent
    /// retries are limited to this fraction of recent requests, and never
    /// exceed `max` per request).
    pub max_per_request: u8,
    /// Maximum in-flight retries as a fraction (0–1) of total requests.
    pub budget_fraction: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_per_request: 2,
            budget_fraction: 0.2,
        }
    }
}

/// Redirect handler.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RedirectHandler {
    /// Redirect to a fixed URL template. `{host}`, `{path}`, `{query}` are
    /// substituted from the request.
    pub to: Option<String>,
    /// Redirect to the same path on another host (and optional port).
    pub host: Option<String>,
    /// Redirect to another scheme, e.g. `https`.
    pub scheme: Option<String>,
    /// Status code: 301, 302, 307 (preserves method+body), or 308.
    pub status: u16,
}

impl Default for RedirectHandler {
    fn default() -> Self {
        Self {
            to: None,
            host: None,
            scheme: None,
            status: 308,
        }
    }
}

/// Fixed response handler.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RespondHandler {
    /// Status code.
    pub status: u16,
    /// Response body (text). `{path}`, `{host}`, `{method}` substitute from
    /// the request.
    pub body: String,
    /// Extra response headers.
    pub headers: BTreeMap<String, String>,
}

impl Default for RespondHandler {
    fn default() -> Self {
        Self {
            status: 200,
            body: String::new(),
            headers: BTreeMap::new(),
        }
    }
}

/// Header manipulation: `set` overwrites, `add` appends, `remove` deletes.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct HeaderOps {
    /// Headers to set (replace any existing values).
    pub set: BTreeMap<String, String>,
    /// Headers to add (append without removing existing values).
    pub add: BTreeMap<String, String>,
    /// Header names to remove.
    pub remove: Vec<String>,
}

/// Authentication configuration; exactly one method per route.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// HTTP Basic authentication.
    pub basic: Option<BasicAuth>,
    /// Bearer token authentication (`Authorization: Bearer <token>`).
    pub bearer: Option<BearerAuth>,
    /// API key in a header or query parameter.
    pub api_key: Option<ApiKeyAuth>,
}

/// HTTP Basic authentication.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct BasicAuth {
    /// User → hashed password. Argon2 hashes (`$argon2id$...`) inline, or
    /// use `htpasswd` for bcrypt `$2y$` files. Generate hashes with any
    /// argon2/bcrypt tool; plaintext values are rejected at validation.
    pub users: BTreeMap<String, String>,
    /// Path to an htpasswd file (bcrypt `$2y$` entries).
    pub htpasswd: Option<PathBuf>,
    /// Basic auth realm.
    pub realm: Option<String>,
}

/// Bearer token authentication.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct BearerAuth {
    /// Valid tokens. Prefer `${VAR}`/`${file:...}` interpolation.
    pub tokens: Vec<String>,
}

/// API key authentication.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyAuth {
    /// Where the key is read: `header` or `query`.
    pub location: ApiKeyLocation,
    /// Header name (e.g. `X-Api-Key`) or query parameter name.
    pub name: String,
    /// Valid keys.
    pub keys: Vec<String>,
}

/// API key location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyLocation {
    /// In a request header.
    Header,
    /// In a query parameter.
    Query,
}

/// Rate limiting.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// What the limit applies to: `ip`, `identity` (authenticated identity),
    /// `route`, or `header:<Name>` for an arbitrary header value.
    pub key: String,
    /// Sustained rate, e.g. `100/s`, `600/m`, `10000/h`.
    pub rate: RateSpec,
    /// Burst size; defaults to the per-second equivalent of `rate`.
    #[serde(default)]
    pub burst: Option<u32>,
    /// CIDRs exempt from limiting.
    #[serde(default)]
    #[schemars(with = "Vec<String>")]
    pub exempt: Vec<ipnet::IpNet>,
    /// Log-only mode: never reject, but emit metrics/logs as if it would.
    #[serde(default)]
    pub dry_run: bool,
}

/// CORS configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CorsConfig {
    /// Allowed origins: exact origins, `*`, `*.suffix` wildcards, or
    /// `re:`-prefixed regular expressions.
    pub origins: Vec<String>,
    /// Allowed methods for preflight.
    pub methods: Vec<String>,
    /// Allowed request headers for preflight.
    pub headers: Vec<String>,
    /// Headers exposed to browsers on real responses.
    pub expose: Vec<String>,
    /// Allow credentials (cookies, Authorization).
    pub credentials: bool,
    /// Preflight cache duration.
    #[serde(with = "humantime_serde::option")]
    #[schemars(with = "Option<String>")]
    pub max_age: Option<Duration>,
}

/// Route cache configuration referencing a named `[cache.<store>]`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteCache {
    /// Name of a top-level cache store.
    pub store: String,
    /// TTL override for responses without explicit freshness. Otherwise
    /// `Cache-Control`/`Expires` semantics apply.
    #[serde(with = "humantime_serde::option", default)]
    #[schemars(with = "Option<String>")]
    pub ttl: Option<Duration>,
    /// Serve stale while revalidating in the background, for this long.
    #[serde(with = "humantime_serde::option", default)]
    #[schemars(with = "Option<String>")]
    pub stale_while_revalidate: Option<Duration>,
    /// Serve stale on upstream error for this long.
    #[serde(with = "humantime_serde::option", default)]
    #[schemars(with = "Option<String>")]
    pub stale_if_error: Option<Duration>,
    /// Short TTL used for error responses (negative caching).
    #[serde(with = "humantime_serde", default = "RouteCache::default_negative_ttl")]
    #[schemars(with = "String")]
    pub negative_ttl: Duration,
    /// Requests that bypass the cache.
    #[serde(default)]
    pub bypass: CacheBypass,
    /// Extra headers folded into the cache key (in addition to the response
    /// `Vary` header).
    #[serde(default)]
    pub vary_headers: Vec<String>,
    /// Emit the `X-Cache` response header.
    #[serde(default = "default_true")]
    pub x_cache: bool,
}

impl Default for RouteCache {
    fn default() -> Self {
        Self {
            store: String::new(),
            ttl: None,
            stale_while_revalidate: None,
            stale_if_error: None,
            negative_ttl: Self::default_negative_ttl(),
            bypass: CacheBypass::default(),
            vary_headers: Vec::new(),
            x_cache: true,
        }
    }
}

impl RouteCache {
    fn default_negative_ttl() -> Duration {
        Duration::from_secs(10)
    }
}

/// Cache bypass rules. Requests carrying `Authorization` bypass by default
/// (`authenticated`).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CacheBypass {
    /// Authenticated requests (`Authorization` header present or identity
    /// resolved by `route.auth`) bypass the cache.
    #[serde(default = "default_true")]
    pub authenticated: bool,
    /// HTTP methods that bypass (default: all except GET and HEAD).
    pub methods: Vec<String>,
    /// Cookie names whose presence bypasses the cache.
    pub cookies: Vec<String>,
    /// Header names whose presence bypasses the cache.
    pub headers: Vec<String>,
    /// Path globs that bypass the cache.
    pub paths: Vec<String>,
}

impl Default for CacheBypass {
    fn default() -> Self {
        Self {
            authenticated: true,
            methods: Vec::new(),
            cookies: Vec::new(),
            headers: Vec::new(),
            paths: Vec::new(),
        }
    }
}

/// Response compression.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CompressConfig {
    /// Enabled algorithms, negotiated by client `Accept-Encoding` q-values:
    /// `br`, `zstd`, `gzip`. Defaults to all.
    pub algorithms: Vec<String>,
    /// Don't compress responses smaller than this (when Content-Length is
    /// known).
    pub min_bytes: ByteSize,
    /// Content types eligible for compression; `*` suffixes allowed.
    pub types: Vec<String>,
    /// Compression level, algorithm-specific (brotli 0–11, gzip 0–9,
    /// zstd 1–19). Default is the algorithm's balanced level.
    pub level: Option<u32>,
}

impl Default for CompressConfig {
    fn default() -> Self {
        Self {
            algorithms: vec!["br".into(), "zstd".into(), "gzip".into()],
            min_bytes: ByteSize::kib(1),
            types: vec![
                "text/*".into(),
                "application/json".into(),
                "application/javascript".into(),
                "application/xml".into(),
                "application/wasm".into(),
                "image/svg+xml".into(),
                "font/ttf".into(),
                "font/otf".into(),
            ],
            level: None,
        }
    }
}
