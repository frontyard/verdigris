//! The configuration model: every type here is a `serde` target, the source
//! of truth for validation, and (via `schemars`) the source of truth for the
//! published JSON Schema. Doc comments become schema descriptions.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::config::values::{ByteSize, RateSpec, cidr, duration, one_or_many};

fn default_true() -> bool {
    true
}

/// `route.cache` accepts `false` (opt out of an inherited site cache),
/// a store name (`cache = "main"`), or a table.
fn opt_route_cache<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<RouteCache>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Flag(bool),
        Name(String),
        Full(RouteCache),
    }
    let r = Option::<Repr>::deserialize(d).map_err(|_| {
        serde::de::Error::custom("cache must be a bool, a store name, or a { store, … } table")
    })?;
    Ok(r.map(|r| match r {
        Repr::Flag(enabled) => RouteCache {
            enabled,
            ..Default::default()
        },
        Repr::Name(store) => RouteCache {
            store,
            ..Default::default()
        },
        Repr::Full(c) => c,
    }))
}

/// `route.compress` accepts `true` (enable with defaults) or a table.
fn opt_compress<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<CompressConfig>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        On(bool),
        Full(CompressConfig),
    }
    let r = Option::<Repr>::deserialize(d)
        .map_err(|_| serde::de::Error::custom("compress must be true or a table"))?;
    Ok(r.map(|r| match r {
        Repr::On(enabled) => CompressConfig {
            enabled,
            ..Default::default()
        },
        Repr::Full(c) => c,
    }))
}

/// `log.access` accepts `false` (no access log) or a table.
fn access_or_off<'de, D: serde::Deserializer<'de>>(d: D) -> Result<AccessLog, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Flag(bool),
        Dest(String),
        Full(AccessLog),
    }
    Ok(
        match Repr::deserialize(d).map_err(|_| {
            serde::de::Error::custom("access must be a bool, an output string, or a table")
        })? {
            Repr::Flag(enabled) => AccessLog {
                enabled,
                ..Default::default()
            },
            Repr::Dest(output) => AccessLog {
                output,
                ..Default::default()
            },
            Repr::Full(a) => a,
        },
    )
}

/// `upstream.dns` accepts a grace duration (`"60s"`) or a table.
fn dns_or_grace<'de, D: serde::Deserializer<'de>>(d: D) -> Result<UpstreamDns, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Grace(String),
        Full(UpstreamDns),
    }
    Ok(
        match Repr::deserialize(d)
            .map_err(|_| serde::de::Error::custom("dns must be a duration or a table"))?
        {
            Repr::Grace(s) => UpstreamDns {
                grace: humantime::parse_duration(&s).map_err(serde::de::Error::custom)?,
            },
            Repr::Full(d) => d,
        },
    )
}

/// `upstream.health.active` accepts a probe path (`"/healthz"`) or a table.
/// `upstream.*.health.passive` accepts a failure count (`passive = 5`)
/// or a full table.
fn opt_passive_health<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<PassiveHealth>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Failures(u32),
        Full(PassiveHealth),
    }
    let r = Option::<Repr>::deserialize(d).map_err(|_| {
        serde::de::Error::custom("health.passive must be a failure count or a table")
    })?;
    Ok(r.map(|r| match r {
        Repr::Failures(failures) => PassiveHealth {
            failures,
            ..Default::default()
        },
        Repr::Full(p) => p,
    }))
}

fn opt_active_health<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<ActiveHealth>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Path(String),
        Full(ActiveHealth),
    }
    let r = Option::<Repr>::deserialize(d)
        .map_err(|_| serde::de::Error::custom("health.active must be a path or a table"))?;
    Ok(r.map(|r| match r {
        Repr::Path(path) => ActiveHealth {
            path,
            ..Default::default()
        },
        Repr::Full(a) => a,
    }))
}

/// `proxy.retries` accepts `false` (no retries) or a table.
fn retries_or_off<'de, D: serde::Deserializer<'de>>(d: D) -> Result<RetryPolicy, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Flag(bool),
        Count(u8),
        Full(RetryPolicy),
    }
    Ok(
        match Repr::deserialize(d).map_err(|_| {
            serde::de::Error::custom("retries must be a bool, a retry count, or a table")
        })? {
            Repr::Flag(false) => RetryPolicy {
                max_per_request: 0,
                ..Default::default()
            },
            Repr::Flag(true) => RetryPolicy::default(),
            Repr::Count(n) => RetryPolicy {
                max_per_request: n,
                ..Default::default()
            },
            Repr::Full(r) => r,
        },
    )
}

/// `route.static` accepts a root path (`static = "/srv/www"`) or a table.
fn opt_static<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<StaticHandler>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Root(PathBuf),
        Full(StaticHandler),
    }
    let r = Option::<Repr>::deserialize(d)
        .map_err(|_| serde::de::Error::custom("static must be a root path or a table"))?;
    Ok(r.map(|r| match r {
        Repr::Root(root) => StaticHandler {
            root,
            ..Default::default()
        },
        Repr::Full(s) => s,
    }))
}

/// `route.redirect` accepts a target URL (`redirect = "https://…"`) or a table.
fn opt_redirect<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<RedirectHandler>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        To(String),
        Full(RedirectHandler),
    }
    let r = Option::<Repr>::deserialize(d)
        .map_err(|_| serde::de::Error::custom("redirect must be a target URL or a table"))?;
    Ok(r.map(|r| match r {
        Repr::To(to) => RedirectHandler {
            to: Some(to),
            ..Default::default()
        },
        Repr::Full(r) => r,
    }))
}

/// `route.respond` accepts a body string (`respond = "text"`) or a table.
fn opt_respond<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<RespondHandler>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Code(u16),
        Body(String),
        Full(RespondHandler),
    }
    let r = Option::<Repr>::deserialize(d).map_err(|_| {
        serde::de::Error::custom("respond must be a status code, a body string, or a table")
    })?;
    Ok(r.map(|r| match r {
        Repr::Code(status) => RespondHandler {
            status,
            ..Default::default()
        },
        Repr::Body(body) => RespondHandler {
            body,
            ..Default::default()
        },
        Repr::Full(r) => r,
    }))
}

/// `route.rate_limit` accepts a rate (`rate_limit = "100/s"`, per-IP
/// key) or a table.
fn opt_rate_limit<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<RateLimitConfig>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Off(bool),
        Rate(String),
        Full(RateLimitConfig),
    }
    let r = Option::<Repr>::deserialize(d).map_err(|_| {
        serde::de::Error::custom("rate_limit must be false, a rate string, or a table")
    })?;
    Ok(match r {
        Some(Repr::Off(b)) => Some(RateLimitConfig {
            enabled: b,
            ..Default::default()
        }),
        Some(Repr::Rate(s)) => Some(RateLimitConfig {
            rate: Some(RateSpec::parse(&s).map_err(serde::de::Error::custom)?),
            ..Default::default()
        }),
        Some(Repr::Full(r)) => Some(r),
        None => None,
    })
}

/// `acme.directory` accepts a directory URL or a short alias —
/// `"letsencrypt"` (production) and `"letsencrypt-staging"`. Aliases
/// resolve to the URL at load so the effective config is canonical.
fn directory_or_alias<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let s = String::deserialize(d)?;
    Ok(match s.to_ascii_lowercase().as_str() {
        "letsencrypt" => "https://acme-v02.api.letsencrypt.org/directory".into(),
        "letsencrypt-staging" => "https://acme-staging-v02.api.letsencrypt.org/directory".into(),
        _ => s,
    })
}

/// `security` accepts `false` (off-switch for inherited headers) or a
/// table — the same convention as other inherited middleware blocks.
fn opt_security<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<RouteSecurity>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Off(bool),
        Full(RouteSecurity),
    }
    Ok(Option::<Repr>::deserialize(d)?.map(|r| match r {
        Repr::Off(b) => RouteSecurity {
            enabled: Some(b),
            ..Default::default()
        },
        Repr::Full(s) => s,
    }))
}

/// Schema shape for `security` — `false` or a table.
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum RouteSecuritySchema {
    /// `security = false` — suppress all security headers on this
    /// site/route, including inherited ones.
    Off(bool),
    /// Table form: per-header overrides.
    Full(Box<RouteSecurity>),
}

/// `auth` accepts `false` — opt a route out of an inherited site
/// `auth` — or a table. Same convention as the other inherited blocks.
fn opt_auth<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<AuthConfig>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Off(bool),
        Full(AuthConfig),
    }
    Ok(Option::<Repr>::deserialize(d)?.map(|r| match r {
        Repr::Off(b) => AuthConfig {
            enabled: b,
            ..Default::default()
        },
        Repr::Full(a) => a,
    }))
}

/// Schema shape for `auth` — `false` or a table.
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum AuthConfigSchema {
    /// `auth = false` — no authentication on this site/route.
    Off(bool),
    /// Table form.
    Full(Box<AuthConfig>),
}

/// `cors` accepts `false` (opt out of inherited CORS handling) or a table.
fn opt_cors<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<CorsConfig>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Off(bool),
        Full(CorsConfig),
    }
    Ok(Option::<Repr>::deserialize(d)?.map(|r| match r {
        Repr::Off(b) => CorsConfig {
            enabled: b,
            ..Default::default()
        },
        Repr::Full(c) => c,
    }))
}

/// Schema shape for `cors` — `false` or a table.
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum CorsConfigSchema {
    /// `cors = false` — no CORS handling on this site/route.
    Off(bool),
    /// Table form.
    Full(Box<CorsConfig>),
}

/// `response_headers` accepts `false` (opt out of the inherited ops)
/// or a table.
fn opt_header_ops<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<HeaderOps>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Off(bool),
        Full(HeaderOps),
    }
    Ok(Option::<Repr>::deserialize(d)?.map(|r| match r {
        Repr::Off(b) => HeaderOps {
            enabled: b,
            ..Default::default()
        },
        Repr::Full(h) => h,
    }))
}

/// Schema shape for `response_headers` — `false` or a table.
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum HeaderOpsSchema {
    /// `response_headers = false` — no header manipulation on this
    /// site/route.
    Off(bool),
    /// Table form.
    Full(Box<HeaderOps>),
}

/// `route.proxy` accepts an upstream reference — cluster name, URL, or
/// list of URLs, same as `site.proxy` — or a full table.
fn opt_proxy<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<ProxyHandler>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Ref(UpstreamRef),
        Full(Box<ProxyHandler>),
    }
    let r = Option::<Repr>::deserialize(d).map_err(|_| {
        serde::de::Error::custom(
            "proxy must be an upstream name, URL, URL list, or an { upstream, … } table",
        )
    })?;
    Ok(r.map(|r| match r {
        Repr::Ref(upstream) => ProxyHandler {
            upstream,
            rewrite: None,
            request_headers: None,
            retries: RetryPolicy::default(),
            host_header: HostHeader::default(),
        },
        Repr::Full(p) => *p,
    }))
}

/// Root configuration for a verdigris instance.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Additional files or directories of `*.toml` fragments merged into this
    /// configuration, relative to the directory containing this file.
    /// Fragment files are loaded in sorted order; scalar conflicts between
    /// fragments and the main file are errors. A glob pattern matching no
    /// files is a no-op; a missing file or directory is an error.
    #[serde(skip_serializing)]
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
    /// port 80. Entries are either `"ip:port"` strings or
    /// `{ addr = "ip:port", tls = true }` tables to terminate TLS.
    #[schemars(with = "Vec<ListenAddrSchema>")]
    #[serde(deserialize_with = "one_or_many::deserialize")]
    pub listen: Vec<ListenAddr>,
    /// Time to wait for in-flight requests during shutdown or reload before
    /// connections are closed.
    #[serde(with = "duration")]
    #[schemars(with = "String")]
    pub graceful_timeout: Duration,
    /// CIDRs whose `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`,
    /// `X-Real-IP` and `Forwarded` headers are trusted. Empty: trust none.
    #[schemars(with = "Vec<String>")]
    #[serde(deserialize_with = "cidr::deserialize")]
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Value of the `Server` response header. `false` or `""` omits it
    /// (the empty-disables convention).
    #[serde(deserialize_with = "server_header_value")]
    #[schemars(with = "ServerHeaderSchema")]
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
    /// HSTS `max-age`, e.g. `"180d"`.
    #[serde(with = "duration")]
    #[schemars(with = "String")]
    pub hsts_max_age: Duration,
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
            hsts_max_age: Duration::from_secs(180 * 24 * 3600),
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
    /// Override HSTS `max-age` (`"180d"`).
    #[serde(with = "duration::option")]
    #[schemars(with = "Option<String>")]
    pub hsts_max_age: Option<Duration>,
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

/// A single listen socket: an `"ip:port"` or `":port"` string or an
/// `{ addr = "ip:port", tls = true }` table.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ListenAddr {
    /// `IP:port` to bind, e.g. `0.0.0.0:80`, `":8080"` (wildcard) or
    /// `[::]:443`.
    #[schemars(with = "String")]
    pub addr: SocketAddr,
    /// Terminate TLS on this listener.
    pub tls: bool,
}

/// `":8080"` reads as all-interfaces wildcard — prepend `0.0.0.0`.
/// A bare `"8080"` stays an error: guessing the host intent is worse
/// than asking for it.
fn parse_listen_addr(s: &str) -> Result<SocketAddr, String> {
    let owned;
    let s = match s.strip_prefix(':') {
        Some(rest) => {
            owned = format!("0.0.0.0:{rest}");
            &owned
        }
        None => s,
    };
    s.parse::<SocketAddr>().map_err(|e| e.to_string())
}

/// `admin.listen` accepts `"IP:port"` and `":port"` (wildcard) strings —
/// same grammar as `server.listen` entries.
fn listen_addr<'de, D: serde::Deserializer<'de>>(d: D) -> Result<SocketAddr, D::Error> {
    let s = String::deserialize(d)?;
    parse_listen_addr(&s).map_err(serde::de::Error::custom)
}

/// `server_header` accepts a header-value string or `false` — `false`
/// omits the header, same as `""`.
fn server_header_value<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Off(bool),
        Value(String),
    }
    match Repr::deserialize(d)
        .map_err(|_| serde::de::Error::custom("server_header must be a string or false"))?
    {
        Repr::Value(s) => Ok(s),
        Repr::Off(false) => Ok(String::new()),
        Repr::Off(true) => Err(serde::de::Error::custom(
            "server_header = true is meaningless — use false, \"\", or a value string",
        )),
    }
}

/// Schema shape for `server_header` — `false` or a string.
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum ServerHeaderSchema {
    /// `server_header = false` — omit the `Server` response header.
    Off(bool),
    /// Header value (`""` also omits).
    Value(String),
}

impl<'de> Deserialize<'de> for ListenAddr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Table {
            #[serde(default)]
            addr: Option<String>,
            #[serde(default)]
            tls: bool,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Addr(String),
            Table(Table),
        }
        match Repr::deserialize(d).map_err(|_| {
            serde::de::Error::custom(
                "listen entries must be \"ip:port\" or \":port\" strings or { addr, tls } tables",
            )
        })? {
            Repr::Addr(s) => Ok(Self {
                addr: parse_listen_addr(&s).map_err(serde::de::Error::custom)?,
                tls: false,
            }),
            Repr::Table(t) => Ok(Self {
                // `tls = true` alone implies the HTTPS port — ending up
                // serving TLS on :80 is never what the operator meant.
                addr: t
                    .addr
                    .map(|s| parse_listen_addr(&s).map_err(serde::de::Error::custom))
                    .transpose()?
                    .unwrap_or_else(|| {
                        if t.tls {
                            SocketAddr::from(([0, 0, 0, 0], 443))
                        } else {
                            ListenAddr::default().addr
                        }
                    }),
                tls: t.tls,
            }),
        }
    }
}

/// Schema shape for a `server.listen` entry (`"ip:port"` or `{addr, tls}`).
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum ListenAddrSchema {
    /// `"ip:port"` or `":port"` (all interfaces) — a plaintext listener.
    Addr(String),
    /// `{ addr = "ip:port", tls = true }` — both optional.
    Full {
        /// `IP:port` to bind (default `0.0.0.0:80`, or `:443` when `tls`).
        addr: Option<String>,
        /// Terminate TLS on this listener (default `false`).
        tls: Option<bool>,
    },
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
    #[serde(with = "duration")]
    #[schemars(with = "String")]
    pub tls_handshake: Duration,
    /// Time allowed to read request headers (slowloris protection).
    #[serde(with = "duration")]
    #[schemars(with = "String")]
    pub header_read: Duration,
    /// Time allowed to read a request body.
    #[serde(with = "duration")]
    #[schemars(with = "String")]
    pub body_read: Duration,
    /// Keep-alive idle time between requests on one connection.
    #[serde(with = "duration")]
    #[schemars(with = "String")]
    pub idle: Duration,
    /// Write-side inactivity deadline: a send that stalls longer than
    /// this closes the connection (slow-client/slow-read protection).
    /// Progress resets it — large slow downloads are fine. `0s` disables.
    #[serde(with = "duration")]
    #[schemars(with = "String")]
    pub send: Duration,
    /// Overall per-request deadline. Set to `0s` for long-lived routes
    /// (SSE, WebSocket, long-polling).
    #[serde(with = "duration")]
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
            send: Duration::from_secs(60),
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
        if let Some(v) = over.send {
            self.send = v;
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
    /// Access log settings; `access = false` disables access logging.
    #[serde(deserialize_with = "access_or_off")]
    #[schemars(with = "AccessLogSchema")]
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
    /// Destination: `stdout`, `stderr`, or a file path. File output is
    /// reopened on `SIGUSR1` for logrotate.
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
    /// Serve the admin API. `false` disables the listener entirely —
    /// `listen`, `token`, and `tls` are then ignored.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// `IP:port` to bind — `":port"` expands to the wildcard
    /// `0.0.0.0:port`, same as `server.listen` entries. Use loopback
    /// unless remote administration is needed.
    #[serde(deserialize_with = "listen_addr")]
    #[schemars(with = "String")]
    pub listen: SocketAddr,
    /// Bearer token required on all admin requests. Mandatory when `listen`
    /// is not a loopback address; use `${VAR}` interpolation to keep it out
    /// of the file.
    pub token: Option<String>,
    /// Optional TLS for the admin listener (recommended when bound
    /// beyond localhost): `"self_signed"` or a `{ cert, key }` table.
    #[schemars(with = "Option<AdminTlsSchema>")]
    pub tls: Option<AdminTls>,
}

/// TLS mode for the admin listener.
#[derive(Debug, Clone)]
pub enum AdminTls {
    /// `admin.tls = "self_signed"` — a generated certificate for
    /// `localhost` and the listen address (development convenience).
    SelfSigned,
    /// PEM pair.
    Manual(ManualTls),
}

impl<'de> Deserialize<'de> for AdminTls {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Mode(String),
            Manual(ManualTls),
        }
        match Repr::deserialize(d).map_err(|_| {
            serde::de::Error::custom("admin.tls must be \"self_signed\" or a { cert, key } table")
        })? {
            Repr::Mode(m) if m == "self_signed" => Ok(Self::SelfSigned),
            Repr::Mode(m) => Err(serde::de::Error::custom(format!(
                "admin.tls mode {m:?} is not supported — use \"self_signed\" or a {{ cert, key }} table"
            ))),
            Repr::Manual(m) => Ok(Self::Manual(m)),
        }
    }
}

impl Serialize for AdminTls {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::SelfSigned => s.serialize_str("self_signed"),
            Self::Manual(m) => m.serialize(s),
        }
    }
}

/// Schema shape for `admin.tls` — `"self_signed"` or a table.
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum AdminTlsSchema {
    /// `"self_signed"` — generated localhost certificate.
    Mode(String),
    /// PEM pair.
    Full(ManualTls),
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
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
    /// ACME directory URL, or an alias: `"letsencrypt"` and
    /// `"letsencrypt-staging"` (use the staging directory while testing
    /// to avoid production rate limits). Aliases resolve to their URL
    /// at load.
    #[serde(deserialize_with = "directory_or_alias")]
    pub directory: String,
    /// Directory holding the account key and issued certificates. Must be
    /// writable; persists across restarts.
    pub storage: PathBuf,
    /// External Account Binding for providers that require it.
    pub eab: Option<ExternalAccountBinding>,
    /// Renew certificates this long before expiry.
    #[serde(with = "duration")]
    #[schemars(with = "String")]
    pub renew_before: Duration,
    /// Preferred challenge type: `http-01`, `tls-alpn-01`, `dns-01`
    /// (requires `acme.dns`), or `auto` (HTTP-01 when a plaintext
    /// listener exists, else TLS-ALPN-01).
    pub challenge: AcmeChallenge,
    /// PEM bundle of extra CA roots to trust when talking to the ACME
    /// directory — for private ACME servers (Pebble, step-ca, internal
    /// PKI). The system/WebPKI roots are always included.
    pub ca_roots: Option<PathBuf>,
    /// DNS provider for the `dns-01` challenge — required when
    /// `acme.challenge = "dns-01"`.
    pub dns: Option<AcmeDns>,
    /// On-demand issuance for previously unseen hostnames.
    pub on_demand: OnDemandAcme,
}

/// Which ACME challenge type to solve.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum AcmeChallenge {
    /// `http-01` — answer challenges over HTTP on port 80.
    #[serde(rename = "http-01", alias = "http_01")]
    Http01,
    /// `tls-alpn-01` — answer challenges inside the TLS handshake.
    #[serde(rename = "tls-alpn-01", alias = "tls_alpn_01")]
    TlsAlpn01,
    /// `dns-01` — publish `_acme-challenge` TXT records via a DNS
    /// provider API (`acme.dns`). Required for wildcard certificates;
    /// works with no ACME-reachable ports at all.
    #[serde(rename = "dns-01", alias = "dns_01")]
    Dns01,
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
            dns: None,
            on_demand: OnDemandAcme::default(),
        }
    }
}

/// DNS provider used to publish `_acme-challenge` TXT records for the
/// `dns-01` challenge (`[acme.dns]`).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub enum AcmeDns {
    /// Cloudflare API v4: `[acme.dns.cloudflare]`.
    #[serde(rename = "cloudflare")]
    Cloudflare(CloudflareDns),
}

/// Cloudflare credentials for `dns-01` (`[acme.dns.cloudflare]`).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CloudflareDns {
    /// API token with `Zone.DNS:Edit` on the zones to validate; zone
    /// discovery also needs `Zone.Zone:Read`. Prefer `${VAR}` or
    /// `${file:…}` interpolation over a literal token.
    pub api_token: String,
    /// Zone ID to pin all records to. When unset the zone is
    /// discovered per hostname by walking up its labels via the API.
    pub zone_id: Option<String>,
    /// API base URL — override only for tests or API gateways
    /// (default `https://api.cloudflare.com/client/v4`).
    pub api_base: Option<String>,
    /// Nameserver (`ip` or `ip:port`) to poll while waiting for TXT
    /// propagation — e.g. the zone's authoritative NS or a fast public
    /// resolver. Defaults to the system resolver.
    pub resolver: Option<String>,
    /// How long to wait for TXT records to appear in DNS before the CA
    /// is told to validate (default `2m`).
    #[serde(default = "default_dns_propagation_timeout", with = "duration")]
    #[schemars(with = "String")]
    pub propagation_timeout: Duration,
}

fn default_dns_propagation_timeout() -> Duration {
    Duration::from_secs(120)
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
    #[serde(deserialize_with = "one_or_many::deserialize")]
    pub allowed_hosts: Vec<String>,
    /// Maximum issuance rate, e.g. `5/hour`.
    pub rate: Option<RateSpec>,
}

fn default_one() -> u32 {
    1
}

/// One upstream server: a bare URL or a `{ url, weight, backup }` entry.
/// `weight` scales how often load balancing picks it relative to the
/// other primaries; `backup` members serve only when no primary is
/// healthy.
#[derive(Debug, Clone, JsonSchema)]
pub struct UpstreamServer {
    /// Server URL: `http://`, `https://`, or `h2c://`.
    pub url: String,
    /// Relative selection weight (≥ 1).
    pub weight: u32,
    /// `true` marks a standby used only when no primary is healthy.
    pub backup: bool,
}

impl UpstreamServer {
    fn new(url: String) -> Self {
        Self {
            url,
            weight: 1,
            backup: false,
        }
    }
}

impl From<String> for UpstreamServer {
    fn from(url: String) -> Self {
        Self::new(url)
    }
}

impl From<&str> for UpstreamServer {
    fn from(url: &str) -> Self {
        Self::new(url.to_string())
    }
}

impl<'de> Deserialize<'de> for UpstreamServer {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Full {
            url: String,
            #[serde(default = "default_one")]
            weight: u32,
            #[serde(default)]
            backup: bool,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Url(String),
            Full(Full),
        }
        match Repr::deserialize(d)? {
            Repr::Url(url) => Ok(Self::new(url)),
            Repr::Full(f) => Ok(Self {
                url: f.url,
                weight: f.weight,
                backup: f.backup,
            }),
        }
    }
}

impl Serialize for UpstreamServer {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // keep the short form on dump for default entries
        if self.weight == 1 && !self.backup {
            return s.serialize_str(&self.url);
        }
        #[derive(Serialize)]
        struct Full<'a> {
            url: &'a str,
            weight: u32,
            backup: bool,
        }
        Full {
            url: &self.url,
            weight: self.weight,
            backup: self.backup,
        }
        .serialize(s)
    }
}

/// Schema shape for one `upstream.*.servers` entry.
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum UpstreamServerSchema {
    /// `"http://host:port"` — weight 1, primary.
    Url(String),
    /// Full entry form.
    Full(UpstreamServerEntry),
}

/// `{ url, weight, backup }` entry form.
#[derive(JsonSchema)]
pub struct UpstreamServerEntry {
    /// Server URL: `http://`, `https://`, or `h2c://`.
    pub url: String,
    /// Relative selection weight (≥ 1). Default 1.
    pub weight: u32,
    /// `true` marks a standby used only when no primary is healthy.
    /// Default false.
    pub backup: bool,
}

/// A named cluster of upstream servers.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamConfig {
    /// Server entries: a URL string or `{ url, weight, backup }` table —
    /// `http://host:port`, `https://host:port`, or `h2c://` for cleartext
    /// HTTP/2 prior knowledge (typical for gRPC backends).
    #[serde(deserialize_with = "one_or_many::deserialize")]
    #[schemars(with = "Vec<UpstreamServerSchema>")]
    pub servers: Vec<UpstreamServer>,
    /// Load balancing algorithm.
    pub lb: LoadBalancing,
    /// Health checking; `health = "/healthz"` enables active probes on
    /// that path (same as `health.active = "/healthz"`).
    #[serde(deserialize_with = "health_or_active")]
    #[schemars(with = "HealthCheckSchema")]
    pub health: HealthCheck,
    /// Per-upstream timeouts.
    pub timeouts: UpstreamTimeouts,
    /// Max concurrent connections to a single upstream.
    #[serde(default = "default_upstream_max_connections")]
    pub max_connections: usize,
    /// DNS re-resolution behaviour for hostname upstreams: a duration
    /// (`"60s"`, the record-loss grace period) or a table.
    #[serde(deserialize_with = "dns_or_grace")]
    #[schemars(with = "UpstreamDnsSchema")]
    pub dns: UpstreamDns,
    /// TLS options for `https://` upstreams.
    pub tls: UpstreamTls,
    /// Response when no upstream in the cluster is healthy —
    /// `unavailable = 503` or a table.
    #[serde(deserialize_with = "unavailable_or_table")]
    #[schemars(with = "UnavailableSchema")]
    pub unavailable: UnavailableResponse,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            lb: LoadBalancing::default(),
            health: HealthCheck::default(),
            timeouts: UpstreamTimeouts::default(),
            max_connections: default_upstream_max_connections(),
            dns: UpstreamDns::default(),
            tls: UpstreamTls::default(),
            unavailable: UnavailableResponse::default(),
        }
    }
}

fn default_upstream_max_connections() -> usize {
    1024
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

/// `unavailable` accepts a status code (`unavailable = 503`) or a table.
fn unavailable_or_table<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<UnavailableResponse, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Code(u16),
        Full(UnavailableResponse),
    }
    Ok(
        match Repr::deserialize(d)
            .map_err(|_| serde::de::Error::custom("unavailable must be a status code or a table"))?
        {
            Repr::Code(status) => UnavailableResponse { status, body: None },
            Repr::Full(u) => u,
        },
    )
}

/// Schema shape for `unavailable` — a status code or a table.
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum UnavailableSchema {
    /// `unavailable = 503` — this status with a default body.
    Code(u16),
    /// Full table form.
    Full(UnavailableResponse),
}

/// Load balancing algorithm.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancing {
    /// Rotate through healthy upstreams in order.
    #[default]
    #[serde(alias = "round-robin")]
    RoundRobin,
    /// Send to the healthy upstream with fewest in-flight requests.
    #[serde(alias = "least-conn")]
    LeastConn,
    /// Hash the client IP so it consistently reaches the same upstream.
    #[serde(alias = "ip-hash")]
    IpHash,
}

/// `health` accepts a probe-path string (`health = "/healthz"`, an
/// `active` shorthand) or a table — the only parent-field shorthand, on
/// the grounds that `active` is overwhelmingly the common case.
fn health_or_active<'de, D: serde::Deserializer<'de>>(d: D) -> Result<HealthCheck, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Path(String),
        Full(HealthCheck),
    }
    Ok(
        match Repr::deserialize(d)
            .map_err(|_| serde::de::Error::custom("health must be a path string or a table"))?
        {
            Repr::Path(path) => HealthCheck {
                active: Some(ActiveHealth {
                    path,
                    ..Default::default()
                }),
                passive: None,
            },
            Repr::Full(h) => h,
        },
    )
}

/// Schema shape for `health` — a probe path or a table.
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum HealthCheckSchema {
    /// `health = "/healthz"` — active probes on this path, default
    /// settings.
    Path(String),
    /// Full table form.
    Full(HealthCheck),
}

/// Health check configuration: active probes and passive failure tracking.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct HealthCheck {
    /// Periodic probes; absent = no active checking. A string is the
    /// probe path (`active = "/healthz"`) with default settings.
    #[serde(deserialize_with = "opt_active_health")]
    #[schemars(with = "Option<ActiveHealthSchema>")]
    pub active: Option<ActiveHealth>,
    /// Mark upstreams unhealthy after consecutive request failures;
    /// `passive = 5` is `{ failures = 5 }` with the default cooldown.
    #[serde(deserialize_with = "opt_passive_health")]
    #[schemars(with = "Option<PassiveHealthSchema>")]
    pub passive: Option<PassiveHealth>,
}

/// Active health probing.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ActiveHealth {
    /// Path to GET on each upstream, e.g. `/healthz`.
    pub path: String,
    /// Probe interval.
    #[serde(with = "duration")]
    #[schemars(with = "String")]
    pub interval: Duration,
    /// Per-probe timeout.
    #[serde(with = "duration")]
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
    #[serde(with = "duration")]
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

/// Per-upstream timeouts.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamTimeouts {
    /// TCP/TLS connect timeout.
    #[serde(with = "duration")]
    #[schemars(with = "String")]
    pub connect: Duration,
    /// Time waiting for upstream response headers.
    #[serde(with = "duration")]
    #[schemars(with = "String")]
    pub response_header: Duration,
    /// Idle keep-alive time for pooled upstream connections.
    #[serde(with = "duration")]
    #[schemars(with = "String")]
    pub idle: Duration,
}

impl Default for UpstreamTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            response_header: Duration::from_secs(30),
            idle: Duration::from_secs(90),
        }
    }
}

/// DNS re-resolution for hostname upstreams.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamDns {
    /// After DNS records disappear, keep last-known-good addresses for this
    /// long before removing the upstream from rotation.
    #[serde(with = "duration")]
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
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum SiteTls {
    /// A mode keyword.
    Mode(TlsMode),
    /// Explicit certificate files.
    Manual(ManualTls),
}

impl<'de> Deserialize<'de> for SiteTls {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Mode(TlsMode),
            Manual(ManualTls),
        }
        match Repr::deserialize(d).map_err(|_| {
            serde::de::Error::custom(
                "tls must be \"auto\", \"off\", \"self_signed\", or a { cert, key } table",
            )
        })? {
            Repr::Mode(m) => Ok(Self::Mode(m)),
            Repr::Manual(m) => Ok(Self::Manual(m)),
        }
    }
}

impl Default for SiteTls {
    fn default() -> Self {
        SiteTls::Mode(TlsMode::Auto)
    }
}

/// TLS mode keyword.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Obtain and renew certificates automatically via ACME.
    #[default]
    Auto,
    /// No TLS for this site.
    Off,
    /// Generate a self-signed certificate (local development).
    #[serde(alias = "self-signed")]
    SelfSigned,
}

/// A virtual site: a set of hosts with routes and optional TLS.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SiteConfig {
    /// Optional display name used in logs, metrics and the admin API.
    pub name: Option<String>,
    /// Hostnames served by this site. Exact names and `*.example.com`
    /// wildcards. May be empty only when `default = true`.
    #[serde(deserialize_with = "one_or_many::deserialize")]
    pub hosts: Vec<String>,
    /// Serve requests whose Host matches no site.
    pub default: bool,
    /// TLS mode: `"auto"` (ACME), `{cert, key}`, `"self_signed"`, or `"off"`.
    pub tls: SiteTls,
    /// Redirect plaintext HTTP to HTTPS when TLS is enabled; defaults on.
    /// Set explicitly `false` only to serve a TLS site on plain HTTP.
    pub redirect_https: Option<bool>,
    /// Host the HTTPS redirect points at; defaults to the request's Host.
    /// Useful for `www → apex` style consolidation across schemes.
    pub redirect_host: Option<String>,
    /// Shorthand for a catch-all static file route rooted here.
    pub root: Option<PathBuf>,
    /// Shorthand for a catch-all reverse proxy route: a named upstream
    /// (`"app"`), an upstream URL (`"http://app:9000"`), a list of URLs,
    /// or a full proxy table like `route.proxy`.
    #[serde(deserialize_with = "opt_proxy")]
    #[schemars(with = "Option<ProxySchema>")]
    pub proxy: Option<ProxyHandler>,
    /// Shorthand for a catch-all respond route — same accepted forms as
    /// `route.respond` (`"text"`, `404`, or a table). Mutually exclusive
    /// with `root`/`proxy`/`redirect`.
    #[serde(deserialize_with = "opt_respond")]
    #[schemars(with = "Option<RespondSchema>")]
    pub respond: Option<RespondHandler>,
    /// Shorthand for a catch-all redirect route — same accepted forms as
    /// `route.redirect` (`"https://…"` or a table). Mutually exclusive
    /// with `root`/`proxy`/`respond`.
    #[serde(deserialize_with = "opt_redirect")]
    #[schemars(with = "Option<RedirectSchema>")]
    pub redirect: Option<RedirectHandler>,
    /// Routes, evaluated in order of specificity, not declaration order.
    pub route: Vec<RouteConfig>,
    /// Default auth for every route in this site; a route's own `auth`
    /// replaces it and `auth = false` opts out.
    #[serde(deserialize_with = "opt_auth")]
    #[schemars(with = "Option<AuthConfigSchema>")]
    pub auth: Option<AuthConfig>,
    /// Default CORS handling; a route's `cors` replaces it and
    /// `cors = false` opts out.
    #[serde(deserialize_with = "opt_cors")]
    #[schemars(with = "Option<CorsConfigSchema>")]
    pub cors: Option<CorsConfig>,
    /// Site-wide rate limit — one shared limiter for every route that
    /// inherits it, so `key = "ip"` limits each client across the whole
    /// site and `key = "route"` is one bucket site-wide. A route's own
    /// `rate_limit` gets a fresh limiter. Same string/table forms as
    /// `route.rate_limit`.
    #[serde(deserialize_with = "opt_rate_limit")]
    #[schemars(with = "Option<RateLimitSchema>")]
    pub rate_limit: Option<RateLimitConfig>,
    /// Default response cache: a store name or a table, like
    /// `route.cache`.
    #[serde(deserialize_with = "opt_route_cache")]
    #[schemars(with = "Option<RouteCacheSchema>")]
    pub cache: Option<RouteCache>,
    /// Default response compression: `true` for defaults or a table,
    /// like `route.compress`.
    #[serde(deserialize_with = "opt_compress")]
    #[schemars(with = "Option<CompressConfigSchema>")]
    pub compress: Option<CompressConfig>,
    /// Response header ops merged into every route's: `set`/`add` maps
    /// union (route keys win), `remove` concatenates. `response_headers =
    /// false` is a no-op.
    #[serde(deserialize_with = "opt_header_ops")]
    #[schemars(with = "Option<HeaderOpsSchema>")]
    pub response_headers: Option<HeaderOps>,
    /// Client CIDRs allowed site-wide; a route's `ip_allow` can only
    /// narrow this — both non-empty lists must pass.
    #[schemars(with = "Vec<String>")]
    #[serde(deserialize_with = "cidr::deserialize")]
    pub ip_allow: Vec<ipnet::IpNet>,
    /// Client CIDRs denied site-wide; unioned with each route's
    /// `ip_deny`.
    #[schemars(with = "Vec<String>")]
    #[serde(deserialize_with = "cidr::deserialize")]
    pub ip_deny: Vec<ipnet::IpNet>,
    /// Site-wide timeout overrides, applied between the global
    /// `timeouts` and each route's own `timeouts`.
    pub timeouts: Option<TimeoutOverrides>,
    /// Site-wide request-limit overrides, applied between the global
    /// `limits` and each route's own `limits`.
    pub limits: Option<LimitOverrides>,
    /// Site-wide security-header overrides, applied between the global
    /// `server.security` and each route's `security`. `security = false`
    /// suppresses all of them for the whole site.
    #[serde(deserialize_with = "opt_security")]
    #[schemars(with = "Option<RouteSecuritySchema>")]
    pub security: Option<RouteSecurity>,
    /// Per-site override of the trusted proxy CIDR list.
    #[schemars(with = "Option<Vec<String>>")]
    #[serde(deserialize_with = "cidr::option::deserialize")]
    pub trusted_proxies: Option<Vec<ipnet::IpNet>>,
}

/// One route: a matcher, one handler, and middleware.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RouteConfig {
    /// Match this exact path only.
    pub exact: Option<String>,
    /// Match paths starting with this prefix. Prefix matching is
    /// segment-aware: `/api` matches `/api` and `/api/…` but not `/apix`.
    pub prefix: Option<String>,
    /// Match paths against this regular expression. Evaluated last; a regex
    /// route never overrides a prefix route.
    pub regex: Option<String>,
    /// Additional match conditions: methods, headers, query parameters.
    #[serde(rename = "match")]
    pub match_: Option<MatchConditions>,
    /// Priority among routes that tie on specificity. Higher wins.
    pub priority: i32,

    /// Serve static files: a root path (`static = "/srv/www"`) or a
    /// table.
    #[serde(rename = "static", deserialize_with = "opt_static")]
    #[schemars(with = "Option<StaticSchema>")]
    pub static_files: Option<StaticHandler>,
    /// Reverse proxy: an upstream reference (`"name"`/`"url"`/`[urls]`,
    /// like `site.proxy`) or a full table.
    #[serde(deserialize_with = "opt_proxy")]
    #[schemars(with = "Option<ProxySchema>")]
    pub proxy: Option<ProxyHandler>,
    /// Redirect handler: a target URL (`redirect = "https://…"`) or a
    /// table.
    #[serde(deserialize_with = "opt_redirect")]
    #[schemars(with = "Option<RedirectSchema>")]
    pub redirect: Option<RedirectHandler>,
    /// Fixed response handler: a body string (`respond = "text"`) or a
    /// table.
    #[serde(deserialize_with = "opt_respond")]
    #[schemars(with = "Option<RespondSchema>")]
    pub respond: Option<RespondHandler>,

    /// Client CIDRs allowed; others get 403.
    #[schemars(with = "Vec<String>")]
    #[serde(deserialize_with = "cidr::deserialize")]
    pub ip_allow: Vec<ipnet::IpNet>,
    /// Client CIDRs denied; they get 403 before allow rules.
    #[schemars(with = "Vec<String>")]
    #[serde(deserialize_with = "cidr::deserialize")]
    pub ip_deny: Vec<ipnet::IpNet>,
    /// Authentication configuration; `auth = false` disables it,
    /// including any inherited site default.
    #[serde(deserialize_with = "opt_auth")]
    #[schemars(with = "Option<AuthConfigSchema>")]
    pub auth: Option<AuthConfig>,
    /// Rate limiting: a rate string (`rate_limit = "100/s"`, per-IP
    /// key) or a table.
    #[serde(deserialize_with = "opt_rate_limit")]
    #[schemars(with = "Option<RateLimitSchema>")]
    pub rate_limit: Option<RateLimitConfig>,
    /// CORS handling; `cors = false` disables it, including any
    /// inherited site default.
    #[serde(deserialize_with = "opt_cors")]
    #[schemars(with = "Option<CorsConfigSchema>")]
    pub cors: Option<CorsConfig>,
    /// Response caching: a store name (`cache = "main"`) or a table.
    #[serde(deserialize_with = "opt_route_cache")]
    #[schemars(with = "Option<RouteCacheSchema>")]
    pub cache: Option<RouteCache>,
    /// Response compression: `true` for defaults, or a table.
    #[serde(deserialize_with = "opt_compress")]
    #[schemars(with = "Option<CompressConfigSchema>")]
    pub compress: Option<CompressConfig>,
    /// Response header manipulation applied to this route's responses;
    /// `response_headers = false` disables it.
    #[serde(deserialize_with = "opt_header_ops")]
    #[schemars(with = "Option<HeaderOpsSchema>")]
    pub response_headers: Option<HeaderOps>,
    /// Per-route security-header overrides; `security = false`
    /// suppresses all security headers on this route.
    #[serde(deserialize_with = "opt_security")]
    #[schemars(with = "Option<RouteSecuritySchema>")]
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
    #[serde(with = "duration::option")]
    #[schemars(with = "Option<String>")]
    pub header_read: Option<Duration>,
    /// See [`Timeouts::body_read`].
    #[serde(with = "duration::option")]
    #[schemars(with = "Option<String>")]
    pub body_read: Option<Duration>,
    /// See [`Timeouts::idle`].
    #[serde(with = "duration::option")]
    #[schemars(with = "Option<String>")]
    pub idle: Option<Duration>,
    /// See [`Timeouts::send`]; also the inactivity bound applied to
    /// upgrade tunnels (e.g. WebSocket) — raise it or set `0s` for
    /// long-idle tunnels.
    #[serde(with = "duration::option")]
    #[schemars(with = "Option<String>")]
    pub send: Option<Duration>,
    /// See [`Timeouts::request_deadline`]; set `0s` for long-lived streams.
    #[serde(with = "duration::option")]
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
    #[serde(deserialize_with = "one_or_many::deserialize")]
    pub methods: Vec<String>,
    /// Required request headers. Values match exactly, or as regex when
    /// prefixed with `re:`. A value of `""` requires only presence —
    /// same rule as `query` (match an empty value with `re:^$`).
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
    #[serde(deserialize_with = "one_or_many::deserialize")]
    pub index: Vec<String>,
    /// HTML directory listing when no index file exists.
    #[serde(default)]
    pub listing: bool,
    /// SPA mode: serve `index.html` for unknown paths.
    #[serde(default)]
    pub spa: bool,
    /// Extra fallback files tried before SPA/listing/404: on a miss each
    /// entry is resolved relative to `root` (or the requested directory
    /// after `index` misses) and the first existing file is served. Not
    /// nginx `try_files` semantics — the request path is not rewritten.
    #[serde(default, deserialize_with = "one_or_many::deserialize")]
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
    pub request_headers: Option<HeaderOps>,
    /// Retry policy for idempotent requests on connection failure.
    /// `retries = false` disables retries entirely.
    #[serde(default, deserialize_with = "retries_or_off")]
    #[schemars(with = "RetryPolicySchema")]
    pub retries: RetryPolicy,
    /// Which `Host` the upstream sees: `"upstream"` (default) rewrites it
    /// to the upstream authority, `"original"` passes the client `Host`
    /// through, any other value is sent verbatim. `{ value = "…" }`
    /// forces verbatim even when the value spells a keyword.
    #[serde(default)]
    #[schemars(with = "HostHeaderSchema")]
    pub host_header: HostHeader,
}

/// Which `Host` value a proxied request carries upstream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum HostHeader {
    /// Rewrite `Host` to the upstream authority (default).
    #[default]
    Upstream,
    /// Pass the client's `Host` through unchanged.
    Original,
    /// Send this value verbatim (a `host[:port]` override).
    Custom(String),
    /// `{ value = "…" }` form — verbatim like `Custom`, but provenance
    /// marks it as deliberate so a value spelling a keyword doesn't trip
    /// the typo warning.
    Verbatim(String),
}

/// `{ value = "…" }` host_header table form — always verbatim, never
/// keyword-resolved.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostHeaderTable {
    value: String,
}

impl<'de> Deserialize<'de> for HostHeader {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Kw(String),
            Table(HostHeaderTable),
        }
        match Repr::deserialize(d).map_err(|_| {
            serde::de::Error::custom("host_header must be a string or { value = \"…\" }")
        })? {
            Repr::Kw(v) => Ok(match v.as_str() {
                "upstream" => Self::Upstream,
                "original" => Self::Original,
                _ => Self::Custom(v),
            }),
            // escape hatch: a table sends `value` verbatim, even when it
            // spells a keyword (`{ value = "upstream" }` is a literal
            // Host header, not the rewrite mode)
            Repr::Table(t) => Ok(Self::Verbatim(t.value)),
        }
    }
}

/// Schema shape for `host_header` — a string or `{ value = "…" }`.
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum HostHeaderSchema {
    /// `"upstream"`, `"original"`, or a verbatim value.
    Kw(String),
    /// `{ value = "…" }` — always verbatim, never keyword-resolved.
    Table(HostHeaderValue),
}

/// `{ value = "…" }` host_header table form.
#[derive(JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct HostHeaderValue {
    /// Sent verbatim as the upstream `Host` header.
    pub value: String,
}

impl Serialize for HostHeader {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            Self::Upstream => "upstream",
            Self::Original => "original",
            Self::Custom(v) | Self::Verbatim(v) => v,
        })
    }
}

/// Upstream reference: a name, a single URL (`"http://app:9000"`), or an
/// inline URL list.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum UpstreamRef {
    /// Name of a top-level `[upstream.<name>]` cluster.
    Name(String),
    /// Inline list of upstream URLs forming an anonymous cluster.
    Urls(Vec<String>),
}

impl<'de> Deserialize<'de> for UpstreamRef {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Name(String),
            Urls(Vec<String>),
        }
        match Repr::deserialize(d).map_err(|_| {
            serde::de::Error::custom("upstream must be a cluster name, URL, or list of URLs")
        })? {
            // `"http://…"`/`"h2c://…"` reads as a one-element URL list;
            // a bare word is a cluster name.
            Repr::Name(s) if s.contains("://") => Ok(Self::Urls(vec![s])),
            Repr::Name(s) => Ok(Self::Name(s)),
            Repr::Urls(u) => Ok(Self::Urls(u)),
        }
    }
}

/// Path rewriting before forwarding upstream.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Rewrite {
    /// Remove this prefix from the request path.
    pub strip_prefix: Option<String>,
    /// Replace this path prefix with another.
    pub replace_prefix: Option<PrefixPair>,
    /// Apply `pattern` regex substitution once to the path.
    pub regex: Option<RegexRewrite>,
}

/// Prefix replacement: `{ from = "/api", to = "/v1" }`.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct PrefixPair {
    /// Existing path prefix to replace.
    pub from: String,
    /// Replacement path prefix.
    pub to: String,
}

impl<'de> Deserialize<'de> for PrefixPair {
    // map-only: the legacy `["/a", "/b"]` positional form is rejected
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Named {
            from: String,
            to: String,
        }
        let t = toml::Table::deserialize(d)?;
        Named::deserialize(toml::Value::Table(t))
            .map(|n| Self {
                from: n.from,
                to: n.to,
            })
            .map_err(serde::de::Error::custom)
    }
}

impl PrefixPair {
    /// Split into `(from, to)`.
    pub fn pair(&self) -> (&str, &str) {
        (&self.from, &self.to)
    }
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
    /// Redirect to a fixed URL template. `{host}`, `{path}`, `{query}`
    /// (leading `?` included), `{method}`, `{scheme}` substitute from the
    /// request.
    pub to: Option<String>,
    /// Redirect to the same path on another host (and optional port).
    pub host: Option<String>,
    /// Redirect to another scheme, e.g. `https`.
    pub scheme: Option<String>,
    /// Status code: 301, 302, 303, 307 (preserves method+body), or 308.
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
    /// Response body (text). `{path}`, `{host}`, `{query}` (leading `?`
    /// included), `{method}`, `{scheme}` substitute from the request.
    pub body: String,
    /// Extra response headers — e.g. `content-type = "text/plain"`; the
    /// body is text, so pick a non-HTML type when placeholders are used.
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
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct HeaderOps {
    /// Set `false` to opt a route out of an inherited site
    /// `response_headers`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Headers to set (replace any existing values).
    pub set: BTreeMap<String, String>,
    /// Headers to add (append without removing existing values).
    pub add: BTreeMap<String, String>,
    /// Header names to remove.
    #[serde(deserialize_with = "one_or_many::deserialize")]
    pub remove: Vec<String>,
}

impl Default for HeaderOps {
    fn default() -> Self {
        Self {
            enabled: true,
            set: BTreeMap::new(),
            add: BTreeMap::new(),
            remove: Vec::new(),
        }
    }
}

/// Authentication configuration; exactly one method per route.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// Set `false` to opt a route out of an inherited site `auth`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// HTTP Basic authentication.
    pub basic: Option<BasicAuth>,
    /// Bearer token authentication (`Authorization: Bearer <token>`).
    pub bearer: Option<BearerAuth>,
    /// API key in a header or query parameter.
    pub api_key: Option<ApiKeyAuth>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            basic: None,
            bearer: None,
            api_key: None,
        }
    }
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
    #[serde(deserialize_with = "one_or_many::deserialize")]
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
    #[serde(deserialize_with = "one_or_many::deserialize")]
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
    /// Set `false` to opt a route out of an inherited site `rate_limit`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// What the limit applies to: `ip`, `identity` (authenticated identity),
    /// `route`, or `header:<Name>` for an arbitrary header value.
    /// Defaults to `ip`.
    #[serde(default = "default_key_ip")]
    pub key: String,
    /// Sustained rate, e.g. `100/s`, `600/m`, `10000/h`. Required when
    /// enabled.
    #[serde(default)]
    pub rate: Option<RateSpec>,
    /// Burst size; defaults to the per-second equivalent of `rate`.
    #[serde(default)]
    pub burst: Option<u32>,
    /// CIDRs exempt from limiting.
    #[serde(default)]
    #[schemars(with = "Vec<String>")]
    #[serde(deserialize_with = "cidr::deserialize")]
    pub exempt: Vec<ipnet::IpNet>,
    /// Log-only mode: never reject, but emit metrics/logs as if it would.
    #[serde(default)]
    pub dry_run: bool,
}

fn default_key_ip() -> String {
    "ip".into()
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            key: default_key_ip(),
            rate: None,
            burst: None,
            exempt: Vec::new(),
            dry_run: false,
        }
    }
}

/// CORS configuration.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CorsConfig {
    /// Set `false` to opt a route out of an inherited site `cors`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Allowed origins: exact origins, `*`, `*.suffix` wildcards, or
    /// `re:`-prefixed regular expressions.
    #[serde(deserialize_with = "one_or_many::deserialize")]
    pub origins: Vec<String>,
    /// Allowed methods for preflight.
    #[serde(deserialize_with = "one_or_many::deserialize")]
    pub methods: Vec<String>,
    /// Allowed request headers for preflight.
    #[serde(deserialize_with = "one_or_many::deserialize")]
    pub headers: Vec<String>,
    /// Headers exposed to browsers on real responses.
    #[serde(deserialize_with = "one_or_many::deserialize")]
    pub expose: Vec<String>,
    /// Allow credentials (cookies, Authorization).
    pub credentials: bool,
    /// Preflight cache duration.
    #[serde(with = "duration::option")]
    #[schemars(with = "Option<String>")]
    pub max_age: Option<Duration>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            origins: Vec::new(),
            methods: Vec::new(),
            headers: Vec::new(),
            expose: Vec::new(),
            credentials: false,
            max_age: None,
        }
    }
}

/// Route cache configuration referencing a named `[cache.<store>]`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteCache {
    /// Set `false` to opt a route out of an inherited site `cache`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Name of a top-level cache store. Required when enabled.
    #[serde(default)]
    pub store: String,
    /// TTL override for responses without explicit freshness. Otherwise
    /// `Cache-Control`/`Expires` semantics apply.
    #[serde(with = "duration::option", default)]
    #[schemars(with = "Option<String>")]
    pub ttl: Option<Duration>,
    /// Serve stale while revalidating in the background, for this long.
    #[serde(with = "duration::option", default)]
    #[schemars(with = "Option<String>")]
    pub stale_while_revalidate: Option<Duration>,
    /// Serve stale on upstream error for this long.
    #[serde(with = "duration::option", default)]
    #[schemars(with = "Option<String>")]
    pub stale_if_error: Option<Duration>,
    /// Short TTL used for error responses (negative caching).
    #[serde(with = "duration", default = "RouteCache::default_negative_ttl")]
    #[schemars(with = "String")]
    pub negative_ttl: Duration,
    /// Requests that bypass the cache.
    #[serde(default)]
    pub bypass: CacheBypass,
    /// Extra headers folded into the cache key (in addition to the response
    /// `Vary` header).
    #[serde(default)]
    #[serde(deserialize_with = "one_or_many::deserialize")]
    pub vary_headers: Vec<String>,
    /// Emit the `X-Cache` response header.
    #[serde(default = "default_true")]
    pub x_cache: bool,
}

impl Default for RouteCache {
    fn default() -> Self {
        Self {
            enabled: true,
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

/// Schema shape for `route.cache` (`"store-name"` or a table).
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum RouteCacheSchema {
    /// `"store-name"` — cache via `[cache.<name>]` with default settings.
    Store(String),
    /// Full table form.
    Full(RouteCache),
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
    /// Additional HTTP methods that bypass the cache. Only GET and HEAD
    /// are cacheable anyway — list them here to bypass even those.
    #[serde(deserialize_with = "one_or_many::deserialize")]
    pub methods: Vec<String>,
    /// Cookie names whose presence bypasses the cache.
    #[serde(deserialize_with = "one_or_many::deserialize")]
    pub cookies: Vec<String>,
    /// Header names whose presence bypasses the cache.
    #[serde(deserialize_with = "one_or_many::deserialize")]
    pub headers: Vec<String>,
    /// Path globs that bypass the cache.
    #[serde(deserialize_with = "one_or_many::deserialize")]
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
    /// Set `false` to opt a route out of an inherited site `compress`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Enabled algorithms, negotiated by client `Accept-Encoding` q-values:
    /// `br`, `zstd`, `gzip`. Defaults to all.
    #[serde(deserialize_with = "one_or_many::deserialize")]
    pub algorithms: Vec<String>,
    /// Don't compress responses smaller than this (when Content-Length is
    /// known).
    pub min_bytes: ByteSize,
    /// Content types eligible for compression; `*` suffixes allowed.
    #[serde(deserialize_with = "one_or_many::deserialize")]
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
            enabled: true,
        }
    }
}

/// Schema shape for `route.compress` (`true` or a table).
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum CompressConfigSchema {
    /// `compress = true` — enable with default settings.
    Flag(bool),
    /// Full table form.
    Full(CompressConfig),
}

/// Schema shape for `proxy.retries` (`false` or a table).
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum RetryPolicySchema {
    /// `retries = false` — disable; `true` enables defaults.
    Flag(bool),
    /// `retries = 3` — retry budget per request, rest defaults.
    Count(u8),
    /// Full table form.
    Full(RetryPolicy),
}

/// Schema shape for `log.access` (`false` or a table).
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum AccessLogSchema {
    /// `access = false` — disable access logging; `true` enables it.
    Flag(bool),
    /// `access = "/var/log/app.log"` — enable, writing to this output
    /// (`stdout`/`stderr` also work).
    Dest(String),
    /// Full table form.
    Full(AccessLog),
}

/// Schema shape for `upstream.dns` (a grace duration or a table).
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum UpstreamDnsSchema {
    /// `"60s"` — keep last-known-good addresses this long.
    Grace(String),
    /// Full table form.
    Full(UpstreamDns),
}

/// Schema shape for `upstream.health.active` (a probe path or a table).
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum ActiveHealthSchema {
    /// `"/healthz"` — probe path with default settings.
    Path(String),
    /// Full table form.
    Full(ActiveHealth),
}

/// Schema shape for `upstream.*.health.passive` (a count or a table).
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum PassiveHealthSchema {
    /// `5` — mark unhealthy after this many consecutive failures.
    Failures(u32),
    /// Full table form.
    Full(PassiveHealth),
}

/// Schema shape for `route.proxy` (upstream shorthand or a table).
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum ProxySchema {
    /// Cluster name, one URL, or a URL list — like `site.proxy`.
    Ref(UpstreamRef),
    /// Full table form.
    Full(Box<ProxyHandler>),
}

/// Schema shape for `route.static` (a root path or a table).
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum StaticSchema {
    /// `"/srv/www"` — document root with default settings.
    Root(String),
    /// Full table form.
    Full(StaticHandler),
}

/// Schema shape for `route.redirect` (a target URL or a table).
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum RedirectSchema {
    /// `"https://…"` — redirect target template, status 308.
    To(String),
    /// Full table form.
    Full(RedirectHandler),
}

/// Schema shape for `route.respond` (a body string or a table).
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum RespondSchema {
    /// `respond = 404` — empty-body status response.
    Code(u16),
    /// `"text"` — a 200 response with this body.
    Body(String),
    /// Full table form.
    Full(RespondHandler),
}

/// Schema shape for `route.rate_limit` (a rate or a table).
#[derive(JsonSchema)]
#[schemars(untagged)]
pub enum RateLimitSchema {
    /// `rate_limit = false` — no rate limiting on this site/route.
    Off(bool),
    /// `"100/s"` — per-IP limit at this rate.
    Rate(String),
    /// Full table form.
    Full(RateLimitConfig),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_apply_overrides() {
        let mut t = Timeouts::default();
        let base = t.clone();
        let over = TimeoutOverrides {
            header_read: Some(Duration::from_secs(1)),
            body_read: Some(Duration::from_secs(2)),
            idle: Some(Duration::from_secs(3)),
            send: Some(Duration::from_secs(4)),
            request_deadline: Some(Duration::from_secs(5)),
        };
        t.apply_overrides(&over);
        assert_eq!(t.header_read.as_secs(), 1);
        assert_eq!(t.body_read.as_secs(), 2);
        assert_eq!(t.idle.as_secs(), 3);
        assert_eq!(t.send.as_secs(), 4);
        assert_eq!(t.request_deadline.as_secs(), 5);

        let mut t2 = base.clone();
        t2.apply_overrides(&TimeoutOverrides::default());
        assert_eq!(t2.send, base.send);
        assert_eq!(t2.idle, base.idle);
    }

    #[test]
    fn listen_table_defaults_addr() {
        // `{ tls = true }` alone selects TLS on the HTTPS port —
        // TLS on :80 is never what the operator meant
        let l: ListenAddr = toml::from_str("tls = true\n").unwrap();
        assert_eq!(l.addr, SocketAddr::from(([0, 0, 0, 0], 443)));
        assert!(l.tls);

        let l: ListenAddr = toml::from_str("addr = \"127.0.0.1:8080\"\n").unwrap();
        assert_eq!(l.addr, SocketAddr::from(([127, 0, 0, 1], 8080)));
        assert!(!l.tls);

        // an empty table is a plaintext :80 listener
        let l: ListenAddr = toml::from_str("").unwrap();
        assert_eq!(l.addr, SocketAddr::from(([0, 0, 0, 0], 80)));
        assert!(!l.tls);
    }

    #[test]
    fn limits_apply_overrides() {
        let mut l = Limits::default();
        let base = l.clone();
        let over = LimitOverrides {
            header_bytes: Some(ByteSize::kib(8)),
            body_bytes: Some(ByteSize::kib(64)),
        };
        l.apply_overrides(&over);
        assert_eq!(l.header_bytes.0, 8 * 1024);
        assert_eq!(l.body_bytes.0, 64 * 1024);

        let mut l2 = base.clone();
        l2.apply_overrides(&LimitOverrides::default());
        assert_eq!(l2.header_bytes, base.header_bytes);
        assert_eq!(l2.body_bytes, base.body_bytes);
    }
}
