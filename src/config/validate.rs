//! Semantic validation beyond what `serde` can express: cross-references
//! (upstream and cache names), handler exclusivity, matcher sanity, TLS
//! consistency, and security invariants. Produces a list of diagnostics —
//! errors are fatal to startup, warnings are not.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use regex::Regex;

use crate::config::model::*;

/// Severity of a [`Diagnostic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Fatal: the configuration cannot run.
    Error,
    /// Suspicious but runnable; worth fixing.
    Warning,
}

/// One validation finding with a human-readable location.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    /// Severity.
    pub severity: Severity,
    /// Where in the config, e.g. `site[0].route[2]`.
    pub path: String,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sev = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(f, "{sev}: {}: {}", self.path, self.message)
    }
}

struct Ctx {
    diags: Vec<Diagnostic>,
}

impl Ctx {
    fn error(&mut self, path: impl Into<String>, msg: impl Into<String>) {
        self.diags.push(Diagnostic {
            severity: Severity::Error,
            path: path.into(),
            message: msg.into(),
        });
    }
    fn warn(&mut self, path: impl Into<String>, msg: impl Into<String>) {
        self.diags.push(Diagnostic {
            severity: Severity::Warning,
            path: path.into(),
            message: msg.into(),
        });
    }
}

/// Validate a parsed [`Config`], returning every diagnostic found.
/// The config is usable iff no [`Severity::Error`] diagnostics are present.
pub fn validate(cfg: &Config) -> Vec<Diagnostic> {
    let mut ctx = Ctx { diags: Vec::new() };

    check_listeners(&mut ctx, cfg);
    check_sites(&mut ctx, cfg);
    check_upstreams(&mut ctx, cfg);
    check_caches(&mut ctx, cfg);
    check_admin(&mut ctx, cfg);
    check_acme(&mut ctx, cfg);
    check_timeouts_limits(&mut ctx, cfg);
    check_log(&mut ctx, cfg);

    ctx.diags
}

fn check_listeners(ctx: &mut Ctx, cfg: &Config) {
    if cfg.server.listen.is_empty() {
        ctx.error("server", "at least one listener is required");
    }
    let mut seen = HashSet::new();
    for (i, l) in cfg.server.listen.iter().enumerate() {
        if !seen.insert(l.addr) {
            ctx.error(
                format!("server.listen[{i}]"),
                format!("duplicate listen address {}", l.addr),
            );
        }
    }
    let any_tls_site = cfg
        .site
        .iter()
        .any(|s| !matches!(s.tls, SiteTls::Mode(TlsMode::Off)));
    let any_tls_listener = cfg.server.listen.iter().any(|l| l.tls);
    if any_tls_site && !any_tls_listener {
        ctx.warn(
            "server.listen",
            "TLS-enabled sites exist but no listener has tls = true",
        );
    }
    if cfg.server.max_connections_per_ip > cfg.server.max_connections {
        ctx.warn(
            "server.max_connections_per_ip",
            "per-IP limit exceeds the global connection limit",
        );
    }
}

fn check_sites(ctx: &mut Ctx, cfg: &Config) {
    let mut exact_hosts: HashMap<String, usize> = HashMap::new();
    let mut wildcards: HashMap<String, usize> = HashMap::new();
    let mut default_count = 0usize;
    let mut any_tls = false;

    for (i, site) in cfg.site.iter().enumerate() {
        let path = format!("site[{i}].hosts");
        if site.hosts.is_empty() && !site.default {
            ctx.error(path, "site has no hosts and is not marked default");
        }
        if site.default {
            default_count += 1;
        }
        for host in &site.hosts {
            let h = host.to_ascii_lowercase();
            if let Some(rest) = h.strip_prefix("*.") {
                if rest.is_empty() || rest.contains('*') {
                    ctx.error(
                        format!("site[{i}].hosts"),
                        format!("invalid wildcard host {host:?}"),
                    );
                    continue;
                }
                if wildcards.insert(rest.to_string(), i).is_some() {
                    ctx.error(
                        format!("site[{i}].hosts"),
                        format!("duplicate wildcard host {host:?}"),
                    );
                }
            } else if h == "*" {
                if site.default {
                    default_count += 1;
                } else {
                    ctx.error(
                        format!("site[{i}].hosts"),
                        "bare \"*\" host needs `default = true`".to_string(),
                    );
                }
            } else if exact_hosts.insert(h, i).is_some() {
                ctx.error(
                    format!("site[{i}].hosts"),
                    format!("duplicate host {host:?}"),
                );
            }
        }
        if matches!(site.tls, SiteTls::Mode(TlsMode::Off)) {
            if site.redirect_https {
                // only warn — redirect on a plain site is a no-op
                ctx.warn(
                    format!("site[{i}]"),
                    "redirect_https is set but tls = \"off\"",
                );
            }
        } else {
            any_tls = true;
        }
        if let SiteTls::Manual(m) = &site.tls {
            if !m.cert.is_file() {
                ctx.warn(
                    format!("site[{i}].tls.cert"),
                    format!("certificate file {} does not exist", m.cert.display()),
                );
            }
            if !m.key.is_file() {
                ctx.warn(
                    format!("site[{i}].tls.key"),
                    format!("key file {} does not exist", m.key.display()),
                );
            }
        }
        if site.root.is_some() && !site.proxy.is_empty() {
            ctx.error(
                format!("site[{i}]"),
                "site.root and site.proxy are mutually exclusive shorthands; use explicit routes",
            );
        }
        for (j, route) in site.route.iter().enumerate() {
            check_route(ctx, cfg, i, j, route);
        }
        check_trusted_proxies(ctx, cfg, i, site);
    }

    if default_count > 1 {
        ctx.error("site", "more than one site is marked default");
    }
    if any_tls {
        let needs_acme = cfg
            .site
            .iter()
            .any(|s| matches!(s.tls, SiteTls::Mode(TlsMode::Auto)));
        if needs_acme && cfg.acme.email.is_none() {
            ctx.warn(
                "acme.email",
                "sites with tls = \"auto\" exist but acme.email is unset; issuance may fail or violate CA terms",
            );
        }
        for (i, s) in cfg.site.iter().enumerate() {
            if matches!(s.tls, SiteTls::Mode(TlsMode::Auto))
                && s.hosts.iter().any(|h| h.starts_with("*."))
            {
                ctx.warn(
                    format!("site[{i}].hosts"),
                    "wildcard hostnames need the dns-01 challenge, which verd does not implement; the cert will cover only non-wildcard hosts",
                );
            }
        }
        if needs_acme
            && matches!(
                cfg.acme.challenge,
                crate::config::model::AcmeChallenge::Http01
            )
            && !cfg.server.listen.iter().any(|l| !l.tls)
        {
            ctx.warn(
                "acme.challenge",
                "acme.challenge = \"http-01\" but every listener is TLS; the CA cannot reach port 80 for validation",
            );
        }
        if !cfg.server.listen.iter().any(|l| l.tls) {
            ctx.warn(
                "server.listen",
                "sites have TLS enabled but no listener sets tls = true; HTTPS is unreachable",
            );
        }
    } else if cfg.server.listen.iter().any(|l| l.tls) {
        ctx.warn(
            "server.listen",
            "a TLS listener exists but every site has tls = \"off\"; all handshakes will fail",
        );
    }
    if cfg.site.is_empty() {
        ctx.warn(
            "site",
            "no sites configured; the server will only serve 404/421 responses",
        );
    }
}

fn check_trusted_proxies(ctx: &mut Ctx, _cfg: &Config, i: usize, site: &SiteConfig) {
    if let Some(proxies) = &site.trusted_proxies
        && proxies.is_empty()
    {
        ctx.warn(
            format!("site[{i}].trusted_proxies"),
            "explicit empty list disables trusted proxies for this site",
        );
    }
}

fn check_route(
    ctx: &mut Ctx,
    cfg: &Config,
    site_idx: usize,
    route_idx: usize,
    route: &RouteConfig,
) {
    let path = format!("site[{site_idx}].route[{route_idx}]");

    // exactly one path matcher
    let matchers = [
        route.path.is_some(),
        route.exact.is_some(),
        route.prefix.is_some(),
        route.regex.is_some(),
    ]
    .into_iter()
    .filter(|b| *b)
    .count();
    if matchers == 0 {
        ctx.error(
            path.clone(),
            "route has no path matcher (set path, exact, prefix, or regex)",
        );
    } else if matchers > 1 {
        ctx.error(
            path.clone(),
            "route sets multiple path matchers; keep exactly one of path/exact/prefix/regex",
        );
    }
    for (name, m) in [
        ("path", &route.path),
        ("exact", &route.exact),
        ("prefix", &route.prefix),
        ("regex", &route.regex),
    ] {
        if let Some(v) = m {
            if name != "regex" && !v.starts_with('/') {
                ctx.error(
                    path.clone(),
                    format!("{name} matcher {v:?} must start with '/'"),
                );
            }
            if name == "regex"
                && let Err(e) = Regex::new(v)
            {
                ctx.error(path.clone(), format!("invalid route regex {v:?}: {e}"));
            }
        }
    }

    if let Some(m) = &route.match_ {
        for method in &m.methods {
            if http::Method::from_bytes(method.as_bytes()).is_err() {
                ctx.error(path.clone(), format!("invalid HTTP method {method:?}"));
            }
        }
        check_patterns(ctx, &path, "headers", &m.headers);
        check_patterns(ctx, &path, "query", &m.query);
    }

    // exactly one handler
    let handlers = [
        route.static_files.is_some(),
        route.proxy.is_some(),
        route.redirect.is_some(),
        route.respond.is_some(),
    ]
    .into_iter()
    .filter(|b| *b)
    .count();
    if handlers != 1 {
        ctx.error(
            path.clone(),
            format!("route must have exactly one handler, found {handlers}"),
        );
    }

    if let Some(st) = &route.static_files {
        if !st.root.is_dir() {
            ctx.warn(
                format!("{path}.static.root"),
                format!(
                    "root {} does not exist or is not a directory",
                    st.root.display()
                ),
            );
        }
        if st.index.is_empty() && !st.listing && !st.spa {
            ctx.warn(
                format!("{path}.static"),
                "no index files, listing disabled, and spa disabled — directory requests will 403/404",
            );
        }
    }

    if let Some(proxy) = &route.proxy {
        check_proxy(ctx, cfg, &path, proxy);
    }

    if let Some(redir) = &route.redirect {
        let targets = [
            redir.to.is_some(),
            redir.host.is_some(),
            redir.scheme.is_some(),
        ]
        .into_iter()
        .filter(|b| *b)
        .count();
        if targets != 1 {
            ctx.error(path.clone(), "redirect sets exactly one of to/host/scheme");
        }
        if ![301, 302, 307, 308].contains(&redir.status) {
            ctx.error(
                path.clone(),
                format!(
                    "redirect status {} must be 301, 302, 307, or 308",
                    redir.status
                ),
            );
        }
        if let Some(scheme) = &redir.scheme
            && scheme != "http"
            && scheme != "https"
        {
            ctx.error(
                path.clone(),
                format!("redirect scheme {scheme:?} must be http or https"),
            );
        }
    }

    if let Some(resp) = &route.respond
        && !(100..=599).contains(&resp.status)
    {
        ctx.error(
            path.clone(),
            format!("respond status {} is not a valid HTTP status", resp.status),
        );
    }

    if let Some(auth) = &route.auth {
        check_auth(ctx, &path, auth);
    }
    if let Some(rl) = &route.rate_limit {
        check_rate_limit(ctx, &path, rl);
    }
    if let Some(cors) = &route.cors {
        check_cors(ctx, &path, cors);
    }
    if let Some(cache) = &route.cache
        && !cfg.cache.contains_key(&cache.store)
    {
        ctx.error(
            format!("{path}.cache.store"),
            format!(
                "unknown cache store {:?}; define [cache.{}]",
                cache.store, cache.store
            ),
        );
    }
    if let Some(comp) = &route.compress {
        for alg in &comp.algorithms {
            if !["br", "brotli", "zstd", "gzip", "gz"].contains(&alg.as_str()) {
                ctx.error(
                    format!("{path}.compress.algorithms"),
                    format!("unknown algorithm {alg:?}; use br, zstd, or gzip"),
                );
            }
        }
    }
    if route.headers.is_some()
        && route.static_files.is_none()
        && route.proxy.is_none()
        && route.respond.is_none()
    {
        // headers middleware applies to all handlers; redirect too — fine
    }
}

fn check_patterns(ctx: &mut Ctx, path: &str, kind: &str, pats: &BTreeMap<String, String>) {
    for (k, v) in pats {
        if let Some(pat) = v.strip_prefix("re:")
            && let Err(e) = Regex::new(pat)
        {
            ctx.error(format!("{path}.{kind}.{k}"), format!("invalid regex: {e}"));
        }
    }
}

fn check_proxy(ctx: &mut Ctx, cfg: &Config, path: &str, proxy: &ProxyHandler) {
    check_proxy_retries(ctx, path, &proxy.retries);
    match &proxy.upstream {
        UpstreamRef::Name(name) => {
            if !cfg.upstream.contains_key(name) {
                ctx.error(
                    format!("{path}.proxy.upstream"),
                    format!("unknown upstream {name:?}; define [upstream.{name}]"),
                );
            }
        }
        UpstreamRef::Urls(urls) => {
            if urls.is_empty() {
                ctx.error(
                    format!("{path}.proxy.upstream"),
                    "upstream URL list is empty".to_string(),
                );
            }
            for url in urls {
                check_upstream_url(ctx, &format!("{path}.proxy.upstream"), url);
            }
        }
    }
    if let Some(rw) = &proxy.rewrite {
        let kinds = [
            rw.strip_prefix.is_some(),
            rw.replace_prefix.is_some(),
            rw.regex.is_some(),
        ]
        .into_iter()
        .filter(|b| *b)
        .count();
        if kinds != 1 {
            ctx.error(
                format!("{path}.proxy.rewrite"),
                "rewrite sets exactly one of strip_prefix/replace_prefix/regex",
            );
        }
        if let Some(re) = &rw.regex
            && let Err(e) = Regex::new(&re.pattern)
        {
            ctx.error(
                format!("{path}.proxy.rewrite.regex"),
                format!("invalid regex: {e}"),
            );
        }
        if let Some(p) = &rw.strip_prefix
            && !p.starts_with('/')
        {
            ctx.error(
                format!("{path}.proxy.rewrite.strip_prefix"),
                format!("{p:?} must start with '/'"),
            );
        }
    }
    if proxy.retries.budget_fraction < 0.0 || proxy.retries.budget_fraction > 1.0 {
        ctx.error(
            format!("{path}.proxy.retries"),
            "budget_fraction must be in [0, 1]",
        );
    }
}

fn check_auth(ctx: &mut Ctx, path: &str, auth: &AuthConfig) {
    let methods = [
        auth.basic.is_some(),
        auth.bearer.is_some(),
        auth.api_key.is_some(),
    ]
    .into_iter()
    .filter(|b| *b)
    .count();
    if methods != 1 {
        ctx.error(
            format!("{path}.auth"),
            format!("auth needs exactly one method, found {methods}"),
        );
    }
    if let Some(basic) = &auth.basic {
        if !basic.users.is_empty() && basic.htpasswd.is_some() {
            ctx.error(
                format!("{path}.auth.basic"),
                "set either users or htpasswd, not both",
            );
        }
        if basic.users.is_empty() && basic.htpasswd.is_none() {
            ctx.error(format!("{path}.auth.basic"), "set users or htpasswd");
        }
        for (user, hash) in &basic.users {
            if !looks_like_password_hash(hash) {
                ctx.error(
                    format!("{path}.auth.basic.users.{user}"),
                    "password value does not look like an argon2 or bcrypt hash; plaintext passwords are not allowed".to_string(),
                );
            }
        }
        if let Some(file) = &basic.htpasswd {
            match std::fs::read_to_string(file) {
                Ok(text) => {
                    for (lineno, line) in text.lines().enumerate() {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }
                        match line.split_once(':') {
                            Some((_, hash)) if looks_like_bcrypt(hash) => {}
                            _ => ctx.error(
                                format!("{path}.auth.basic.htpasswd"),
                                format!(
                                    "{} line {}: expected user:$2y$... bcrypt hash",
                                    file.display(),
                                    lineno + 1
                                ),
                            ),
                        }
                    }
                }
                Err(e) => ctx.warn(
                    format!("{path}.auth.basic.htpasswd"),
                    format!("cannot read {}: {e}", file.display()),
                ),
            }
        }
    }
    if let Some(bearer) = &auth.bearer
        && bearer.tokens.is_empty()
    {
        ctx.error(format!("{path}.auth.bearer"), "tokens list is empty");
    }
    if let Some(key) = &auth.api_key {
        if key.name.is_empty() {
            ctx.error(format!("{path}.auth.api_key"), "name must not be empty");
        }
        if key.keys.is_empty() {
            ctx.error(format!("{path}.auth.api_key"), "keys list is empty");
        }
    }
}

fn looks_like_password_hash(s: &str) -> bool {
    s.starts_with("$argon2") || looks_like_bcrypt(s)
}

fn looks_like_bcrypt(s: &str) -> bool {
    s.starts_with("$2a$") || s.starts_with("$2b$") || s.starts_with("$2y$")
}

fn check_rate_limit(ctx: &mut Ctx, path: &str, rl: &RateLimitConfig) {
    let valid = matches!(rl.key.as_str(), "ip" | "identity" | "route")
        || rl
            .key
            .strip_prefix("header:")
            .is_some_and(|h| !h.is_empty());
    if !valid {
        ctx.error(
            format!("{path}.rate_limit.key"),
            format!(
                "invalid key {:?}; use ip, identity, route, or header:<Name>",
                rl.key
            ),
        );
    }
    if rl.rate.permits == 0 {
        ctx.error(
            format!("{path}.rate_limit.rate"),
            "rate must be greater than zero",
        );
    }
}

fn check_cors(ctx: &mut Ctx, path: &str, cors: &CorsConfig) {
    if cors.origins.is_empty() {
        ctx.warn(
            format!("{path}.cors"),
            "origins is empty — no cross-origin requests will be allowed",
        );
    }
    for origin in &cors.origins {
        if let Some(pat) = origin.strip_prefix("re:")
            && let Err(e) = Regex::new(pat)
        {
            ctx.error(
                format!("{path}.cors.origins"),
                format!("invalid regex {origin:?}: {e}"),
            );
        }
    }
    if cors.credentials && cors.origins.iter().any(|o| o == "*") {
        ctx.warn(
            format!("{path}.cors"),
            "credentials with wildcard origin is rejected by browsers; credentials are ignored for \"*\"",
        );
    }
}

fn check_upstreams(ctx: &mut Ctx, cfg: &Config) {
    for (name, up) in &cfg.upstream {
        let path = format!("upstream.{name}");
        if up.servers.is_empty() {
            ctx.error(path.clone(), "upstream has no servers");
        }
        for url in &up.servers {
            check_upstream_url(ctx, &path, url);
        }
        if let Some(active) = &up.health.active
            && !(100..=599).contains(&active.expect)
        {
            ctx.error(
                format!("{path}.health.active.expect"),
                "expected status must be 100–599",
            );
        }
        if !(100..=599).contains(&up.unavailable.status) {
            ctx.error(
                format!("{path}.unavailable.status"),
                "unavailable status must be 100–599",
            );
        }
        if let Some(p) = &up.health.passive
            && p.failures == 0
        {
            ctx.warn(
                format!("{path}.health.passive.failures"),
                "failures = 0 marks members sick after a single failure",
            );
        }
    }
}

fn check_proxy_retries(ctx: &mut Ctx, path: &str, retries: &crate::config::model::RetryPolicy) {
    if !(0.0..=1.0).contains(&retries.budget_fraction) {
        ctx.error(
            format!("{path}.retries.budget_fraction"),
            "budget_fraction must be between 0 and 1",
        );
    }
}

fn check_upstream_url(ctx: &mut Ctx, path: &str, url: &str) {
    match url.split_once("://") {
        Some(("http" | "https" | "h2c", rest)) => {
            let authority = rest.split('/').next().unwrap_or("");
            if authority.is_empty() {
                ctx.error(
                    path.to_string(),
                    format!("upstream URL {url:?} has no host"),
                );
            }
        }
        _ => ctx.error(
            path.to_string(),
            format!("upstream URL {url:?} must have scheme http, https, or h2c"),
        ),
    }
}

fn check_caches(ctx: &mut Ctx, cfg: &Config) {
    for (name, store) in &cfg.cache {
        let path = format!("cache.{name}");
        match store.tier {
            CacheTier::Ram => {
                if store.disk_path.is_some() {
                    ctx.warn(
                        path.clone(),
                        "disk_path set but tier = \"ram\"; it is unused",
                    );
                }
                if store.ram_bytes.0 == 0 {
                    ctx.error(path.clone(), "ram_bytes must be > 0 for tier = \"ram\"");
                }
            }
            CacheTier::Disk | CacheTier::Hybrid => {
                if store.disk_path.is_none() {
                    ctx.error(
                        path.clone(),
                        format!("disk_path required for tier = {:?}", store.tier),
                    );
                }
                if store.disk_bytes.0 == 0 {
                    ctx.error(
                        path.clone(),
                        "disk_bytes must be > 0 for a disk-backed tier",
                    );
                }
            }
        }
        if store.tier == CacheTier::Hybrid && store.ram_bytes.0 == 0 {
            ctx.error(path.clone(), "ram_bytes must be > 0 for tier = \"hybrid\"");
        }
        if store.max_object_bytes.0 == 0 {
            ctx.error(path.clone(), "max_object_bytes must be > 0");
        }
    }
}

fn check_admin(ctx: &mut Ctx, cfg: &Config) {
    let a = &cfg.admin;
    if !a.listen.ip().is_loopback() {
        if a.token.is_none() {
            ctx.error(
                "admin.listen",
                "admin listener bound to a non-loopback address requires admin.token",
            );
        }
        if a.tls.is_none() {
            ctx.warn(
                "admin.tls",
                "admin listener is non-loopback without TLS; the bearer token will travel in cleartext",
            );
        }
    }
    if let Some(m) = &a.tls {
        for (field, p) in [("cert", &m.cert), ("key", &m.key)] {
            if !p.is_file() {
                ctx.warn(
                    format!("admin.tls.{field}"),
                    format!("file {} does not exist", p.display()),
                );
            }
        }
    }
}

fn check_acme(ctx: &mut Ctx, cfg: &Config) {
    let acme = &cfg.acme;
    if let Some(eab) = &acme.eab
        && (eab.key_id.is_empty() || eab.key.is_empty())
    {
        ctx.error("acme.eab", "EAB requires both key_id and key");
    }
    let od = &acme.on_demand;
    if od.enabled && od.allowed_hosts.is_empty() {
        ctx.error(
            "acme.on_demand.allowed_hosts",
            "on-demand issuance requires an explicit allowlist (refusing to issue for arbitrary domains)",
        );
    }
    if od.enabled && od.rate.is_none() {
        ctx.warn(
            "acme.on_demand.rate",
            "on-demand issuance has no rate limit; a hostile client could trigger unbounded CA requests",
        );
    }
}

fn check_timeouts_limits(ctx: &mut Ctx, cfg: &Config) {
    let t = &cfg.timeouts;
    if t.header_read.is_zero() {
        ctx.warn(
            "timeouts.header_read",
            "0s disables the header read timeout — vulnerable to slowloris",
        );
    }
    if t.tls_handshake.is_zero() {
        ctx.warn(
            "timeouts.tls_handshake",
            "0s disables the TLS handshake timeout",
        );
    }
    if cfg.limits.header_bytes.0 == 0 {
        ctx.error("limits.header_bytes", "must be > 0");
    }
    if cfg.limits.body_bytes.0 == 0 {
        ctx.error("limits.body_bytes", "must be > 0");
    }
    if !(0.0..=1.0).contains(&cfg.log.access.sample) {
        ctx.error("log.access.sample", "must be within 0.0–1.0");
    }
}

fn check_log(ctx: &mut Ctx, cfg: &Config) {
    let ok_levels = ["error", "warn", "info", "debug", "trace", "off"];
    if !ok_levels.contains(&cfg.log.level.as_str()) && !cfg.log.level.contains('=')
    // allow env-filter style "verd=debug,hyper=info"
    {
        ctx.warn(
            "log.level",
            format!(
                "unusual log level {:?}; expected one of {ok_levels:?} or a filter",
                cfg.log.level
            ),
        );
    }
}

/// Build a [`Config`] from a TOML string after interpolation; shared by
/// `validate` tests and the loader.
#[cfg(test)]
pub(crate) fn parse_test_config(text: &str) -> Config {
    let mut v: toml::Value = toml::from_str(text).unwrap();
    crate::config::interpolate::interpolate(&mut v).unwrap();
    v.try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn errors(cfg: &Config) -> Vec<Diagnostic> {
        validate(cfg)
            .into_iter()
            .filter(|d| d.severity == Severity::Error)
            .collect()
    }

    #[test]
    fn minimal_mission_config_is_valid() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["example.com", "www.example.com"]
root = "/srv/www"

[[site]]
hosts = ["api.example.com"]
proxy = ["http://10.0.0.2:8080", "http://10.0.0.3:8080"]
"#,
        );
        assert!(errors(&cfg).is_empty(), "{:?}", validate(&cfg));
    }

    #[test]
    fn duplicate_host_rejected() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["example.com"]
root = "/tmp"

[[site]]
hosts = ["EXAMPLE.com"]
root = "/tmp"
"#,
        );
        assert!(
            errors(&cfg)
                .iter()
                .any(|d| d.message.contains("duplicate host"))
        );
    }

    #[test]
    fn exact_and_wildcard_may_coexist() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["foo.example.com"]
root = "/tmp"

[[site]]
hosts = ["*.example.com"]
root = "/tmp"
"#,
        );
        assert!(errors(&cfg).is_empty(), "{:?}", validate(&cfg));
    }

    #[test]
    fn route_needs_one_matcher_and_handler() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
path = "/a"
exact = "/b"
respond = { status = 200 }
[[site.route]]
respond = { status = 200 }
"#,
        );
        let errs = errors(&cfg);
        assert!(
            errs.iter()
                .any(|d| d.message.contains("multiple path matchers")),
            "{errs:?}"
        );
        assert!(
            errs.iter().any(|d| d.message.contains("no path matcher")),
            "{errs:?}"
        );
    }

    #[test]
    fn unknown_upstream_ref_rejected() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
path = "/"
proxy = { upstream = "nope" }
"#,
        );
        assert!(
            errors(&cfg)
                .iter()
                .any(|d| d.message.contains("unknown upstream"))
        );
    }

    #[test]
    fn plaintext_password_rejected() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
path = "/"
respond = { status = 200 }
auth = { basic = { users = { u = "plaintext" } } }
"#,
        );
        assert!(errors(&cfg).iter().any(|d| d.message.contains("plaintext")));
    }

    #[test]
    fn non_loopback_admin_needs_token() {
        let cfg = parse_test_config(
            r#"
[admin]
listen = "0.0.0.0:2019"
"#,
        );
        assert!(errors(&cfg).iter().any(|d| d.path == "admin.listen"));
    }

    #[test]
    fn on_demand_requires_allowlist() {
        let cfg = parse_test_config(
            r#"
[acme.on_demand]
enabled = true
"#,
        );
        assert!(
            errors(&cfg)
                .iter()
                .any(|d| d.path == "acme.on_demand.allowed_hosts")
        );
    }

    #[test]
    fn disk_tier_requires_path() {
        let cfg = parse_test_config(
            r#"
[cache.main]
tier = "disk"
"#,
        );
        assert!(errors(&cfg).iter().any(|d| d.path == "cache.main"));
    }

    #[test]
    fn redirect_status_checked() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
path = "/old"
redirect = { scheme = "https", status = 303 }
"#,
        );
        assert!(
            errors(&cfg)
                .iter()
                .any(|d| d.message.contains("301, 302, 307, or 308"))
        );
    }
}
