//! Semantic validation beyond what `serde` can express: cross-references
//! (upstream and cache names), handler exclusivity, matcher sanity, TLS
//! consistency, and security invariants. Produces a list of diagnostics —
//! errors are fatal to startup, warnings are not.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use regex::Regex;

use crate::config::model::*;

/// Severity of a [`Diagnostic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Fatal: the configuration cannot run.
    Error,
    /// Suspicious but runnable; worth fixing.
    Warning,
}

/// One validation finding with a human-readable location.
#[derive(Debug, Clone, serde::Serialize)]
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
    if cfg.server.max_connections == 0 {
        ctx.error(
            "server.max_connections",
            "max_connections must be > 0 — 0 rejects every connection",
        );
    }
    if cfg.server.max_connections_per_ip == 0 {
        ctx.error(
            "server.max_connections_per_ip",
            "must be > 0 — 0 rejects every connection",
        );
    }
    if cfg.server.max_connections_per_ip > cfg.server.max_connections {
        ctx.warn(
            "server.max_connections_per_ip",
            "per-IP limit exceeds the global connection limit",
        );
    }
}

/// Label a site by its first host (or `default`), falling back to the
/// index — `site["example.com"]` reads better than `site[0]` after
/// includes have merged fragments from several files.
fn site_label(i: usize, site: &SiteConfig) -> String {
    if let Some(h) = site.hosts.first() {
        format!("site[{h:?}]")
    } else if site.default {
        "site[default]".to_string()
    } else {
        format!("site[{i}]")
    }
}

fn check_sites(ctx: &mut Ctx, cfg: &Config) {
    let mut exact_hosts: HashMap<String, usize> = HashMap::new();
    let mut wildcards: HashMap<String, usize> = HashMap::new();
    let mut default_count = 0usize;
    let mut any_tls = false;

    for (i, site) in cfg.site.iter().enumerate() {
        let site_path = site_label(i, site);
        let path = format!("{site_path}.hosts");
        if site.hosts.is_empty() && !site.default {
            ctx.error(path, "site has no hosts and is not marked default");
        }
        if site.default {
            default_count += 1;
        }
        for host in &site.hosts {
            let raw = host.trim();
            // `hosts` takes hostnames only — a scheme, path, whitespace,
            // or `host:port` is a copy-paste mistake the matcher would
            // silently normalize away. Bracketed IPv6 (`[::1]`) is fine.
            if raw.is_empty()
                || raw.contains("://")
                || raw.contains('/')
                || raw.chars().any(char::is_whitespace)
                || (!raw.starts_with('[')
                    && raw
                        .rsplit_once(':')
                        .is_some_and(|(_, t)| t.parse::<u16>().is_ok()))
            {
                ctx.error(
                    format!("{site_path}.hosts"),
                    format!(
                        "invalid host {host:?} — hosts takes hostnames only, no scheme/port/path"
                    ),
                );
                continue;
            }
            // `*.` is detected on the raw spelling (normalizing first
            // would eat the dot in "*."); the suffix is normalized so
            // "*.X.com." and "*.x.com" still collide as duplicates.
            if let Some(rest) = raw.strip_prefix("*.") {
                let rest = crate::router::normalize_host(rest);
                if rest.is_empty() || rest.contains('*') {
                    ctx.error(
                        format!("{site_path}.hosts"),
                        format!("invalid wildcard host {host:?}"),
                    );
                    continue;
                }
                if wildcards.insert(rest, i).is_some() {
                    ctx.error(
                        format!("{site_path}.hosts"),
                        format!("duplicate wildcard host {host:?}"),
                    );
                }
                continue;
            }
            let h = crate::router::normalize_host(raw);
            if h == "*" {
                // a catch-all host claims defaultness via `default = true`,
                // which `if site.default` above already counted once
                if !site.default {
                    ctx.error(
                        format!("{site_path}.hosts"),
                        "bare \"*\" host needs `default = true`".to_string(),
                    );
                }
            } else if h.contains('*') {
                // mid-label `*` is never a legal wildcard — it would
                // sit in the exact index as a dead entry
                ctx.error(
                    format!("{site_path}.hosts"),
                    format!("invalid wildcard host {host:?}"),
                );
            } else if exact_hosts.insert(h, i).is_some() {
                ctx.error(
                    format!("{site_path}.hosts"),
                    format!("duplicate host {host:?}"),
                );
            }
        }
        if matches!(site.tls, SiteTls::Mode(TlsMode::Off)) {
            if site.redirect_https == Some(true) {
                // only warn — redirect on a plain site is a no-op
                ctx.warn(site_path.clone(), "redirect_https is set but tls = \"off\"");
            }
        } else {
            any_tls = true;
        }
        if let SiteTls::Manual(m) = &site.tls {
            if !m.cert.is_file() {
                ctx.warn(
                    format!("{site_path}.tls.cert"),
                    format!("certificate file {} does not exist", m.cert.display()),
                );
            }
            if !m.key.is_file() {
                ctx.warn(
                    format!("{site_path}.tls.key"),
                    format!("key file {} does not exist", m.key.display()),
                );
            }
        }
        if site.root.is_some() && site.proxy.is_some() {
            ctx.error(
                site_path.clone(),
                "site.root and site.proxy are mutually exclusive shorthands; use explicit routes",
            );
        }
        if let Some(up) = &site.proxy {
            check_upstream_ref(ctx, cfg, &format!("{site_path}.proxy"), up);
        }
        for (j, route) in site.route.iter().enumerate() {
            check_route(ctx, cfg, &site_path, j, route);
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
        let dns01 = matches!(cfg.acme.challenge, AcmeChallenge::Dns01);
        for (i, s) in cfg.site.iter().enumerate() {
            if matches!(s.tls, SiteTls::Mode(TlsMode::Auto))
                && s.hosts.iter().any(|h| h.starts_with("*."))
                && !dns01
            {
                ctx.warn(
                    format!("{}.hosts", site_label(i, s)),
                    "wildcard hostnames need the dns-01 challenge (acme.challenge = \"dns-01\" + [acme.dns]); the cert will cover only non-wildcard hosts",
                );
            }
        }
        for (i, s) in cfg.site.iter().enumerate() {
            if !matches!(s.tls, SiteTls::Mode(TlsMode::Auto)) {
                continue;
            }
            // a hostless default site is still legitimate with on-demand
            // issuance (certs mint per-SNI against the allowlist)
            if s.hosts.is_empty() && !cfg.acme.on_demand.enabled {
                ctx.warn(
                    format!("{}.hosts", site_label(i, s)),
                    "site has tls = \"auto\" but no hostnames — ACME cannot issue a certificate",
                );
            }
            for host in &s.hosts {
                if !looks_public_dns(host.strip_prefix("*.").unwrap_or(host)) {
                    ctx.warn(
                        format!("{}.hosts", site_label(i, s)),
                        format!(
                            "{host:?} is not a public DNS name — ACME issuance will fail; use tls = \"off\" or \"self_signed\""
                        ),
                    );
                }
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

/// Can a public CA plausibly issue for `host`? IPs, single labels,
/// catch-alls, and known-local TLDs can never pass ACME validation.
fn looks_public_dns(host: &str) -> bool {
    let h = crate::router::normalize_host(host);
    if h.is_empty() || h == "*" || h.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    if !h.contains('.') {
        return false;
    }
    const LOCAL_TLDS: [&str; 8] = [
        "test",
        "example",
        "invalid",
        "localhost",
        "local",
        "internal",
        "lan",
        "corp",
    ];
    !LOCAL_TLDS
        .iter()
        .any(|t| h == *t || h.ends_with(&format!(".{t}")))
}

fn check_trusted_proxies(ctx: &mut Ctx, _cfg: &Config, i: usize, site: &SiteConfig) {
    if let Some(proxies) = &site.trusted_proxies
        && proxies.is_empty()
    {
        ctx.warn(
            format!("{}.trusted_proxies", site_label(i, site)),
            "explicit empty list disables trusted proxies for this site",
        );
    }
}

fn check_route(
    ctx: &mut Ctx,
    cfg: &Config,
    site_label: &str,
    route_idx: usize,
    route: &RouteConfig,
) {
    let path = format!("{site_label}.route[{route_idx}]");

    // exactly one path matcher
    let matchers = [
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
            "route has no path matcher (set exact, prefix, or regex)",
        );
    } else if matchers > 1 {
        ctx.error(
            path.clone(),
            "route sets multiple path matchers; keep exactly one of exact/prefix/regex",
        );
    }
    for (name, m) in [
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
    let handlers: Vec<&str> = [
        ("static", route.static_files.is_some()),
        ("proxy", route.proxy.is_some()),
        ("redirect", route.redirect.is_some()),
        ("respond", route.respond.is_some()),
    ]
    .into_iter()
    .filter_map(|(name, set)| set.then_some(name))
    .collect();
    if handlers.len() != 1 {
        ctx.error(
            path.clone(),
            if handlers.is_empty() {
                "route must have exactly one handler (static, proxy, redirect, or respond)"
                    .to_string()
            } else {
                format!(
                    "route must have exactly one handler; found {}",
                    handlers.join(" + ")
                )
            },
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
        for status in st.error_pages.keys() {
            if !(400..=599).contains(status) {
                ctx.warn(
                    format!("{path}.static.error_pages"),
                    format!(
                        "status {status} is not an error status — error_pages only apply to 400–599"
                    ),
                );
            }
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

    if let Some(resp) = &route.respond {
        if !(100..=599).contains(&resp.status) {
            ctx.error(
                path.clone(),
                format!("respond status {} is not a valid HTTP status", resp.status),
            );
        }
        // reflected-request placeholders + text/html = XSS by config
        let htmlish = resp.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("content-type") && v.to_ascii_lowercase().contains("text/html")
        });
        if htmlish
            && ["{path}", "{host}", "{method}"]
                .iter()
                .any(|p| resp.body.contains(p))
        {
            ctx.warn(
                format!("{path}.respond"),
                "respond body substitutes request data under a text/html content-type — reflected content without escaping; use text/plain",
            );
        }
    }

    if let Some(auth) = &route.auth {
        check_auth(ctx, &path, auth);
    }
    if let Some(rl) = &route.rate_limit {
        check_rate_limit(ctx, &path, rl);
        if rl.key == "identity" && route.auth.is_none() {
            ctx.warn(
                format!("{path}.rate_limit.key"),
                "key \"identity\" but the route has no auth — requests are keyed by client IP",
            );
        }
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
    if route.cache.is_some()
        && let Some(key) = route.auth.as_ref().and_then(|a| a.api_key.as_ref())
        && key.location == ApiKeyLocation::Query
    {
        // the cache layer strips the param from keys (see
        // key::strip_query_param) — this warns it ever existed
        ctx.warn(
            format!("{path}.auth.api_key"),
            "query-parameter api keys on a cached route put credentials in URLs; the param is stripped from cache keys, but header-based keys are safer",
        );
    }
    if let Some(comp) = &route.compress {
        for alg in &comp.algorithms {
            if !["br", "zstd", "gzip"].contains(&alg.as_str()) {
                ctx.error(
                    format!("{path}.compress.algorithms"),
                    format!("unknown algorithm {alg:?}; use br, zstd, or gzip"),
                );
            }
        }
        if let Some(level) = comp.level {
            for alg in &comp.algorithms {
                let max = match alg.as_str() {
                    "gzip" => 9,
                    "br" => 11,
                    "zstd" => 19,
                    _ => continue, // unknown names error above
                };
                if level > max {
                    ctx.error(
                        format!("{path}.compress.level"),
                        format!("level {level} exceeds {alg}'s maximum ({max})"),
                    );
                }
            }
        }
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

/// Validate an upstream reference (named cluster or inline URL list).
fn check_upstream_ref(ctx: &mut Ctx, cfg: &Config, path: &str, upstream: &UpstreamRef) {
    match upstream {
        UpstreamRef::Name(name) => {
            if !cfg.upstream.contains_key(name) {
                // `upstream = "app:9000"` smells like a missing scheme —
                // point at the URL form instead of a nonsense table name
                let hint = if name.contains(':') {
                    format!("or use a URL such as \"http://{name}\"")
                } else {
                    format!("or use a URL such as \"http://{name}:PORT\"")
                };
                ctx.error(
                    path.to_string(),
                    format!("unknown upstream {name:?}; define [upstream.{name}] {hint}"),
                );
            }
        }
        UpstreamRef::Urls(urls) => {
            if urls.is_empty() {
                ctx.error(path.to_string(), "upstream URL list is empty".to_string());
            }
            for url in urls {
                check_upstream_url(ctx, path, url);
            }
        }
    }
}

fn check_proxy(ctx: &mut Ctx, cfg: &Config, path: &str, proxy: &ProxyHandler) {
    check_proxy_retries(ctx, path, &proxy.retries);
    check_upstream_ref(ctx, cfg, &format!("{path}.proxy.upstream"), &proxy.upstream);
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
                            Some((_, hash)) if looks_like_password_hash(hash) => {}
                            _ => ctx.error(
                                format!("{path}.auth.basic.htpasswd"),
                                format!(
                                    "{} line {}: expected user:$2y$... bcrypt or $argon2$... hash",
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

/// Names referenced by `site.proxy`/`route.proxy.upstream` — for the
/// unused-definition warning.
fn referenced_upstreams(cfg: &Config) -> HashSet<&str> {
    cfg.site
        .iter()
        .flat_map(|s| {
            s.proxy.iter().chain(
                s.route
                    .iter()
                    .filter_map(|r| r.proxy.as_ref().map(|p| &p.upstream)),
            )
        })
        .filter_map(|u| match u {
            UpstreamRef::Name(n) => Some(n.as_str()),
            UpstreamRef::Urls(_) => None,
        })
        .collect()
}

fn check_upstreams(ctx: &mut Ctx, cfg: &Config) {
    let referenced = referenced_upstreams(cfg);
    for (name, up) in &cfg.upstream {
        let path = format!("upstream.{name}");
        if !referenced.contains(name.as_str()) {
            ctx.warn(
                path.clone(),
                "upstream is defined but never referenced by any site or route",
            );
        }
        if up.servers.is_empty() {
            ctx.error(path.clone(), "upstream has no servers");
        }
        if up.max_connections == 0 {
            ctx.error(
                format!("{path}.max_connections"),
                "max_connections must be > 0",
            );
        }
        let mut seen_urls = HashSet::new();
        for url in &up.servers {
            if !seen_urls.insert(url) {
                ctx.warn(
                    format!("{path}.servers"),
                    format!("duplicate server URL {url:?}"),
                );
            }
            check_upstream_url(ctx, &path, url);
        }
        if !up.tls.verify && up.servers.iter().any(|u| u.starts_with("https://")) {
            ctx.warn(
                format!("{path}.tls.verify"),
                "tls.verify = false disables upstream certificate verification — traffic to this upstream is MITM-able; prefer a custom ca or sni override",
            );
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
    let used: HashSet<&str> = cfg
        .site
        .iter()
        .flat_map(|s| s.route.iter())
        .filter_map(|r| r.cache.as_ref().map(|c| c.store.as_str()))
        .collect();
    for (name, store) in &cfg.cache {
        let path = format!("cache.{name}");
        if !used.contains(name.as_str()) {
            ctx.warn(
                path.clone(),
                "cache store is defined but never referenced by any route",
            );
        }
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
    if a.listen.ip().is_loopback() && a.token.is_none() {
        ctx.warn(
            "admin.token",
            "admin listener has no token — requests are restricted to loopback Host headers, but any local process can still manage the server; set admin.token",
        );
    }
}

fn check_acme(ctx: &mut Ctx, cfg: &Config) {
    let acme = &cfg.acme;
    if !acme.directory.starts_with("https://") && !acme.directory.starts_with("http://") {
        ctx.error(
            "acme.directory",
            format!("{:?} is not an http(s) URL", acme.directory),
        );
    }
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
    match (&acme.challenge, &acme.dns) {
        (AcmeChallenge::Dns01, None) => ctx.error(
            "acme.dns",
            "acme.challenge = \"dns-01\" requires an [acme.dns] provider configuration",
        ),
        (challenge, Some(_)) if !matches!(challenge, AcmeChallenge::Dns01) => ctx.warn(
            "acme.dns",
            "acme.dns is configured but acme.challenge is not \"dns-01\"; the credentials are unused",
        ),
        _ => {}
    }
    if let Some(AcmeDns::Cloudflare(cf)) = &acme.dns {
        if cf.api_token.trim().is_empty() {
            ctx.error("acme.dns.cloudflare.api_token", "API token is empty");
        }
        if cf.zone_id.as_deref().is_some_and(|z| z.trim().is_empty()) {
            ctx.error("acme.dns.cloudflare.zone_id", "zone id is empty");
        }
        if let Some(b) = &cf.api_base
            && !b.starts_with("https://")
            && !b.starts_with("http://")
        {
            ctx.error(
                "acme.dns.cloudflare.api_base",
                format!("{b:?} is not an http(s) URL"),
            );
        }
        if let Some(r) = &cf.resolver
            && r.parse::<std::net::SocketAddr>().is_err()
            && r.parse::<std::net::IpAddr>().is_err()
        {
            ctx.error(
                "acme.dns.cloudflare.resolver",
                format!("{r:?} is not `ip` or `ip:port`"),
            );
        }
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
    if cfg.limits.header_bytes.0 > 1024 * 1024 {
        ctx.warn(
            "limits.header_bytes",
            "header_bytes above 1 MiB scales the per-connection h1 read buffer — combined with a high connection count this is a memory multiplier",
        );
    }
    if cfg.limits.body_bytes.0 == 0 {
        ctx.error("limits.body_bytes", "must be > 0");
    }
    if t.send.is_zero() {
        ctx.warn(
            "timeouts.send",
            "0s disables the send inactivity timeout — clients that stop reading can pin connections indefinitely",
        );
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
    if !(0.0..=1.0).contains(&cfg.log.access.sample) {
        ctx.error("log.access.sample", "must be within 0.0–1.0");
    }
}

/// Build a [`Config`] from a TOML string after interpolation; shared by
/// `validate` tests and the loader.
#[cfg(test)]
pub(crate) fn parse_test_config(text: &str) -> Config {
    let mut v: toml::Value = toml::from_str(text).unwrap();
    crate::config::interpolate::interpolate(&mut v, std::path::Path::new(".")).unwrap();
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
prefix = "/a"
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
prefix = "/"
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
prefix = "/"
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
prefix = "/old"
redirect = { scheme = "https", status = 303 }
"#,
        );
        assert!(
            errors(&cfg)
                .iter()
                .any(|d| d.message.contains("301, 302, 307, or 308"))
        );
    }

    fn warnings(cfg: &Config) -> Vec<Diagnostic> {
        validate(cfg)
            .into_iter()
            .filter(|d| d.severity == Severity::Warning)
            .collect()
    }

    fn has_err(cfg: &Config, path: &str, needle: &str) -> bool {
        errors(cfg)
            .iter()
            .any(|d| d.path == path && d.message.contains(needle))
    }

    fn has_warn(cfg: &Config, path: &str, needle: &str) -> bool {
        warnings(cfg)
            .iter()
            .any(|d| d.path == path && d.message.contains(needle))
    }

    #[test]
    fn diagnostic_display_renders() {
        let d = Diagnostic {
            severity: Severity::Error,
            path: "site[0]".into(),
            message: "boom".into(),
        };
        assert_eq!(d.to_string(), "error: site[0]: boom");
        let w = Diagnostic {
            severity: Severity::Warning,
            path: "x".into(),
            message: "y".into(),
        };
        assert!(w.to_string().starts_with("warning:"));
    }

    #[test]
    fn listener_checks() {
        let cfg = parse_test_config("[server]\nlisten = []");
        assert!(has_err(&cfg, "server", "at least one listener"));

        let cfg = parse_test_config(
            r#"
[server]
listen = [{ addr = "127.0.0.1:8080" }, { addr = "127.0.0.1:8080" }]
max_connections = 10
max_connections_per_ip = 100
"#,
        );
        assert!(has_err(
            &cfg,
            "server.listen[1]",
            "duplicate listen address"
        ));
        assert!(has_warn(
            &cfg,
            "server.max_connections_per_ip",
            "per-IP limit exceeds"
        ));
    }

    #[test]
    fn tls_listener_site_mismatch_warnings() {
        // TLS site but no TLS listener
        let cfg = parse_test_config(
            r#"
[server]
listen = [{ addr = "127.0.0.1:8080" }]
[acme]
email = "a@b.c"
[[site]]
hosts = ["x"]
tls = "auto"
root = "/tmp"
"#,
        );
        assert!(has_warn(&cfg, "server.listen", "HTTPS is unreachable"));
        // exactly one such warning — not duplicated across checks
        assert_eq!(
            warnings(&cfg)
                .iter()
                .filter(|d| d.path == "server.listen" && d.message.contains("tls"))
                .count(),
            1,
            "{:?}",
            warnings(&cfg)
        );

        // TLS listener but every site is plaintext
        let cfg = parse_test_config(
            r#"
[server]
listen = [{ addr = "127.0.0.1:8080", tls = true }]
[[site]]
hosts = ["x"]
tls = "off"
root = "/tmp"
"#,
        );
        assert!(has_warn(&cfg, "server.listen", "all handshakes will fail"));
    }

    #[test]
    fn host_rules() {
        let cfg = parse_test_config(
            r#"
[[site]]
root = "/tmp"
"#,
        );
        assert!(has_err(&cfg, "site[0].hosts", "no hosts"));

        for bad in ["*.", "*.*.x.com"] {
            let cfg = parse_test_config(&format!("[[site]]\nhosts = [{bad:?}]\nroot = \"/tmp\""));
            assert!(
                has_err(&cfg, &format!("site[{bad:?}].hosts"), "invalid wildcard"),
                "{bad}"
            );
        }

        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["*.x.com"]
root = "/tmp"
[[site]]
hosts = ["*.X.com"]
root = "/tmp"
"#,
        );
        assert!(has_err(
            &cfg,
            "site[\"*.X.com\"].hosts",
            "duplicate wildcard"
        ));

        let cfg = parse_test_config("[[site]]\nhosts = [\"*\"]\nroot = \"/tmp\"");
        assert!(has_err(&cfg, "site[\"*\"].hosts", "needs `default = true`"));

        // `default = true` + `hosts = ["*"]` on ONE site claims the
        // default slot once — it must not trip the duplicate check
        let cfg = parse_test_config("[[site]]\nhosts = [\"*\"]\ndefault = true\nroot = \"/tmp\"");
        assert!(
            !has_err(&cfg, "site", "more than one site is marked default"),
            "{:?}",
            errors(&cfg)
        );

        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["*"]
default = true
root = "/tmp"
[[site]]
hosts = ["x"]
default = true
root = "/tmp"
"#,
        );
        assert!(has_err(
            &cfg,
            "site",
            "more than one site is marked default"
        ));
    }

    #[test]
    fn host_spellings_normalized_for_dups() {
        // case and a trailing dot collide after normalization
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["example.com."]
root = "/tmp"
[[site]]
hosts = ["EXAMPLE.com"]
root = "/tmp"
"#,
        );
        assert!(has_err(
            &cfg,
            "site[\"EXAMPLE.com\"].hosts",
            "duplicate host"
        ));
    }

    #[test]
    fn urlish_hosts_rejected() {
        for bad in ["https://x.com", "x.com/path", "x.com:8443", " "] {
            let cfg = parse_test_config(&format!("[[site]]\nhosts = [{bad:?}]\nroot = \"/tmp\""));
            assert!(
                errors(&cfg)
                    .iter()
                    .any(|d| d.message.contains("hostnames only")),
                "{bad}"
            );
        }
        // bracketed IPv6 is a hostname, not a host:port mistake
        let cfg = parse_test_config("[[site]]\nhosts = [\"[::1]\"]\nroot = \"/tmp\"");
        assert!(
            errors(&cfg)
                .iter()
                .all(|d| !d.message.contains("hostnames only")),
            "{:?}",
            errors(&cfg)
        );
    }

    #[test]
    fn acme_nonpublic_names_warn() {
        let cfg = parse_test_config(
            r#"
[server]
listen = [{ addr = "127.0.0.1:8443", tls = true }]
[acme]
email = "a@b.c"
[[site]]
hosts = ["wiki.internal", "localhost", "10.0.0.5"]
tls = "auto"
root = "/tmp"
"#,
        );
        let n = warnings(&cfg)
            .iter()
            .filter(|d| d.message.contains("not a public DNS name"))
            .count();
        assert_eq!(n, 3, "{:?}", validate(&cfg));

        // a public name is quiet
        let cfg = parse_test_config(
            r#"
[server]
listen = ["127.0.0.1:8080", { addr = "127.0.0.1:8443", tls = true }]
[acme]
email = "a@b.c"
[[site]]
hosts = ["app.example.com"]
tls = "auto"
root = "/tmp"
"#,
        );
        assert!(
            warnings(&cfg)
                .iter()
                .all(|d| !d.message.contains("not a public DNS name")),
            "{:?}",
            validate(&cfg)
        );
    }

    #[test]
    fn error_pages_status_range_warned() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/"
static = { root = "/tmp", error_pages = { 200 = "/ok.html", 404 = "/nf.html" } }
"#,
        );
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[0].static.error_pages",
            "200"
        ));
    }

    #[test]
    fn identity_key_without_auth_warns() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/"
respond = { status = 200 }
rate_limit = { key = "identity", rate = "10/s" }
"#,
        );
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[0].rate_limit.key",
            "no auth"
        ));

        // auth present → identity keying is meaningful, stays quiet
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/"
respond = { status = 200 }
auth = { bearer = { tokens = ["t"] } }
rate_limit = { key = "identity", rate = "10/s" }
"#,
        );
        assert!(!has_warn(
            &cfg,
            "site[\"x\"].route[0].rate_limit.key",
            "no auth"
        ));
    }

    #[test]
    fn zero_connection_caps_rejected() {
        for field in ["max_connections", "max_connections_per_ip"] {
            let cfg = parse_test_config(&format!("[server]\n{field} = 0"));
            assert!(has_err(&cfg, &format!("server.{field}"), "> 0"), "{field}");
        }
        let cfg =
            parse_test_config("[upstream.app]\nservers = [\"http://x\"]\nmax_connections = 0");
        assert!(has_err(&cfg, "upstream.app.max_connections", "> 0"));
    }

    #[test]
    fn unused_definitions_and_dup_servers_warned() {
        let cfg = parse_test_config(
            r#"
[upstream.used]
servers = ["http://u", "http://u", "http://v"]
[upstream.orphan]
servers = ["http://u"]
[cache.main]
tier = "ram"
[cache.orphan]
tier = "ram"
[[site]]
hosts = ["x"]
proxy = "used"
[[site.route]]
prefix = "/c"
respond = { status = 200 }
cache = "main"
"#,
        );
        assert!(has_warn(&cfg, "upstream.orphan", "never referenced"));
        assert!(!has_warn(&cfg, "upstream.used", "never referenced"));
        assert!(has_warn(
            &cfg,
            "upstream.used.servers",
            "duplicate server URL"
        ));
        assert!(has_warn(&cfg, "cache.orphan", "never referenced"));
        assert!(!has_warn(&cfg, "cache.main", "never referenced"));
    }

    #[test]
    fn compress_level_checked_against_algorithms() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/a"
respond = { status = 200 }
compress = { algorithms = ["zstd"], level = 15 }
[[site.route]]
prefix = "/b"
respond = { status = 200 }
compress = { algorithms = ["gzip"], level = 12 }
"#,
        );
        assert!(!has_err(&cfg, "site[\"x\"].route[0].compress.level", ""));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[1].compress.level",
            "exceeds gzip"
        ));
    }

    #[test]
    fn acme_directory_needs_http_scheme() {
        let cfg = parse_test_config("[acme]\ndirectory = \"ftp://ca.local/dir\"");
        assert!(has_err(&cfg, "acme.directory", "http(s)"));
        let cfg = parse_test_config("[acme]\ndirectory = \"http://ca.local/dir\"");
        assert!(!has_err(&cfg, "acme.directory", ""));
    }

    #[test]
    fn manual_tls_missing_files_warn() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
tls = { cert = "/definitely/missing.crt", key = "/definitely/missing.key" }
root = "/tmp"
"#,
        );
        assert!(has_warn(&cfg, "site[\"x\"].tls.cert", "does not exist"));
        assert!(has_warn(&cfg, "site[\"x\"].tls.key", "does not exist"));
    }

    #[test]
    fn site_shorthands_and_redirect_https() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
root = "/tmp"
proxy = ["http://127.0.0.1:1"]
"#,
        );
        assert!(has_err(&cfg, "site[\"x\"]", "mutually exclusive"));

        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
tls = "off"
redirect_https = true
root = "/tmp"
"#,
        );
        assert!(has_warn(&cfg, "site[\"x\"]", "redirect_https"));
    }

    #[test]
    fn acme_http01_needs_plaintext_listener() {
        let cfg = parse_test_config(
            r#"
[server]
listen = [{ addr = "127.0.0.1:8443", tls = true }]
[acme]
email = "a@b.c"
challenge = "http-01"
[[site]]
hosts = ["x"]
tls = "auto"
root = "/tmp"
"#,
        );
        assert!(has_warn(&cfg, "acme.challenge", "cannot reach port 80"));
    }

    #[test]
    fn empty_trusted_proxies_warns() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
trusted_proxies = []
root = "/tmp"
"#,
        );
        assert!(has_warn(&cfg, "site[\"x\"].trusted_proxies", "disables"));
    }

    #[test]
    fn matcher_sanity() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
exact = "noslash"
respond = { status = 200 }
[[site.route]]
regex = "(["
respond = { status = 200 }
[[site.route]]
prefix = "/m"
match = { methods = ["B A D"], headers = { "X-A" = "re:([" }, query = { q = "re:)(" } }
respond = { status = 200 }
"#,
        );
        assert!(has_err(&cfg, "site[\"x\"].route[0]", "must start with '/'"));
        assert!(has_err(&cfg, "site[\"x\"].route[1]", "invalid route regex"));
        assert!(has_err(&cfg, "site[\"x\"].route[2]", "invalid HTTP method"));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[2].headers.X-A",
            "invalid regex"
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[2].query.q",
            "invalid regex"
        ));
    }

    #[test]
    fn handler_count_and_static_warnings() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/none"
[[site.route]]
prefix = "/two"
respond = { status = 200 }
redirect = { scheme = "https" }
"#,
        );
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0]",
            "exactly one handler (static"
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[1]",
            "found redirect + respond"
        ));

        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/s"
static = { root = "/definitely/missing-dir", index = [] }
"#,
        );
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[0].static.root",
            "does not exist"
        ));
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[0].static",
            "directory requests"
        ));
    }

    #[test]
    fn redirect_and_respond_rules() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/a"
redirect = { to = "https://x/{path}", scheme = "https" }
[[site.route]]
prefix = "/b"
redirect = { scheme = "gopher" }
[[site.route]]
prefix = "/c"
respond = { status = 99 }
[[site.route]]
prefix = "/d"
respond = { status = 200, body = "you asked for {path}", headers = { "content-type" = "text/html" } }
[[site.route]]
prefix = "/e"
redirect = { to = "https://x" }
response_headers = { set = { "x-a" = "1" } }
"#,
        );
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0]",
            "exactly one of to/host/scheme"
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[1]",
            "must be http or https"
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[2]",
            "not a valid HTTP status"
        ));
        assert!(has_warn(&cfg, "site[\"x\"].route[3].respond", "text/plain"));
        assert!(errors(&cfg).iter().all(|d| !d.path.contains("route[4]")));
    }

    #[test]
    fn auth_rules() {
        // zero and two methods
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/a"
respond = { status = 200 }
auth = {}
[[site.route]]
prefix = "/b"
respond = { status = 200 }
auth = { basic = { users = { u = "$argon2id$x" } }, bearer = { tokens = ["t"] } }
[[site.route]]
prefix = "/c"
respond = { status = 200 }
auth = { basic = { users = { u = "$argon2id$x" }, htpasswd = "/tmp/x.htpasswd" } }
[[site.route]]
prefix = "/d"
respond = { status = 200 }
auth = { basic = {} }
"#,
        );
        assert!(has_err(&cfg, "site[\"x\"].route[0].auth", "found 0"));
        assert!(has_err(&cfg, "site[\"x\"].route[1].auth", "found 2"));
        assert!(has_err(&cfg, "site[\"x\"].route[2].auth.basic", "not both"));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[3].auth.basic",
            "set users or htpasswd"
        ));
    }

    #[test]
    fn htpasswd_file_checked() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("good.htpasswd");
        let bad = dir.path().join("bad.htpasswd");
        std::fs::write(&good, "u:$2y$10$abcdefghijklmnopqrstuv\n\nv:$2b$10$w\n").unwrap();
        std::fs::write(&bad, "u:notahash\n").unwrap();

        let cfg = parse_test_config(&format!(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/g"
respond = {{ status = 200 }}
auth = {{ basic = {{ htpasswd = {:?} }} }}
[[site.route]]
prefix = "/b"
respond = {{ status = 200 }}
auth = {{ basic = {{ htpasswd = {:?} }} }}
[[site.route]]
prefix = "/m"
respond = {{ status = 200 }}
auth = {{ basic = {{ htpasswd = "{}" }} }}
"#,
            good.display(),
            bad.display(),
            dir.path().join("missing.htpasswd").display()
        ));
        let errs = errors(&cfg);
        assert!(
            errs.iter()
                .any(|d| d.path.contains("htpasswd") && d.message.contains("expected user:$2y$")),
            "{errs:?}"
        );
        assert!(
            warnings(&cfg)
                .iter()
                .any(|d| d.message.contains("cannot read")),
            "{:?}",
            validate(&cfg)
        );
        // good file produces no htpasswd diagnostics at route[0]
        assert!(validate(&cfg).iter().all(|d| !d.path.contains("route[0]")));
    }

    #[test]
    fn bearer_and_api_key_rules() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/a"
respond = { status = 200 }
auth = { bearer = {} }
[[site.route]]
prefix = "/b"
respond = { status = 200 }
auth = { api_key = { location = "header", name = "", keys = [] } }
"#,
        );
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0].auth.bearer",
            "tokens list is empty"
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[1].auth.api_key",
            "name must not be empty"
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[1].auth.api_key",
            "keys list is empty"
        ));
    }

    #[test]
    fn rate_limit_rules() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/a"
respond = { status = 200 }
rate_limit = { key = "bogus", rate = "100/s" }
[[site.route]]
prefix = "/b"
respond = { status = 200 }
rate_limit = { key = "ip", rate = "0/s" }
"#,
        );
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0].rate_limit.key",
            "invalid key"
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[1].rate_limit.rate",
            "greater than zero"
        ));
    }

    #[test]
    fn cors_rules() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/a"
respond = { status = 200 }
cors = {}
[[site.route]]
prefix = "/b"
respond = { status = 200 }
cors = { origins = ["re:(broken"] }
[[site.route]]
prefix = "/c"
respond = { status = 200 }
cors = { origins = ["*"], credentials = true }
"#,
        );
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[0].cors",
            "origins is empty"
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[1].cors.origins",
            "invalid regex"
        ));
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[2].cors",
            "credentials with wildcard"
        ));
    }

    #[test]
    fn upstream_rules() {
        let cfg = parse_test_config(
            r#"
[upstream.empty]
servers = []
[upstream.badurl]
servers = ["ftp://x", "http://"]
[upstream.noVerify]
servers = ["https://secure.internal"]
tls.verify = false
[upstream.health]
servers = ["http://x"]
health = { active = { path = "/h", interval = "10s", timeout = "3s", expect = 99 }, passive = { failures = 0, cooldown = "5s" } }
unavailable = { status = 42 }
"#,
        );
        assert!(has_err(&cfg, "upstream.empty", "no servers"));
        assert!(has_err(&cfg, "upstream.badurl", "must have scheme http"));
        assert!(has_err(&cfg, "upstream.badurl", "has no host"));
        assert!(has_warn(&cfg, "upstream.noVerify.tls.verify", "MITM"));
        assert!(has_err(
            &cfg,
            "upstream.health.health.active.expect",
            "100–599"
        ));
        assert!(has_err(
            &cfg,
            "upstream.health.unavailable.status",
            "100–599"
        ));
        assert!(has_warn(
            &cfg,
            "upstream.health.health.passive.failures",
            "single failure"
        ));
    }

    #[test]
    fn proxy_rewrite_and_retry_rules() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/a"
proxy = { upstream = ["http://u"] }
[[site.route]]
prefix = "/b"
proxy = { upstream = [], rewrite = { strip_prefix = "/a", regex = { pattern = "x", replace = "y" } } }
[[site.route]]
prefix = "/c"
proxy = { upstream = ["http://u"], rewrite = { regex = { pattern = "(", replace = "y" } } }
[[site.route]]
prefix = "/d"
proxy = { upstream = ["http://u"], rewrite = { strip_prefix = "noslash" } }
[[site.route]]
prefix = "/e"
proxy = { upstream = ["http://u"], retries = { budget_fraction = 1.5 } }
"#,
        );
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[1].proxy.upstream",
            "URL list is empty"
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[1].proxy.rewrite",
            "exactly one of"
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[2].proxy.rewrite.regex",
            "invalid regex"
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[3].proxy.rewrite.strip_prefix",
            "must start with '/'"
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[4].retries.budget_fraction",
            "between 0 and 1"
        ));
        // exactly one budget_fraction diagnostic, not two
        assert_eq!(
            errors(&cfg)
                .iter()
                .filter(|d| d.path.contains("route[4]") && d.message.contains("budget_fraction"))
                .count(),
            1,
            "{:?}",
            errors(&cfg)
        );
        // inline URL list is checked per-url
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/f"
proxy = { upstream = ["bogus"] }
"#,
        );
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0].proxy.upstream",
            "scheme"
        ));
    }

    #[test]
    fn cache_store_rules() {
        let cfg = parse_test_config(
            r#"
[cache.unusedpath]
tier = "ram"
disk_path = "/tmp/x"
[cache.zeroram]
tier = "ram"
ram_bytes = "0B"
[cache.zerodisk]
tier = "disk"
disk_path = "/tmp/x"
disk_bytes = "0B"
[cache.noram]
tier = "hybrid"
disk_path = "/tmp/x"
ram_bytes = "0B"
[cache.noobj]
tier = "ram"
max_object_bytes = "0B"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/a"
respond = { status = 200 }
cache = { store = "missing" }
[[site.route]]
prefix = "/b"
respond = { status = 200 }
cache = { store = "unusedpath" }
auth = { api_key = { location = "query", name = "k", keys = ["x"] } }
"#,
        );
        assert!(has_warn(&cfg, "cache.unusedpath", "unused"));
        assert!(has_err(&cfg, "cache.zeroram", "ram_bytes must be > 0"));
        assert!(has_err(&cfg, "cache.zerodisk", "disk_bytes must be > 0"));
        assert!(has_err(&cfg, "cache.noram", "ram_bytes must be > 0"));
        assert!(has_err(&cfg, "cache.noobj", "max_object_bytes"));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0].cache.store",
            "unknown cache store"
        ));
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[1].auth.api_key",
            "credentials in URLs"
        ));
    }

    #[test]
    fn compress_algorithm_checked() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/a"
respond = { status = 200 }
compress = { algorithms = ["br", "deflate"] }
"#,
        );
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0].compress.algorithms",
            "unknown algorithm"
        ));
    }

    #[test]
    fn admin_warnings() {
        // loopback without token → warning (CSRF mitigations apply, but a
        // local process can still manage the server)
        let cfg = parse_test_config("[admin]\nlisten = \"127.0.0.1:2019\"");
        assert!(has_warn(&cfg, "admin.token", "no token"));

        // loopback with token → no admin diagnostics
        let cfg = parse_test_config("[admin]\nlisten = \"127.0.0.1:2019\"\ntoken = \"t\"");
        assert!(validate(&cfg).iter().all(|d| !d.path.starts_with("admin")));

        // non-loopback with token but no TLS → cleartext warning
        let cfg = parse_test_config(
            "[admin]\nlisten = \"0.0.0.0:2019\"\ntoken = \"t\"\ntls = { cert = \"/x.crt\", key = \"/x.key\" }",
        );
        assert!(has_warn(&cfg, "admin.tls.cert", "does not exist"));
        assert!(has_warn(&cfg, "admin.tls.key", "does not exist"));
        assert!(!has_warn(&cfg, "admin.tls", "cleartext"));

        let cfg = parse_test_config("[admin]\nlisten = \"0.0.0.0:2019\"\ntoken = \"t\"");
        assert!(has_warn(&cfg, "admin.tls", "cleartext"));
    }

    #[test]
    fn acme_rules() {
        let cfg = parse_test_config("[acme]\neab = { key_id = \"k\", key = \"\" }");
        assert!(has_err(&cfg, "acme.eab", "both key_id and key"));

        let cfg = parse_test_config(
            r#"
[acme.eab]
key_id = "k"
key = "v"
[acme.on_demand]
enabled = true
allowed_hosts = ["*.ok.com"]
"#,
        );
        assert!(has_warn(&cfg, "acme.on_demand.rate", "no rate limit"));
    }

    #[test]
    fn acme_dns01_rules() {
        // dns-01 without [acme.dns] is fatal
        let cfg = parse_test_config("[acme]\nchallenge = \"dns-01\"");
        assert!(has_err(&cfg, "acme.dns", "requires an [acme.dns]"));

        // [acme.dns] without challenge = "dns-01" is dead config
        let cfg = parse_test_config(
            r#"
[acme]
challenge = "auto"
[acme.dns.cloudflare]
api_token = "tok"
"#,
        );
        assert!(has_warn(&cfg, "acme.dns", "credentials are unused"));

        // empty token, bad resolver, bad api_base
        let cfg = parse_test_config(
            r#"
[acme]
challenge = "dns-01"
[acme.dns.cloudflare]
api_token = "  "
zone_id = " "
api_base = "ftp://x"
resolver = "not-an-ip"
"#,
        );
        assert!(has_err(&cfg, "acme.dns.cloudflare.api_token", "empty"));
        assert!(has_err(&cfg, "acme.dns.cloudflare.zone_id", "empty"));
        assert!(has_err(&cfg, "acme.dns.cloudflare.api_base", "http(s)"));
        assert!(has_err(&cfg, "acme.dns.cloudflare.resolver", "ip"));

        // well-formed dns-01 config — no dns errors; wildcard warning gone
        let cfg = parse_test_config(
            r#"
[server]
listen = [{ addr = "127.0.0.1:8443", tls = true }]
[acme]
email = "a@b.c"
challenge = "dns-01"
[acme.dns.cloudflare]
api_token = "tok"
[[site]]
hosts = ["*.example.com"]
tls = "auto"
root = "/tmp"
"#,
        );
        assert!(!has_err(&cfg, "acme.dns", ""));
        assert!(!has_warn(&cfg, "site[\"*.example.com\"].hosts", "wildcard"));
    }

    #[test]
    fn acme_wildcard_needs_dns01() {
        let cfg = parse_test_config(
            r#"
[server]
listen = [{ addr = "127.0.0.1:8443", tls = true }]
[acme]
email = "a@b.c"
[[site]]
hosts = ["*.example.com"]
tls = "auto"
root = "/tmp"
"#,
        );
        assert!(has_warn(
            &cfg,
            "site[\"*.example.com\"].hosts",
            "need the dns-01 challenge"
        ));
    }

    #[test]
    fn timeout_and_limit_rules() {
        let cfg = parse_test_config(
            r#"
[timeouts]
header_read = "0s"
tls_handshake = "0s"
send = "0s"
[limits]
header_bytes = "0B"
body_bytes = "0B"
[log.access]
sample = 1.5
"#,
        );
        assert!(has_warn(&cfg, "timeouts.header_read", "slowloris"));
        assert!(has_warn(&cfg, "timeouts.tls_handshake", "handshake"));
        assert!(has_warn(&cfg, "timeouts.send", "send inactivity"));
        assert!(has_err(&cfg, "limits.header_bytes", "> 0"));
        assert!(has_err(&cfg, "limits.body_bytes", "> 0"));
        assert!(has_err(&cfg, "log.access.sample", "0.0–1.0"));

        let cfg = parse_test_config("[limits]\nheader_bytes = \"2MiB\"");
        assert!(has_warn(&cfg, "limits.header_bytes", "memory multiplier"));
    }

    #[test]
    fn unusual_log_level_warns() {
        let cfg = parse_test_config("[log]\nlevel = \"banana\"");
        assert!(has_warn(&cfg, "log.level", "unusual log level"));
        let cfg = parse_test_config("[log]\nlevel = \"verd=debug,hyper=info\"");
        assert!(!has_warn(&cfg, "log.level", "unusual"));
        let cfg = parse_test_config("[log]\nlevel = \"debug\"");
        assert!(!has_warn(&cfg, "log.level", "unusual"));
    }
}
