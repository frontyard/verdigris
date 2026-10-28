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
    /// Config file that set the offending value, when known — filled by
    /// the loader for configs assembled from `include`d fragments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<std::path::PathBuf>,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sev = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(f, "{sev}: {}: {}", self.path, self.message)?;
        if let Some(src) = &self.source {
            write!(f, " (in {})", src.display())?;
        }
        Ok(())
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
            source: None,
        });
    }
    fn warn(&mut self, path: impl Into<String>, msg: impl Into<String>) {
        self.diags.push(Diagnostic {
            severity: Severity::Warning,
            path: path.into(),
            message: msg.into(),
            source: None,
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
    check_global_security(&mut ctx, cfg);

    ctx.diags
}

/// A `host`/`redirect_host`-style value: hostname, optionally `host:port`.
/// Anything else produces a `Location`/`Host` header that fails
/// `HeaderValue` encoding at request time — silently.
fn check_host_target(ctx: &mut Ctx, path: String, v: &str, extra: &str) {
    if v.is_empty()
        || v.contains("://")
        || v.contains('/')
        || v.chars().any(char::is_whitespace)
        || http::HeaderValue::from_str(v).is_err()
    {
        ctx.error(
            path,
            format!(
                "{v:?} is not a valid Host value — use a hostname (optionally host:port){extra}"
            ),
        );
    }
}

/// `{ident}`-looking tokens in `redirect.to`/`respond.body` templates.
/// The placeholder set is closed; anything else passes through
/// literally at request time — almost always a typo, but possibly
/// intentional text, so warn rather than error.
fn check_placeholder_tokens(ctx: &mut Ctx, path: &str, template: &str) {
    const KNOWN: [&str; 9] = [
        "path",
        "host",
        "query",
        "method",
        "scheme",
        "uri",
        "args",
        "remote_ip",
        "request_id",
    ];
    let mut seen = HashSet::new();
    for cap in placeholder_re().captures_iter(template) {
        let name = cap[1].to_string();
        if !KNOWN.contains(&name.as_str()) && seen.insert(name.clone()) {
            ctx.warn(
                path.to_string(),
                format!(
                    "unknown placeholder {{{name}}} in {template:?} — the closed set is {{path}}, {{host}}, {{query}}, {{method}}, {{scheme}}, {{uri}}, {{args}}, {{remote_ip}}, {{request_id}}; other text passes through literally"
                ),
            );
        }
    }
}

/// `{{path}}`-style tokens: `{` + identifier + `}` — letter/underscore
/// only, so `{"json": "…"}` and `{ css }` braces are not flagged.
fn placeholder_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\{([A-Za-z_]+)\}").expect("static regex"))
}

/// Security-header token sets, shared by the global `[security]` table
/// and `RouteSecurity` overrides. Values are emitted verbatim — an
/// out-of-set token is dead config, and an unparseable one is silently
/// dropped at request time. Empty means "emit nothing" at every layer.
fn check_security_tokens(
    ctx: &mut Ctx,
    path: &str,
    frame_options: Option<&str>,
    referrer_policy: Option<&str>,
    csp: Option<&str>,
    cross_domain_policy: Option<&str>,
) {
    const REFERRER_POLICIES: [&str; 8] = [
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    ];
    const CROSS_DOMAIN_POLICIES: [&str; 4] = ["none", "master-only", "by-content-type", "all"];
    let token_set =
        |v: &str, set: &[&str]| v.is_empty() || set.contains(&v.to_ascii_lowercase().as_str());
    if let Some(v) = frame_options
        && !v.is_empty()
    {
        if http::HeaderValue::from_str(v).is_err() {
            ctx.error(
                format!("{path}.frame_options"),
                format!("{v:?} is not a valid header value"),
            );
        } else if !token_set(v, &["deny", "sameorigin"]) {
            ctx.error(
                format!("{path}.frame_options"),
                format!(
                    "{v:?} — X-Frame-Options accepts DENY or SAMEORIGIN (\"\" disables the header)"
                ),
            );
        }
    }
    if let Some(v) = referrer_policy
        && !v.is_empty()
    {
        if http::HeaderValue::from_str(v).is_err() {
            ctx.error(
                format!("{path}.referrer_policy"),
                format!("{v:?} is not a valid header value"),
            );
        } else if !token_set(v, &REFERRER_POLICIES) {
            ctx.error(
                format!("{path}.referrer_policy"),
                format!("{v:?} is not a Referrer-Policy token (\"\" disables the header)"),
            );
        }
    }
    if let Some(v) = csp
        && !v.is_empty()
        && http::HeaderValue::from_str(v).is_err()
    {
        ctx.error(
            format!("{path}.csp"),
            format!("{v:?} is not a valid header value"),
        );
    }
    if let Some(v) = cross_domain_policy
        && !v.is_empty()
    {
        if http::HeaderValue::from_str(v).is_err() {
            ctx.error(
                format!("{path}.cross_domain_policy"),
                format!("{v:?} is not a valid header value"),
            );
        } else if !token_set(v, &CROSS_DOMAIN_POLICIES) {
            ctx.error(
                format!("{path}.cross_domain_policy"),
                format!(
                    "{v:?} — X-Permitted-Cross-Domain-Policies accepts none, master-only, by-content-type, or all (\"\" disables)"
                ),
            );
        }
    }
}

/// Global `[security]` — every field is concrete (`""` disables).
fn check_global_security(ctx: &mut Ctx, cfg: &Config) {
    let s = &cfg.server.security;
    check_security_tokens(
        ctx,
        "server.security",
        Some(&s.frame_options),
        Some(&s.referrer_policy),
        s.csp.as_deref(),
        Some(&s.cross_domain_policy),
    );
}

/// `RouteSecurity` overrides — `Some(v)` fields only; absent inherits.
fn check_route_security(ctx: &mut Ctx, path: &str, s: &RouteSecurity) {
    // `security = false` alone is fine — extra fields alongside it are
    // dead config (parity with cache/compress disabled-block warnings)
    if s.enabled == Some(false)
        && (s.hsts.is_some()
            || s.hsts_max_age.is_some()
            || s.hsts_subdomains.is_some()
            || s.content_type_options.is_some()
            || s.frame_options.is_some()
            || s.referrer_policy.is_some()
            || s.csp.is_some()
            || s.cross_domain_policy.is_some())
    {
        ctx.warn(
            path.to_string(),
            "settings are ignored — security is disabled",
        );
    }
    check_security_tokens(
        ctx,
        path,
        s.frame_options.as_deref(),
        s.referrer_policy.as_deref(),
        s.csp.as_deref(),
        s.cross_domain_policy.as_deref(),
    );
}

/// Warn when a CIDR list contains a `/0` entry — it matches every
/// address of its family, which is almost never the intent in ACLs,
/// exemptions, or proxy trust.
fn check_catchall_nets(ctx: &mut Ctx, path: String, nets: &[ipnet::IpNet], msg: &str) {
    if nets.iter().any(|n| n.prefix_len() == 0) {
        ctx.warn(path, msg.to_string());
    }
}

/// HTTP methods the validator treats as standard — `Method::from_bytes`
/// accepts any token, so a closed-set check is the only way to catch
/// `"GTE"`-style typos. Custom extension methods are legal; they get a
/// warning, not an error.
const STANDARD_METHODS: [&str; 9] = [
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE",
];

/// Method lists are matched verbatim at request time — an invalid
/// token is dead config; an unusual-but-valid method is usually a typo.
fn check_method(ctx: &mut Ctx, path: String, m: &str, allow_star: bool) {
    if m == "*" && allow_star {
        return;
    }
    if http::Method::from_bytes(m.as_bytes()).is_err() {
        ctx.error(path, format!("invalid HTTP method {m:?}"));
    } else if !STANDARD_METHODS.contains(&m) {
        ctx.warn(
            path,
            format!(
                "unusual HTTP method {m:?} — methods are matched exactly; a typo never matches"
            ),
        );
    }
}

/// Rough DNS-name shape for `upstream.tls.sni` — labels of
/// alphanumerics and interior hyphens; IPs pass via a separate check.
fn looks_like_dns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
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
    // `""`/`"off"`/`false` omit the header; anything else is emitted
    // verbatim — an invalid value would be silently dropped at build
    // time. `"off"` is the legacy spelling — `false` is preferred.
    let sh = cfg.server.server_header.as_str();
    if sh == "off" {
        ctx.warn(
            "server.server_header",
            "\"off\" is deprecated — prefer `server_header = false` (or \"\")",
        );
    } else if !sh.is_empty() && http::HeaderValue::from_str(sh).is_err() {
        ctx.error(
            "server.server_header",
            format!("{sh:?} is not a valid header value"),
        );
    }
    check_catchall_nets(
        ctx,
        "server.trusted_proxies".to_string(),
        &cfg.server.trusted_proxies,
        "a /0 CIDR trusts X-Forwarded-* from every client — ACLs and ip-keyed rate limits become spoofable",
    );
}

/// Label a site by `name`, else its first host (or `default`), falling
/// back to the index — `site["api"]` reads better than `site[2]` after
/// includes have merged fragments from several files.
fn site_label(i: usize, site: &SiteConfig) -> String {
    if let Some(n) = &site.name {
        format!("site[{n:?}]")
    } else if let Some(h) = site.hosts.first() {
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
    let mut names: HashMap<&str, usize> = HashMap::new();
    let mut default_count = 0usize;
    let mut any_tls = false;

    for (i, site) in cfg.site.iter().enumerate() {
        let site_path = site_label(i, site);
        // `name` feeds the site["…"] diagnostic label AND the `route`
        // metric id prefix `{name}.r{j}` — duplicates collide in both
        if let Some(n) = &site.name
            && names.insert(n.as_str(), i).is_some()
        {
            ctx.error(
                site_path.clone(),
                format!(
                    "duplicate site name {n:?} — metric `route` labels and diagnostics collide"
                ),
            );
        }
        if let Some(h) = &site.redirect_host {
            check_host_target(ctx, format!("{site_path}.redirect_host"), h, "");
        }
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
            if site.redirect_host.is_some() {
                ctx.warn(
                    format!("{site_path}.redirect_host"),
                    "redirect_host is ignored — it only affects the http→https upgrade, which never runs with tls = \"off\"",
                );
            }
        } else {
            any_tls = true;
        }
        if site.redirect_https == Some(false) && site.redirect_host.is_some() {
            ctx.warn(
                format!("{site_path}.redirect_host"),
                "redirect_host is ignored — it only affects the http→https upgrade, which redirect_https = false disables",
            );
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
        let shorthands = [
            site.root.is_some(),
            site.proxy.is_some(),
            site.respond.is_some(),
            site.redirect.is_some(),
        ]
        .into_iter()
        .filter(|b| *b)
        .count();
        if shorthands > 1 {
            ctx.error(
                site_path.clone(),
                "site.root, site.proxy, site.respond and site.redirect are mutually exclusive shorthands; use explicit routes",
            );
        }
        if let Some(up) = &site.proxy {
            check_proxy(ctx, cfg, &format!("{site_path}.proxy"), up);
        }
        if let Some(redir) = &site.redirect {
            check_redirect(ctx, &site_path, redir);
        }
        if let Some(resp) = &site.respond {
            check_respond(ctx, &site_path, resp);
        }
        for (j, route) in site.route.iter().enumerate() {
            check_route(ctx, cfg, &site_path, j, site, route);
        }
        check_site_defaults(ctx, cfg, &site_path, site);
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

/// Site-level middleware defaults — same checks as the route forms.
fn check_site_defaults(ctx: &mut Ctx, cfg: &Config, site_path: &str, site: &SiteConfig) {
    if let Some(auth) = &site.auth {
        check_auth(ctx, site_path, auth);
    }
    if let Some(rl) = &site.rate_limit {
        check_rate_limit(ctx, site_path, rl);
        if rl.enabled && rl.key == "identity" && !site.auth.as_ref().is_some_and(|a| a.enabled) {
            ctx.warn(
                format!("{site_path}.rate_limit.key"),
                "key \"identity\" but the site has no auth — requests are keyed by client IP",
            );
        }
    }
    if let Some(cors) = &site.cors {
        check_cors(ctx, site_path, cors);
    }
    if let Some(cache) = &site.cache {
        check_route_cache(ctx, cfg, site_path, cache);
    }
    if let Some(comp) = &site.compress {
        check_compress(ctx, site_path, comp);
    }
    if let Some(ops) = &site.response_headers {
        check_header_ops(ctx, site_path, "response_headers", ops);
    }
    if let Some(sec) = &site.security {
        check_route_security(ctx, &format!("{site_path}.security"), sec);
    }
    check_catchall_nets(
        ctx,
        format!("{site_path}.ip_allow"),
        &site.ip_allow,
        "a /0 CIDR matches every client — the allowlist is a no-op",
    );
    check_overrides(ctx, site_path, &site.timeouts, &site.limits);
    check_catchall_nets(
        ctx,
        format!("{site_path}.ip_deny"),
        &site.ip_deny,
        "a /0 CIDR denies every client — all requests get 403",
    );
}

fn check_trusted_proxies(ctx: &mut Ctx, _cfg: &Config, i: usize, site: &SiteConfig) {
    if let Some(proxies) = &site.trusted_proxies {
        if proxies.is_empty() {
            ctx.warn(
                format!("{}.trusted_proxies", site_label(i, site)),
                "explicit empty list disables trusted proxies for this site",
            );
        }
        check_catchall_nets(
            ctx,
            format!("{}.trusted_proxies", site_label(i, site)),
            proxies,
            "a /0 CIDR trusts X-Forwarded-* from every client — ACLs and ip-keyed rate limits become spoofable",
        );
    }
}

fn check_route(
    ctx: &mut Ctx,
    cfg: &Config,
    site_label: &str,
    route_idx: usize,
    site: &SiteConfig,
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
            } else if !STANDARD_METHODS.contains(&method.as_str()) {
                ctx.warn(
                    format!("{path}.match.methods"),
                    format!("unusual HTTP method {method:?} — methods are matched exactly; a typo never matches"),
                );
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
        let root_exists = st.root.is_dir();
        if !root_exists {
            ctx.warn(
                format!("{path}.static.root"),
                format!(
                    "root {} does not exist or is not a directory",
                    st.root.display()
                ),
            );
        }
        for status in st.error_pages.exact.keys() {
            if !(400..=599).contains(status) {
                ctx.warn(
                    format!("{path}.static.error_pages"),
                    format!(
                        "status {status} is not an error status — error_pages only apply to 400–599"
                    ),
                );
            }
        }
        // pages resolve against `root` at serve time — a missing file
        // silently falls back to the default error body
        if root_exists {
            for (key, page) in st.error_pages.entries() {
                let resolved = st.root.join(page.to_string_lossy().trim_start_matches('/'));
                if !resolved.is_file() {
                    ctx.warn(
                        format!("{path}.static.error_pages"),
                        format!("page {key} → {} does not exist under root", page.display()),
                    );
                }
            }
        }
        if st.index.is_empty() && !st.listing && !st.spa {
            ctx.warn(
                format!("{path}.static"),
                "no index files, listing disabled, and spa disabled — directory requests will 403/404",
            );
        }
        // `spa` serves `index[0]` from root as the catch-all — with no
        // index configured or the file missing it can never fire
        let spa_dead = st.index.is_empty()
            || (root_exists && st.index.first().is_some_and(|i| !st.root.join(i).is_file()));
        if st.spa && st.index.is_empty() {
            ctx.warn(
                format!("{path}.static.spa"),
                "spa serves index[0] as its fallback — index = [] means spa never applies",
            );
        } else if st.spa && root_exists && spa_dead {
            let i = &st.index[0];
            ctx.warn(
                format!("{path}.static.spa"),
                format!("spa fallback {i:?} does not exist under root — spa never applies"),
            );
        }
        if st.spa && st.listing && !spa_dead {
            // directory requests hit the SPA file before listing runs;
            // listing is only reachable while the SPA file is missing
            ctx.warn(
                format!("{path}.static.listing"),
                "listing only applies when the SPA fallback file is missing — spa takes precedence over listing",
            );
        }
    }

    if let Some(proxy) = &route.proxy {
        check_proxy(ctx, cfg, &path, proxy);
    }

    if let Some(redir) = &route.redirect {
        check_redirect(ctx, &path, redir);
    }

    if let Some(resp) = &route.respond {
        check_respond(ctx, &path, resp);
    }

    let eff_auth = route
        .auth
        .as_ref()
        .or(site.auth.as_ref())
        .filter(|a| a.enabled);
    if let Some(auth) = &route.auth {
        check_auth(ctx, &path, auth);
    }
    if let Some(rl) = &route.rate_limit {
        check_rate_limit(ctx, &path, rl);
        if rl.enabled && rl.key == "identity" && eff_auth.is_none() {
            ctx.warn(
                format!("{path}.rate_limit.key"),
                "key \"identity\" but neither the route nor its site has auth — requests are keyed by client IP",
            );
        }
    }
    if let Some(cors) = &route.cors {
        check_cors(ctx, &path, cors);
    }
    if let Some(cache) = &route.cache {
        check_route_cache(ctx, cfg, &path, cache);
        if cache.enabled
            && let Some(key) = eff_auth.and_then(|a| a.api_key.as_ref())
            && key.location == ApiKeyLocation::Query
        {
            // the cache layer strips the param from keys (see
            // key::strip_query_param) — this warns it ever existed
            ctx.warn(
                format!("{path}.auth.api_key"),
                "query-parameter api keys on a cached route put credentials in URLs; the param is stripped from cache keys, but header-based keys are safer",
            );
        }
    }
    if let Some(comp) = &route.compress {
        check_compress(ctx, &path, comp);
    }
    if let Some(ops) = &route.response_headers {
        check_header_ops(ctx, &path, "response_headers", ops);
    }
    if let Some(sec) = &route.security {
        check_route_security(ctx, &format!("{path}.security"), sec);
    }
    check_catchall_nets(
        ctx,
        format!("{path}.ip_allow"),
        &route.ip_allow,
        "a /0 CIDR matches every client — the allowlist is a no-op",
    );
    check_catchall_nets(
        ctx,
        format!("{path}.ip_deny"),
        &route.ip_deny,
        "a /0 CIDR denies every client — all requests get 403",
    );
    check_overrides(ctx, &path, &route.timeouts, &route.limits);
    // A route's ip_allow can only narrow the site's — entries that
    // admit nothing the site allows, or that the site denylist covers,
    // can never pass
    for net in &route.ip_allow {
        if !site.ip_allow.is_empty()
            && !site.ip_allow.iter().any(|s| {
                same_family(s, net) && (s.contains(&net.network()) || net.contains(&s.network()))
            })
        {
            ctx.warn(
                format!("{path}.ip_allow"),
                format!(
                    "{net} is outside every {site_label}.ip_allow entry — it can never admit a client"
                ),
            );
        }
        if site.ip_deny.iter().any(|d| {
            same_family(d, net) && d.prefix_len() <= net.prefix_len() && d.contains(&net.network())
        }) {
            ctx.warn(
                format!("{path}.ip_allow"),
                format!(
                    "{net} is fully denied by {site_label}.ip_deny — it can never admit a client"
                ),
            );
        }
    }
}

fn same_family(a: &ipnet::IpNet, b: &ipnet::IpNet) -> bool {
    matches!(a, ipnet::IpNet::V4(_)) == matches!(b, ipnet::IpNet::V4(_))
}

/// Dead-config check for a disabled `response_headers` block — field
/// syntax itself is enforced when the ops compile at build.
fn check_header_ops(ctx: &mut Ctx, path: &str, leaf: &str, ops: &HeaderOps) {
    if !ops.enabled && (!ops.set.is_empty() || !ops.add.is_empty() || !ops.remove.is_empty()) {
        ctx.warn(
            format!("{path}.{leaf}"),
            format!("settings are ignored — {leaf}.enabled = false"),
        );
    }
    // hop-by-hop/framing headers are managed by the server — a manual
    // value lands next to the computed one and corrupts framing on
    // either direction (a set `content-length` duplicates the real one)
    for (field, map) in [("set", &ops.set), ("add", &ops.add)] {
        for k in map.keys() {
            if HOP_BY_HOP.contains(&k.to_ascii_lowercase().as_str()) {
                ctx.error(
                    format!("{path}.{leaf}.{field}.{k}"),
                    "managed by the server — setting it here corrupts request/response framing",
                );
            }
        }
    }
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "transfer-encoding",
    "content-length",
    "te",
    "trailer",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
];

/// Cache checks shared by site defaults and routes.
fn check_route_cache(ctx: &mut Ctx, cfg: &Config, path: &str, cache: &RouteCache) {
    if !cache.enabled {
        let d = RouteCache::default();
        let nondefault_bypass = !cache.bypass.authenticated
            || !cache.bypass.methods.is_empty()
            || !cache.bypass.cookies.is_empty()
            || !cache.bypass.headers.is_empty()
            || !cache.bypass.paths.is_empty();
        if !cache.store.is_empty()
            || cache.ttl.is_some()
            || cache.stale_while_revalidate.is_some()
            || cache.stale_if_error.is_some()
            || cache.negative_ttl != d.negative_ttl
            || !cache.vary_headers.is_empty()
            || !cache.x_cache
            || nondefault_bypass
        {
            ctx.warn(
                format!("{path}.cache"),
                "settings are ignored — cache.enabled = false",
            );
        }
        return;
    }
    if !cfg.cache.contains_key(&cache.store) {
        let suggestion = name_hint(&cache.store, cfg.cache.keys());
        ctx.error(
            format!("{path}.cache.store"),
            format!(
                "unknown cache store {:?}{suggestion}; define [cache.{}]",
                cache.store, cache.store
            ),
        );
    }
    // bypass entries are matched verbatim — typos are silently dead
    for m in &cache.bypass.methods {
        check_method(ctx, format!("{path}.cache.bypass.methods"), m, false);
    }
    for h in &cache.bypass.headers {
        if http::HeaderName::from_bytes(h.as_bytes()).is_err() {
            ctx.error(
                format!("{path}.cache.bypass.headers"),
                format!("invalid header name {h:?}"),
            );
        }
    }
    for c in &cache.bypass.cookies {
        if c.chars()
            .any(|ch| ch.is_whitespace() || ch.is_control() || matches!(ch, ',' | ';' | '='))
        {
            ctx.warn(
                format!("{path}.cache.bypass.cookies"),
                format!("{c:?} can never match a cookie name"),
            );
        }
    }
    if cache.ttl.is_some_and(|t| t.is_zero()) {
        ctx.warn(
            format!("{path}.cache.ttl"),
            "ttl = 0s expires responses instantly — nothing is ever served from cache",
        );
    }
    for h in &cache.vary_headers {
        if http::HeaderName::from_bytes(h.as_bytes()).is_err() {
            ctx.error(
                format!("{path}.cache.vary_headers"),
                format!("invalid header name {h:?}"),
            );
        }
    }
}

/// Compression checks shared by site defaults and routes.
fn check_compress(ctx: &mut Ctx, path: &str, comp: &CompressConfig) {
    if !comp.enabled {
        // `compress = false` always carries the default algorithm list,
        // so only non-default extras are flagged.
        if comp.level.is_some() || comp.algorithms != CompressConfig::default().algorithms {
            ctx.warn(
                format!("{path}.compress"),
                "settings are ignored — compress.enabled = false",
            );
        }
        return;
    }
    for alg in &comp.algorithms {
        if !["br", "zstd", "gzip"].contains(&alg.as_str()) {
            ctx.error(
                format!("{path}.compress.algorithms"),
                format!("unknown algorithm {alg:?}; use br, zstd, or gzip"),
            );
        }
    }
    if comp.types.is_empty() {
        ctx.warn(
            format!("{path}.compress.types"),
            "types is empty — nothing is compressed; use compress = false to disable",
        );
    }
    for t in &comp.types {
        // `type/subtype` or `type/*` — anything else can never equal a
        // Content-Type value
        let ok = t
            .split_once('/')
            .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty() && !b.contains('/'));
        if !ok {
            ctx.warn(
                format!("{path}.compress.types"),
                format!("{t:?} is not a type/subtype — it can never match a Content-Type"),
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

fn check_patterns(ctx: &mut Ctx, path: &str, kind: &str, pats: &BTreeMap<String, String>) {
    for (k, v) in pats {
        if let Some(pat) = v.strip_prefix("re:")
            && let Err(e) = Regex::new(pat)
        {
            ctx.error(format!("{path}.{kind}.{k}"), format!("invalid regex: {e}"));
        }
    }
}

/// Suggest defined names for an unknown named reference — the closest
/// within edit distance 2, else the full list so the fix is visible.
fn name_hint<'a>(typo: &str, defined: impl Iterator<Item = &'a String>) -> String {
    let names: Vec<&String> = defined.collect();
    if names.is_empty() {
        return String::new();
    }
    let typo_lc = typo.to_lowercase();
    if let Some((d, n)) = names
        .iter()
        .map(|n| (crate::config::levenshtein(&typo_lc, &n.to_lowercase()), *n))
        .min_by_key(|(d, _)| *d)
        && d <= 2
    {
        return format!("; did you mean {n:?}?");
    }
    let list: Vec<String> = names.iter().map(|n| format!("{n:?}")).collect();
    format!("; defined: {}", list.join(", "))
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
                let suggestion = name_hint(name, cfg.upstream.keys());
                ctx.error(
                    path.to_string(),
                    format!(
                        "unknown upstream {name:?}{suggestion}; define [upstream.{name}] {hint}"
                    ),
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

/// Shared redirect checks — `path` is the owning route or site; field
/// paths are `{path}.redirect.*`.
fn check_redirect(ctx: &mut Ctx, path: &str, redir: &RedirectHandler) {
    let targets = [
        redir.to.is_some(),
        redir.host.is_some(),
        redir.scheme.is_some(),
    ]
    .into_iter()
    .filter(|b| *b)
    .count();
    if targets != 1 {
        ctx.error(
            path.to_owned(),
            "redirect sets exactly one of to/host/scheme",
        );
    }
    if ![301, 302, 303, 307, 308].contains(&redir.status) {
        ctx.error(
            path.to_owned(),
            format!(
                "redirect status {} must be 301, 302, 303, 307, or 308",
                redir.status
            ),
        );
    }
    if let Some(scheme) = &redir.scheme
        && scheme != "http"
        && scheme != "https"
    {
        ctx.error(
            path.to_owned(),
            format!("redirect scheme {scheme:?} must be http or https"),
        );
    }
    if let Some(h) = &redir.host {
        check_host_target(ctx, format!("{path}.redirect.host"), h, "");
    }
    if let Some(to) = &redir.to {
        check_placeholder_tokens(ctx, &format!("{path}.redirect.to"), to);
        // audit the literal parts — placeholders become their values
        // at request time, so stub them first. Spaces parse as
        // header values but break Location semantically.
        let stubbed = placeholder_re().replace_all(to, "x");
        if stubbed.chars().any(|c| c.is_whitespace() || c.is_control()) {
            ctx.error(
                format!("{path}.redirect.to"),
                format!(
                    "{to:?} contains whitespace or control characters — Location would be broken"
                ),
            );
        } else if !(to.starts_with('/') || to.starts_with('{') || to.contains("://")) {
            ctx.warn(
                format!("{path}.redirect.to"),
                format!(
                    "{to:?} has no scheme and does not start with '/' — it emits a relative-path redirect; use \"https://{to}\" for a URL or {{ host = {to:?} }} for a host redirect"
                ),
            );
        }
    }
}

/// Shared respond checks — `path` is the owning route or site; field
/// paths are `{path}.respond.*`.
/// Status/body legality — 1xx is an interim status (never a final
/// response), and 204/304 must not carry a body; a configured body is
/// silently dropped at serve time, so flag it.
fn check_status_body_rules(ctx: &mut Ctx, path: String, status: u16, has_body: bool) {
    if (100..200).contains(&status) {
        ctx.error(
            path.clone(),
            "1xx is an interim status, not a final response",
        );
    }
    if has_body && matches!(status, 204 | 304) {
        ctx.warn(path, "the body is ignored — 204/304 forbid a response body");
    }
}

fn check_respond(ctx: &mut Ctx, path: &str, resp: &RespondHandler) {
    check_placeholder_tokens(ctx, &format!("{path}.respond.body"), &resp.body);
    if !(100..=599).contains(&resp.status) {
        ctx.error(
            path.to_owned(),
            format!("respond status {} is not a valid HTTP status", resp.status),
        );
    }
    check_status_body_rules(
        ctx,
        format!("{path}.respond"),
        resp.status,
        !resp.body.is_empty(),
    );
    // framing/hop-by-hop headers are managed by the server — a manual
    // value appends next to the computed one and corrupts framing
    for k in resp.headers.keys() {
        if [
            "content-length",
            "transfer-encoding",
            "connection",
            "keep-alive",
            "upgrade",
        ]
        .contains(&k.to_ascii_lowercase().as_str())
        {
            ctx.error(
                format!("{path}.respond.headers.{k}"),
                "managed by the server — setting it here corrupts response framing",
            );
        }
    }
    // a redirect status with no Location won't redirect anywhere
    if matches!(resp.status, 301 | 302 | 303 | 307 | 308)
        && !resp
            .headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("location"))
    {
        ctx.warn(
            format!("{path}.respond"),
            format!(
                "{} without a `Location` header won't redirect — set respond.headers.location",
                resp.status
            ),
        );
    }
    // reflected-request placeholders + text/html = XSS by config
    let htmlish = resp.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("content-type") && v.to_ascii_lowercase().contains("text/html")
    });
    if htmlish
        && ["{path}", "{host}", "{query}", "{method}"]
            .iter()
            .any(|p| resp.body.contains(p))
    {
        ctx.warn(
            format!("{path}.respond"),
            "respond body substitutes request data under a text/html content-type — reflected content without escaping; use text/plain",
        );
    }
}

fn check_proxy(ctx: &mut Ctx, cfg: &Config, path: &str, proxy: &ProxyHandler) {
    check_proxy_retries(ctx, path, &proxy.retries);
    let custom = match &proxy.host_header {
        HostHeader::Custom(v) => Some((v, true)),
        HostHeader::Verbatim(v) => Some((v, false)),
        _ => None,
    };
    if let Some((v, warn_typos)) = custom {
        // must read like a host[:port] and survive as a header value
        check_host_target(
            ctx,
            format!("{path}.proxy.host_header"),
            v,
            ", \"upstream\", or \"original\"",
        );
        // a custom value is sent verbatim — a keyword typo silently does
        // the wrong thing (Verbatim is deliberate: `{ value = "…" }`)
        if warn_typos {
            for kw in ["upstream", "original"] {
                if crate::config::levenshtein(&v.to_lowercase(), kw) <= 2 {
                    ctx.warn(
                        format!("{path}.proxy.host_header"),
                        format!(
                            "{v:?} looks like a typo of the {kw:?} keyword — a custom value is sent verbatim"
                        ),
                    );
                    break;
                }
            }
        }
    }
    if let Some(ops) = &proxy.request_headers {
        check_header_ops(ctx, &format!("{path}.proxy"), "request_headers", ops);
    }
    if let Some(ops) = &proxy.request_headers
        && ops
            .set
            .keys()
            .chain(ops.add.keys())
            .any(|k| k.eq_ignore_ascii_case("host"))
    {
        ctx.warn(
            format!("{path}.proxy.request_headers"),
            "a `host` op here is applied after `host_header` and overrides it — prefer `proxy.host_header`",
        );
    }
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
        if let Some(pp) = &rw.replace_prefix {
            for (field, v) in [("from", &pp.from), ("to", &pp.to)] {
                if !v.starts_with('/') {
                    ctx.error(
                        format!("{path}.proxy.rewrite.replace_prefix.{field}"),
                        format!("{v:?} must start with '/' — paths always do"),
                    );
                }
            }
        }
    }
}

/// `enabled = false` opt-outs flag leftover settings that silently do
/// nothing — same contract as `admin.enabled = false`.
fn check_auth(ctx: &mut Ctx, path: &str, auth: &AuthConfig) {
    if !auth.enabled {
        if auth.basic.is_some() || auth.bearer.is_some() || auth.api_key.is_some() {
            ctx.warn(
                format!("{path}.auth"),
                "settings are ignored — auth.enabled = false",
            );
        }
        return;
    }
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
    if !rl.enabled {
        // opt-out marker: flag settings that silently do nothing — a
        // `key` equal to the default ("ip") counts as unset so a bare
        // `rate_limit = false` stays quiet
        if !(rl.key.is_empty() || rl.key == "ip")
            || rl.rate.is_some()
            || rl.burst.is_some()
            || !rl.exempt.is_empty()
            || rl.dry_run
        {
            ctx.warn(
                format!("{path}.rate_limit"),
                "settings are ignored — rate_limit.enabled = false",
            );
        }
        return;
    }
    if rl.key.is_empty() {
        ctx.error(
            format!("{path}.rate_limit.key"),
            "key is required — use ip, identity, route, or header:<Name>",
        );
    } else {
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
        } else if let Some(h) = rl.key.strip_prefix("header:")
            && http::HeaderName::from_bytes(h.as_bytes()).is_err()
        {
            ctx.error(
                format!("{path}.rate_limit.key"),
                format!("{h:?} is not a valid header name"),
            );
        }
    }
    check_catchall_nets(
        ctx,
        format!("{path}.rate_limit.exempt"),
        &rl.exempt,
        "a /0 CIDR exempts every client — rate limiting is effectively disabled",
    );
    match rl.rate {
        None => ctx.error(
            format!("{path}.rate_limit.rate"),
            "rate is required when rate limiting is enabled",
        ),
        Some(spec) if spec.permits == 0 => ctx.error(
            format!("{path}.rate_limit.rate"),
            "rate must be greater than zero",
        ),
        Some(_) => {}
    }
    if rl.burst == Some(0) {
        ctx.error(
            format!("{path}.rate_limit.burst"),
            "burst = 0 leaves no token capacity — every request is rejected",
        );
    }
}

fn check_cors(ctx: &mut Ctx, path: &str, cors: &CorsConfig) {
    if !cors.enabled {
        if !cors.origins.is_empty()
            || !cors.methods.is_empty()
            || !cors.headers.is_empty()
            || !cors.expose.is_empty()
            || cors.credentials
            || cors.max_age.is_some()
        {
            ctx.warn(
                format!("{path}.cors"),
                "settings are ignored — cors.enabled = false",
            );
        }
        return;
    }
    if cors.origins.is_empty() {
        ctx.warn(
            format!("{path}.cors"),
            "origins is empty — no cross-origin requests will be allowed",
        );
    }
    for origin in &cors.origins {
        if let Some(pat) = origin.strip_prefix("re:") {
            if let Err(e) = Regex::new(pat) {
                ctx.error(
                    format!("{path}.cors.origins"),
                    format!("invalid regex {origin:?}: {e}"),
                );
            }
        } else if origin != "*" && !origin.starts_with("*.") && !origin.contains("://") {
            // `Origin::Exact` compares the whole header value — a bare
            // hostname can never equal `scheme://host`
            ctx.error(
                format!("{path}.cors.origins"),
                format!(
                    "origin {origin:?} has no scheme — exact origins look like \"https://{origin}\" and never match an Origin header otherwise"
                ),
            );
        }
    }
    if cors.credentials && cors.origins.iter().any(|o| o == "*") {
        ctx.warn(
            format!("{path}.cors"),
            "credentials with wildcard origin is rejected by browsers; credentials are ignored for \"*\"",
        );
    }
    // methods/headers/expose are joined verbatim into ACA-* response
    // headers — a typo never matches and produces no diagnostic
    for m in &cors.methods {
        check_method(ctx, format!("{path}.cors.methods"), m, true);
    }
    for (field, names) in [("headers", &cors.headers), ("expose", &cors.expose)] {
        for h in names {
            if h != "*" && http::HeaderName::from_bytes(h.as_bytes()).is_err() {
                ctx.error(
                    format!("{path}.cors.{field}"),
                    format!("invalid header name {h:?}"),
                );
            }
        }
    }
    if cors.credentials && cors.expose.iter().any(|h| h == "*") {
        ctx.warn(
            format!("{path}.cors.expose"),
            "\"*\" in expose is treated literally (not as a wildcard) when credentials are enabled",
        );
    }
}

/// Names referenced by `site.proxy`/`route.proxy.upstream` — for the
/// unused-definition warning.
fn referenced_upstreams(cfg: &Config) -> HashSet<&str> {
    cfg.site
        .iter()
        .flat_map(|s| {
            s.proxy.iter().map(|p| &p.upstream).chain(
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
        for srv in &up.servers {
            if !seen_urls.insert(&srv.url) {
                ctx.warn(
                    format!("{path}.servers"),
                    format!("duplicate server URL {:?}", srv.url),
                );
            }
            if srv.weight == 0 {
                ctx.error(format!("{path}.servers"), "server weight must be >= 1");
            }
            check_upstream_url(ctx, &path, &srv.url);
        }
        if up.servers.iter().all(|s| s.backup) && !up.servers.is_empty() {
            ctx.warn(
                format!("{path}.servers"),
                "every server is a backup — no primary receives traffic while any backup is healthy",
            );
        }
        if !up.tls.verify && up.servers.iter().any(|u| u.url.starts_with("https://")) {
            ctx.warn(
                format!("{path}.tls.verify"),
                "tls.verify = false disables upstream certificate verification — traffic to this upstream is MITM-able; prefer a custom ca or sni override",
            );
        }
        if up.tls != crate::config::model::UpstreamTls::default()
            && !up.servers.iter().any(|u| u.url.starts_with("https://"))
        {
            ctx.warn(
                format!("{path}.tls"),
                "tls settings are ignored — no https:// server in this upstream",
            );
        }
        if !up.tls.verify && up.tls.ca.is_some() {
            ctx.warn(
                format!("{path}.tls.ca"),
                "tls.ca is ignored — verify = false skips certificate verification entirely",
            );
        }
        // unlike server timeouts, a 0s upstream timeout doesn't disable
        // anything — tokio times out instantly, killing every request
        for (field, d) in [
            ("connect", up.timeouts.connect),
            ("response_header", up.timeouts.response_header),
        ] {
            if d.is_zero() {
                ctx.error(
                    format!("{path}.timeouts.{field}"),
                    "0s times out instantly — every upstream request fails",
                );
            }
        }
        if up.timeouts.idle.is_zero() {
            ctx.warn(
                format!("{path}.timeouts.idle"),
                "0s retires pooled connections immediately — every request opens a fresh connection",
            );
        }
        if let Some(sni) = &up.tls.sni
            && sni.parse::<std::net::IpAddr>().is_err()
            && !looks_like_dns_name(sni)
        {
            ctx.error(
                format!("{path}.tls.sni"),
                format!("{sni:?} is not a valid DNS name or IP address"),
            );
        }
        if let Some(ca) = &up.tls.ca
            && !ca.is_file()
        {
            ctx.warn(
                format!("{path}.tls.ca"),
                format!("CA bundle {} does not exist", ca.display()),
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
        check_status_body_rules(
            ctx,
            format!("{path}.unavailable.status"),
            up.unavailable.status,
            up.unavailable.body.is_some(),
        );
        if let Some(b) = &up.unavailable.body {
            check_placeholder_tokens(ctx, &format!("{path}.unavailable.body"), b);
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

/// Upstream URLs are authority-only — the same parse the cluster
/// builder runs, surfaced here so the diagnostic carries a config path.
/// The scheme/host pre-check keeps the precise messages the URI parser
/// doesn't produce ("http://" is just "empty string" to it).
fn check_upstream_url(ctx: &mut Ctx, path: &str, url: &str) {
    match url.split_once("://") {
        Some(("http" | "https" | "h2c", rest)) => {
            if rest
                .split(['/', '?', '@'])
                .next()
                .unwrap_or_default()
                .is_empty()
            {
                ctx.error(
                    path.to_string(),
                    format!("upstream URL {url:?} has no host"),
                );
                return;
            }
        }
        _ => {
            ctx.error(
                path.to_string(),
                format!("upstream URL {url:?} must have scheme http, https, or h2c"),
            );
            return;
        }
    }
    if let Err(e) = crate::proxy::cluster::UpstreamUrl::parse(url) {
        ctx.error(path.to_string(), e);
    }
}

fn check_caches(ctx: &mut Ctx, cfg: &Config) {
    let used: HashSet<&str> = cfg
        .site
        .iter()
        .flat_map(|s| {
            s.route
                .iter()
                .filter_map(|r| r.cache.as_ref().map(|c| c.store.as_str()))
                .chain(s.cache.as_ref().map(|c| c.store.as_str()))
        })
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
                } else if let Err(e) = crate::cache::disk::Disk::check_path(store) {
                    ctx.error(format!("{path}.disk_path"), e);
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
        if store.max_items == 0 {
            ctx.error(path.clone(), "max_items = 0 caches nothing");
        }
    }
}

fn check_admin(ctx: &mut Ctx, cfg: &Config) {
    let a = &cfg.admin;
    if !a.enabled {
        // The listener is never bound; flag settings that silently do
        // nothing so the config doesn't read as if it serves.
        for (field, set) in [
            ("token", a.token.is_some()),
            ("tls", a.tls.is_some()),
            (
                "listen",
                a.listen != crate::config::model::AdminConfig::default().listen,
            ),
        ] {
            if set {
                ctx.warn(
                    format!("admin.{field}"),
                    format!("admin.{field} is ignored — admin.enabled = false"),
                );
            }
        }
        return;
    }
    if a.listen.is_empty() {
        ctx.error(
            "admin.listen",
            "admin.listen = [] binds no listener — remove the key or set admin.enabled = false",
        );
    }
    let mut seen = HashSet::new();
    for (i, l) in a.listen.iter().enumerate() {
        if !seen.insert(*l) {
            ctx.error(
                format!("admin.listen[{i}]"),
                format!("duplicate listen address {l}"),
            );
        }
        if cfg.server.listen.iter().any(|sl| sl.addr == *l) {
            ctx.error(
                format!("admin.listen[{i}]"),
                format!("{l} is also in server.listen — the bind will fail"),
            );
        }
    }
    if a.listen.iter().any(|l| !l.ip().is_loopback()) {
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
    if let Some(crate::config::model::AdminTls::Manual(m)) = &a.tls {
        for (field, p) in [("cert", &m.cert), ("key", &m.key)] {
            if !p.is_file() {
                ctx.warn(
                    format!("admin.tls.{field}"),
                    format!("file {} does not exist", p.display()),
                );
            }
        }
    }
    if !a.listen.is_empty() && a.listen.iter().all(|l| l.ip().is_loopback()) && a.token.is_none() {
        ctx.warn(
            "admin.token",
            "admin listener has no token — requests are restricted to loopback Host headers, but any local process can still manage the server; set admin.token",
        );
    }
}

fn check_acme(ctx: &mut Ctx, cfg: &Config) {
    let acme = &cfg.acme;
    // [acme] only activates through site.tls = "auto" — a configured
    // block with no such site silently does nothing
    if *acme != crate::config::model::AcmeConfig::default()
        && !cfg.site.iter().any(|s| {
            matches!(
                s.tls,
                crate::config::model::SiteTls::Mode(crate::config::model::TlsMode::Auto)
            )
        })
    {
        ctx.warn("acme", "settings are ignored — no site uses tls = \"auto\"");
    }
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
    for h in &od.allowed_hosts {
        if h == "*"
            || h.contains("://")
            || h.contains('/')
            || h.chars().any(char::is_whitespace)
            || (h.starts_with('*') && !h.starts_with("*."))
        {
            ctx.error(
                "acme.on_demand.allowed_hosts",
                format!("invalid allowlist entry {h:?} — use hostnames or \"*.suffix\" patterns"),
            );
        } else if let Some(suffix) = h.strip_prefix("*.")
            && !suffix.contains('.')
        {
            // `*.x` where x is a single label covers e.g. every `a.com`
            // — the exact abuse the allowlist exists to prevent
            ctx.warn(
                "acme.on_demand.allowed_hosts",
                format!(
                    "{h:?} covers the entire {suffix:?} suffix — any `a.{suffix}` can trigger issuance; use a narrower suffix"
                ),
            );
        }
    }
    if !od.enabled && (!od.allowed_hosts.is_empty() || od.rate.is_some()) {
        ctx.warn(
            "acme.on_demand",
            "settings are ignored — acme.on_demand.enabled = false",
        );
    }
    if let Some(cr) = &acme.ca_roots
        && !cr.is_file()
    {
        ctx.warn(
            "acme.ca_roots",
            format!("CA bundle {} does not exist", cr.display()),
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
    if t.body_read.is_zero() {
        ctx.warn(
            "timeouts.body_read",
            "0s disables the request body read timeout — slow uploads can pin connections",
        );
    }
    if t.idle.is_zero() {
        ctx.warn(
            "timeouts.idle",
            "0s closes connections after each request — keep-alive never applies",
        );
    }
    // request_deadline = 0s is deliberate (SSE/WebSocket/long-polling)
    // — documented, not warned
}

/// `0s`/`0B` overrides carry the same meanings as the global keys —
/// a route opting out of inherited timeouts still opts into the risk.
fn check_overrides(
    ctx: &mut Ctx,
    path: &str,
    t: &Option<TimeoutOverrides>,
    l: &Option<LimitOverrides>,
) {
    if let Some(t) = t {
        for (name, v, msg) in [
            (
                "header_read",
                t.header_read,
                "disables the header read timeout — vulnerable to slowloris",
            ),
            (
                "body_read",
                t.body_read,
                "disables the request body read timeout — slow uploads can pin connections",
            ),
            (
                "idle",
                t.idle,
                "closes connections after each request — keep-alive never applies",
            ),
            (
                "send",
                t.send,
                "disables the send inactivity timeout — stalled clients can pin connections",
            ),
        ] {
            if v.is_some_and(|d| d.is_zero()) {
                ctx.warn(format!("{path}.timeouts.{name}"), format!("0s {msg}"));
            }
        }
    }
    if let Some(l) = l {
        if l.header_bytes.is_some_and(|b| b.0 == 0) {
            ctx.error(
                format!("{path}.limits.header_bytes"),
                "0B rejects every request — headers can't be read",
            );
        }
        if l.body_bytes.is_some_and(|b| b.0 == 0) {
            ctx.warn(
                format!("{path}.limits.body_bytes"),
                "0B rejects every request with a body",
            );
        }
    }
}

fn check_log(ctx: &mut Ctx, cfg: &Config) {
    let a = &cfg.log.access;
    if !a.enabled {
        let d = AccessLog::default();
        let set = [
            ("format", a.format != d.format),
            ("output", a.output != d.output),
            ("filter", a.filter.is_some()),
            ("sample", a.sample != d.sample),
        ];
        for (field, set) in set {
            if set {
                ctx.warn(
                    format!("log.access.{field}"),
                    "settings are ignored — log.access.enabled = false",
                );
            }
        }
    }
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
    if let Some(f) = &cfg.log.access.filter
        && let Err(e) = crate::observe::Filter::parse(f)
    {
        ctx.error("log.access.filter", format!("invalid filter {f:?}: {e}"));
    }
    // outputs open at startup — a missing parent dir fails with a bare
    // io error; flag it at validate time instead
    for (path, out) in [
        ("log.output", cfg.log.output.as_str()),
        ("log.access.output", cfg.log.access.output.as_str()),
    ] {
        let access = path == "log.access.output";
        // "off" is a literal filename to both sinks — a plausible
        // misread of the real off-switches (`enabled = false` for the
        // access log, `log.level = "off"` for the server log). `""`
        // means stdout for the access log but a broken path upstream.
        if out == "off" && (!access || a.enabled) {
            ctx.warn(
                path,
                if access {
                    "output = \"off\" opens a file named `off` — use enabled = false to disable access logging"
                } else {
                    "output = \"off\" opens a file named `off` — use log.level = \"off\" to silence logging"
                },
            );
            continue;
        }
        if out.is_empty() && !access {
            ctx.error(
                path,
                "log.output is empty — use \"stdout\", \"stderr\", or a file path",
            );
            continue;
        }
        if (access && !a.enabled) || matches!(out, "stdout" | "stderr" | "") {
            continue;
        }
        if let Err(e) = crate::observe::check_log_path(out) {
            ctx.error(path, e);
            continue;
        }
        let parent = std::path::Path::new(out).parent();
        if let Some(d) = parent
            && !d.as_os_str().is_empty()
            && !d.is_dir()
        {
            ctx.warn(
                path,
                format!(
                    "log directory {} does not exist — startup will fail to open the file",
                    d.display()
                ),
            );
        }
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
    fn host_header_custom_validated() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/"
[site.route.proxy]
upstream = "http://u:1"
host_header = "http://bad/host"
"#,
        );
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0].proxy.host_header",
            "not a valid Host"
        ));

        // a plain host[:port] is fine
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/"
[site.route.proxy]
upstream = "http://u:1"
host_header = "api.internal:8443"
"#,
        );
        assert!(!has_err(&cfg, "site[\"x\"].route[0].proxy.host_header", ""));
    }

    #[test]
    fn request_headers_host_op_warns() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/"
[site.route.proxy]
upstream = "http://u:1"
host_header = "api.internal"
[site.route.proxy.request_headers]
set = { host = "other.internal" }
"#,
        );
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[0].proxy.request_headers",
            "overrides"
        ));
    }

    #[test]
    fn redirect_status_checked() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/old"
redirect = { scheme = "https", status = 300 }
"#,
        );
        assert!(
            errors(&cfg)
                .iter()
                .any(|d| d.message.contains("301, 302, 303, 307, or 308"))
        );
        // 303 (post/redirect/get) is accepted
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/old"
redirect = { scheme = "https", status = 303 }
"#,
        );
        assert!(!has_err(&cfg, "site[\"x\"].route[0].redirect", ""));
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
            source: None,
        };
        assert_eq!(d.to_string(), "error: site[0]: boom");
        let w = Diagnostic {
            severity: Severity::Warning,
            path: "x".into(),
            message: "y".into(),
            source: Some(std::path::PathBuf::from("/tmp/frag.toml")),
        };
        assert_eq!(w.to_string(), "warning: x: y (in /tmp/frag.toml)");
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
    fn site_defaults_validate_with_site_paths() {
        // site-level blocks get the same checks as routes, labelled at
        // the site path
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
cors = { origins = ["*"], credentials = true }
rate_limit = { key = "bogus", rate = "10/s" }
cache = { store = "nope" }
[[site.route]]
prefix = "/"
respond = { status = 200 }
"#,
        );
        assert!(has_warn(&cfg, "site[\"x\"].cors", "wildcard origin"));
        assert!(
            errors(&cfg)
                .iter()
                .any(|d| d.path == "site[\"x\"].rate_limit.key" && d.message.contains("bogus"))
        );
        assert!(
            errors(&cfg)
                .iter()
                .any(|d| d.path == "site[\"x\"].cache.store"
                    && d.message.contains("unknown cache store"))
        );

        // identity keying at site level without site auth warns once
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
rate_limit = { key = "identity", rate = "10/s" }
[[site.route]]
prefix = "/"
respond = { status = 200 }
"#,
        );
        assert!(has_warn(&cfg, "site[\"x\"].rate_limit.key", "no auth"));
        assert!(!has_warn(&cfg, "site[\"x\"].route[0].rate_limit.key", ""));
    }

    #[test]
    fn disabled_middleware_warns_on_dead_settings() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/"
respond = { status = 200 }
auth = { enabled = false, bearer = { tokens = ["t"] } }
cors = { enabled = false, origins = ["*"] }
rate_limit = { enabled = false, rate = "10/s" }
response_headers = { enabled = false, set = { x-a = "1" } }
"#,
        );
        for (field, present) in [
            ("auth", "bearer"),
            ("cors", "origins"),
            ("rate_limit", "rate"),
            ("response_headers", "set"),
        ] {
            assert!(
                has_warn(
                    &cfg,
                    &format!("site[\"x\"].route[0].{field}"),
                    "enabled = false"
                ),
                "expected dead-config warning for {field} ({present} set)"
            );
        }
        // pure opt-outs stay quiet
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/"
respond = { status = 200 }
auth = { enabled = false }
compress = false
cache = false
"#,
        );
        assert!(
            warnings(&cfg)
                .iter()
                .all(|d| !d.message.contains("enabled = false"))
        );
    }

    #[test]
    fn site_auth_satisfies_route_identity_key() {
        let cfg = parse_test_config(
            r#"
[[site]]
hosts = ["x"]
auth = { bearer = { tokens = ["t"] } }
[[site.route]]
prefix = "/"
respond = { status = 200 }
rate_limit = { key = "identity", rate = "10/s" }
"#,
        );
        assert!(!has_warn(&cfg, "site[\"x\"].route[0].rate_limit.key", ""));
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
            "neither the route nor its site has auth"
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

        // weight 0 rejected; all-backup cluster warned
        let cfg = parse_test_config(
            r#"
[upstream.w]
servers = [{ url = "http://x", weight = 0 }]
[upstream.b]
servers = [{ url = "http://x", backup = true }]
"#,
        );
        assert!(has_err(&cfg, "upstream.w.servers", "weight must be >= 1"));
        assert!(has_warn(
            &cfg,
            "upstream.b.servers",
            "every server is a backup"
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

    fn site_route(body: &str) -> String {
        format!("[[site]]\nhosts = \"x\"\ntls = \"off\"\n[[site.route]]\nprefix = \"/\"\n{body}\n")
    }

    #[test]
    fn redirect_targets_validated() {
        // a host value that can't survive as a Location is an error
        let cfg = parse_test_config(&site_route("redirect = { host = \"exa mple.com\" }"));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0].redirect.host",
            "not a valid Host"
        ));
        let cfg = parse_test_config(&site_route("redirect = { host = \"https://x.com\" }"));
        assert!(has_err(&cfg, "site[\"x\"].route[0].redirect.host", ""));
        let cfg = parse_test_config(&site_route("redirect = { host = \"api.internal:8443\" }"));
        assert!(!has_err(&cfg, "site[\"x\"].route[0].redirect.host", ""));

        // redirect_host on the site follows the same rule
        let cfg = parse_test_config(
            "[[site]]\nhosts = \"x\"\ntls = \"off\"\nredirect_host = \"bad host\"\nroot = \"/tmp\"",
        );
        assert!(has_err(
            &cfg,
            "site[\"x\"].redirect_host",
            "not a valid Host"
        ));

        // `to` without scheme or leading slash looks like a host — warn
        let cfg = parse_test_config(&site_route("redirect = { to = \"example.com\" }"));
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[0].redirect.to",
            "relative-path"
        ));
        let cfg = parse_test_config(&site_route("redirect = { to = \"/new{path}\" }"));
        assert!(!has_warn(&cfg, "site[\"x\"].route[0].redirect.to", ""));
        // whitespace in the literal template is an error — spaces
        // survive as header values but break Location semantically
        let cfg = parse_test_config(&site_route("redirect = { to = \"https://x.com/sp ace\" }"));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0].redirect.to",
            "whitespace"
        ));
    }

    #[test]
    fn unknown_placeholders_warn() {
        let cfg = parse_test_config(&site_route("redirect = { to = \"https://x.com{pah}\" }"));
        assert!(has_warn(&cfg, "site[\"x\"].route[0].redirect.to", "{pah}"));
        let cfg = parse_test_config(&site_route(
            "respond = { status = 200, body = \"ip is {ipadress}\" }",
        ));
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[0].respond.body",
            "{ipadress}"
        ));
        // known placeholders and non-token braces stay quiet
        let cfg = parse_test_config(&site_route(
            "respond = { status = 200, body = \"{\\\"ok\\\": true} {path}{host}{query}{method}{scheme}\" }",
        ));
        assert!(!has_warn(&cfg, "site[\"x\"].route[0].respond.body", ""));
    }

    #[test]
    fn replace_prefix_needs_slashes() {
        let cfg = parse_test_config(&site_route(
            "[site.route.proxy]\nupstream = \"http://x:1\"\n[site.route.proxy.rewrite]\nreplace_prefix = { from = \"api\", to = \"/v1\" }",
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0].proxy.rewrite.replace_prefix.from",
            "'/'"
        ));
    }

    #[test]
    fn security_header_tokens_validated() {
        let cfg = parse_test_config("[server.security]\nframe_options = \"ALLOWALL\"");
        assert!(has_err(
            &cfg,
            "server.security.frame_options",
            "DENY or SAMEORIGIN"
        ));
        let cfg = parse_test_config("[server.security]\nreferrer_policy = \"sometimes\"");
        assert!(has_err(
            &cfg,
            "server.security.referrer_policy",
            "Referrer-Policy"
        ));
        let cfg = parse_test_config("[server.security]\ncross_domain_policy = \"maybe\"");
        assert!(has_err(&cfg, "server.security.cross_domain_policy", ""));
        let cfg = parse_test_config(
            "[server.security]\nframe_options = \"sameorigin\"\nreferrer_policy = \"unsafe-url\"\ncross_domain_policy = \"all\"\ncsp = \"default-src 'self'\"",
        );
        assert!(errors(&cfg).is_empty(), "{:?}", errors(&cfg));
        // route overrides take the same tokens
        let cfg = parse_test_config(&site_route(
            "respond = { status = 200 }\n[site.route.security]\nframe_options = \"BANANA\"",
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0].security.frame_options",
            ""
        ));
    }

    #[test]
    fn server_header_value_checked() {
        // `\n` escapes to a real newline inside the TOML string —
        // control chars are the only thing HeaderValue rejects
        let cfg = parse_test_config("[server]\nserver_header = \"verd\\n1.0\"");
        assert!(has_err(&cfg, "server.server_header", "header value"));
        let cfg = parse_test_config("[server]\nserver_header = \"off\"");
        assert!(!has_err(&cfg, "server.server_header", ""));
        let cfg = parse_test_config("[server]\nserver_header = \"verd 1.0\"");
        assert!(!has_err(&cfg, "server.server_header", ""));
    }

    #[test]
    fn status_class_rules() {
        // 1xx is never a final response — error on respond+unavailable
        let cfg = parse_test_config(
            "[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\n[[site.route]]\nrespond = { status = 101 }",
        );
        assert!(has_err(&cfg, "site[\"x\"].route[0].respond", "interim"));
        let cfg =
            parse_test_config("[upstream.u]\nservers = \"x:1\"\nunavailable = { status = 100 }");
        assert!(has_err(&cfg, "upstream.u.unavailable.status", "interim"));

        // a redirect-class respond without Location won't redirect
        let cfg = parse_test_config(
            "[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\n[[site.route]]\nrespond = { status = 302 }",
        );
        assert!(has_warn(&cfg, "site[\"x\"].route[0].respond", "Location"));
        let cfg = parse_test_config(
            "[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\n[[site.route]]\nrespond = { status = 307, headers = { location = \"/x\" } }",
        );
        assert!(!has_warn(&cfg, "site[\"x\"].route[0].respond", "Location"));

        // a configured body under 204/304 is dropped at serve — warn
        let cfg = parse_test_config(
            "[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\n[[site.route]]\nrespond = { status = 204, body = \"x\" }",
        );
        assert!(has_warn(&cfg, "site[\"x\"].route[0].respond", "ignored"));
        let cfg = parse_test_config(
            "[upstream.u]\nservers = \"x:1\"\nunavailable = { status = 304, body = \"x\" }",
        );
        assert!(has_warn(&cfg, "upstream.u.unavailable.status", "ignored"));
        // defaults (502 + no body) stay quiet
        let cfg = parse_test_config("[upstream.u]\nservers = \"x:1\"");
        assert!(!has_warn(&cfg, "upstream.u.unavailable.status", "ignored"));
    }

    #[test]
    fn server_header_off_deprecated() {
        let cfg = parse_test_config("[server]\nserver_header = \"off\"");
        assert!(has_warn(&cfg, "server.server_header", "deprecated"));
        let cfg = parse_test_config("[server]\nserver_header = false");
        assert!(!has_warn(&cfg, "server.server_header", "deprecated"));
    }

    #[test]
    fn request_headers_disabled_warns_on_dead_settings() {
        let cfg = parse_test_config(
            "[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\n[[site.route]]\n[site.route.proxy]\nupstream = \"http://x:1\"\nrequest_headers = { enabled = false, set = { x-a = \"1\" } }",
        );
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[0].proxy.request_headers",
            "enabled = false"
        ));
        let cfg = parse_test_config(
            "[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\n[[site.route]]\n[site.route.proxy]\nupstream = \"http://x:1\"\nrequest_headers = false",
        );
        assert!(!has_warn(
            &cfg,
            "site[\"x\"].route[0].proxy.request_headers",
            "enabled = false"
        ));
    }

    #[test]
    fn admin_listen_list_rules() {
        let cfg = parse_test_config("[admin]\nlisten = []");
        assert!(has_err(&cfg, "admin.listen", "binds no listener"));
        // any non-loopback entry triggers the token requirement
        let cfg = parse_test_config("[admin]\nlisten = [\"127.0.0.1:2019\", \"0.0.0.0:2020\"]");
        assert!(has_err(&cfg, "admin.listen", "non-loopback"));
    }

    #[test]
    fn redirect_host_dead_when_no_https_upgrade() {
        // redirect_host only affects the http→https upgrade — dead
        // when the upgrade can't run
        let cfg = parse_test_config(
            "[[site]]\nhosts = [\"x\"]\ntls = \"off\"\nredirect_host = \"y\"\nroot = \"/tmp\"",
        );
        assert!(has_warn(&cfg, "site[\"x\"].redirect_host", "ignored"));
        let cfg = parse_test_config(
            "[[site]]\nhosts = [\"x\"]\nredirect_https = false\nredirect_host = \"y\"\nroot = \"/tmp\"",
        );
        assert!(has_warn(&cfg, "site[\"x\"].redirect_host", "ignored"));
    }

    #[test]
    fn access_log_disabled_warns_on_dead_settings() {
        let cfg = parse_test_config(
            "[log.access]\nenabled = false\noutput = \"/var/log/x\"\nfilter = \"status >= 500\"",
        );
        assert!(has_warn(&cfg, "log.access.output", "enabled = false"));
        assert!(has_warn(&cfg, "log.access.filter", "enabled = false"));
        let cfg = parse_test_config("[log]\naccess = false");
        assert!(
            warnings(&cfg)
                .iter()
                .all(|d| !d.path.starts_with("log.access."))
        );
    }

    #[test]
    fn reaudit_dead_config_rules() {
        // [acme] configured but no site uses tls = "auto"
        let cfg = parse_test_config(
            "[acme]\nemail = \"a@b.c\"\n[[site]]\nhosts = [\"x\"]\ntls = \"off\"\nroot = \"/tmp\"",
        );
        assert!(has_warn(&cfg, "acme", "no site uses tls"));
        // route ip_allow outside the site's allowlist can never pass
        let cfg = parse_test_config(
            "[[site]]\nhosts = [\"x\"]\nip_allow = \"10.0.0.0/8\"\n[[site.route]]\nrespond = 200\nip_allow = \"192.168.0.0/16\"",
        );
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[0].ip_allow",
            "can never admit"
        ));
        // admin.listen duplicates + server.listen collision error
        let cfg = parse_test_config(
            "[admin]\nlisten = [\"127.0.0.1:9\", \"127.0.0.1:9\"]\n[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"",
        );
        assert!(has_err(&cfg, "admin.listen[1]", "duplicate"));
        // upstream.tls on an all-http cluster is dead
        let cfg = parse_test_config(
            "[upstream.u]\nservers = \"http://x:1\"\n[upstream.u.tls]\nsni = \"x\"\n[[site]]\nhosts = [\"x\"]\nproxy = \"u\"",
        );
        assert!(has_warn(&cfg, "upstream.u.tls", "no https://"));
        // 0s upstream timeouts fail instantly; burst = 0 rejects all
        let cfg = parse_test_config(
            "[upstream.u]\nservers = \"http://x:1\"\n[upstream.u.timeouts]\nconnect = \"0s\"\n[[site]]\nhosts = [\"x\"]\nproxy = \"u\"\nrate_limit = { rate = \"10/s\", burst = 0 }",
        );
        assert!(has_err(&cfg, "upstream.u.timeouts.connect", "instantly"));
        assert!(has_err(
            &cfg,
            "site[\"x\"].rate_limit.burst",
            "token capacity"
        ));
        // log.output "off" is a filename; missing parent warns
        let cfg = parse_test_config(
            "[log]\noutput = \"off\"\n[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"",
        );
        assert!(has_warn(&cfg, "log.output", "file named `off`"));
        let cfg = parse_test_config(
            "[log]\noutput = \"/no/such/dir/x.log\"\n[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"",
        );
        assert!(has_warn(&cfg, "log.output", "does not exist"));
        // spa + empty index never fires; spa + listing precedence
        let cfg = parse_test_config(
            "[[site]]\nhosts = [\"x\"]\n[[site.route]]\n[site.route.static]\nroot = \"/tmp\"\nindex = []\nspa = true",
        );
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[0].static.spa",
            "never applies"
        ));
        // cache ttl = 0s caches nothing; max_items = 0 errors
        let cfg = parse_test_config(
            "[cache.c]\nmax_items = 0\n[[site]]\nhosts = [\"x\"]\n[[site.route]]\nrespond = 200\ncache = { store = \"c\", ttl = \"0s\" }",
        );
        assert!(has_err(&cfg, "cache.c", "caches nothing"));
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[0].cache.ttl",
            "nothing is ever served"
        ));
        // compress.types shape + empty
        let cfg = parse_test_config(
            "[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\ncompress = { types = [\"texthtml\"] }",
        );
        assert!(has_warn(&cfg, "site[\"x\"].compress.types", "type/subtype"));
        // 0s timeout overrides warn at scope
        let cfg = parse_test_config(
            "[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\n[site.timeouts]\nheader_read = \"0s\"\n[[site.route]]\nrespond = 200\n[site.route.limits]\nheader_bytes = \"0B\"",
        );
        assert!(has_warn(
            &cfg,
            "site[\"x\"].timeouts.header_read",
            "slowloris"
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0].limits.header_bytes",
            "rejects every request"
        ));
        // framing headers in respond.headers / header ops corrupt the wire
        let cfg = parse_test_config(
            "[[site]]\nhosts = [\"x\"]\n[[site.route]]\nrespond = { status = 204, headers = { content-length = \"10\" } }",
        );
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0].respond.headers.content-length",
            "framing"
        ));
        let cfg = parse_test_config(
            "[[site]]\nhosts = [\"x\"]\n[[site.route]]\nproxy = { upstream = \"http://x:1\", request_headers = { set = { connection = \"close\" } } }",
        );
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0].proxy.request_headers.set.connection",
            "framing"
        ));
    }

    #[test]
    fn new_placeholders_known() {
        // the expanded closed set doesn't trip the unknown-token warn
        let cfg = parse_test_config(
            "[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\n[[site.route]]\nrespond = \"{uri}|{args}|{remote_ip}|{request_id}\"",
        );
        assert!(
            !warnings(&cfg)
                .iter()
                .any(|d| d.message.contains("unknown placeholder"))
        );
        let cfg = parse_test_config(
            "[upstream.u]\nservers = \"x:1\"\nunavailable = { status = 503, body = \"down for {uri}\" }",
        );
        assert!(
            !warnings(&cfg)
                .iter()
                .any(|d| d.message.contains("unknown placeholder"))
        );
    }

    #[test]
    fn disk_path_checked() {
        // /dev/null is a file — no directory can be created beneath it
        let cfg = parse_test_config(
            "[cache.c]\ntier = \"disk\"\ndisk_path = \"/dev/null/x\"\ndisk_bytes = \"1k\"\nmax_object_bytes = \"1k\"",
        );
        assert!(has_err(&cfg, "cache.c.disk_path", ""));
    }

    #[test]
    fn upstream_sni_and_ca_checked() {
        let cfg = parse_test_config(
            "[upstream.u]\nservers = \"https://x:1\"\n[upstream.u.tls]\nsni = \"bad host\"",
        );
        assert!(has_err(&cfg, "upstream.u.tls.sni", ""));
        let cfg = parse_test_config(
            "[upstream.u]\nservers = \"https://x:1\"\n[upstream.u.tls]\nsni = \"api.internal\"",
        );
        assert!(!has_err(&cfg, "upstream.u.tls.sni", ""));
        let cfg = parse_test_config(
            "[upstream.u]\nservers = \"https://x:1\"\n[upstream.u.tls]\nca = \"/nonexistent/ca.pem\"",
        );
        assert!(has_warn(&cfg, "upstream.u.tls.ca", "does not exist"));
    }

    #[test]
    fn host_header_typo_warns() {
        let cfg = parse_test_config(&site_route(
            "[site.route.proxy]\nupstream = \"http://x:1\"\nhost_header = \"upsteam\"",
        ));
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[0].proxy.host_header",
            "typo"
        ));
        let cfg = parse_test_config(&site_route(
            "[site.route.proxy]\nupstream = \"http://x:1\"\nhost_header = \"api.internal\"",
        ));
        assert!(!has_warn(
            &cfg,
            "site[\"x\"].route[0].proxy.host_header",
            ""
        ));
    }

    #[test]
    fn rate_limit_header_key_validated() {
        let cfg = parse_test_config(&site_route(
            "respond = { status = 200 }\n[site.route.rate_limit]\nrate = \"10/s\"\nkey = \"header:x bad\"",
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0].rate_limit.key",
            "header name"
        ));
        let cfg = parse_test_config(&site_route(
            "respond = { status = 200 }\n[site.route.rate_limit]\nrate = \"10/s\"\nkey = \"header:x-tenant\"\nexempt = \"0.0.0.0/0\"",
        ));
        assert!(!has_err(&cfg, "site[\"x\"].route[0].rate_limit.key", ""));
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[0].rate_limit.exempt",
            "every client"
        ));
    }

    #[test]
    fn cache_bypass_entries_validated() {
        let cfg = parse_test_config(&format!(
            "[cache.c]\n{}",
            site_route(
                "[site.route.cache]\nstore = \"c\"\n[site.route.cache.bypass]\nmethods = [\"GTE\", \"B A D\"]\nheaders = [\"x bad\"]\ncookies = [\"bad;name\"]",
            )
        ));
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[0].cache.bypass.methods",
            "GTE"
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0].cache.bypass.methods",
            "B A D"
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0].cache.bypass.headers",
            "x bad"
        ));
        assert!(has_warn(
            &cfg,
            "site[\"x\"].route[0].cache.bypass.cookies",
            "bad;name"
        ));
    }

    #[test]
    fn cors_tokens_and_origins_validated() {
        let cfg = parse_test_config(&site_route(
            "respond = { status = 200 }\n[site.route.cors]\norigins = [\"app.example.com\"]",
        ));
        assert!(has_err(
            &cfg,
            "site[\"x\"].route[0].cors.origins",
            "no scheme"
        ));
        let cfg = parse_test_config(&site_route(
            "respond = { status = 200 }\n[site.route.cors]\norigins = [\"https://app.example.com\", \"*.staging.example.com\", \"*\", \"re:^https://a.*$\"]\nmethods = [\"GTE\", \"B A D\"]\nheaders = [\"content-type\"]\nexpose = [\"x bad\"]",
        ));
        assert!(!has_err(&cfg, "site[\"x\"].route[0].cors.origins", ""));
        assert!(has_warn(&cfg, "site[\"x\"].route[0].cors.methods", "GTE"));
        assert!(has_err(&cfg, "site[\"x\"].route[0].cors.methods", "B A D"));
        assert!(has_err(&cfg, "site[\"x\"].route[0].cors.expose", "x bad"));
    }

    #[test]
    fn site_name_duplicates_error() {
        let cfg = parse_test_config(
            "[[site]]\nname = \"api\"\nhosts = \"a.example\"\nroot = \"/tmp\"\n[[site]]\nname = \"api\"\nhosts = \"b.example\"\nroot = \"/tmp\"",
        );
        assert!(has_err(&cfg, "site[\"api\"]", "duplicate site name"));
    }

    #[test]
    fn catchall_cidrs_warn() {
        let cfg = parse_test_config("[server]\ntrusted_proxies = \"0.0.0.0/0\"");
        assert!(has_warn(&cfg, "server.trusted_proxies", "spoofable"));
        let cfg = parse_test_config(&site_route(
            "respond = { status = 200 }\nip_allow = \"0.0.0.0/0\"\nip_deny = \"::/0\"",
        ));
        assert!(has_warn(&cfg, "site[\"x\"].route[0].ip_allow", "no-op"));
        assert!(has_warn(&cfg, "site[\"x\"].route[0].ip_deny", "403"));
    }

    #[test]
    fn log_access_filter_checked() {
        let cfg = parse_test_config("[log.access]\nfilter = \"bogus = x\"");
        assert!(has_err(&cfg, "log.access.filter", ""));
        let cfg = parse_test_config(
            "[log.access]\nfilter = \"path != \\\"/healthz\\\" && status >= 500\"",
        );
        assert!(!has_err(&cfg, "log.access.filter", ""));
    }

    #[test]
    fn upstream_url_full_parse() {
        for (url, needle) in [
            ("http://h:1/path", "must not contain a path"),
            ("http://h:1?q=1", "must not contain a path"),
            ("http://u:p@h:1", "userinfo"),
            ("gopher://h", "scheme"),
        ] {
            let cfg = parse_test_config(&format!("[upstream.u]\nservers = \"{url}\""));
            assert!(has_err(&cfg, "upstream.u", needle), "{url}");
        }
    }

    #[test]
    fn on_demand_allowlist_checked() {
        let cfg = parse_test_config("[acme.on_demand]\nenabled = true\nallowed_hosts = [\"*\"]");
        assert!(has_err(
            &cfg,
            "acme.on_demand.allowed_hosts",
            "invalid allowlist"
        ));
        let cfg =
            parse_test_config("[acme.on_demand]\nenabled = true\nallowed_hosts = [\"*.com\"]");
        assert!(has_warn(&cfg, "acme.on_demand.allowed_hosts", "entire"));
        // disabled with leftovers → dead config
        let cfg =
            parse_test_config("[acme.on_demand]\nenabled = false\nallowed_hosts = [\"a.example\"]");
        assert!(has_warn(&cfg, "acme.on_demand", "ignored"));
        let cfg = parse_test_config("[acme]\nca_roots = \"/nonexistent/ca.pem\"");
        assert!(has_warn(&cfg, "acme.ca_roots", "does not exist"));
    }
}
