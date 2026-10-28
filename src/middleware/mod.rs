//! Per-route middleware, compiled once into a [`Middleware`] and executed in
//! a fixed order on every request:
//!
//! `ip_acl → cors-preflight → auth → rate_limit → cache → handler → security → cors → headers → compress`

pub mod auth;
pub mod compress;
pub mod cors;
pub mod ratelimit;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::{HeaderName, HeaderValue, StatusCode};

use crate::body::BoxBody;
use crate::cache::stage::RouteCacheMw;
use crate::config::model as cfg;
use crate::middleware::auth::Auth;
use crate::middleware::compress::Compress;
use crate::middleware::cors::Cors;
use crate::middleware::ratelimit::RateLimiter;

/// Compiled response-header manipulation (`set`/`add`/`remove`).
#[derive(Debug, Default)]
pub struct HeaderOps {
    /// Headers to set.
    pub set: Vec<(HeaderName, HeaderValue)>,
    /// Headers to append.
    pub add: Vec<(HeaderName, HeaderValue)>,
    /// Header names to strip.
    pub remove: Vec<HeaderName>,
}

impl HeaderOps {
    /// Compile from config. Invalid names/values are build errors.
    pub fn build(c: &cfg::HeaderOps) -> Result<Self, String> {
        let compile_map = |m: &std::collections::BTreeMap<String, String>| -> Result<Vec<(HeaderName, HeaderValue)>, String> {
            m.iter()
                .map(|(k, v)| {
                    let name = HeaderName::from_bytes(k.as_bytes())
                        .map_err(|_| format!("invalid header name {k:?}"))?;
                    let value = HeaderValue::from_str(v)
                        .map_err(|_| format!("invalid value for header {k}"))?;
                    Ok((name, value))
                })
                .collect()
        };
        Ok(Self {
            set: compile_map(&c.set)?,
            add: compile_map(&c.add)?,
            remove: c
                .remove
                .iter()
                .map(|k| {
                    HeaderName::from_bytes(k.as_bytes())
                        .map_err(|_| format!("invalid header name {k:?}"))
                })
                .collect::<Result<_, _>>()?,
        })
    }

    /// Apply to a response's headers.
    pub fn apply(&self, headers: &mut http::HeaderMap) {
        for name in &self.remove {
            headers.remove(name);
        }
        for (name, value) in &self.set {
            headers.insert(name.clone(), value.clone());
        }
        for (name, value) in &self.add {
            headers.append(name.clone(), value.clone());
        }
    }
}

/// Compiled security headers for a route: global defaults merged with the
/// route's overrides. `None` means disabled entirely.
#[derive(Debug)]
pub struct Security {
    /// Emit `Strict-Transport-Security` on TLS responses.
    pub hsts: bool,
    /// HSTS `max-age`.
    pub hsts_max_age: Duration,
    /// HSTS `includeSubDomains` flag.
    pub hsts_subdomains: bool,
    /// Emit `X-Content-Type-Options: nosniff`.
    pub content_type_options: bool,
    /// `X-Frame-Options` value; empty = no header.
    pub frame_options: String,
    /// `Referrer-Policy` value; empty = no header.
    pub referrer_policy: String,
    /// `Content-Security-Policy` value; empty = no header.
    pub csp: String,
    /// `X-Permitted-Cross-Domain-Policies` value; empty = no header.
    pub cross_domain_policy: String,
}

impl Security {
    /// Merge global defaults with site and route overrides, field-wise —
    /// a set field at a narrower scope wins. Returns `None` when the
    /// effective config is disabled.
    pub fn build(
        global: &cfg::SecurityConfig,
        site_o: Option<&cfg::RouteSecurity>,
        route_o: Option<&cfg::RouteSecurity>,
    ) -> Option<Self> {
        let enabled = route_o
            .and_then(|o| o.enabled)
            .or_else(|| site_o.and_then(|o| o.enabled))
            .unwrap_or(global.enabled);
        if !enabled {
            return None;
        }
        Some(Self {
            hsts: route_o
                .and_then(|o| o.hsts)
                .or_else(|| site_o.and_then(|o| o.hsts))
                .unwrap_or(global.hsts),
            hsts_max_age: route_o
                .and_then(|o| o.hsts_max_age)
                .or_else(|| site_o.and_then(|o| o.hsts_max_age))
                .unwrap_or(global.hsts_max_age),
            hsts_subdomains: route_o
                .and_then(|o| o.hsts_subdomains)
                .or_else(|| site_o.and_then(|o| o.hsts_subdomains))
                .unwrap_or(global.hsts_subdomains),
            content_type_options: route_o
                .and_then(|o| o.content_type_options)
                .or_else(|| site_o.and_then(|o| o.content_type_options))
                .unwrap_or(global.content_type_options),
            frame_options: route_o
                .and_then(|o| o.frame_options.clone())
                .or_else(|| site_o.and_then(|o| o.frame_options.clone()))
                .unwrap_or_else(|| global.frame_options.clone()),
            referrer_policy: route_o
                .and_then(|o| o.referrer_policy.clone())
                .or_else(|| site_o.and_then(|o| o.referrer_policy.clone()))
                .unwrap_or_else(|| global.referrer_policy.clone()),
            // `csp = ""` clears an inherited value.
            csp: route_o
                .and_then(|o| o.csp.clone())
                .or_else(|| site_o.and_then(|o| o.csp.clone()))
                .unwrap_or_else(|| global.csp.clone().unwrap_or_default()),
            cross_domain_policy: route_o
                .and_then(|o| o.cross_domain_policy.clone())
                .or_else(|| site_o.and_then(|o| o.cross_domain_policy.clone()))
                .unwrap_or_else(|| global.cross_domain_policy.clone()),
        })
    }

    /// Apply to a response's headers (insert-if-absent — a handler's own
    /// headers win; explicit per-route `headers` ops run afterwards and
    /// can still override).
    pub fn apply(&self, headers: &mut http::HeaderMap, tls: bool) {
        let insert = |h: &mut http::HeaderMap, name: http::header::HeaderName, value: String| {
            if !h.contains_key(&name)
                && let Ok(v) = HeaderValue::from_str(&value)
            {
                h.insert(name, v);
            }
        };
        if tls && self.hsts {
            let mut v = format!("max-age={}", self.hsts_max_age.as_secs());
            if self.hsts_subdomains {
                v.push_str("; includeSubDomains");
            }
            insert(headers, http::header::STRICT_TRANSPORT_SECURITY, v);
        }
        if self.content_type_options {
            insert(
                headers,
                http::header::X_CONTENT_TYPE_OPTIONS,
                "nosniff".to_string(),
            );
        }
        if !self.frame_options.is_empty() {
            insert(
                headers,
                http::header::X_FRAME_OPTIONS,
                self.frame_options.clone(),
            );
        }
        if !self.referrer_policy.is_empty() {
            insert(
                headers,
                http::header::REFERRER_POLICY,
                self.referrer_policy.clone(),
            );
        }
        if !self.csp.is_empty() {
            insert(
                headers,
                http::header::CONTENT_SECURITY_POLICY,
                self.csp.clone(),
            );
        }
        if !self.cross_domain_policy.is_empty() {
            insert(
                headers,
                http::header::HeaderName::from_static("x-permitted-cross-domain-policies"),
                self.cross_domain_policy.clone(),
            );
        }
    }
}

/// A route's compiled middleware chain.
pub struct Middleware {
    /// Allowed client CIDRs at site scope; empty = no site allowlist.
    /// Checked together with `ip_allow` — a route can never widen a
    /// site ACL.
    pub site_ip_allow: Vec<ipnet::IpNet>,
    /// Allowed client CIDRs at route scope; empty = no route allowlist.
    pub ip_allow: Vec<ipnet::IpNet>,
    /// Denied client CIDRs, union of site and route rules (evaluated
    /// before allows).
    pub ip_deny: Vec<ipnet::IpNet>,
    /// Authentication; runs before rate limiting so `identity` keys work.
    pub auth: Option<Auth>,
    /// CORS: preflight short-circuit + response decoration.
    pub cors: Option<Cors>,
    /// Rate limiter; shared with the runtime's idle-bucket sweeper.
    pub rate_limit: Option<Arc<RateLimiter>>,
    /// Response header ops applied after the handler.
    pub headers: Option<HeaderOps>,
    /// Baseline security headers; `None` = disabled for this route.
    pub security: Option<Security>,
    /// Response compression; runs last so it sees final headers.
    pub compress: Option<Compress>,
    /// Response cache; runs between rate limiting and the handler.
    pub cache: Option<RouteCacheMw>,
    /// The route's raw config — later middleware phases compile from it.
    pub cfg: cfg::RouteConfig,
}

impl Middleware {
    /// IP access check: deny rules first, then every non-empty allow
    /// list must pass — site ACLs can only tighten, never widen.
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), StatusCode> {
        if self.ip_deny.iter().any(|n| n.contains(&ip)) {
            return Err(StatusCode::FORBIDDEN);
        }
        for allow in [&self.site_ip_allow, &self.ip_allow] {
            if !allow.is_empty() && !allow.iter().any(|n| n.contains(&ip)) {
                return Err(StatusCode::FORBIDDEN);
            }
        }
        Ok(())
    }
}

/// Effective middleware config: a route's own block wins; an absent
/// route block inherits the site's. A present-but-`enabled = false`
/// block at either level means "off" — a route opt-out also suppresses
/// the site default.
fn effective<'a, T: HasEnabled>(route: &'a Option<T>, site: &'a Option<T>) -> Option<&'a T> {
    let c = route.as_ref().or(site.as_ref())?;
    c.is_enabled().then_some(c)
}

/// Middleware config types gated by an `enabled` flag.
trait HasEnabled {
    fn is_enabled(&self) -> bool;
}

macro_rules! has_enabled {
    ($($t:ty),* $(,)?) => {
        $(impl HasEnabled for $t {
            fn is_enabled(&self) -> bool { self.enabled }
        })*
    };
}

has_enabled!(
    cfg::AuthConfig,
    cfg::CorsConfig,
    cfg::RateLimitConfig,
    cfg::RouteCache,
    cfg::CompressConfig,
    cfg::HeaderOps,
);

/// Merge site and route `response_headers` configs: `set`/`add` maps
/// union with route keys winning; `remove` concatenates.
fn merge_header_ops(
    site: Option<&cfg::HeaderOps>,
    route: Option<&cfg::HeaderOps>,
) -> cfg::HeaderOps {
    let mut merged = cfg::HeaderOps::default();
    if let Some(s) = site {
        merged.set = s.set.clone();
        merged.add = s.add.clone();
        merged.remove = s.remove.clone();
    }
    if let Some(r) = route {
        merged
            .set
            .extend(r.set.iter().map(|(k, v)| (k.clone(), v.clone())));
        merged
            .add
            .extend(r.add.iter().map(|(k, v)| (k.clone(), v.clone())));
        merged.remove.extend(r.remove.iter().cloned());
    }
    merged
}

/// Builds per-route [`Middleware`] — constructed once per runtime so global
/// settings can be threaded into every route.
pub struct Factory {
    /// Global trusted proxies — routes inherit unless overridden.
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Global security-header defaults.
    pub security: cfg::SecurityConfig,
    /// All rate limiters built for this generation — the runtime sweeps
    /// their idle buckets periodically.
    limiters: Mutex<Vec<Arc<RateLimiter>>>,
    /// One shared limiter per site-level `rate_limit`, index-aligned
    /// with `config.site` — every route inheriting it shares buckets.
    site_limiters: Vec<Option<Arc<RateLimiter>>>,
    /// Named cache stores shared by routes.
    caches: std::collections::HashMap<String, Arc<crate::cache::Cache>>,
}

impl Factory {
    /// New factory from global config; builds the named cache stores.
    /// `prior` reuses unchanged stores across a reload so RAM contents and
    /// open disk indexes survive a config generation swap. `mode`
    /// [`crate::BuildMode::Check`] builds everything read-only (no cache dirs
    /// created) for `verd validate` dry runs.
    pub fn new(
        cfg: &cfg::Config,
        prior: Option<&Factory>,
        mode: crate::BuildMode,
    ) -> Result<Self, String> {
        let mut limiters = Vec::new();
        let mut site_limiters = Vec::with_capacity(cfg.site.len());
        for site in &cfg.site {
            match site.rate_limit.as_ref().filter(|rl| rl.enabled) {
                Some(rl) => {
                    let rl = Arc::new(RateLimiter::build_site(rl)?);
                    limiters.push(rl.clone());
                    site_limiters.push(Some(rl));
                }
                None => site_limiters.push(None),
            }
        }
        Ok(Self {
            trusted_proxies: cfg.server.trusted_proxies.clone(),
            security: cfg.server.security.clone(),
            limiters: Mutex::new(limiters),
            site_limiters,
            caches: crate::cache::Cache::build_all(cfg, prior.map(|p| p.caches()), mode)?,
        })
    }

    /// The named cache stores — for admin purge/introspection.
    pub fn caches(&self) -> &std::collections::HashMap<String, Arc<crate::cache::Cache>> {
        &self.caches
    }

    /// Compile a route's middleware. `site_idx` identifies `site` in
    /// `config.site` so an inherited `rate_limit` gets the site's
    /// shared limiter.
    pub fn build(
        &self,
        site_idx: usize,
        site: &cfg::SiteConfig,
        route: &cfg::RouteConfig,
    ) -> Result<Middleware, String> {
        // A disabled route block opts out of the site default too.
        let mut merged_ops = None;
        let headers = if route.response_headers.as_ref().is_some_and(|h| !h.enabled) {
            None
        } else {
            let site_h = site.response_headers.as_ref().filter(|h| h.enabled);
            match (site_h, route.response_headers.as_ref()) {
                (None, None) => None,
                (s, r) => {
                    let merged = merge_header_ops(s, r);
                    let built = HeaderOps::build(&merged)?;
                    merged_ops = Some(merged);
                    Some(built)
                }
            }
        };
        let auth = effective(&route.auth, &site.auth)
            .map(Auth::build)
            .transpose()?;
        let cors = effective(&route.cors, &site.cors)
            .map(Cors::build)
            .transpose()?;
        let rate_limit = match &route.rate_limit {
            Some(rl) if rl.enabled => {
                let rl = Arc::new(RateLimiter::build(rl)?);
                self.limiters
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(rl.clone());
                Some(rl)
            }
            Some(_) => None,
            None => self.site_limiters.get(site_idx).cloned().flatten(),
        };
        let compress = effective(&route.compress, &site.compress)
            .map(Compress::build)
            .transpose()?;
        let cache = effective(&route.cache, &site.cache)
            .map(|rc| -> Result<RouteCacheMw, String> {
                let store = self
                    .caches
                    .get(&rc.store)
                    .cloned()
                    .ok_or_else(|| format!("cache store {:?} not found", rc.store))?;
                Ok(RouteCacheMw {
                    store,
                    vary_headers: rc
                        .vary_headers
                        .iter()
                        .map(|v| v.to_ascii_lowercase())
                        .collect(),
                    cfg: rc.clone(),
                })
            })
            .transpose()?;
        // Materialize the effective middleware fields so `cfg` readers
        // see what actually applies to this route.
        let mut eff = route.clone();
        macro_rules! inherit {
            ($($f:ident),* $(,)?) => {
                $(if eff.$f.is_none() { eff.$f = site.$f.clone(); })*
            };
        }
        inherit!(auth, cors, rate_limit, cache, compress, response_headers);
        if let Some(merged) = merged_ops {
            eff.response_headers = Some(merged);
        }
        Ok(Middleware {
            site_ip_allow: site.ip_allow.clone(),
            ip_allow: route.ip_allow.clone(),
            ip_deny: site
                .ip_deny
                .iter()
                .chain(route.ip_deny.iter())
                .cloned()
                .collect(),
            auth,
            cors,
            rate_limit,
            headers,
            security: Security::build(
                &self.security,
                site.security.as_ref(),
                route.security.as_ref(),
            ),
            compress,
            cache,
            cfg: eff,
        })
    }

    /// Every rate limiter built this generation — for the idle-bucket
    /// sweep task.
    pub fn limiters(&self) -> Vec<Arc<RateLimiter>> {
        self.limiters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// Convenience: 403 response.
pub fn forbidden() -> http::Response<BoxBody> {
    let mut resp = http::Response::new(crate::body::empty());
    *resp.status_mut() = StatusCode::FORBIDDEN;
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn header_ops_set_add_remove_and_errors() {
        let c = cfg::HeaderOps {
            set: vec![("x-a".into(), "1".into())].into_iter().collect(),
            add: vec![("x-b".into(), "2".into())].into_iter().collect(),
            remove: vec!["x-c".into()],
            enabled: true,
        };
        let ops = HeaderOps::build(&c).unwrap();
        let mut h = http::HeaderMap::new();
        h.insert("x-c", HeaderValue::from_static("old"));
        ops.apply(&mut h);
        assert_eq!(h["x-a"], "1");
        assert_eq!(h["x-b"], "2");
        assert!(h.get("x-c").is_none());
        // add appends a second value
        ops.apply(&mut h);
        assert_eq!(h.get_all("x-b").iter().count(), 2);

        // invalid name / value rejected at build
        let mut c2 = cfg::HeaderOps::default();
        c2.set.insert("bad name".into(), "v".into());
        assert!(HeaderOps::build(&c2).is_err());
        let mut c3 = cfg::HeaderOps::default();
        c3.add.insert("x".into(), "bad\r\nv".into());
        assert!(HeaderOps::build(&c3).is_err());
        let c4 = cfg::HeaderOps {
            remove: vec!["bad name".into()],
            ..Default::default()
        };
        assert!(HeaderOps::build(&c4).is_err());
    }

    #[test]
    fn security_headers_merge_and_apply() {
        let global = cfg::SecurityConfig {
            enabled: true,
            hsts: true,
            hsts_max_age: Duration::from_secs(100),
            hsts_subdomains: true,
            content_type_options: true,
            frame_options: "DENY".into(),
            referrer_policy: "no-referrer".into(),
            csp: Some("default-src 'self'".into()),
            cross_domain_policy: "none".into(),
        };
        // disabled global → None
        let off = cfg::SecurityConfig {
            enabled: false,
            ..global.clone()
        };
        assert!(Security::build(&off, None, None).is_none());
        // route disables → None
        let r = cfg::RouteSecurity {
            enabled: Some(false),
            ..Default::default()
        };
        assert!(Security::build(&global, None, Some(&r)).is_none());
        // route override wins; csp="" clears
        let r = cfg::RouteSecurity {
            frame_options: Some("SAMEORIGIN".into()),
            csp: Some(String::new()),
            ..Default::default()
        };
        let s = Security::build(&global, None, Some(&r)).unwrap();
        assert_eq!(s.frame_options, "SAMEORIGIN");
        assert!(s.csp.is_empty());
        // site layer sits between global and route
        let site_r = cfg::RouteSecurity {
            frame_options: Some("SITE".into()),
            ..Default::default()
        };
        let s = Security::build(&global, Some(&site_r), Some(&r)).unwrap();
        assert_eq!(s.frame_options, "SAMEORIGIN");
        let s = Security::build(&global, Some(&site_r), None).unwrap();
        assert_eq!(s.frame_options, "SITE");

        let s = Security::build(&global, None, None).unwrap();
        let mut h = http::HeaderMap::new();
        s.apply(&mut h, true);
        assert_eq!(
            h["strict-transport-security"],
            "max-age=100; includeSubDomains"
        );
        assert_eq!(h["x-frame-options"], "DENY");
        // hsts skipped on plain http
        let mut h = http::HeaderMap::new();
        s.apply(&mut h, false);
        assert!(h.get("strict-transport-security").is_none());
        // handler's own headers are not clobbered
        let mut h = http::HeaderMap::new();
        h.insert("x-frame-options", HeaderValue::from_static("CUSTOM"));
        s.apply(&mut h, false);
        assert_eq!(h["x-frame-options"], "CUSTOM");
    }

    #[test]
    fn check_ip_deny_then_allow() {
        let mw = Middleware {
            site_ip_allow: vec!["10.0.0.0/16".parse().unwrap()],
            ip_allow: vec!["10.0.0.0/8".parse().unwrap()],
            ip_deny: vec!["10.0.0.9/32".parse().unwrap()],
            auth: None,
            cors: None,
            rate_limit: None,
            headers: None,
            security: None,
            compress: None,
            cache: None,
            cfg: cfg::RouteConfig::default(),
        };
        let denied: IpAddr = "10.0.0.9".parse().unwrap();
        let allowed: IpAddr = "10.0.0.1".parse().unwrap();
        let outsider: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(mw.check_ip(denied).is_err(), "deny beats allow");
        assert!(mw.check_ip(allowed).is_ok());
        // inside the route allowlist (10/8) but outside the narrower
        // site allowlist (10.0/16) — a route cannot widen a site ACL
        let site_only_miss: IpAddr = "10.1.0.1".parse().unwrap();
        assert!(
            mw.check_ip(site_only_miss).is_err(),
            "route allow cannot widen site allow"
        );
        assert!(mw.check_ip(outsider).is_err(), "allowlist empty-match");
    }

    fn factory(toml: &str) -> (Factory, cfg::Config) {
        let c = crate::config::validate::parse_test_config(toml);
        let f = Factory::new(&c, None, crate::BuildMode::Check).unwrap();
        (f, c)
    }

    #[test]
    fn site_middleware_inherits_opts_out_and_merges() {
        let (f, c) = factory(
            r#"
[[site]]
hosts = ["x"]
auth = { bearer = { tokens = ["t"] } }
compress = true
response_headers = { set = { x-site = "1", x-shared = "site" }, remove = ["x-gone"] }
[[site.route]]
prefix = "/"
respond = { status = 200 }
[[site.route]]
prefix = "/off"
respond = { status = 200 }
auth = { enabled = false }
compress = false
response_headers = { set = { x-shared = "route" } }
"#,
        );
        let site = &c.site[0];

        // route[0]: inherits everything
        let m = f.build(0, site, &site.route[0]).unwrap();
        assert!(m.auth.is_some(), "site auth inherited");
        assert!(m.compress.is_some(), "site compress inherited");
        let ops = m.headers.unwrap();
        assert_eq!(
            ops.set
                .iter()
                .find(|(n, _)| n == "x-shared")
                .map(|(_, v)| v.clone()),
            Some(HeaderValue::from_static("site"))
        );
        assert!(ops.set.iter().any(|(n, _)| n == "x-site"));
        assert!(ops.remove.iter().any(|n| n == "x-gone"));
        assert!(m.cfg.auth.is_some(), "effective cfg materialized");

        // route[1]: opts out of auth+compress, merges headers
        let m = f.build(0, site, &site.route[1]).unwrap();
        assert!(m.auth.is_none(), "auth.enabled = false opts out");
        assert!(m.compress.is_none(), "compress = false opts out");
        let ops = m.headers.unwrap();
        assert_eq!(
            ops.set
                .iter()
                .find(|(n, _)| n == "x-shared")
                .map(|(_, v)| v.clone()),
            Some(HeaderValue::from_static("route")),
            "route key wins over site"
        );
        assert!(ops.set.iter().any(|(n, _)| n == "x-site"));
        assert!(ops.remove.iter().any(|n| n == "x-gone"));
    }

    #[test]
    fn site_rate_limit_shares_one_limiter() {
        let (f, c) = factory(
            r#"
[[site]]
hosts = ["x"]
rate_limit = { key = "ip", rate = "100/s" }
[[site.route]]
prefix = "/a"
respond = { status = 200 }
[[site.route]]
prefix = "/b"
respond = { status = 200 }
rate_limit = { key = "route", rate = "5/s" }
[[site.route]]
prefix = "/c"
respond = { status = 200 }
rate_limit = { enabled = false }
"#,
        );
        let site = &c.site[0];
        let a = f.build(0, site, &site.route[0]).unwrap();
        let b = f.build(0, site, &site.route[1]).unwrap();
        let d = f.build(0, site, &site.route[2]).unwrap();

        let shared = a.rate_limit.expect("inherits site limiter");
        let own = b.rate_limit.expect("route limiter");
        assert!(
            !Arc::ptr_eq(&shared, &own),
            "route override gets its own limiter"
        );
        assert!(d.rate_limit.is_none(), "enabled = false opts out");

        // a second inheriting route shares the same site limiter
        let (f2, c2) = factory(
            r#"
[[site]]
hosts = ["x"]
rate_limit = { key = "ip", rate = "100/s" }
[[site.route]]
prefix = "/a"
respond = { status = 200 }
[[site.route]]
prefix = "/b"
respond = { status = 200 }
"#,
        );
        let s2 = &c2.site[0];
        let a = f2.build(0, s2, &s2.route[0]).unwrap();
        let b = f2.build(0, s2, &s2.route[1]).unwrap();
        assert!(Arc::ptr_eq(&a.rate_limit.unwrap(), &b.rate_limit.unwrap()));
    }

    #[test]
    fn site_acls_tighten_only() {
        let (f, c) = factory(
            r#"
[[site]]
hosts = ["x"]
ip_allow = ["10.0.0.0/8"]
ip_deny = ["10.0.0.9/32"]
[[site.route]]
prefix = "/"
respond = { status = 200 }
ip_allow = ["10.0.1.0/24"]
ip_deny = ["10.0.1.5/32"]
"#,
        );
        let m = f.build(0, &c.site[0], &c.site[0].route[0]).unwrap();
        let ip = |s: &str| s.parse().unwrap();
        assert!(m.check_ip(ip("10.0.1.1")).is_ok());
        assert!(m.check_ip(ip("10.0.9.1")).is_err(), "outside route allow");
        assert!(m.check_ip(ip("10.0.0.9")).is_err(), "site deny applies");
        assert!(m.check_ip(ip("10.0.1.5")).is_err(), "route deny applies");
        assert!(m.check_ip(ip("192.168.0.1")).is_err());
    }
}
