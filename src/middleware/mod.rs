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
    /// Merge a global config with an optional route override. Returns
    /// `None` when the effective config is disabled.
    pub fn build(global: &cfg::SecurityConfig, o: Option<&cfg::RouteSecurity>) -> Option<Self> {
        let enabled = o.and_then(|o| o.enabled).unwrap_or(global.enabled);
        if !enabled {
            return None;
        }
        Some(Self {
            hsts: o.and_then(|o| o.hsts).unwrap_or(global.hsts),
            hsts_max_age: o
                .and_then(|o| o.hsts_max_age)
                .unwrap_or(global.hsts_max_age),
            hsts_subdomains: o
                .and_then(|o| o.hsts_subdomains)
                .unwrap_or(global.hsts_subdomains),
            content_type_options: o
                .and_then(|o| o.content_type_options)
                .unwrap_or(global.content_type_options),
            frame_options: o
                .and_then(|o| o.frame_options.clone())
                .unwrap_or_else(|| global.frame_options.clone()),
            referrer_policy: o
                .and_then(|o| o.referrer_policy.clone())
                .unwrap_or_else(|| global.referrer_policy.clone()),
            // `csp = ""` clears an inherited value.
            csp: o
                .and_then(|o| o.csp.clone())
                .unwrap_or_else(|| global.csp.clone().unwrap_or_default()),
            cross_domain_policy: o
                .and_then(|o| o.cross_domain_policy.clone())
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
    /// Allowed client CIDRs; empty = all allowed.
    pub ip_allow: Vec<ipnet::IpNet>,
    /// Denied client CIDRs (evaluated before allows).
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
    /// IP access check: deny rules first, then allowlist (empty = allow all).
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), StatusCode> {
        if self.ip_deny.iter().any(|n| n.contains(&ip)) {
            return Err(StatusCode::FORBIDDEN);
        }
        if !self.ip_allow.is_empty() && !self.ip_allow.iter().any(|n| n.contains(&ip)) {
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(())
    }
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
    /// Named cache stores shared by routes.
    caches: std::collections::HashMap<String, Arc<crate::cache::Cache>>,
}

impl Factory {
    /// New factory from global config; builds the named cache stores.
    /// `prior` reuses unchanged stores across a reload so RAM contents and
    /// open disk indexes survive a config generation swap.
    pub fn new(cfg: &cfg::Config, prior: Option<&Factory>) -> Result<Self, String> {
        Ok(Self {
            trusted_proxies: cfg.server.trusted_proxies.clone(),
            security: cfg.server.security.clone(),
            limiters: Mutex::new(Vec::new()),
            caches: crate::cache::Cache::build_all(cfg, prior.map(|p| p.caches()))?,
        })
    }

    /// The named cache stores — for admin purge/introspection.
    pub fn caches(&self) -> &std::collections::HashMap<String, Arc<crate::cache::Cache>> {
        &self.caches
    }

    /// Compile a route's middleware.
    pub fn build(
        &self,
        _site: &cfg::SiteConfig,
        route: &cfg::RouteConfig,
    ) -> Result<Middleware, String> {
        let headers = route
            .response_headers
            .as_ref()
            .map(HeaderOps::build)
            .transpose()?;
        let auth = route.auth.as_ref().map(Auth::build).transpose()?;
        let cors = route.cors.as_ref().map(Cors::build).transpose()?;
        let rate_limit = route
            .rate_limit
            .as_ref()
            .map(RateLimiter::build)
            .transpose()?
            .map(|rl| {
                let rl = Arc::new(rl);
                self.limiters
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(rl.clone());
                rl
            });
        Ok(Middleware {
            ip_allow: route.ip_allow.clone(),
            ip_deny: route.ip_deny.clone(),
            auth,
            cors,
            rate_limit,
            headers,
            security: Security::build(&self.security, route.security.as_ref()),
            compress: route.compress.as_ref().map(Compress::build).transpose()?,
            cache: route
                .cache
                .as_ref()
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
                .transpose()?,
            cfg: route.clone(),
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
        assert!(Security::build(&off, None).is_none());
        // route disables → None
        let r = cfg::RouteSecurity {
            enabled: Some(false),
            ..Default::default()
        };
        assert!(Security::build(&global, Some(&r)).is_none());
        // route override wins; csp="" clears
        let r = cfg::RouteSecurity {
            frame_options: Some("SAMEORIGIN".into()),
            csp: Some(String::new()),
            ..Default::default()
        };
        let s = Security::build(&global, Some(&r)).unwrap();
        assert_eq!(s.frame_options, "SAMEORIGIN");
        assert!(s.csp.is_empty());

        let s = Security::build(&global, None).unwrap();
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
        assert!(mw.check_ip(outsider).is_err(), "allowlist empty-match");
    }
}
