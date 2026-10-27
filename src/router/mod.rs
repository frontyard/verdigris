//! Host and route matching: per-host site lookup (exact → wildcard →
//! default) and per-site path routing (exact → longest prefix → regex) with
//! method/header/query conditions as filters.

pub mod condition;
pub mod normalize;

use std::collections::HashMap;
use std::sync::Arc;

use regex::Regex;

use crate::config::model as cfg;
use crate::handler::{self, Handler};
use crate::middleware::{self, Middleware};
use crate::proxy::Clusters;
use crate::router::condition::Conditions;

/// How a route matches the path.
#[derive(Debug)]
pub enum PathMatch {
    /// Exact path equality.
    Exact(String),
    /// Path prefix.
    Prefix(String),
    /// Regex match; evaluated last, never overrides a prefix route.
    Regex(Regex),
}

/// A compiled route.
pub struct Route {
    /// Identifier for logs/metrics: `{site}.r{n}`.
    pub id: String,
    /// Resolved metric handles — request-time emission is a few atomic
    /// ops, no registry lookups or allocations.
    pub meters: Arc<crate::observe::metrics::RouteMeters>,
    /// Path matcher.
    pub matcher: PathMatch,
    /// Method/header/query conditions.
    pub conditions: Conditions,
    /// Priority among routes that tie on path specificity.
    pub priority: i32,
    /// The handler.
    pub handler: Handler,
    /// Per-route middleware.
    pub middleware: Middleware,
    /// Resolved timeouts (route overrides applied over global defaults).
    pub timeouts: cfg::Timeouts,
    /// Resolved limits.
    pub limits: cfg::Limits,
}

/// A compiled site: a set of routes plus the matchit index over them.
pub struct Site {
    /// Site name (config name or first host).
    pub name: String,
    /// Route list.
    pub routes: Vec<Route>,
    /// matchit pattern → route indices, ordered by descending priority.
    patterns: matchit::Router<Vec<usize>>,
    /// Regex routes evaluated after matchit misses.
    regexes: Vec<(Regex, Vec<usize>)>,
    /// TLS mode of this site.
    pub tls: cfg::SiteTls,
    /// Redirect plaintext to HTTPS.
    pub redirect_https: bool,
    /// Redirect target host override.
    pub redirect_host: Option<String>,
    /// Per-site trusted proxies; `None` = inherit global.
    pub trusted_proxies: Option<Vec<ipnet::IpNet>>,
}

impl Site {
    /// Find the route for a request: the most specific matchit hit whose
    /// conditions pass, falling back to shorter prefixes when candidates
    /// fail conditions, then to regex routes.
    pub fn match_route(
        &self,
        parts: &http::request::Parts,
        normalized_path: &str,
    ) -> Option<&Route> {
        self.match_route_idx(parts, normalized_path).map(|(_, r)| r)
    }

    /// [`Self::match_route`] plus the route's index in `self.routes` (needed by
    /// the cache's background-revalidation handles).
    pub fn match_route_idx(
        &self,
        parts: &http::request::Parts,
        normalized_path: &str,
    ) -> Option<(usize, &Route)> {
        let mut query = normalized_path.to_string();
        let mut tried: Vec<usize> = Vec::new();
        while let Ok(m) = self.patterns.at(&query) {
            if let Some(route) = self.pick_idx(m.value, parts, &mut tried) {
                return Some(route);
            }
            let next = normalize::parent_prefix(&query).to_string();
            if next == query || query == "/" {
                break;
            }
            query = next;
        }
        // regex routes: linear scan, only when no path match survived
        for (re, idxs) in &self.regexes {
            if re.is_match(normalized_path)
                && let Some(route) = self.pick_idx(idxs, parts, &mut tried)
            {
                return Some(route);
            }
        }
        None
    }

    /// Among candidate route indices not in `tried`, pick the
    /// highest-priority one whose conditions match. Rejected candidates are
    /// pushed onto `tried`.
    fn pick_idx(
        &self,
        idxs: &[usize],
        parts: &http::request::Parts,
        tried: &mut Vec<usize>,
    ) -> Option<(usize, &Route)> {
        for &i in idxs {
            if tried.contains(&i) {
                continue;
            }
            let route = &self.routes[i];
            if route.conditions.matches(parts) {
                return Some((i, route));
            }
            tried.push(i);
        }
        None
    }
}

/// Host → site index: exact hosts in a map, wildcard suffixes in a
/// (typically short) list, optional default site.
pub struct HostIndex {
    exact: HashMap<String, usize>,
    wildcards: Vec<(String, usize)>,
    default: Option<usize>,
    /// All sites; index values above point here.
    pub sites: Vec<Site>,
    /// Upstream clusters referenced by proxy routes (kept for health
    /// probes, reload diffing and admin inspection).
    pub clusters: Clusters,
}

/// Normalize a Host header for lookup: strip port, trailing dot, lowercase.
pub(crate) fn normalize_host(raw: &str) -> String {
    let h = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    // strip ":port" only when it really is a port (avoid eating IPv6)
    if let Ok(sa) = h.parse::<std::net::SocketAddr>() {
        return sa.ip().to_string();
    }
    match h.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => host.to_string(),
        _ => h,
    }
}

impl HostIndex {
    /// Look up the site for a `Host` header value.
    pub fn lookup(&self, host: &str) -> Option<&Site> {
        self.lookup_idx(host).map(|(_, s)| s)
    }

    /// [`Self::lookup`] plus the site's index in `self.sites`.
    pub fn lookup_idx(&self, host: &str) -> Option<(usize, &Site)> {
        let host = normalize_host(host);
        if let Some(&i) = self.exact.get(&host) {
            return Some((i, &self.sites[i]));
        }
        for (suffix, i) in &self.wildcards {
            if host.ends_with(suffix.as_str()) && host.len() > suffix.len() {
                return Some((*i, &self.sites[*i]));
            }
        }
        self.default.map(|i| (i, &self.sites[i]))
    }
}

/// Build all sites + the host index from config.
pub fn build(config: &cfg::Config, mw: &middleware::Factory) -> Result<HostIndex, BuildError> {
    let mut exact = HashMap::new();
    let mut wildcards = Vec::new();
    let mut default = None;
    let mut sites = Vec::new();
    let mut clusters = Clusters::build(config).map_err(BuildError::Route)?;

    for (si, site_cfg) in config.site.iter().enumerate() {
        let site_name = site_cfg
            .name
            .clone()
            .or_else(|| site_cfg.hosts.first().cloned())
            .unwrap_or_else(|| format!("site{si}"));

        // site-level shorthands become implicit catch-all routes appended
        // after explicit routes (least specific)
        let mut route_cfgs: Vec<cfg::RouteConfig> = site_cfg.route.clone();
        if let Some(root) = &site_cfg.root {
            route_cfgs.push(cfg::RouteConfig {
                prefix: Some("/".into()),
                static_files: Some(cfg::StaticHandler {
                    root: root.clone(),
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
        if let Some(up) = &site_cfg.proxy {
            route_cfgs.push(cfg::RouteConfig {
                prefix: Some("/".into()),
                proxy: Some(up.clone()),
                ..Default::default()
            });
        }
        if let Some(resp) = &site_cfg.respond {
            route_cfgs.push(cfg::RouteConfig {
                prefix: Some("/".into()),
                respond: Some(resp.clone()),
                ..Default::default()
            });
        }
        if let Some(redir) = &site_cfg.redirect {
            route_cfgs.push(cfg::RouteConfig {
                prefix: Some("/".into()),
                redirect: Some(redir.clone()),
                ..Default::default()
            });
        }

        let mut routes = Vec::new();
        let empty_match = cfg::MatchConditions::default();
        for (ri, route_cfg) in route_cfgs.iter().enumerate() {
            let ctx = || format!("site[{si}].route[{ri}]");
            let matcher = build_matcher(route_cfg)
                .map_err(|e| BuildError::Route(format!("{}: {e}", ctx())))?;
            let conditions = Conditions::build(route_cfg.match_.as_ref().unwrap_or(&empty_match))
                .map_err(|e| BuildError::Route(format!("{}: {e}", ctx())))?;
            let route_id = format!("{site_name}.r{ri}");
            let handler = handler::build(route_cfg, &site_name, &mut clusters, &route_id)
                .map_err(|e| BuildError::Route(format!("{}: {e}", ctx())))?;
            let middleware = mw
                .build(si, site_cfg, route_cfg)
                .map_err(|e| BuildError::Route(format!("{}: {e}", ctx())))?;

            let mut timeouts = config.timeouts.clone();
            if let Some(over) = &site_cfg.timeouts {
                timeouts.apply_overrides(over);
            }
            if let Some(over) = &route_cfg.timeouts {
                timeouts.apply_overrides(over);
            }
            let mut limits = config.limits.clone();
            if let Some(over) = &site_cfg.limits {
                limits.apply_overrides(over);
            }
            if let Some(over) = &route_cfg.limits {
                limits.apply_overrides(over);
            }
            routes.push(Route {
                id: route_id.clone(),
                meters: Arc::new(crate::observe::metrics::RouteMeters::new(&route_id)),
                matcher,
                conditions,
                priority: route_cfg.priority,
                handler,
                middleware,
                timeouts,
                limits,
            });
        }

        // group route indices by matchit pattern; a prefix without a
        // trailing slash registers both its exact form and catch-all form
        let mut pattern_routes: Vec<(String, Vec<usize>)> = Vec::new();
        let mut regexes: Vec<(Regex, Vec<usize>)> = Vec::new();
        for (ri, route) in routes.iter().enumerate() {
            match &route.matcher {
                PathMatch::Exact(p) => push_pattern(&mut pattern_routes, p.clone(), ri),
                PathMatch::Prefix(p) => {
                    // matchit's `{*rest}` needs a non-empty tail, so every
                    // boundary form gets a literal pattern alongside the
                    // catch-all.
                    if p == "/" {
                        push_pattern(&mut pattern_routes, "/".into(), ri);
                        push_pattern(&mut pattern_routes, "/{*rest}".into(), ri);
                    } else if let Some(base) = p.strip_suffix('/') {
                        push_pattern(&mut pattern_routes, p.clone(), ri);
                        push_pattern(&mut pattern_routes, format!("{base}/{{*rest}}"), ri);
                    } else {
                        push_pattern(&mut pattern_routes, p.clone(), ri);
                        push_pattern(&mut pattern_routes, format!("{p}/"), ri);
                        push_pattern(&mut pattern_routes, format!("{p}/{{*rest}}"), ri);
                    }
                }
                PathMatch::Regex(re) => {
                    if let Some((_, idxs)) =
                        regexes.iter_mut().find(|(r, _)| r.as_str() == re.as_str())
                    {
                        idxs.push(ri);
                    } else {
                        regexes.push((re.clone(), vec![ri]));
                    }
                }
            }
        }
        let mut patterns = matchit::Router::new();
        for (pattern, mut idxs) in pattern_routes {
            idxs.sort_by_key(|&i| -routes[i].priority);
            patterns
                .insert(pattern.as_str(), idxs)
                .map_err(|e| BuildError::Route(format!("route pattern {pattern:?}: {e}")))?;
        }
        for (_, idxs) in regexes.iter_mut() {
            idxs.sort_by_key(|&i| -routes[i].priority);
        }

        let idx = sites.len();
        sites.push(Site {
            name: site_name,
            routes,
            patterns,
            regexes,
            tls: site_cfg.tls.clone(),
            redirect_https: site_cfg.redirect_https.unwrap_or(true),
            redirect_host: site_cfg.redirect_host.clone(),
            trusted_proxies: site_cfg.trusted_proxies.clone(),
        });

        for host in &site_cfg.hosts {
            let h = normalize_host(host);
            if let Some(suffix) = h.strip_prefix("*") {
                wildcards.push((suffix.to_string(), idx));
            } else {
                exact.insert(h, idx);
            }
        }
        if site_cfg.default {
            default = Some(idx);
        }
    }

    // longest suffix first: `*.b.com` must beat `*.com` regardless of
    // declaration order (stable sort keeps decl order within ties)
    wildcards.sort_by_key(|w| std::cmp::Reverse(w.0.len()));

    Ok(HostIndex {
        exact,
        wildcards,
        default,
        sites,
        clusters,
    })
}

fn push_pattern(routes: &mut Vec<(String, Vec<usize>)>, pattern: String, ri: usize) {
    if let Some((_, idxs)) = routes.iter_mut().find(|(p, _)| *p == pattern) {
        idxs.push(ri);
    } else {
        routes.push((pattern, vec![ri]));
    }
}

fn build_matcher(route: &cfg::RouteConfig) -> Result<PathMatch, String> {
    if let Some(p) = &route.exact {
        return Ok(PathMatch::Exact(p.clone()));
    }
    if let Some(p) = route.prefix.as_ref() {
        return Ok(PathMatch::Prefix(p.clone()));
    }
    if let Some(r) = &route.regex {
        return Ok(PathMatch::Regex(
            Regex::new(r).map_err(|e| format!("invalid regex: {e}"))?,
        ));
    }
    Err("no path matcher".into())
}

/// Errors while compiling a [`HostIndex`].
#[derive(Debug)]
pub enum BuildError {
    /// A route failed to compile.
    Route(String),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Route(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for BuildError {}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    fn site_index(text: &str) -> HostIndex {
        let cfg = crate::config::validate::parse_test_config(text);
        let mw = middleware::Factory::new(&cfg, None, crate::BuildMode::Live).unwrap();
        build(&cfg, &mw).unwrap()
    }

    #[test]
    fn host_index_exact_wildcard_default() {
        let idx = site_index(
            r#"
[[site]]
hosts = ["a.example.com"]
[[site.route]]
prefix = "/"
respond = { body = "a" }
[[site]]
hosts = ["*.example.com"]
[[site.route]]
prefix = "/"
respond = { body = "wild" }
[[site]]
default = true
[[site.route]]
prefix = "/"
respond = { body = "d" }
"#,
        );
        assert_eq!(idx.lookup("a.example.com").unwrap().name, "a.example.com");
        assert_eq!(idx.lookup("b.example.com").unwrap().name, "*.example.com");
        assert_eq!(
            idx.lookup("deep.b.example.com").unwrap().name,
            "*.example.com"
        );
        // "example.com" is not under the wildcard — default site answers
        assert_eq!(idx.lookup("example.com").unwrap().name, "site2");
        assert_eq!(idx.lookup("other.org").unwrap().name, "site2");
        assert_eq!(
            idx.lookup("A.EXAMPLE.COM:443").unwrap().name,
            "a.example.com"
        );
    }

    #[test]
    fn longest_wildcard_suffix_wins_regardless_of_order() {
        let idx = site_index(
            r#"
[[site]]
hosts = ["*.com"]
[[site.route]]
prefix = "/"
respond = { body = "broad" }
[[site]]
hosts = ["*.b.com"]
[[site.route]]
prefix = "/"
respond = { body = "specific" }
"#,
        );
        // declared after the broad wildcard but must win
        assert_eq!(idx.lookup("x.b.com").unwrap().name, "*.b.com");
        assert_eq!(idx.lookup("x.c.com").unwrap().name, "*.com");
    }

    #[test]
    fn normalize_host_strips_port_and_dot() {
        assert_eq!(normalize_host("Example.COM:8080"), "example.com");
        assert_eq!(normalize_host("example.com."), "example.com");
        assert_eq!(normalize_host("[::1]:80"), "::1");
    }

    fn req(path: &str) -> http::request::Parts {
        Request::builder()
            .uri(format!("http://x{path}"))
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    fn matched_id(idx: &HostIndex, host: &str, path: &str) -> Option<String> {
        let site = idx.lookup(host)?;
        let p = normalize::normalize_path(path).unwrap();
        site.match_route(&req(path), &p).map(|r| r.id.clone())
    }

    #[test]
    fn exact_beats_prefix() {
        let idx = site_index(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/api/"
respond = { status = 200, body = "prefix" }
[[site.route]]
exact = "/api/v1"
respond = { status = 200, body = "exact" }
"#,
        );
        assert_eq!(matched_id(&idx, "x", "/api/v1").unwrap(), "x.r1");
        assert_eq!(matched_id(&idx, "x", "/api/v2").unwrap(), "x.r0");
    }

    #[test]
    fn longest_prefix_wins() {
        let idx = site_index(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/"
respond = { body = "root" }
[[site.route]]
prefix = "/api/"
respond = { body = "api" }
[[site.route]]
prefix = "/api/v1/"
respond = { body = "v1" }
"#,
        );
        assert_eq!(matched_id(&idx, "x", "/").unwrap(), "x.r0");
        assert_eq!(matched_id(&idx, "x", "/api/").unwrap(), "x.r1");
        assert_eq!(matched_id(&idx, "x", "/api/v2/").unwrap(), "x.r1");
        assert_eq!(matched_id(&idx, "x", "/api/v1/x").unwrap(), "x.r2");
    }

    #[test]
    fn regex_evaluated_last() {
        let idx = site_index(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/app/"
respond = { body = "prefix" }
[[site.route]]
regex = "^/app/.*\\.php$"
respond = { body = "regex" }
"#,
        );
        // prefix route beats regex even though the regex also matches
        assert_eq!(matched_id(&idx, "x", "/app/x.php").unwrap(), "x.r0");
        assert!(matched_id(&idx, "x", "/other/a.php").is_none());
    }

    #[test]
    fn method_conditions_filter_then_shorter_prefix_serves() {
        let idx = site_index(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/api/"
match = { methods = ["DELETE"] }
respond = { body = "delete" }
[[site.route]]
prefix = "/"
respond = { body = "fallback" }
"#,
        );
        let del = Request::builder()
            .method("DELETE")
            .uri("http://x/api/x")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let get = req("/api/x");
        let site = idx.lookup("x").unwrap();
        let p = "/api/x";
        assert_eq!(site.match_route(&del, p).unwrap().id, "x.r0");
        assert_eq!(site.match_route(&get, p).unwrap().id, "x.r1");
    }

    #[test]
    fn priority_breaks_ties() {
        let idx = site_index(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/api/"
match = { methods = ["POST"] }
priority = 1
respond = { body = "one" }
[[site.route]]
prefix = "/api/"
priority = 2
respond = { body = "two" }
"#,
        );
        let post = Request::builder()
            .method("POST")
            .uri("http://x/api/x")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let site = idx.lookup("x").unwrap();
        assert_eq!(site.match_route(&post, "/api/x").unwrap().id, "x.r1");
    }

    #[test]
    fn prefix_without_trailing_slash_matches_both() {
        let idx = site_index(
            r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/api"
respond = { body = "api" }
"#,
        );
        assert!(matched_id(&idx, "x", "/api").is_some());
        assert!(matched_id(&idx, "x", "/api/x/y").is_some());
    }
}
