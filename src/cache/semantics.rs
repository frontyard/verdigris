//! HTTP caching semantics: `Cache-Control`/`Expires`/`Age`/`Date`
//! interpretation and the store/serve/bypass decisions (RFC 7234's
//! cacheable subset).

use std::time::Duration;

use http::HeaderMap;

/// Request-side cache directives that change lookup behavior.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReqDirectives {
    /// `no-store`: bypass the cache entirely.
    pub no_store: bool,
    /// `no-cache` / `max-age=0`: force revalidation.
    pub no_cache: bool,
    /// `only-if-cached`: respond from cache or 504.
    pub only_if_cached: bool,
    /// `max-age=n`: entry older than this is unacceptable.
    pub max_age: Option<u64>,
    /// `max-stale[=n]`: stale within this bound is acceptable.
    pub max_stale: Option<Option<u64>>,
    /// `min-fresh=n`: require this much remaining freshness.
    pub min_fresh: Option<u64>,
}

/// Response-side cache directives that drive the store decision.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RespDirectives {
    /// `no-store`: never cache.
    pub no_store: bool,
    /// `no-cache`: store but always revalidate before serving.
    pub no_cache: bool,
    /// `private`: shared cache must not store.
    pub private: bool,
    /// `public`: explicitly cacheable (e.g. past Authorization).
    pub public: bool,
    /// `must-revalidate`: no stale serving of any kind.
    pub must_revalidate: bool,
    /// `s-maxage=n` (shared-cache TTL).
    pub s_maxage: Option<u64>,
    /// `max-age=n`.
    pub max_age: Option<u64>,
    /// `stale-while-revalidate=n`.
    pub swr: Option<u64>,
    /// `stale-if-error=n`.
    pub sie: Option<u64>,
}

/// Split a `Cache-Control` header list into (name, optional value) pairs.
fn cc_pairs(headers: &HeaderMap) -> impl Iterator<Item = (String, Option<String>)> + '_ {
    headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|p| {
            let p = p.trim();
            match p.split_once('=') {
                Some((k, v)) => (
                    k.trim().to_ascii_lowercase(),
                    Some(v.trim().trim_matches('"').to_string()),
                ),
                None => (p.to_ascii_lowercase(), None),
            }
        })
        .filter(|(k, _)| !k.is_empty())
}

fn secs(v: &Option<String>) -> Option<u64> {
    v.as_deref()?.parse().ok()
}

/// Parse request `Cache-Control`.
pub fn request_directives(headers: &HeaderMap) -> ReqDirectives {
    let mut d = ReqDirectives::default();
    for (k, v) in cc_pairs(headers) {
        match k.as_str() {
            "no-store" => d.no_store = true,
            "no-cache" => d.no_cache = true,
            "only-if-cached" => d.only_if_cached = true,
            "max-age" => {
                d.max_age = secs(&v);
                if d.max_age == Some(0) {
                    d.no_cache = true;
                }
            }
            "max-stale" => d.max_stale = Some(secs(&v)),
            "min-fresh" => d.min_fresh = secs(&v),
            _ => {}
        }
    }
    // HTTP/1.0 legacy pragma
    if headers
        .get(http::header::PRAGMA)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|p| p.trim().eq_ignore_ascii_case("no-cache"))
    {
        d.no_cache = true;
    }
    d
}

/// Parse response `Cache-Control`.
pub fn response_directives(headers: &HeaderMap) -> RespDirectives {
    let mut d = RespDirectives::default();
    for (k, v) in cc_pairs(headers) {
        match k.as_str() {
            "no-store" => d.no_store = true,
            "no-cache" => d.no_cache = true,
            "private" => d.private = true,
            "public" => d.public = true,
            "must-revalidate" | "proxy-revalidate" => d.must_revalidate = true,
            "s-maxage" => d.s_maxage = secs(&v),
            "max-age" => d.max_age = secs(&v),
            "stale-while-revalidate" => d.swr = secs(&v),
            "stale-if-error" => d.sie = secs(&v),
            _ => {}
        }
    }
    d
}

/// Statuses eligible for negative caching — transient errors where a
/// short TTL smooths upstream flapping. 408/409/425/429 are request-
/// specific and excluded.
fn negative_cacheable(status: http::StatusCode) -> bool {
    matches!(
        status.as_u16(),
        404 | 410 | 414 | 500 | 502 | 503 | 504 | 501 | 505
    )
}

/// Whether the outcome of a handler call may be stored at all.
/// `req_had_auth`: the request carried `Authorization` (RFC 7234 §3.2 —
/// shared caches must not store unless the response opts in).
pub fn storable(
    status: http::StatusCode,
    resp: &RespDirectives,
    headers: &HeaderMap,
    req_had_auth: bool,
) -> Store {
    if resp.no_store
        || resp.private
        || headers.contains_key(http::header::SET_COOKIE)
        || headers
            .get_all(http::header::VARY)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|v| v.trim() == "*")
        || status == http::StatusCode::PARTIAL_CONTENT
        || status.is_informational()
        || status.is_redirection() && status == http::StatusCode::MULTIPLE_CHOICES
    {
        return Store::No;
    }
    if req_had_auth && !resp.public && !resp.must_revalidate && resp.s_maxage.is_none() {
        return Store::No;
    }
    if negative_cacheable(status) {
        return Store::Negative;
    }
    // heuristic-cacheable statuses (RFC 7231 §6.1 list, trimmed to those
    // meaningful here) always store; anything else needs explicit
    // freshness to be worth keeping.
    let heuristic = matches!(
        status.as_u16(),
        200 | 203 | 204 | 300 | 301 | 308 | 404 | 405 | 410 | 414 | 501
    );
    if heuristic || resp.max_age.is_some() || resp.s_maxage.is_some() {
        Store::Yes
    } else {
        Store::No
    }
}

/// Whether a response may be committed to the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Store {
    /// Cacheable object.
    Yes,
    /// Only as a negative entry (`negative_ttl` lifetime).
    Negative,
    /// Not cacheable.
    No,
}

/// Declared freshness lifetime in seconds from the response headers:
/// `s-maxage` > `max-age` > `Expires` > `None`. `no-cache` forces 0
/// (stored but always revalidated).
pub fn declared_freshness(resp: &RespDirectives, headers: &HeaderMap) -> Option<u64> {
    if resp.no_cache {
        return Some(0);
    }
    if let Some(s) = resp.s_maxage.or(resp.max_age) {
        return Some(s);
    }
    if let (Some(exp), Some(date)) = (
        headers.get(http::header::EXPIRES).and_then(httpdate_value),
        headers.get(http::header::DATE).and_then(httpdate_value),
    ) {
        return Some(exp.saturating_sub(date));
    }
    headers
        .get(http::header::EXPIRES)
        .and_then(httpdate_value)
        .map(|exp| exp.saturating_sub(crate::cache::entry::now_secs()))
}

/// Seconds the object has already lived when it reached us: explicit
/// `Age` header or `Date`-based apparent age.
pub fn initial_age(headers: &HeaderMap) -> u64 {
    if let Some(age) = headers
        .get(http::header::AGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        return age;
    }
    headers
        .get(http::header::DATE)
        .and_then(httpdate_value)
        .map(|d| crate::cache::entry::now_secs().saturating_sub(d))
        .unwrap_or(0)
}

/// Heuristic freshness when nothing is declared: 10% of the time since
/// `Last-Modified`, capped at a day (RFC 7234 §4.2.2 spirit).
pub fn heuristic_freshness(headers: &HeaderMap) -> u64 {
    headers
        .get(http::header::LAST_MODIFIED)
        .and_then(httpdate_value)
        .map(|lm| {
            crate::cache::entry::now_secs()
                .saturating_sub(lm)
                .min(86_400)
                / 10
        })
        .unwrap_or(0)
}

/// Parse an HTTP-date header to unix seconds.
fn httpdate_value(v: &http::HeaderValue) -> Option<u64> {
    let t = httpdate::parse_http_date(v.to_str().ok()?).ok()?;
    t.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Resolve the vary header names the response demands.
pub fn response_vary(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(http::header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty() && v != "*")
        .collect()
}

/// Whether a stored variant's recorded request values match this request.
pub fn vary_matches(meta_vary: &[(String, Option<String>)], headers: &HeaderMap) -> bool {
    meta_vary.iter().all(|(name, want)| {
        let got = headers.get(name).and_then(|v| v.to_str().ok());
        got == want.as_deref()
    })
}

/// Resolve `(name, request-value)` pairs for the given header names.
pub fn vary_values(names: &[String], headers: &HeaderMap) -> Vec<(String, Option<String>)> {
    names
        .iter()
        .map(|n| {
            (
                n.clone(),
                headers
                    .get(n)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string),
            )
        })
        .collect()
}

/// Merge route config + response directives into final freshness windows.
/// `ttl` is the route's fallback TTL when the origin declares nothing;
/// `negative_ttl` bounds error entries; `swr`/`sie` are the route's own
/// stale windows used when the response doesn't specify larger ones.
#[allow(clippy::too_many_arguments)]
pub fn freshness_windows(
    resp: &RespDirectives,
    headers: &HeaderMap,
    negative: bool,
    ttl: Option<Duration>,
    negative_ttl: Duration,
    swr: Option<Duration>,
    sie: Option<Duration>,
) -> (u64, u64, u64) {
    let declared =
        declared_freshness(resp, headers).map(|f| f.saturating_sub(initial_age(headers)));
    // for negative entries the store's negative TTL is the default — the
    // heuristic (usually 0 on a bare 404) must not make it instantly stale
    let fresh = if negative {
        declared
            .or_else(|| ttl.map(|t| t.as_secs()))
            .map(|f| f.min(negative_ttl.as_secs()))
            .unwrap_or_else(|| negative_ttl.as_secs())
    } else {
        declared
            .or_else(|| ttl.map(|t| t.as_secs()))
            .unwrap_or_else(|| heuristic_freshness(headers))
    };
    // must-revalidate forbids any stale service.
    let (swr_for, sie_for) = if resp.must_revalidate {
        (0, 0)
    } else {
        (
            resp.swr
                .map(|s| s.max(swr.map(|d| d.as_secs()).unwrap_or(0)))
                .or_else(|| swr.map(|d| d.as_secs()))
                .unwrap_or(0),
            resp.sie
                .map(|s| s.max(sie.map(|d| d.as_secs()).unwrap_or(0)))
                .or_else(|| sie.map(|d| d.as_secs()))
                .unwrap_or(0),
        )
    };
    (fresh, swr_for, sie_for)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn hdrs(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn request_cc() {
        let h = hdrs(&[("cache-control", "no-cache, max-stale=30")]);
        let d = request_directives(&h);
        assert!(d.no_cache);
        assert_eq!(d.max_stale, Some(Some(30)));
        let h = hdrs(&[("cache-control", "max-age=0")]);
        assert!(request_directives(&h).no_cache);
    }

    #[test]
    fn response_cc() {
        let h = hdrs(&[(
            "cache-control",
            "public, max-age=60, stale-while-revalidate=30",
        )]);
        let d = response_directives(&h);
        assert!(d.public);
        assert_eq!(d.max_age, Some(60));
        assert_eq!(d.swr, Some(30));
    }

    #[test]
    fn store_decisions() {
        let ok = hdrs(&[("cache-control", "max-age=60")]);
        let d = response_directives(&ok);
        assert_eq!(storable(http::StatusCode::OK, &d, &ok, false), Store::Yes);
        // private / no-store / set-cookie / vary:* all refuse
        for cc in ["private", "no-store"] {
            let h = hdrs(&[("cache-control", cc)]);
            let d = response_directives(&h);
            assert_eq!(storable(http::StatusCode::OK, &d, &h, false), Store::No);
        }
        let h = hdrs(&[("set-cookie", "a=b")]);
        let d = response_directives(&h);
        assert_eq!(storable(http::StatusCode::OK, &d, &h, false), Store::No);
        let h = hdrs(&[("vary", "*")]);
        let d = response_directives(&h);
        assert_eq!(storable(http::StatusCode::OK, &d, &h, false), Store::No);
        // auth'd request: only explicit-public responses store
        let h = hdrs(&[("cache-control", "max-age=60")]);
        let d = response_directives(&h);
        assert_eq!(storable(http::StatusCode::OK, &d, &h, true), Store::No);
        let h = hdrs(&[("cache-control", "public, max-age=60")]);
        let d = response_directives(&h);
        assert_eq!(storable(http::StatusCode::OK, &d, &h, true), Store::Yes);
        // negative statuses → Negative store
        let h = hdrs(&[]);
        let d = response_directives(&h);
        assert_eq!(
            storable(http::StatusCode::NOT_FOUND, &d, &h, false),
            Store::Negative
        );
        assert_eq!(
            storable(http::StatusCode::TOO_MANY_REQUESTS, &d, &h, false),
            Store::No
        );
    }

    #[test]
    fn vary_round_trip() {
        let h = hdrs(&[("vary", "Accept-Language, Accept-Encoding")]);
        assert_eq!(
            response_vary(&h),
            vec!["accept-language", "accept-encoding"]
        );
        let meta = vec![("accept-language".to_string(), Some("en".to_string()))];
        assert!(vary_matches(&meta, &hdrs(&[("accept-language", "en")])));
        assert!(!vary_matches(&meta, &hdrs(&[("accept-language", "de")])));
        assert!(!vary_matches(&meta, &hdrs(&[])));
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;
    use http::HeaderValue;

    fn h(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.append(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    #[test]
    fn request_directives_full() {
        let d = request_directives(&h(&[(
            "cache-control",
            "no-cache, max-stale=30, min-fresh=5, only-if-cached",
        )]));
        assert!(d.no_cache && d.only_if_cached);
        assert_eq!(d.max_stale, Some(Some(30)));
        assert_eq!(d.min_fresh, Some(5));
        // max-age=0 implies no-cache
        let d = request_directives(&h(&[("cache-control", "max-age=0")]));
        assert!(d.no_cache);
        // legacy pragma
        let d = request_directives(&h(&[("pragma", "no-cache")]));
        assert!(d.no_cache);
        // unbounded max-stale (no value)
        let d = request_directives(&h(&[("cache-control", "max-stale")]));
        assert_eq!(d.max_stale, Some(None));
    }

    #[test]
    fn negative_ttl_is_the_default_not_a_floor() {
        // bare 404: nothing declared → negative_ttl applies
        let d = response_directives(&h(&[]));
        let (fresh, _, _) =
            freshness_windows(&d, &h(&[]), true, None, Duration::from_secs(10), None, None);
        assert_eq!(fresh, 10);
        // declared freshness wins but is capped at negative_ttl
        let hd = h(&[("cache-control", "max-age=60")]);
        let d = response_directives(&hd);
        let (fresh, _, _) =
            freshness_windows(&d, &hd, true, None, Duration::from_secs(10), None, None);
        assert_eq!(fresh, 10);
        // shorter declared stays shorter
        let hd = h(&[("cache-control", "max-age=2")]);
        let d = response_directives(&hd);
        let (fresh, _, _) =
            freshness_windows(&d, &hd, true, None, Duration::from_secs(10), None, None);
        assert_eq!(fresh, 2);
        // route ttl override still applies to negatives
        let d = response_directives(&h(&[]));
        let (fresh, _, _) = freshness_windows(
            &d,
            &h(&[]),
            true,
            Some(Duration::from_secs(4)),
            Duration::from_secs(10),
            None,
            None,
        );
        assert_eq!(fresh, 4);
    }

    #[test]
    fn freshness_windows_positive() {
        // declared max-age wins over route ttl
        let hd = h(&[("cache-control", "max-age=120")]);
        let d = response_directives(&hd);
        let (fresh, swr, sie) = freshness_windows(
            &d,
            &hd,
            false,
            Some(Duration::from_secs(10)),
            Duration::from_secs(10),
            Some(Duration::from_secs(30)),
            Some(Duration::from_secs(60)),
        );
        assert_eq!((fresh, swr, sie), (120, 30, 60));
        // must-revalidate disables stale service
        let hd = h(&[("cache-control", "max-age=120, must-revalidate")]);
        let d = response_directives(&hd);
        let (_, swr, sie) = freshness_windows(
            &d,
            &hd,
            false,
            None,
            Duration::from_secs(10),
            Some(Duration::from_secs(30)),
            Some(Duration::from_secs(60)),
        );
        assert_eq!((swr, sie), (0, 0));
        // heuristic: Last-Modified-based fraction
        let lm = httpdate::fmt_http_date(
            std::time::SystemTime::now() - std::time::Duration::from_secs(100),
        );
        let hd = h(&[("last-modified", lm.as_str())]);
        let d = response_directives(&hd);
        let (fresh, _, _) =
            freshness_windows(&d, &hd, false, None, Duration::from_secs(10), None, None);
        assert!(fresh > 0 && fresh <= 10, "heuristic fraction: {fresh}");
    }
}
