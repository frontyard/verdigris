//! The pipeline-facing cache stage: bypass rules, lookup, conditional
//! revalidation, SWR background refresh, stale-if-error fallback, and
//! request coalescing. The route's handler is invoked through
//! `run_handler` so revalidation uses identical semantics.

use std::sync::Arc;

use http::HeaderMap;

use crate::body::{self, BoxBody};
use crate::cache::entry::{Freshness, Meta, now_secs};
use crate::cache::key::{self, Key};
use crate::cache::semantics::{self, ReqDirectives, Store, vary_values};
use crate::cache::{Cache, FetchGuard, Leadership, Lookup, Stored};

/// How long a coalesced follower waits on the leader before fetching
/// independently — the equivalent of nginx's `proxy_cache_lock_timeout`
/// (5s default). The leader's `FetchGuard` lives until its body finishes
/// streaming to *its* client, so an unbounded wait lets one slow reader
/// stall every requester of the key.
const FOLLOWER_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
use crate::config::model as cfg;
use crate::handler::RequestCtx;
use crate::router::Route;

/// A route's compiled cache attachment: shared store + route-level knobs.
pub struct RouteCacheMw {
    /// The named store.
    pub store: Arc<Cache>,
    /// This route's `cache` block.
    pub cfg: cfg::RouteCache,
    /// Vary header names lowercased once for key building.
    pub vary_headers: Vec<String>,
}

/// What the request may do with the cache.
pub enum Plan {
    /// Don't touch the cache — `X-Cache: BYPASS`.
    Bypass,
    /// Eligible request — work the cache for `key`.
    Use {
        /// Primary vary key for this request.
        key: Key,
        /// Request cache-control directives.
        dir: ReqDirectives,
        /// `Authorization` was present (header or resolved identity) —
        /// constrains what may be stored.
        had_auth: bool,
    },
}

/// Evaluate the request against the route's bypass rules; `authed` is the
/// pipeline's auth outcome (identity resolved), independent of a raw
/// `Authorization` header which is also honored.
/// `host` is the request's authority (raw `Host`/URI authority) and
/// `scheme` is the listener's (`http`/`https`) — both feed the key so
/// the same path on different authorities or transports cannot share an
/// entry. `path` is the decoded/normalized path used only for
/// `bypass.paths` glob matching; the key itself is built from the raw
/// request target (see [`key::primary`]). `strip_query`, when set, is a
/// query parameter name carrying a credential (ApiKey auth with
/// `location = "query"`) that must be dropped from the key so the
/// secret never lands in the RAM index or on disk.
pub fn plan(
    cm: &RouteCacheMw,
    parts: &http::request::Parts,
    host: &str,
    scheme: &str,
    path: &str,
    authed: bool,
    strip_query: Option<&str>,
) -> Plan {
    let b = &cm.cfg.bypass;
    let m = &parts.method;
    let headers = &parts.headers;
    let had_auth = authed || headers.contains_key(http::header::AUTHORIZATION);
    let eligible = (m == http::Method::GET || m == http::Method::HEAD)
        && !b.methods.iter().any(|x| x.eq_ignore_ascii_case(m.as_str()));
    let bypass = !eligible
        || (b.authenticated && had_auth)
        || b.headers.iter().any(|h| headers.contains_key(h.as_str()))
        || cookie_bypass(&b.cookies, headers)
        || b.paths
            .iter()
            .any(|g| crate::handler::static_files::glob_match(g, path))
        || semantics::request_directives(headers).no_store;
    if bypass {
        return Plan::Bypass;
    }
    let vary = vary_values(&cm.vary_headers, headers);
    let target = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let target = strip_query.map_or_else(
        || std::borrow::Cow::Borrowed(target),
        |name| key::strip_query_param(target, name),
    );
    let key = key::primary(m, scheme, host, &target, &vary);
    Plan::Use {
        key,
        dir: semantics::request_directives(headers),
        had_auth,
    }
}

/// Is any listed cookie (or `*`) present in the Cookie header?
fn cookie_bypass(names: &[String], headers: &HeaderMap) -> bool {
    if names.is_empty() {
        return false;
    }
    if names.iter().any(|n| n == "*") {
        return headers.contains_key(http::header::COOKIE);
    }
    headers
        .get(http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|c| {
            c.split(';')
                .filter_map(|p| p.split('=').next())
                .map(str::trim)
                .any(|n| names.iter().any(|w| w.eq_ignore_ascii_case(n)))
        })
}

/// Work the cache around `route`'s handler. `handle` locates the route by
/// (site, route) index for background revalidation tasks.
pub async fn serve(
    cm: &RouteCacheMw,
    plan: Plan,
    rt: &Arc<crate::server::Runtime>,
    handle: (usize, usize),
    route: &Route,
    req: http::Request<BoxBody>,
    req_ctx: &RequestCtx,
) -> http::Response<BoxBody> {
    let Plan::Use { key, dir, had_auth } = plan else {
        let resp = run_handler(route, req, req_ctx).await;
        return tag(resp, "BYPASS", cm);
    };
    let head_only = req.method() == http::Method::HEAD;
    let req_headers = req.headers().clone();

    let stored = match cm.store.lookup(&key, &req_headers).await {
        Lookup::Found(s) => Some(s),
        Lookup::Miss => None,
    };

    if let Some(stored) = stored {
        let freshness = effective_freshness(&stored.meta, &dir);
        match freshness {
            Freshness::Fresh if !dir.no_cache => {
                return serve_stored(&stored, head_only, &req_headers, "HIT", cm);
            }
            _ if max_stale_ok(&stored.meta, &dir) => {
                return serve_stored(&stored, head_only, &req_headers, "STALE", cm);
            }
            Freshness::Swr if !dir.no_cache => {
                spawn_revalidate(
                    cm,
                    rt,
                    handle,
                    &key,
                    &req,
                    req_ctx,
                    &req_headers,
                    stored.clone(),
                );
                return serve_stored(&stored, head_only, &req_headers, "STALE", cm);
            }
            _ => match cm.store.begin_fetch(&key) {
                Leadership::Leader(guard) => {
                    return fetch_and_decide(
                        cm,
                        &key,
                        req,
                        req_ctx,
                        route,
                        Some(stored),
                        dir.no_cache,
                        head_only,
                        &req_headers,
                        had_auth,
                        Some(guard),
                    )
                    .await;
                }
                Leadership::Follower(slot) => {
                    if tokio::time::timeout(FOLLOWER_WAIT, slot.wait())
                        .await
                        .is_err()
                    {
                        // leader's client is too slow — fetch
                        // independently rather than stall behind it
                        return fetch_and_decide(
                            cm,
                            &key,
                            req,
                            req_ctx,
                            route,
                            Some(stored),
                            dir.no_cache,
                            head_only,
                            &req_headers,
                            had_auth,
                            None,
                        )
                        .await;
                    }
                    return follower(
                        cm,
                        key,
                        req,
                        req_ctx,
                        route,
                        dir,
                        head_only,
                        &req_headers,
                        had_auth,
                    )
                    .await;
                }
            },
        }
    }

    if dir.only_if_cached {
        return tag(
            crate::server::service::error_response(
                http::StatusCode::GATEWAY_TIMEOUT,
                "only-if-cached: no cached response",
            ),
            "MISS",
            cm,
        );
    }
    match cm.store.begin_fetch(&key) {
        Leadership::Leader(guard) => {
            fetch_and_decide(
                cm,
                &key,
                req,
                req_ctx,
                route,
                None,
                false,
                head_only,
                &req_headers,
                had_auth,
                Some(guard),
            )
            .await
        }
        Leadership::Follower(slot) => {
            if tokio::time::timeout(FOLLOWER_WAIT, slot.wait())
                .await
                .is_err()
            {
                // leader's client is too slow — fetch independently
                return fetch_and_decide(
                    cm,
                    &key,
                    req,
                    req_ctx,
                    route,
                    None,
                    false,
                    head_only,
                    &req_headers,
                    had_auth,
                    None,
                )
                .await;
            }
            if let Lookup::Found(s) = cm.store.lookup(&key, &req_headers).await
                && usable(&s.meta, &dir)
            {
                let v = if s.meta.freshness() == Freshness::Fresh {
                    "HIT"
                } else {
                    "STALE"
                };
                return tag(crate::cache::respond(&s, head_only), v, cm);
            }
            tag(
                maybe_store(
                    cm,
                    &key,
                    run_handler(route, req, req_ctx).await,
                    &req_headers,
                    head_only,
                    had_auth,
                    None,
                )
                .await,
                "MISS",
                cm,
            )
        }
    }
}

/// Coalesced-waiter path after the leader commits: re-lookup once, serve
/// a usable entry, otherwise fetch directly (no second coalesce).
#[allow(clippy::too_many_arguments)]
async fn follower(
    cm: &RouteCacheMw,
    key: Key,
    req: http::Request<BoxBody>,
    req_ctx: &RequestCtx,
    route: &Route,
    dir: ReqDirectives,
    head_only: bool,
    req_headers: &HeaderMap,
    had_auth: bool,
) -> http::Response<BoxBody> {
    if let Lookup::Found(s) = cm.store.lookup(&key, req_headers).await
        && usable(&s.meta, &dir)
    {
        let v = if s.meta.freshness() == Freshness::Fresh {
            "HIT"
        } else {
            "STALE"
        };
        return tag(crate::cache::respond(&s, head_only), v, cm);
    }
    tag(
        maybe_store(
            cm,
            &key,
            run_handler(route, req, req_ctx).await,
            req_headers,
            head_only,
            had_auth,
            None,
        )
        .await,
        "MISS",
        cm,
    )
}

/// Entry is good enough to serve without touching the handler.
fn usable(m: &Meta, dir: &ReqDirectives) -> bool {
    !dir.no_cache
        && dir.max_age.is_none_or(|ma| m.age() <= ma)
        && dir
            .min_fresh
            .is_none_or(|mf| m.fresh_for.saturating_sub(m.age()) >= mf)
        && (m.freshness() == Freshness::Fresh || max_stale_ok(m, dir))
}

/// Request `max-stale` allowance against this entry's current staleness.
fn max_stale_ok(m: &Meta, dir: &ReqDirectives) -> bool {
    let Some(bound) = dir.max_stale else {
        return false;
    };
    let staleness = m.age().saturating_sub(m.fresh_for);
    bound.is_none_or(|b| staleness <= b)
}

/// Freshness adjusted by request directives (`max-age`/`min-fresh` can
/// demote an otherwise-fresh entry to revalidation).
fn effective_freshness(m: &Meta, dir: &ReqDirectives) -> Freshness {
    if dir.max_age.is_some_and(|ma| m.age() > ma)
        || dir
            .min_fresh
            .is_some_and(|mf| m.fresh_for.saturating_sub(m.age()) < mf)
    {
        return Freshness::Dead;
    }
    m.freshness()
}

/// Leader path: run the handler (conditionally when revalidating) and
/// fold the result into the cache. `guard` is held until the commit
/// completes so followers wake to a landed entry.
#[allow(clippy::too_many_arguments)]
async fn fetch_and_decide(
    cm: &RouteCacheMw,
    key: &Key,
    req: http::Request<BoxBody>,
    req_ctx: &RequestCtx,
    route: &Route,
    stale: Option<Arc<Stored>>,
    force_reval: bool,
    head_only: bool,
    req_headers: &HeaderMap,
    had_auth: bool,
    guard: Option<FetchGuard>,
) -> http::Response<BoxBody> {
    let (req, revalidating) = match &stale {
        Some(s) if s.meta.etag.is_some() || s.meta.last_modified.is_some() || force_reval => {
            (conditional_request(&req, &s.meta), true)
        }
        _ => (req, false),
    };
    let resp = run_handler(route, req, req_ctx).await;
    let status = resp.status();

    if revalidating && status == http::StatusCode::NOT_MODIFIED {
        let mut meta = stale
            .as_ref()
            .expect("revalidating implies stale")
            .meta
            .clone();
        apply_304_headers(&mut meta, resp.headers());
        cm.store
            .freshen(key, req_headers, &move |m: &mut Meta| *m = meta.clone())
            .await;
        drop(guard);
        if let Lookup::Found(s) = cm.store.lookup(key, req_headers).await {
            return serve_stored(&s, head_only, req_headers, "HIT", cm);
        }
        let s = stale.expect("checked above");
        return serve_stored(&s, head_only, req_headers, "HIT", cm);
    }

    if status.is_server_error()
        && let Some(s) = &stale
        && s.meta.freshness() != Freshness::Dead
    {
        drop(guard);
        return serve_stored(s, head_only, req_headers, "STALE", cm);
    }

    tag(
        maybe_store(cm, key, resp, req_headers, head_only, had_auth, guard).await,
        "MISS",
        cm,
    )
}

/// Headers a 304 is allowed to update on the stored entry — validator
/// and freshness metadata only. Merging the full 304 header set would
/// let an origin smuggle per-user headers (`set-cookie`, hop-by-hop
/// names) into a shared cache entry that gets replayed to everyone.
const REFRESH_WHITELIST: &[&str] = &[
    "etag",
    "last-modified",
    "cache-control",
    "expires",
    "date",
    "vary",
    "age",
    "content-type",
    "content-location",
];

/// Merge a 304's validator/freshness hints into the stored meta.
fn apply_304_headers(meta: &mut Meta, headers: &HeaderMap) {
    meta.stored_at = now_secs();
    let merge = |target: &mut Vec<(String, String)>| {
        for (k, v) in headers {
            let name = k.as_str();
            if !REFRESH_WHITELIST.contains(&name) {
                continue;
            }
            let name = name.to_string();
            let value = v.to_str().unwrap_or_default().to_string();
            if let Some(e) = target.iter_mut().find(|(n, _)| n == &name) {
                e.1 = value;
            } else {
                target.push((name, value));
            }
        }
    };
    merge(&mut meta.headers);
    if let Some(v) = headers
        .get(http::header::ETAG)
        .and_then(|v| v.to_str().ok())
    {
        meta.etag = Some(v.to_string());
    }
    if let Some(v) = headers
        .get(http::header::LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
    {
        meta.last_modified = Some(v.to_string());
    }
    let dir = semantics::response_directives(headers);
    if let Some(f) = semantics::declared_freshness(&dir, headers) {
        meta.fresh_for = f;
    }
}

/// Rebuild `req` as a conditional request against the stored validators.
fn conditional_request(req: &http::Request<BoxBody>, meta: &Meta) -> http::Request<BoxBody> {
    let mut b = http::Request::builder()
        .method(req.method().clone())
        .uri(req.uri().clone());
    let headers = b.headers_mut().expect("request builder headers");
    *headers = req.headers().clone();
    for h in [
        http::header::IF_NONE_MATCH,
        http::header::IF_MODIFIED_SINCE,
        http::header::IF_MATCH,
        http::header::IF_UNMODIFIED_SINCE,
        http::header::IF_RANGE,
    ] {
        headers.remove(h);
    }
    if let Some(e) = &meta.etag
        && let Ok(v) = http::HeaderValue::from_str(e)
    {
        headers.insert(http::header::IF_NONE_MATCH, v);
    }
    if let Some(l) = &meta.last_modified
        && let Ok(v) = http::HeaderValue::from_str(l)
    {
        headers.insert(http::header::IF_MODIFIED_SINCE, v);
    }
    b.body(body::empty()).expect("conditional request")
}

/// Decide whether `resp` may be stored; if so wrap its body in a tee
/// that commits on completion. The fetch `guard` moves into the commit
/// task so coalesced followers wake to a landed entry. `head_only`
/// responses are never stored: HEAD shares the GET key, and persisting
/// its empty body would poison subsequent GETs with a 200 + `Content-
/// Length: 0` entry until expiry. (A HEAD 304 still freshens an existing
/// entry via the revalidation path — that's RFC 9111 §4.3.5.)
async fn maybe_store(
    cm: &RouteCacheMw,
    key: &Key,
    resp: http::Response<BoxBody>,
    req_headers: &HeaderMap,
    head_only: bool,
    had_auth: bool,
    guard: Option<FetchGuard>,
) -> http::Response<BoxBody> {
    if head_only {
        return resp;
    }
    let dir = semantics::response_directives(resp.headers());
    let kind = semantics::storable(resp.status(), &dir, resp.headers(), had_auth);
    if kind == Store::No {
        return resp;
    }
    let negative = kind == Store::Negative;
    let (parts, body) = resp.into_parts();
    let (fresh_for, swr_for, sie_for) = semantics::freshness_windows(
        &dir,
        &parts.headers,
        negative,
        cm.cfg.ttl,
        cm.cfg.negative_ttl,
        cm.cfg.stale_while_revalidate,
        cm.cfg.stale_if_error,
    );
    let mut vary = semantics::response_vary(&parts.headers);
    for v in &cm.vary_headers {
        if !vary.contains(v) {
            vary.push(v.clone());
        }
    }
    let meta = Meta {
        key: key.raw.clone(),
        path: key
            .raw
            .split('\u{1f}')
            .nth(3)
            .and_then(|t| t.split('?').next())
            .unwrap_or_default()
            .to_string(),
        status: parts.status.as_u16(),
        headers: parts
            .headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect(),
        stored_at: now_secs(),
        fresh_for,
        swr_for,
        sie_for,
        etag: parts
            .headers
            .get(http::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
        last_modified: parts
            .headers
            .get(http::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
        // the *request's* values for each vary axis
        vary: vary_values(&vary, req_headers),
        negative,
        body_len: 0, // fixed when the tee completes
    };
    let (tx, rx) = tokio::sync::oneshot::channel::<bytes::Bytes>();
    let store = cm.store.clone();
    tokio::spawn(async move {
        let _guard = guard; // hold the slot until the entry lands
        if let Ok(body) = rx.await {
            let mut meta = meta;
            meta.body_len = body.len() as u64;
            store.record(meta, body).await;
        }
    });
    let expected = parts
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    http::Response::from_parts(
        parts,
        crate::cache::tee::new(body, tx, cm.store.max_object(), expected),
    )
}

/// Run the route's handler under its request deadline.
async fn run_handler(
    route: &Route,
    req: http::Request<BoxBody>,
    req_ctx: &RequestCtx,
) -> http::Response<BoxBody> {
    let fut = route.handler.handle(req, req_ctx);
    if route.timeouts.request_deadline.is_zero() {
        fut.await
    } else {
        match tokio::time::timeout(route.timeouts.request_deadline, fut).await {
            Ok(r) => r,
            Err(_) => crate::server::service::error_response(
                http::StatusCode::GATEWAY_TIMEOUT,
                "request deadline exceeded",
            ),
        }
    }
}

/// Background revalidation for SWR — deduped via the fetch slot.
#[allow(clippy::too_many_arguments)]
fn spawn_revalidate(
    cm: &RouteCacheMw,
    rt: &Arc<crate::server::Runtime>,
    handle: (usize, usize),
    key: &Key,
    req: &http::Request<BoxBody>,
    req_ctx: &RequestCtx,
    req_headers: &HeaderMap,
    stale: Arc<Stored>,
) {
    let Leadership::Leader(guard) = cm.store.begin_fetch(key) else {
        return; // another revalidation in flight
    };
    let cm_store = cm.store.clone();
    let cm_cfg = cm.cfg.clone();
    let vary_headers = cm.vary_headers.clone();
    let key = key.clone();
    let req_headers = req_headers.clone();
    let req = conditional_request(req, &stale.meta);
    let req_ctx = req_ctx.clone();
    let rt = rt.clone();
    tokio::spawn(async move {
        let _guard = guard;
        let Some(route) = rt
            .hosts
            .sites
            .get(handle.0)
            .and_then(|s| s.routes.get(handle.1))
        else {
            return;
        };
        let cm = RouteCacheMw {
            store: cm_store,
            cfg: cm_cfg,
            vary_headers,
        };
        let resp = run_handler(route, req, &req_ctx).await;
        if resp.status() == http::StatusCode::NOT_MODIFIED {
            let mut meta = stale.meta.clone();
            apply_304_headers(&mut meta, resp.headers());
            cm.store
                .freshen(&key, &req_headers, &move |m: &mut Meta| *m = meta.clone())
                .await;
            return;
        }
        let resp = maybe_store(&cm, &key, resp, &req_headers, false, false, None).await;
        // drain the revalidated body so the tee can commit
        let _ = http_body_util::BodyExt::collect(resp.into_body()).await;
    });
}

/// Serve a stored entry — a client conditional that matches the
/// entry's validators short-circuits to a 304.
fn serve_stored(
    stored: &Stored,
    head_only: bool,
    req_headers: &HeaderMap,
    value: &'static str,
    cm: &RouteCacheMw,
) -> http::Response<BoxBody> {
    if client_conditional(req_headers, &stored.meta) {
        return tag(not_modified(&stored.meta), value, cm);
    }
    tag(crate::cache::respond(stored, head_only), value, cm)
}

/// RFC 7232 client-side conditional evaluation against a stored entry:
/// `If-None-Match` wins; `If-Modified-Since` applies when no INM.
fn client_conditional(headers: &HeaderMap, meta: &Meta) -> bool {
    if let Some(inm) = headers
        .get(http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        let Some(etag) = &meta.etag else { return false };
        return inm.split(',').map(str::trim).any(|c| {
            c == "*" || c.strip_prefix("W/").unwrap_or(c) == etag.strip_prefix("W/").unwrap_or(etag)
        });
    }
    if headers
        .get(http::header::IF_MODIFIED_SINCE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| httpdate::parse_http_date(v).ok())
        .zip(
            meta.last_modified
                .as_deref()
                .and_then(|v| httpdate::parse_http_date(v).ok()),
        )
        .is_some_and(|(since, lm)| lm <= since)
    {
        return true;
    }
    false
}

/// Compose a 304 from the stored meta's freshness/validator headers.
fn not_modified(meta: &Meta) -> http::Response<BoxBody> {
    let keep = [
        "etag",
        "last-modified",
        "cache-control",
        "date",
        "expires",
        "vary",
    ];
    let mut resp = http::Response::new(body::empty());
    *resp.status_mut() = http::StatusCode::NOT_MODIFIED;
    for (k, v) in meta.header_map().iter() {
        if keep.contains(&k.as_str()) {
            resp.headers_mut().append(k.clone(), v.clone());
        }
    }
    resp
}

/// Attach `X-Cache` when the route enables it.
fn tag(
    mut resp: http::Response<BoxBody>,
    value: &'static str,
    cm: &RouteCacheMw,
) -> http::Response<BoxBody> {
    if cm.cfg.x_cache {
        resp.headers_mut().insert(
            http::header::HeaderName::from_static("x-cache"),
            http::HeaderValue::from_static(value),
        );
    }
    cm.store.meters.result(value);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    /// Base config: one cached route serving `respond` — no external deps.
    const BASE: &str = r#"
[cache.c]
tier = "ram"
[[site]]
hosts = ["x"]
tls = "off"
[[site.route]]
prefix = "/p"
respond = { status = 200, body = "hi", headers = { "cache-control" = "max-age=60", "etag" = "\"v1\"" } }
cache = { store = "c" }
"#;

    struct Rig {
        rt: Arc<crate::server::Runtime>,
    }

    impl Rig {
        fn new(extra: &str) -> Self {
            let cfg = crate::config::validate::parse_test_config(extra);
            let rt = crate::server::Runtime::build(Arc::new(cfg)).unwrap();
            Self { rt }
        }
        fn cm(&self) -> &RouteCacheMw {
            self.rt.hosts.sites[0].routes[0]
                .middleware
                .cache
                .as_ref()
                .unwrap()
        }
        fn route(&self) -> &Route {
            &self.rt.hosts.sites[0].routes[0]
        }
        /// Full plan+serve round trip for a request to /p on host x.
        async fn call(
            &self,
            req: http::Request<BoxBody>,
            handle: (usize, usize),
            authed: bool,
        ) -> http::Response<BoxBody> {
            let (parts, b) = req.into_parts();
            let req_ctx = RequestCtx {
                path: "/p".into(),
                host: "x".into(),
                client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                peer_trusted: false,
                tls: false,
                scheme: "http",
            };
            let p = plan(self.cm(), &parts, "x", "http", "/p", authed, None);
            serve(
                self.cm(),
                p,
                &self.rt,
                handle,
                self.route(),
                http::Request::from_parts(parts, b),
                &req_ctx,
            )
            .await
        }
        /// The cache key a GET /p request would use (for manual record()).
        async fn key_for(&self) -> Key {
            let req = req_for("/p", &[]);
            let (parts, _) = req.into_parts();
            match plan(self.cm(), &parts, "x", "http", "/p", false, None) {
                Plan::Use { key, .. } => key,
                Plan::Bypass => panic!("expected Use plan"),
            }
        }
        /// Insert an entry directly into the store.
        async fn seed(&self, age: u64, fresh_for: u64, swr: u64, sie: u64) {
            let key = self.key_for().await;
            self.cm()
                .store
                .record(
                    Meta {
                        key: key.raw.clone(),
                        path: "/p".into(),
                        status: 200,
                        headers: vec![
                            ("cache-control".into(), "max-age=60".into()),
                            ("etag".into(), "\"v1\"".into()),
                            (
                                "last-modified".into(),
                                "Thu, 01 Jan 1970 00:00:00 GMT".into(),
                            ),
                        ],
                        stored_at: now_secs() - age,
                        fresh_for,
                        swr_for: swr,
                        sie_for: sie,
                        etag: Some("\"v1\"".into()),
                        last_modified: Some("Thu, 01 Jan 1970 00:00:00 GMT".into()),
                        vary: vec![],
                        negative: false,
                        body_len: 2,
                    },
                    bytes::Bytes::from_static(b"hi"),
                )
                .await;
        }
    }

    fn req_for(uri: &str, headers: &[(&str, &str)]) -> http::Request<BoxBody> {
        let mut b = http::Request::builder().uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(body::empty()).unwrap()
    }

    fn x_cache(resp: &http::Response<BoxBody>) -> &str {
        resp.headers()
            .get("x-cache")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }

    #[tokio::test]
    async fn miss_then_hit() {
        let rig = Rig::new(BASE);
        let r1 = rig.call(req_for("/p", &[]), (0, 0), false).await;
        assert_eq!(x_cache(&r1), "MISS");
        // drain the tee so the entry lands
        let _ = http_body_util::BodyExt::collect(r1.into_body()).await;
        tokio::task::yield_now().await;
        let r2 = rig.call(req_for("/p", &[]), (0, 0), false).await;
        assert_eq!(x_cache(&r2), "HIT");
    }

    #[tokio::test]
    async fn bypasses() {
        // POST bypasses (ineligible method)
        let rig = Rig::new(BASE);
        let req = http::Request::builder()
            .method("POST")
            .uri("/p")
            .body(body::empty())
            .unwrap();
        let r = rig.call(req, (0, 0), false).await;
        assert_eq!(x_cache(&r), "BYPASS");

        // authenticated requests bypass when bypass.authenticated
        let r = rig.call(req_for("/p", &[]), (0, 0), true).await;
        assert_eq!(x_cache(&r), "BYPASS");
        // raw Authorization header also bypasses
        let r = rig
            .call(
                req_for("/p", &[("authorization", "Bearer t")]),
                (0, 0),
                false,
            )
            .await;
        assert_eq!(x_cache(&r), "BYPASS");
        // request no-store bypasses
        let r = rig
            .call(
                req_for("/p", &[("cache-control", "no-store")]),
                (0, 0),
                false,
            )
            .await;
        assert_eq!(x_cache(&r), "BYPASS");
    }

    #[tokio::test]
    async fn bypass_cookies_headers_paths() {
        let toml = r#"
[cache.c]
tier = "ram"
[[site]]
hosts = ["x"]
tls = "off"
[[site.route]]
prefix = "/p"
respond = { status = 200, body = "hi" }
cache = { store = "c", bypass = { cookies = ["session"], headers = ["x-skip"], paths = ["/p"] } }
"#;
        let rig = Rig::new(toml);
        // matching path glob
        assert_eq!(
            x_cache(&rig.call(req_for("/p", &[]), (0, 0), false).await),
            "BYPASS"
        );
        // bypass header
        assert_eq!(
            x_cache(
                &rig.call(req_for("/x", &[("x-skip", "1")]), (0, 0), false)
                    .await
            ),
            "BYPASS"
        );
        // named cookie / wildcard list / non-matching cookie
        let rig2 = Rig::new(
            r#"
[cache.c]
tier = "ram"
[[site]]
hosts = ["x"]
tls = "off"
[[site.route]]
prefix = "/p"
respond = { status = 200, body = "hi" }
cache = { store = "c", bypass = { cookies = ["session"] } }
"#,
        );
        assert_eq!(
            x_cache(
                &rig2
                    .call(
                        req_for("/p", &[("cookie", "session=1; other=2")]),
                        (0, 0),
                        false
                    )
                    .await
            ),
            "BYPASS"
        );
        assert_ne!(
            x_cache(
                &rig2
                    .call(req_for("/p", &[("cookie", "other=2")]), (0, 0), false)
                    .await
            ),
            "BYPASS"
        );
        let rig3 = Rig::new(
            r#"
[cache.c]
tier = "ram"
[[site]]
hosts = ["x"]
tls = "off"
[[site.route]]
prefix = "/p"
respond = { status = 200, body = "hi" }
cache = { store = "c", bypass = { cookies = ["*"] } }
"#,
        );
        assert_eq!(
            x_cache(
                &rig3
                    .call(req_for("/p", &[("cookie", "a=b")]), (0, 0), false)
                    .await
            ),
            "BYPASS"
        );
        // bypass.methods: GET listed → even GET bypasses
        let rig4 = Rig::new(
            r#"
[cache.c]
tier = "ram"
[[site]]
hosts = ["x"]
tls = "off"
[[site.route]]
prefix = "/p"
respond = { status = 200, body = "hi" }
cache = { store = "c", bypass = { methods = ["get"] } }
"#,
        );
        assert_eq!(
            x_cache(&rig4.call(req_for("/p", &[]), (0, 0), false).await),
            "BYPASS"
        );
    }

    #[tokio::test]
    async fn strip_query_keeps_secret_out_of_key() {
        let rig = Rig::new(BASE);
        let req = req_for("/p?api_key=sekret&b=2", &[]);
        let (parts, _) = req.into_parts();
        let p = plan(rig.cm(), &parts, "x", "http", "/p", false, Some("api_key"));
        let Plan::Use { key, .. } = p else { panic!() };
        assert!(!key.raw.contains("sekret"));
        assert!(key.raw.contains("b=2"));
    }

    #[tokio::test]
    async fn stale_entry_with_max_stale() {
        let rig = Rig::new(BASE);
        rig.seed(100, 60, 0, 0).await; // 40s stale
        let r = rig
            .call(
                req_for("/p", &[("cache-control", "max-stale=50")]),
                (0, 0),
                false,
            )
            .await;
        assert_eq!(x_cache(&r), "STALE");
        // bound too tight → refetch
        let r = rig
            .call(
                req_for("/p", &[("cache-control", "max-stale=10")]),
                (0, 0),
                false,
            )
            .await;
        assert_eq!(x_cache(&r), "MISS");
        // bare max-stale accepts any staleness
        let r = rig
            .call(
                req_for("/p", &[("cache-control", "max-stale")]),
                (0, 0),
                false,
            )
            .await;
        assert_eq!(x_cache(&r), "STALE");
    }

    #[tokio::test]
    async fn stale_if_error_serves_stale() {
        let toml = r#"
[cache.c]
tier = "ram"
[[site]]
hosts = ["x"]
tls = "off"
[[site.route]]
prefix = "/p"
respond = { status = 500, body = "boom" }
cache = { store = "c" }
"#;
        let rig = Rig::new(toml);
        rig.seed(100, 60, 0, 300).await; // dead-ish but inside SIE window
        let r = rig.call(req_for("/p", &[]), (0, 0), false).await;
        assert_eq!(x_cache(&r), "STALE");
        assert_eq!(r.status(), 200);
    }

    #[tokio::test]
    async fn swr_revalidates_in_background() {
        let rig = Rig::new(BASE);
        rig.seed(100, 60, 300, 0).await; // stale, inside SWR window
        let r = rig.call(req_for("/p", &[]), (0, 0), false).await;
        assert_eq!(x_cache(&r), "STALE");
        // background revalidation replaces the entry — give it a beat
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let r = rig.call(req_for("/p", &[]), (0, 0), false).await;
        assert_eq!(x_cache(&r), "HIT");

        // dead handle → the revalidation task exits early
        rig.seed(100, 60, 300, 0).await;
        let r = rig.call(req_for("/p", &[]), (0, 99), false).await;
        assert_eq!(x_cache(&r), "STALE");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn revalidate_304_refreshes() {
        // handler answers 304 to the conditional request
        let toml = r#"
[cache.c]
tier = "ram"
[[site]]
hosts = ["x"]
tls = "off"
[[site.route]]
prefix = "/p"
respond = { status = 304, headers = { "etag" = "\"v2\"", "cache-control" = "max-age=600" } }
cache = { store = "c" }
"#;
        let rig = Rig::new(toml);
        rig.seed(100, 60, 0, 0).await; // dead, has validators
        let r = rig.call(req_for("/p", &[]), (0, 0), false).await;
        // 304 freshened the entry → served as a HIT
        assert_eq!(x_cache(&r), "HIT");
        assert_eq!(r.status(), 200);
    }

    #[tokio::test]
    async fn only_if_cached_without_entry_is_504() {
        let rig = Rig::new(BASE);
        let r = rig
            .call(
                req_for("/p", &[("cache-control", "only-if-cached")]),
                (0, 0),
                false,
            )
            .await;
        assert_eq!(r.status(), http::StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(x_cache(&r), "MISS");
    }

    #[tokio::test]
    async fn no_store_response_is_not_stored() {
        let toml = r#"
[cache.c]
tier = "ram"
[[site]]
hosts = ["x"]
tls = "off"
[[site.route]]
prefix = "/p"
respond = { status = 200, body = "hi", headers = { "cache-control" = "no-store" } }
cache = { store = "c" }
"#;
        let rig = Rig::new(toml);
        let r1 = rig.call(req_for("/p", &[]), (0, 0), false).await;
        let _ = http_body_util::BodyExt::collect(r1.into_body()).await;
        tokio::task::yield_now().await;
        let r2 = rig.call(req_for("/p", &[]), (0, 0), false).await;
        assert_eq!(x_cache(&r2), "MISS");
    }

    #[tokio::test]
    async fn min_fresh_and_max_age_demote() {
        let rig = Rig::new(BASE);
        rig.seed(10, 60, 0, 0).await; // fresh: age 10 < 60
        let r = rig
            .call(
                req_for("/p", &[("cache-control", "max-age=5")]),
                (0, 0),
                false,
            )
            .await;
        assert_eq!(x_cache(&r), "MISS");
        let r = rig
            .call(
                req_for("/p", &[("cache-control", "min-fresh=3600")]),
                (0, 0),
                false,
            )
            .await;
        assert_eq!(x_cache(&r), "MISS");
    }

    #[tokio::test]
    async fn client_conditionals_short_circuit_304() {
        let rig = Rig::new(BASE);
        rig.seed(0, 60, 0, 0).await; // fresh
        for inm in ["\"v1\"", "*", "W/\"v1\"", "\"other\", \"v1\""] {
            let r = rig
                .call(req_for("/p", &[("if-none-match", inm)]), (0, 0), false)
                .await;
            assert_eq!(r.status(), http::StatusCode::NOT_MODIFIED, "{inm}");
        }
        let r = rig
            .call(
                req_for("/p", &[("if-none-match", "\"nope\"")]),
                (0, 0),
                false,
            )
            .await;
        assert_eq!(r.status(), 200);
        // If-Modified-Since with stored last-modified in the past → 304
        let r = rig
            .call(
                req_for(
                    "/p",
                    &[("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT")],
                ),
                (0, 0),
                false,
            )
            .await;
        assert_eq!(r.status(), http::StatusCode::NOT_MODIFIED);
    }

    #[tokio::test(start_paused = true)]
    async fn follower_times_out_and_fetches_itself() {
        let rig = Rig::new(BASE);
        let key = rig.key_for().await;
        let _guard = match rig.cm().store.begin_fetch(&key) {
            Leadership::Leader(g) => g,
            Leadership::Follower(_) => panic!("first fetch must lead"),
        };
        // no stored entry → MISS path → Follower → wait 5s (paused → instant)
        let r = rig.call(req_for("/p", &[]), (0, 0), false).await;
        assert_eq!(x_cache(&r), "MISS");
        assert_eq!(r.status(), 200);
    }

    #[tokio::test]
    async fn follower_serves_committed_entry() {
        let rig = Rig::new(BASE);
        let key = rig.key_for().await;
        let guard = match rig.cm().store.begin_fetch(&key) {
            Leadership::Leader(g) => g,
            Leadership::Follower(_) => panic!(),
        };
        // serve sees the in-flight slot as Follower; meanwhile the "leader"
        // commits an entry and drops its guard, waking us
        let serve = rig.call(req_for("/p", &[]), (0, 0), false);
        tokio::pin!(serve);
        let work = async {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            rig.seed(0, 60, 0, 0).await;
            drop(guard);
        };
        let resp = tokio::select! {
            r = &mut serve => r,
            _ = work => serve.await,
        };
        assert_eq!(x_cache(&resp), "HIT");
    }

    #[tokio::test]
    async fn vary_headers_partition_entries() {
        let toml = r#"
[cache.c]
tier = "ram"
[[site]]
hosts = ["x"]
tls = "off"
[[site.route]]
prefix = "/p"
respond = { status = 200, body = "hi", headers = { "cache-control" = "max-age=60" } }
cache = { store = "c", vary_headers = ["x-tenant"] }
"#;
        let rig = Rig::new(toml);
        let r = rig
            .call(req_for("/p", &[("x-tenant", "a")]), (0, 0), false)
            .await;
        let _ = http_body_util::BodyExt::collect(r.into_body()).await;
        tokio::task::yield_now().await;
        let r = rig
            .call(req_for("/p", &[("x-tenant", "b")]), (0, 0), false)
            .await;
        assert_eq!(x_cache(&r), "MISS"); // different tenant → different key
        let _ = http_body_util::BodyExt::collect(r.into_body()).await;
        tokio::task::yield_now().await;
        let r = rig
            .call(req_for("/p", &[("x-tenant", "a")]), (0, 0), false)
            .await;
        assert_eq!(x_cache(&r), "HIT");
    }

    #[tokio::test]
    async fn head_shares_get_but_never_stores() {
        let rig = Rig::new(BASE);
        let head = || {
            http::Request::builder()
                .method("HEAD")
                .uri("/p")
                .body(body::empty())
                .unwrap()
        };
        // HEAD on an empty cache: MISS, and nothing may be recorded —
        // storing the empty HEAD body under the shared GET key poisoned
        // subsequent GETs with `200 Content-Length: 0` until expiry
        let r = rig.call(head(), (0, 0), false).await;
        assert_eq!(x_cache(&r), "MISS");
        let _ = http_body_util::BodyExt::collect(r.into_body()).await;
        tokio::task::yield_now().await;
        // the GET must still fetch the real body
        let r = rig.call(req_for("/p", &[]), (0, 0), false).await;
        assert_eq!(x_cache(&r), "MISS");
        let got = http_body_util::BodyExt::collect(r.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&got[..], b"hi");
        tokio::task::yield_now().await;
        // HEAD *lookups* still ride the stored GET entry
        let r = rig.call(head(), (0, 0), false).await;
        assert_eq!(x_cache(&r), "HIT");
    }

    #[tokio::test]
    async fn prefix_purge_matches_request_path() {
        let rig = Rig::new(BASE);
        let r = rig.call(req_for("/p", &[]), (0, 0), false).await;
        assert_eq!(x_cache(&r), "MISS");
        let _ = http_body_util::BodyExt::collect(r.into_body()).await;
        tokio::task::yield_now().await;
        // regression: meta.path held the authority (key field 2), not the
        // request path — a prefix purge could never match anything
        assert_eq!(rig.cm().store.purge_prefix("/p").await, 1);
        let r = rig.call(req_for("/p", &[]), (0, 0), false).await;
        assert_eq!(x_cache(&r), "MISS");
    }
}
