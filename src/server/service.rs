//! The request pipeline: every request flows through these stages in order.
//! Keep this ordering aligned with the architecture docs.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use hyper::body::Incoming;

use crate::body::{self, BoxBody, LimitBody, TimeoutBody};
use crate::config::model as cfg;
use crate::handler::RequestCtx;
use crate::observe::{self, RequestId};
use crate::router::normalize::{self, NormalizeError};
use crate::server::Runtime;

/// Per-connection context shared with every request on the connection.
#[derive(Clone)]
pub struct ConnCtx {
    /// Peer address.
    pub remote: SocketAddr,
    /// Whether the connection carries TLS.
    pub tls: bool,
    /// Requests served on this connection so far.
    pub request_counter: Arc<AtomicUsize>,
    /// Negotiated TLS version label (e.g. `TLSv1_3`), when TLS.
    pub tls_version: Option<String>,
    /// Set once the first request completes — switches the connection's
    /// read deadline from `header_read` to keep-alive `idle`.
    pub first_request_done: Arc<AtomicBool>,
    /// Read-deadline gate: incremented while a request cycle is in
    /// flight, permanently `off` for upgrade tunnels.
    pub read_gate: crate::server::timeout::DeadlineGate,
    /// This connection's admission slot. Clones share one slot — the
    /// proxy's upgrade path hands a clone to the tunnel task so an
    /// upgraded tunnel keeps counting against connection limits until
    /// it actually closes.
    pub conn_guard: crate::server::ConnGuard,
}

/// Entry point for every request, called by hyper per request on a
/// connection. Never fails: all errors become responses.
pub async fn handle(
    req: http::Request<Incoming>,
    ctx: ConnCtx,
    rt: Arc<Runtime>,
) -> Result<http::Response<BoxBody>, std::convert::Infallible> {
    let started = Instant::now();
    ctx.request_counter.fetch_add(1, Ordering::Relaxed);
    // the response cycle owns the connection until its body ends —
    // disarm the between-requests read deadline (re-armed by the
    // AccessLogBody at stream end/drop). `armed` must be cleared here,
    // not just on a gated poll_read: hyper may never poll the read side
    // while `active > 0`, so a stale window entry would otherwise
    // outlive the response and kill the conn on the old deadline.
    ctx.read_gate.active.fetch_add(1, Ordering::Relaxed);
    ctx.read_gate
        .armed
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();

    let (mut parts, body) = req.into_parts();
    // let the proxy's upgrade path permanently disarm the deadline
    parts
        .extensions
        .insert(crate::server::timeout::DeadlineOff(ctx.read_gate.clone()));
    // ...and hold the connection's admission slot for the tunnel's
    // lifetime, so upgrade tunnels can't escape max_connections limits
    parts.extensions.insert(ctx.conn_guard.clone());
    let req_id = RequestId::extract(&parts.headers);
    parts.extensions.insert(req_id.clone());
    let method_is_head = parts.method == http::Method::HEAD;
    let mut log = observe::LogRecord::new(&ctx, &parts, &req_id);

    let response = pipeline(parts, body, &ctx, &rt, &mut log).await;
    let mut response = match response {
        Ok(r) => r,
        Err(resp) => resp, // early-exit responses travel the error channel
    };

    finish_response(&mut response, &rt, &req_id);
    ctx.first_request_done.store(true, Ordering::Relaxed);
    // response-side fields now; the body wrapper counts streamed bytes
    // and emits the record (or 499 on client abort) at stream end
    log.finish_headers(&response);
    crate::observe::logbody::wrap(
        &mut response,
        log,
        rt.clone(),
        started,
        method_is_head,
        ctx.read_gate.clone(),
    );
    Ok(response)
}

/// The pipeline proper; `Err` carries a ready-made response for early exits
/// (limits, auth, redirects) that skip the handler.
// Err is deliberately a full Response — it's a hot early-exit path and
// the variant IS the value; boxing would add an alloc per rejection.
#[allow(clippy::result_large_err)]
async fn pipeline(
    mut parts: http::request::Parts,
    body: Incoming,
    ctx: &ConnCtx,
    rt: &Arc<Runtime>,
    log: &mut observe::LogRecord,
) -> Result<http::Response<BoxBody>, http::Response<BoxBody>> {
    // 1. global header-size limit
    if !within_header_limit(&parts, rt.config.limits.header_bytes.0) {
        return Err(error_response(
            http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "request headers too large",
        ));
    }

    // 1.5 ACME http-01 — before site routing since on-demand hosts may
    // not have a configured site at all. Tokens are unguessable.
    if let Some(am) = &rt.acme
        && let Some(token) = parts
            .uri
            .path()
            .strip_prefix("/.well-known/acme-challenge/")
        && let Some(key_auth) = am.http01.lookup(token)
    {
        let mut resp = http::Response::new(body::full(key_auth));
        resp.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/plain"),
        );
        return Err(resp);
    }

    // 2. path normalization
    let path = parts.uri.path().to_string();
    let normalized = normalize::normalize_path(&path).map_err(|e| match e {
        NormalizeError::Nul | NormalizeError::Control | NormalizeError::Utf8 => {
            error_response(http::StatusCode::BAD_REQUEST, "malformed path")
        }
    })?;

    // 3. host routing
    let host = parts
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| parts.uri.authority().map(|a| a.to_string()))
        .ok_or_else(|| error_response(http::StatusCode::BAD_REQUEST, "missing Host"))?;
    let (site_idx, site) = rt
        .hosts
        .lookup_idx(&host)
        .ok_or_else(|| error_response(http::StatusCode::MISDIRECTED_REQUEST, "no site for host"))?;

    // 3.5 HTTP→HTTPS redirect: site wants TLS, a certificate exists for
    // this host, and the request arrived in plaintext.
    if !ctx.tls
        && site.redirect_https
        && !matches!(site.tls, cfg::SiteTls::Mode(cfg::TlsMode::Off))
        && let Some(resp) = https_redirect(&parts, &host, site, rt)
    {
        return Err(resp);
    }

    // 4. effective client IP (trusted proxy aware)
    let trusted = site
        .trusted_proxies
        .as_ref()
        .unwrap_or(&rt.config.server.trusted_proxies);
    let peer_trusted = trusted.iter().any(|n| n.contains(&ctx.remote.ip()));
    let client_ip = real_ip(ctx.remote.ip(), &parts, trusted);

    // 5. route match
    let (route_idx, route) = site
        .match_route_idx(&parts, &normalized)
        .ok_or_else(|| error_response(http::StatusCode::NOT_FOUND, "not found"))?;
    log.set_route(&route.id, route.meters.clone());

    // post-route early exits still carry this route's security headers
    // and CORS decoration (a denied cross-origin request can't read the
    // response without ACAO, but the headers do no harm and keep the
    // browser console/debug view accurate)
    let cors_origin = parts
        .headers
        .get(http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    // request facts the response-stage middleware needs after `parts`
    // moves into the handler request
    let compress_ctx = crate::middleware::compress::ReqCtx {
        method_is_head: parts.method == http::Method::HEAD,
        has_range: parts.headers.contains_key(http::header::RANGE),
        accept_encoding: parts
            .headers
            .get(http::header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
    };
    let early = |mut resp: http::Response<BoxBody>| -> http::Response<BoxBody> {
        if let Some(sec) = &route.middleware.security {
            sec.apply(resp.headers_mut(), ctx.tls);
        }
        if let Some(cors) = &route.middleware.cors {
            cors.apply(resp.headers_mut(), cors_origin.as_deref());
        }
        resp
    };

    // 6. ip acl
    if route.middleware.check_ip(client_ip).is_err() {
        return Err(early(crate::middleware::forbidden()));
    }

    // 6.5 CORS preflight — short-circuits before auth since preflights
    // carry no credentials
    if let Some(cors) = &route.middleware.cors
        && let Some(resp) = cors.preflight(&parts)
    {
        return Err(early(resp));
    }

    // 6.6 rate limit — pre-auth pass keyed by IP. Credential
    // verification below costs ~50-100ms of CPU per attempt; without a
    // cheap gate in front, a bogus-credentials spray consumes the limit
    // *after* paying for the hashing it was meant to prevent.
    let mut rate_stamp = None;
    if let Some(rl) = &route.middleware.rate_limit
        && let Some(decision) = rl.check(client_ip, None, &parts, &route.id)
    {
        if !decision.allowed {
            route.meters.ratelimit();
            let mut r = crate::middleware::ratelimit::too_many(&decision);
            rl.headers(&decision, r.headers_mut());
            return Err(early(r));
        }
        // allowed: RateLimit-* headers ride the eventual response
        rate_stamp = Some((rl.clone(), decision));
    }

    // 6.7 authentication — the hash verify runs on the blocking pool so
    // a credential spray can't pin reactor workers.
    let mut identity = None;
    if let Some(auth) = &route.middleware.auth {
        match auth.check_throttled(&parts).await {
            crate::middleware::auth::Outcome::Authenticated(id) => {
                log.set_identity(&id.0);
                parts.extensions.insert(id.clone());
                identity = Some(id.0);
            }
            crate::middleware::auth::Outcome::Rejected(resp) => return Err(early(resp)),
        }
    }

    // 6.8 rate limit — post-auth pass, identity-keyed limiters only:
    // every other key kind already consumed its token pre-auth.
    if let Some(rl) = &route.middleware.rate_limit
        && identity.is_some()
        && rl.identity_keyed()
        && let Some(decision) = rl.check(client_ip, identity.as_deref(), &parts, &route.id)
    {
        if !decision.allowed {
            route.meters.ratelimit();
            let mut r = crate::middleware::ratelimit::too_many(&decision);
            rl.headers(&decision, r.headers_mut());
            return Err(early(r));
        }
        rate_stamp = Some((rl.clone(), decision));
    }

    // 6.8 cache — decide cacheability while `parts` is still available;
    // the actual lookup happens after the request body is wrapped below.
    // A query-carried api key is stripped from the key so credentials
    // don't persist in the store.
    let strip_query = route
        .middleware
        .auth
        .as_ref()
        .and_then(|a| a.credential_query_param());
    let cache_stage = route.middleware.cache.as_ref().map(|cm| {
        crate::cache::stage::plan(
            cm,
            &parts,
            &host,
            if ctx.tls { "https" } else { "http" },
            &normalized,
            identity.is_some(),
            strip_query,
        )
    });

    // 7. request limits: body size (early via Content-Length, then streamed)
    if let Some(cl) = content_length(&parts)
        && cl > route.limits.body_bytes.0
    {
        return Err(early(error_response(
            http::StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large",
        )));
    }
    let body = TimeoutBody::new(
        LimitBody::counted(
            body::boxed(body),
            route.limits.body_bytes.0,
            log.req_bytes(),
        ),
        route.timeouts.body_read,
    );
    // the route's send deadline also bounds tunnel inactivity if this
    // request upgrades downstream of here
    parts
        .extensions
        .insert(crate::server::timeout::SendDeadline(route.timeouts.send));
    let req = http::Request::from_parts(parts, body::boxed(body));

    // 8. handler under the route's request deadline
    let req_ctx = RequestCtx {
        path: normalized,
        host,
        client_ip,
        peer_ip: ctx.remote.ip(),
        peer_trusted,
        tls: ctx.tls,
        scheme: if ctx.tls { "https" } else { "http" },
    };
    let mut resp = match (route.middleware.cache.as_ref(), cache_stage) {
        // 8a. cached route — the stage wraps the handler invocation with
        // lookup/revalidate/store/coalesce semantics
        (Some(cm), Some(plan)) => {
            crate::cache::stage::serve(cm, plan, rt, (site_idx, route_idx), route, req, &req_ctx)
                .await
        }
        // 8b. uncached route — handler under its request deadline
        _ => {
            let handler_fut = route.handler.handle(req, &req_ctx);
            if route.timeouts.request_deadline.is_zero() {
                handler_fut.await
            } else {
                match tokio::time::timeout(route.timeouts.request_deadline, handler_fut).await {
                    Ok(r) => r,
                    Err(_) => {
                        return Err(early(error_response(
                            http::StatusCode::GATEWAY_TIMEOUT,
                            "request deadline exceeded",
                        )));
                    }
                }
            }
        }
    };

    // 9. response middleware: security defaults first (absent-only), then
    // CORS decoration, RateLimit-*, then explicit route header ops which
    // may override any of the above
    if let Some(sec) = &route.middleware.security {
        sec.apply(resp.headers_mut(), ctx.tls);
    }
    if let Some(cors) = &route.middleware.cors {
        cors.apply(resp.headers_mut(), cors_origin.as_deref());
    }
    if let Some((rl, d)) = &rate_stamp {
        rl.headers(d, resp.headers_mut());
    }
    if let Some(ops) = &route.middleware.headers {
        ops.apply(resp.headers_mut());
    }
    // compression is outermost: it transforms the body and
    // Content-Encoding/ETag/Vary on the final representation
    if let Some(comp) = &route.middleware.compress {
        comp.apply(&mut resp, &compress_ctx);
    }
    Ok(resp)
}

/// Build the `308` HTTPS-redirect response when the request deserves one:
/// the site wants TLS, a certificate is actually registered for this
/// host, and a TLS listener exists to send clients to. Path and query are
/// preserved verbatim.
fn https_redirect(
    parts: &http::request::Parts,
    host: &str,
    site: &crate::router::Site,
    rt: &Runtime,
) -> Option<http::Response<BoxBody>> {
    let tls_rt = rt.tls.as_ref()?;
    let host_norm = crate::router::normalize_host(host);
    if !tls_rt.resolver.has_cert(&host_norm) {
        // e.g. tls = "auto" before ACME issuance — serve HTTP for now
        return None;
    }
    let port = rt
        .config
        .server
        .listen
        .iter()
        .find(|l| l.tls)
        .map(|l| l.addr.port())?;
    // normalize_host already stripped any port
    let target_host = site.redirect_host.as_deref().unwrap_or(&host_norm);
    let authority = if port == 443 {
        target_host.to_string()
    } else {
        format!("{target_host}:{port}")
    };
    let pq = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let location = format!("https://{authority}{pq}");
    let mut resp = http::Response::new(body::full(format!("redirecting to {location}\n")));
    *resp.status_mut() = http::StatusCode::PERMANENT_REDIRECT;
    if let Ok(v) = http::HeaderValue::from_str(&location) {
        resp.headers_mut().insert(http::header::LOCATION, v);
    }
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    Some(resp)
}

/// Post-pipeline response decoration: Server header, request id echo.
fn finish_response(resp: &mut http::Response<BoxBody>, rt: &Runtime, req_id: &RequestId) {
    let headers = resp.headers_mut();
    if let Some(v) = &rt.server_header {
        headers.insert(http::header::SERVER, v.clone());
    }
    if let Ok(v) = http::HeaderValue::from_str(req_id.as_str()) {
        headers.insert(http::HeaderName::from_static("x-request-id"), v);
    }
}

/// Sum of header name+value+4 bytes; `false` = limit exceeded.
fn within_header_limit(parts: &http::request::Parts, limit: u64) -> bool {
    let size: u64 = parts
        .headers
        .iter()
        .map(|(k, v)| k.as_str().len() as u64 + v.len() as u64 + 4)
        .sum();
    size <= limit
}

/// Parse a Content-Length header.
fn content_length(parts: &http::request::Parts) -> Option<u64> {
    parts
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
}

/// Resolve the client IP: if the direct peer is trusted, walk
/// `X-Forwarded-For` from the right and take the first untrusted entry.
pub fn real_ip(peer: IpAddr, parts: &http::request::Parts, trusted: &[ipnet::IpNet]) -> IpAddr {
    if !trusted.iter().any(|n| n.contains(&peer)) {
        return peer;
    }
    let xff = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    let Some(xff) = xff else { return peer };
    let ips: Vec<IpAddr> = xff
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    // leftmost entry is the original client per convention; entries to the
    // right of an untrusted one could be spoofed — take the first untrusted
    // from the right, which is the last hop we cannot verify.
    for ip in ips.iter().rev() {
        if !trusted.iter().any(|n| n.contains(ip)) {
            return *ip;
        }
    }
    ips.first().copied().unwrap_or(peer)
}

/// Build a plain-text error response.
pub fn error_response(status: http::StatusCode, msg: &str) -> http::Response<BoxBody> {
    let mut resp = http::Response::new(body::full(format!("{status} {msg}\n")));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn real_ip_trust_walk() {
        let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let untrusted_peer: IpAddr = "203.0.113.9".parse().unwrap();
        let trusted_peer: IpAddr = "10.0.0.5".parse().unwrap();
        let mk = |xff: Option<&str>| {
            let mut b = http::Request::builder().uri("/");
            if let Some(v) = xff {
                b = b.header("x-forwarded-for", v);
            }
            b.body(crate::body::empty()).unwrap().into_parts().0
        };
        // untrusted peer: XFF ignored entirely
        let p = mk(Some("1.2.3.4"));
        assert_eq!(real_ip(untrusted_peer, &p, &trusted), untrusted_peer);
        // trusted peer, no XFF → peer
        let p = mk(None);
        assert_eq!(real_ip(trusted_peer, &p, &trusted), trusted_peer);
        // trusted peer: first untrusted from the right
        let p = mk(Some("1.1.1.1, 10.0.0.9, 2.2.2.2"));
        assert_eq!(
            real_ip(trusted_peer, &p, &trusted),
            IpAddr::from([2, 2, 2, 2])
        );
        // all-trusted chain → leftmost
        let p = mk(Some("10.1.1.1, 10.2.2.2"));
        assert_eq!(
            real_ip(trusted_peer, &p, &trusted),
            IpAddr::from([10, 1, 1, 1])
        );
        // garbage XFF → peer
        let p = mk(Some("not-an-ip"));
        assert_eq!(real_ip(trusted_peer, &p, &trusted), trusted_peer);
    }

    #[test]
    fn header_limit_and_content_length() {
        let p = http::Request::builder()
            .uri("/")
            .header("x-a", "1")
            .header("content-length", "7")
            .body(crate::body::empty())
            .unwrap()
            .into_parts()
            .0;
        assert!(within_header_limit(&p, 100));
        assert!(!within_header_limit(&p, 1));
        assert_eq!(content_length(&p), Some(7));

        let p = http::Request::builder()
            .uri("/")
            .header("content-length", "garbage")
            .body(crate::body::empty())
            .unwrap()
            .into_parts()
            .0;
        assert_eq!(content_length(&p), None);
    }

    #[test]
    fn error_response_shape() {
        let r = error_response(http::StatusCode::BAD_GATEWAY, "upstream down");
        assert_eq!(r.status(), 502);
        assert_eq!(r.headers()["content-type"], "text/plain; charset=utf-8");
    }
}
