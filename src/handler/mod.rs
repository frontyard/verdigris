//! Route handlers — exactly one per route. Each produces the downstream
//! response; middleware wraps them.

mod redirect;
mod respond;
pub(crate) mod static_files;

pub use redirect::Redirect;
pub use respond::Respond;
pub use static_files::Static;

use std::collections::BTreeMap;
use std::fmt;

use http::{HeaderName, HeaderValue, StatusCode};

use crate::body::{self, BoxBody};
use crate::config::model as cfg;
use crate::proxy::{Clusters, Proxy};

/// A compiled handler.
pub enum Handler {
    /// Fixed response.
    Respond(Respond),
    /// HTTP redirect.
    Redirect(Redirect),
    /// Static file serving.
    Static(Static),
    /// Reverse proxy.
    Proxy(Proxy),
}

impl Handler {
    /// Produce the response for a request. The request is taken by value so
    /// the returned future is `Send` — `UnsyncBoxBody` is `Send` but not
    /// `Sync`, so `&Request<BoxBody>` must never be held across an `.await`.
    pub async fn handle(
        &self,
        req: http::Request<BoxBody>,
        ctx: &RequestCtx,
    ) -> http::Response<BoxBody> {
        match self {
            Self::Respond(h) => h.handle(&req, ctx),
            Self::Redirect(h) => h.handle(&req, ctx),
            Self::Static(h) => h.handle(req, ctx).await,
            Self::Proxy(h) => h.handle(req, ctx).await,
        }
    }
}

/// Per-request context handed to handlers: routing and connection details
/// needed to build responses.
#[derive(Debug, Clone)]
pub struct RequestCtx {
    /// Normalized request path (absolute, decoded, dot-resolved).
    pub path: String,
    /// Matched host (lowercase, port stripped).
    pub host: String,
    /// Client IP as seen by this route's trust model.
    pub client_ip: std::net::IpAddr,
    /// Direct peer IP of this connection.
    pub peer_ip: std::net::IpAddr,
    /// Whether the direct peer is a trusted proxy.
    pub peer_trusted: bool,
    /// Whether the request arrived over TLS.
    pub tls: bool,
    /// Scheme as seen by the client: `http` or `https`.
    pub scheme: &'static str,
}

/// Build a handler from config. `key` is the route id (used to name
/// anonymous upstream clusters); `clusters` resolves named upstreams and
/// materializes anonymous ones.
pub fn build(
    route: &cfg::RouteConfig,
    site: &str,
    clusters: &mut Clusters,
    key: &str,
) -> Result<Handler, BuildError> {
    if let Some(r) = &route.respond {
        return Ok(Handler::Respond(Respond::build(r, site)?));
    }
    if let Some(r) = &route.redirect {
        return Ok(Handler::Redirect(Redirect::build(r, site)?));
    }
    if let Some(r) = &route.static_files {
        let prefix = route
            .prefix
            .as_ref()
            .or(route.path.as_ref())
            .cloned()
            .unwrap_or_default();
        return Ok(Handler::Static(Static::build(r, &prefix, site)?));
    }
    if let Some(p) = &route.proxy {
        let proxy = Proxy::build(p, clusters, key).map_err(BuildError::Invalid)?;
        return Ok(Handler::Proxy(proxy));
    }
    Err(BuildError::Missing)
}

/// Why a handler could not be built.
#[derive(Debug)]
pub enum BuildError {
    /// No handler configured (validation should have caught this).
    Missing,
    /// Configured but not yet implemented in this build.
    Unsupported(&'static str),
    /// A header name/value or status failed to parse.
    Invalid(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => write!(f, "route has no handler"),
            Self::Unsupported(kind) => write!(f, "handler {kind:?} is not implemented yet"),
            Self::Invalid(m) => write!(f, "invalid handler config: {m}"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Compile a `{key = value}` header map.
fn compile_headers(
    map: &BTreeMap<String, String>,
) -> Result<Vec<(HeaderName, HeaderValue)>, BuildError> {
    map.iter()
        .map(|(k, v)| {
            let name = HeaderName::from_bytes(k.as_bytes())
                .map_err(|_| BuildError::Invalid(format!("bad header name {k:?}")))?;
            let value = HeaderValue::from_str(v)
                .map_err(|_| BuildError::Invalid(format!("bad header value for {k}")))?;
            Ok((name, value))
        })
        .collect()
}

/// Compile a status code.
fn compile_status(status: u16) -> Result<StatusCode, BuildError> {
    StatusCode::from_u16(status)
        .map_err(|_| BuildError::Invalid(format!("invalid status {status}")))
}

/// Substitute `{path}`, `{host}`, `{method}`, `{scheme}` in a template.
fn substitute(template: &str, req: &http::Request<BoxBody>, ctx: &RequestCtx) -> String {
    template
        .replace("{path}", &ctx.path)
        .replace("{host}", &ctx.host)
        .replace("{method}", req.method().as_str())
        .replace("{scheme}", ctx.scheme)
}

/// Convenience: build a minimal response with a text body (respecting
/// `HEAD`/bodyless statuses).
fn response(
    status: StatusCode,
    headers: Vec<(HeaderName, HeaderValue)>,
    body_text: String,
    method: &http::Method,
) -> http::Response<BoxBody> {
    let mut resp = http::Response::new(if body::response_body_forbidden(method, status) {
        body::empty()
    } else {
        body::full(body_text.clone())
    });
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    if !body_text.is_empty() && !body::response_body_forbidden(method, status) {
        h.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&body_text.len().to_string()).unwrap(),
        );
        if !headers.iter().any(|(n, _)| n == http::header::CONTENT_TYPE) {
            h.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
        }
    }
    for (name, value) in headers {
        h.append(name, value);
    }
    resp
}
