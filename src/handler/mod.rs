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
        let prefix = route.prefix.clone().unwrap_or_default();
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

/// Substitute `{path}`, `{host}`, `{query}`, `{method}`, `{scheme}`,
/// `{uri}` (path + `?query` as sent), `{args}` (query without `?`),
/// `{remote_ip}` (client IP under the route's trust model), and
/// `{request_id}` (extracted or generated `X-Request-Id`; empty when
/// the pipeline didn't run, e.g. tests). `path` lets callers pass an
/// encoded path — redirect targets must stay header-safe. `{query}`
/// carries its leading `?` and is empty when the request has no
/// query string.
pub(crate) fn substitute(
    template: &str,
    path: &str,
    req: &http::Request<BoxBody>,
    ctx: &RequestCtx,
) -> String {
    substitute_parts(
        template,
        path,
        req.uri(),
        req.method(),
        req.extensions()
            .get::<crate::observe::RequestId>()
            .map(|r| r.as_str()),
        ctx,
    )
}

/// `substitute` over request parts — for callers whose `Request` was
/// already consumed (e.g. the proxy retry loop).
pub(crate) fn substitute_parts(
    template: &str,
    path: &str,
    uri: &http::Uri,
    method: &http::Method,
    request_id: Option<&str>,
    ctx: &RequestCtx,
) -> String {
    let args = uri.query().unwrap_or_default();
    let query = if args.is_empty() {
        String::new()
    } else {
        format!("?{args}")
    };
    let uri = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or(path);
    template
        .replace("{path}", path)
        .replace("{host}", &ctx.host)
        .replace("{query}", &query)
        .replace("{method}", method.as_str())
        .replace("{scheme}", ctx.scheme)
        .replace("{uri}", uri)
        .replace("{args}", args)
        .replace("{remote_ip}", &ctx.client_ip.to_string())
        .replace("{request_id}", request_id.unwrap_or_default())
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

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    fn ctx() -> RequestCtx {
        RequestCtx {
            path: "/a b".into(),
            host: "h".into(),
            client_ip: "10.0.0.1".parse().unwrap(),
            peer_ip: "10.0.0.1".parse().unwrap(),
            peer_trusted: false,
            tls: false,
            scheme: "http",
        }
    }

    fn req(method: Method, uri: &str) -> http::Request<BoxBody> {
        http::Request::builder()
            .method(method)
            .uri(uri)
            .body(crate::body::empty())
            .unwrap()
    }

    #[test]
    fn substitute_covers_all_placeholders() {
        let out = super::substitute(
            "{path}|{host}|{query}|{method}|{scheme}|{uri}|{args}|{remote_ip}",
            "/a b",
            &req(Method::POST, "/x?q=1"),
            &ctx(),
        );
        assert_eq!(out, "/a b|h|?q=1|POST|http|/x?q=1|q=1|10.0.0.1");
        // no query → {query}/{args} empty, {uri} is the bare path
        let out = super::substitute(
            "{query}|{args}|{uri}",
            "/p",
            &req(Method::GET, "/x"),
            &ctx(),
        );
        assert_eq!(out, "||/x");
        // {request_id} resolves from the request extensions when the
        // pipeline ran; absent in hand-built requests → empty
        let mut r = req(Method::GET, "/x");
        r.extensions_mut()
            .insert(crate::observe::RequestId::extract(&http::HeaderMap::new()));
        let out = super::substitute("{request_id}", "/p", &r, &ctx());
        assert_eq!(out.len(), 36); // generated uuid
        let out = super::substitute("{request_id}", "/p", &req(Method::GET, "/x"), &ctx());
        assert_eq!(out, "");
    }

    #[test]
    fn redirect_targets() {
        // To template — all five placeholders
        let c = cfg::RedirectHandler {
            to: Some("https://x{path}{query}?h={host}&m={method}&s={scheme}".into()),
            ..Default::default()
        };
        let r = redirect::Redirect::build(&c, "s").unwrap();
        let resp = r.handle(&req(Method::GET, "/p?q=1"), &ctx());
        assert_eq!(resp.status(), 308);
        let loc = resp.headers()["location"].to_str().unwrap();
        assert!(
            loc.contains("h=h")
                && loc.contains("m=GET")
                && loc.contains("s=http")
                && loc.contains("q=1"),
            "{loc}"
        );

        // Host target
        let c = cfg::RedirectHandler {
            host: Some("other.example".into()),
            status: 301,
            ..Default::default()
        };
        let r = redirect::Redirect::build(&c, "s").unwrap();
        let resp = r.handle(&req(Method::GET, "/p?q=1"), &ctx());
        assert_eq!(resp.status(), 301);
        assert!(
            resp.headers()["location"]
                .to_str()
                .unwrap()
                .starts_with("http://other.example/")
        );

        // Scheme target
        let c = cfg::RedirectHandler {
            scheme: Some("https".into()),
            ..Default::default()
        };
        let r = redirect::Redirect::build(&c, "s").unwrap();
        let resp = r.handle(&req(Method::GET, "/p"), &ctx());
        assert!(
            resp.headers()["location"]
                .to_str()
                .unwrap()
                .starts_with("https://h/")
        );

        // nothing configured → Missing
        let c = cfg::RedirectHandler::default();
        assert!(matches!(
            redirect::Redirect::build(&c, "s"),
            Err(BuildError::Missing)
        ));
        // invalid status
        let c = cfg::RedirectHandler {
            to: Some("/x".into()),
            status: 99,
            ..Default::default()
        };
        assert!(redirect::Redirect::build(&c, "s").is_err());
    }

    #[test]
    fn respond_placeholders_and_head() {
        let mut headers = BTreeMap::new();
        headers.insert("x-fixed".to_string(), "v".to_string());
        let c = cfg::RespondHandler {
            status: 200,
            body: "{method} {host} {scheme}".into(),
            headers,
        };
        let r = respond::Respond::build(&c, "s").unwrap();
        let resp = r.handle(&req(Method::GET, "/"), &ctx());
        assert_eq!(resp.headers()["x-fixed"], "v");
        assert_eq!(resp.headers()["content-type"], "text/plain; charset=utf-8");

        // bodyless status: no content-length/type
        let c = cfg::RespondHandler {
            status: 204,
            body: "ignored".into(),
            ..Default::default()
        };
        let r = respond::Respond::build(&c, "s").unwrap();
        let resp = r.handle(&req(Method::GET, "/"), &ctx());
        assert!(resp.headers().get("content-length").is_none());
        assert!(resp.headers().get("content-type").is_none());

        // bad header name/value and status rejected at build time
        let mut headers = BTreeMap::new();
        headers.insert("bad name".into(), "v".into());
        let c = cfg::RespondHandler {
            headers,
            ..Default::default()
        };
        assert!(respond::Respond::build(&c, "s").is_err());
        let mut headers = BTreeMap::new();
        headers.insert("x".into(), "bad\r\nvalue".into());
        let c = cfg::RespondHandler {
            headers,
            ..Default::default()
        };
        assert!(respond::Respond::build(&c, "s").is_err());
        let c = cfg::RespondHandler {
            status: 42,
            ..Default::default()
        };
        assert!(respond::Respond::build(&c, "s").is_err());
    }

    #[test]
    fn build_dispatches_and_rejects_missing() {
        // no handler configured
        let route = cfg::RouteConfig {
            prefix: Some("/x".into()),
            ..Default::default()
        };
        let empty = crate::config::model::Config::default();
        let mut clusters = crate::proxy::Clusters::build(&empty).unwrap();
        assert!(matches!(
            build(&route, "s", &mut clusters, "r"),
            Err(BuildError::Missing)
        ));

        // respond arm
        let route = cfg::RouteConfig {
            prefix: Some("/x".into()),
            respond: Some(cfg::RespondHandler {
                status: 200,
                body: "ok".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(matches!(
            build(&route, "s", &mut clusters, "r"),
            Ok(Handler::Respond(_))
        ));
    }

    #[test]
    fn build_error_display() {
        assert!(BuildError::Missing.to_string().contains("no handler"));
        assert!(
            BuildError::Unsupported("x")
                .to_string()
                .contains("not implemented")
        );
        assert!(BuildError::Invalid("m".into()).to_string().contains("m"));
    }
}
