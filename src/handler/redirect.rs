//! `redirect` handler: 301/302/307/308 to a URL template, another host, or
//! another scheme.

use http::{HeaderValue, StatusCode};

use super::{BuildError, RequestCtx};
use crate::body::{self, BoxBody};
use crate::config::model as cfg;

/// Where a redirect points.
#[derive(Debug)]
enum Target {
    /// Full URL template — `{host}`, `{path}`, `{query}`, `{method}`,
    /// `{scheme}` substitute from the request.
    To(String),
    /// Same path on a different host.
    Host(String),
    /// Same URL on a different scheme.
    Scheme(String),
}

/// Compiled `redirect` handler.
#[derive(Debug)]
pub struct Redirect {
    target: Target,
    status: StatusCode,
}

impl Redirect {
    /// Build from config.
    pub fn build(c: &cfg::RedirectHandler, _site: &str) -> Result<Self, BuildError> {
        let target = if let Some(to) = &c.to {
            Target::To(to.clone())
        } else if let Some(host) = &c.host {
            Target::Host(host.clone())
        } else if let Some(scheme) = &c.scheme {
            Target::Scheme(scheme.clone())
        } else {
            return Err(BuildError::Missing);
        };
        Ok(Self {
            target,
            status: super::compile_status(c.status)?,
        })
    }

    /// Produce the redirect response.
    pub fn handle(
        &self,
        req: &http::Request<BoxBody>,
        ctx: &RequestCtx,
    ) -> http::Response<BoxBody> {
        let query = req
            .uri()
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();
        // ctx.path is decoded — re-encode so raw spaces or control chars
        // never land in a Location value
        let path = crate::proxy::headers::encode_path(&ctx.path);
        let location = match &self.target {
            Target::To(tpl) => super::substitute(tpl, &path, req, ctx),
            Target::Host(host) => format!("{}://{}{}{}", ctx.scheme, host, path, query),
            Target::Scheme(scheme) => {
                format!("{scheme}://{}{}{}", ctx.host, path, query)
            }
        };
        let mut resp = http::Response::new(body::empty());
        *resp.status_mut() = self.status;
        // Protocol-relative guard: templates whose substituted result
        // starts with `//` — or with `\`, or `/`+`\`, which WHATWG URL
        // parsing folds into `//` for http/https — are open redirects
        // (`Location: /\evil.com` navigates to `https://evil.com`).
        // `{path}` reaches here decoded, so `/%5Cevil.com` survives
        // normalization as `/\evil.com` (backslash is not a separator
        // the normalizer collapses).
        if let Ok(v) = HeaderValue::from_str(&location) {
            if is_scheme_relative(&location) {
                tracing::warn!(target = %self.target_name(), "refused scheme-relative redirect target");
            } else {
                resp.headers_mut().insert(http::header::LOCATION, v);
            }
        }
        resp
    }

    fn target_name(&self) -> &'static str {
        match &self.target {
            Target::To(_) => "to",
            Target::Host(_) => "host",
            Target::Scheme(_) => "scheme",
        }
    }
}

/// True when `location` resolves as a scheme-relative URL — `//host`,
/// `/\host`, `\/host` or any leading `\` (WHATWG treats a leading
/// backslash as `//` for special schemes). The check looks through a
/// percent-encoded prefix too: `{uri}` substitutes the raw request
/// target, so `/%5Cevil.com` arrives encoded — the decoded form is
/// what `{path}`-style templates are refused for, and any client that
/// decodes-then-reparses would turn it into the same open redirect.
fn is_scheme_relative(location: &str) -> bool {
    // only positions 0-1 can change the authority — decode just the
    // head (an incomplete `%x` tail decodes to literals, harmlessly)
    let head = location.get(..8).unwrap_or(location);
    let mut decoded = percent_encoding::percent_decode_str(head).take(2);
    match decoded.next() {
        Some(b'\\') => true,
        Some(b'/') => matches!(decoded.next(), Some(b'/') | Some(b'\\')),
        _ => false,
    }
}
