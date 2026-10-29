//! CORS middleware: preflight short-circuit (before auth — preflights
//! carry no credentials) and response decoration for actual requests.
//! Origins support exact values, `*`, `*.suffix` wildcards and `re:`-prefixed
//! regexes; matched origins are echoed, which keeps credentials working.

use http::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE,
    ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN, VARY,
};
use http::{HeaderMap, HeaderValue, StatusCode};
use regex::Regex;

use crate::body::{self, BoxBody};
use crate::config::model as cfg;

/// One origin rule.
enum Origin {
    /// `*` — any origin.
    Any,
    /// Exact string equality.
    Exact(String),
    /// `*.example.com` — host suffix, one or more labels.
    Suffix(String),
    /// `re:` regex over the whole Origin value.
    Regex(Regex),
}

/// Compiled CORS config.
pub struct Cors {
    origins: Vec<Origin>,
    methods: String,
    headers: String,
    wildcard_headers: bool,
    expose: String,
    credentials: bool,
    max_age: Option<u64>,
}

impl Cors {
    /// Compile from config.
    pub fn build(c: &cfg::CorsConfig) -> Result<Self, String> {
        let origins = c
            .origins
            .iter()
            .map(|o| match o.as_str() {
                "*" => Ok(Origin::Any),
                s if s.starts_with("*.") => Ok(Origin::Suffix(s[1..].to_string())),
                s if s.starts_with("re:") => Regex::new(&s[3..])
                    .map(Origin::Regex)
                    .map_err(|e| format!("invalid CORS origin regex {s:?}: {e}")),
                s => Ok(Origin::Exact(s.to_string())),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let methods = if c.methods.is_empty() {
            "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS".to_string()
        } else {
            c.methods.join(", ")
        };
        if c.credentials && origins.iter().any(|o| matches!(o, Origin::Any)) {
            // `*` + credentials echoes the caller's origin with
            // Allow-Credentials — same-origin protection off entirely.
            // Supported deliberately, but it should be a loud choice.
            tracing::warn!(
                "cors: origins=[\"*\"] with credentials=true reflects ANY \
                 origin with credentials — this disables same-origin \
                 protection for the route"
            );
        }
        Ok(Self {
            origins,
            methods,
            headers: c.headers.join(", "),
            wildcard_headers: c.headers.iter().any(|h| h == "*"),
            expose: c.expose.join(", "),
            credentials: c.credentials,
            max_age: c.max_age.map(|d| d.as_secs()),
        })
    }

    /// The value to put in `Access-Control-Allow-Origin` for `origin`, or
    /// `None` when the origin is not allowed.
    fn allowed_origin(&self, origin: &str) -> Option<String> {
        for o in &self.origins {
            let hit = match o {
                Origin::Any => return Some(self.any_value(origin)),
                Origin::Exact(e) => e == origin,
                Origin::Suffix(suf) => {
                    let host = origin_host(origin);
                    host.len() > suf.len() && host.ends_with(suf.as_str())
                }
                Origin::Regex(re) => re.is_match(origin),
            };
            if hit {
                // echo the concrete origin — valid with credentials too
                return Some(origin.to_string());
            }
        }
        None
    }

    /// `*` unless credentials are on (browsers reject `*` + credentials —
    /// echo the origin instead).
    fn any_value(&self, origin: &str) -> String {
        if self.credentials {
            origin.to_string()
        } else {
            "*".to_string()
        }
    }

    /// Is this request a CORS preflight?
    fn is_preflight(parts: &http::request::Parts) -> bool {
        parts.method == http::Method::OPTIONS
            && parts.headers.contains_key(ORIGIN)
            && parts.headers.contains_key(ACCESS_CONTROL_REQUEST_METHOD)
    }

    /// Handle a preflight request. Returns `Some(response)` when the
    /// request was a preflight (allowed or not), `None` for real requests.
    pub fn preflight(&self, parts: &http::request::Parts) -> Option<http::Response<BoxBody>> {
        if !Self::is_preflight(parts) {
            return None;
        }
        let origin = parts
            .headers
            .get(ORIGIN)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let Some(acao) = self.allowed_origin(origin) else {
            // not an allowed origin — the request is still a preflight,
            // just a denied one
            let mut r = http::Response::new(body::empty());
            *r.status_mut() = StatusCode::FORBIDDEN;
            return Some(r);
        };
        let mut r = http::Response::new(body::empty());
        *r.status_mut() = StatusCode::NO_CONTENT;
        let h = r.headers_mut();
        set(h, ACCESS_CONTROL_ALLOW_ORIGIN, &acao);
        set(
            h,
            VARY,
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
        );
        set(h, ACCESS_CONTROL_ALLOW_METHODS, &self.methods);
        // request headers echoed when `*` is configured; otherwise the
        // configured list is authoritative
        let req_headers = parts
            .headers
            .get(ACCESS_CONTROL_REQUEST_HEADERS)
            .and_then(|v| v.to_str().ok());
        if self.wildcard_headers
            && let Some(v) = req_headers
        {
            set(h, ACCESS_CONTROL_ALLOW_HEADERS, v);
        } else if !self.headers.is_empty() {
            set(h, ACCESS_CONTROL_ALLOW_HEADERS, &self.headers.clone());
        }
        if let Some(secs) = self.max_age {
            set(h, ACCESS_CONTROL_MAX_AGE, &secs.to_string());
        }
        if self.credentials {
            set(h, ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
        }
        Some(r)
    }

    /// Decorate an actual (non-preflight) response with the request's
    /// `Origin` header value, if any.
    pub fn apply(&self, resp_headers: &mut HeaderMap, origin: Option<&str>) {
        let Some(origin) = origin else { return };
        let Some(acao) = self.allowed_origin(origin) else {
            return;
        };
        set(resp_headers, ACCESS_CONTROL_ALLOW_ORIGIN, &acao);
        if acao != "*" {
            append_vary(resp_headers, "Origin");
        }
        if self.credentials {
            set(resp_headers, ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
        }
        if !self.expose.is_empty() {
            set(
                resp_headers,
                ACCESS_CONTROL_EXPOSE_HEADERS,
                &self.expose.clone(),
            );
        }
    }
}

/// Extract the host part of an Origin header (`https://a.b:8443` → `a.b`).
fn origin_host(origin: &str) -> &str {
    let rest = origin.split("://").nth(1).unwrap_or(origin);
    rest.split('/')
        .next()
        .unwrap_or(rest)
        .split(':')
        .next()
        .unwrap_or(rest)
}

fn set(h: &mut HeaderMap, name: http::header::HeaderName, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        h.insert(name, v);
    }
}

/// Add `value` to `Vary` without duplicating an existing token.
fn append_vary(h: &mut HeaderMap, value: &str) {
    let cur = h
        .get(VARY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if cur.split(',').any(|t| t.trim().eq_ignore_ascii_case(value)) {
        return;
    }
    let merged = if cur.is_empty() {
        value.to_string()
    } else {
        format!("{cur}, {value}")
    };
    set(h, VARY, &merged);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cors(origins: &[&str]) -> Cors {
        Cors::build(&cfg::CorsConfig {
            origins: origins.iter().map(|s| s.to_string()).collect(),
            methods: vec!["GET".into(), "POST".into()],
            headers: vec!["content-type".into()],
            expose: vec!["x-total".into()],
            credentials: false,
            max_age: Some(std::time::Duration::from_secs(600)),
            enabled: true,
        })
        .unwrap()
    }

    fn preflight_parts(origin: &str) -> http::request::Parts {
        http::Request::builder()
            .method("OPTIONS")
            .uri("http://x/")
            .header("origin", origin)
            .header("access-control-request-method", "GET")
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    #[test]
    fn wildcard_any() {
        let c = cors(&["*"]);
        let r = c.preflight(&preflight_parts("https://a.com")).unwrap();
        assert_eq!(r.status(), 204);
        assert_eq!(r.headers()["access-control-allow-origin"], "*");
        assert!(
            r.headers()["access-control-allow-methods"]
                .to_str()
                .unwrap()
                .contains("GET")
        );
    }

    #[test]
    fn exact_echoed() {
        let c = cors(&["https://app.example.com"]);
        let r = c
            .preflight(&preflight_parts("https://app.example.com"))
            .unwrap();
        assert_eq!(
            r.headers()["access-control-allow-origin"],
            "https://app.example.com"
        );
        let denied = c.preflight(&preflight_parts("https://evil.com")).unwrap();
        assert_eq!(denied.status(), 403);
    }

    #[test]
    fn suffix_wildcard() {
        let c = cors(&["*.example.com"]);
        assert!(
            c.preflight(&preflight_parts("https://a.example.com"))
                .unwrap()
                .status()
                == 204
        );
        assert!(
            c.preflight(&preflight_parts("https://deep.a.example.com"))
                .unwrap()
                .status()
                == 204
        );
        // bare suffix does not match (needs at least one label)
        assert!(
            c.preflight(&preflight_parts("https://example.com"))
                .unwrap()
                .status()
                == 403
        );
        assert!(
            c.preflight(&preflight_parts("https://notexample.com"))
                .unwrap()
                .status()
                == 403
        );
    }

    #[test]
    fn regex_origin() {
        let c = cors(&[r"re:^https://(dev|staging)\.example\.com$"]);
        assert!(
            c.preflight(&preflight_parts("https://dev.example.com"))
                .unwrap()
                .status()
                == 204
        );
        assert!(
            c.preflight(&preflight_parts("https://prod.example.com"))
                .unwrap()
                .status()
                == 403
        );
    }

    #[test]
    fn credentials_echoes_wildcard() {
        let mut cc = cfg::CorsConfig {
            origins: vec!["*".into()],
            credentials: true,
            ..Default::default()
        };
        cc.methods = vec!["GET".into()];
        let c = Cors::build(&cc).unwrap();
        let r = c.preflight(&preflight_parts("https://a.com")).unwrap();
        assert_eq!(r.headers()["access-control-allow-origin"], "https://a.com");
        assert_eq!(r.headers()["access-control-allow-credentials"], "true");
    }

    #[test]
    fn actual_request_vary() {
        let c = cors(&["https://app.example.com"]);
        let req = http::Request::builder()
            .uri("http://x/")
            .header("origin", "https://app.example.com")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let mut h = HeaderMap::new();
        c.apply(
            &mut h,
            req.headers.get(ORIGIN).and_then(|v| v.to_str().ok()),
        );
        assert_eq!(h["access-control-allow-origin"], "https://app.example.com");
        assert_eq!(h["vary"], "Origin");
        assert_eq!(h["access-control-expose-headers"], "x-total");
    }

    #[test]
    fn only_a_full_preflight_is_intercepted() {
        let c = cors(&["*"]);
        let mk = |method: &str, headers: &[(&str, &str)]| {
            let mut b = http::Request::builder().method(method).uri("http://x/");
            for (k, v) in headers {
                b = b.header(*k, *v);
            }
            b.body(()).unwrap().into_parts().0
        };
        // a bare OPTIONS is an ordinary request, not a CORS preflight
        assert!(c.preflight(&mk("OPTIONS", &[])).is_none());
        // OPTIONS + Origin without a requested method → not a preflight
        assert!(
            c.preflight(&mk("OPTIONS", &[("origin", "https://a.com")]))
                .is_none()
        );
        // OPTIONS + ACRM without Origin → not a preflight
        assert!(
            c.preflight(&mk("OPTIONS", &[("access-control-request-method", "GET")]))
                .is_none()
        );
        // a real CORS request (GET + Origin + ACRM) passes through too
        assert!(
            c.preflight(&mk(
                "GET",
                &[
                    ("origin", "https://a.com"),
                    ("access-control-request-method", "GET")
                ]
            ))
            .is_none()
        );
        assert!(c.preflight(&preflight_parts("https://a.com")).is_some());
    }
}
