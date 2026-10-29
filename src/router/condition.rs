//! Route match conditions: HTTP methods, request headers and query
//! parameters. Conditions filter candidate routes — they never change path
//! precedence.

use std::collections::BTreeMap;

use http::{HeaderName, Method};
use regex::Regex;

use crate::config::model::MatchConditions;

/// A value pattern: exact string or `re:`-prefixed regex.
#[derive(Debug)]
pub enum Pattern {
    /// Byte-exact match.
    Exact(String),
    /// Regular expression (from a `re:` value).
    Regex(Regex),
}

impl Pattern {
    /// Compile a config value into a pattern.
    pub fn compile(v: &str) -> Result<Self, regex::Error> {
        match v.strip_prefix("re:") {
            Some(re) => Ok(Self::Regex(Regex::new(re)?)),
            None => Ok(Self::Exact(v.to_string())),
        }
    }

    /// Test a value against the pattern.
    pub fn is_match(&self, v: &str) -> bool {
        match self {
            Self::Exact(s) => s == v,
            Self::Regex(re) => re.is_match(v),
        }
    }
}

/// Compiled match conditions.
#[derive(Debug, Default)]
pub struct Conditions {
    /// Allowed methods; empty = any.
    pub methods: Vec<Method>,
    /// Required headers. An empty pattern requires presence only —
    /// same rule as `query` (match an empty value with `re:^$`).
    pub headers: Vec<(HeaderName, Pattern)>,
    /// Required query params. An empty pattern requires presence only.
    pub query: Vec<(String, Pattern)>,
}

impl Conditions {
    /// Compile config conditions. Invalid header names, methods or regexes
    /// surface as errors at config-build time.
    pub fn build(m: &MatchConditions) -> Result<Self, String> {
        let methods = m
            .methods
            .iter()
            .map(|s| Method::from_bytes(s.as_bytes()).map_err(|_| format!("invalid method {s:?}")))
            .collect::<Result<_, _>>()?;
        let headers = compile_named(&m.headers, |name| {
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| format!("invalid header name {name:?}"))
        })?;
        let query = compile_named(&m.query, |name| Ok(name.clone()))?;
        Ok(Self {
            methods,
            headers,
            query,
        })
    }

    /// Whether the request satisfies all conditions.
    pub fn matches(&self, parts: &http::request::Parts) -> bool {
        if !self.methods.is_empty() && !self.methods.contains(&parts.method) {
            return false;
        }
        for (name, pat) in &self.headers {
            // an empty exact pattern means "presence only" — same rule
            // as query params (an empty-value match is `re:^$`)
            if matches!(pat, Pattern::Exact(s) if s.is_empty()) {
                if !parts.headers.contains_key(name) {
                    return false;
                }
                continue;
            }
            match parts.headers.get(name).and_then(|v| v.to_str().ok()) {
                Some(v) if pat.is_match(v) => {}
                _ => return false,
            }
        }
        if !self.query.is_empty() {
            let query = form_urlencoded_parse(parts.uri.query().unwrap_or_default());
            for (key, pat) in &self.query {
                // an empty exact pattern means "presence only"
                let presence_only = matches!(pat, Pattern::Exact(s) if s.is_empty());
                let found = query
                    .iter()
                    .any(|(k, v)| k == key && (presence_only || pat.is_match(v)));
                if !found {
                    return false;
                }
            }
        }
        true
    }
}

fn compile_named<K>(
    map: &BTreeMap<String, String>,
    key: impl Fn(&String) -> Result<K, String>,
) -> Result<Vec<(K, Pattern)>, String> {
    map.iter()
        .map(|(k, v)| {
            let key = key(k)?;
            let pat = Pattern::compile(v).map_err(|e| format!("invalid pattern for {k}: {e}"))?;
            Ok((key, pat))
        })
        .collect()
}

/// Parse `a=1&b=2` into ordered pairs (repeated keys preserved).
fn form_urlencoded_parse(q: &str) -> Vec<(String, String)> {
    form_urlencoded::parse(q.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_exact_and_regex() {
        assert!(Pattern::compile("abc").unwrap().is_match("abc"));
        assert!(!Pattern::compile("abc").unwrap().is_match("abd"));
        assert!(Pattern::compile("re:^a.c$").unwrap().is_match("abc"));
        assert!(!Pattern::compile("re:^a.c$").unwrap().is_match("abd"));
    }

    #[test]
    fn query_parses() {
        let q = form_urlencoded_parse("a=1&b=%202&a=3");
        assert_eq!(
            q,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), " 2".to_string()),
                ("a".to_string(), "3".to_string())
            ]
        );
    }

    #[test]
    fn build_rejects_bad_method_header_and_regex() {
        let m = MatchConditions {
            methods: vec!["NOT A METHOD".into()],
            ..Default::default()
        };
        assert!(Conditions::build(&m).is_err());
        let m = MatchConditions {
            headers: [("bad name".into(), "v".into())].into_iter().collect(),
            ..Default::default()
        };
        assert!(Conditions::build(&m).is_err());
        let m = MatchConditions {
            query: [("k".into(), "re:(".into())].into_iter().collect(),
            ..Default::default()
        };
        assert!(Conditions::build(&m).is_err());
    }

    #[test]
    fn matches_all_condition_kinds() {
        let m = MatchConditions {
            methods: vec!["GET".into()],
            headers: [("x-env".into(), "re:^prod".into())].into_iter().collect(),
            query: [
                ("debug".into(), "".into()), // presence only
                ("v".into(), "2".into()),
            ]
            .into_iter()
            .collect(),
        };
        let c = Conditions::build(&m).unwrap();
        let mk = |method: &str, uri: &str, env: Option<&str>| {
            let mut b = http::Request::builder().method(method).uri(uri);
            if let Some(v) = env {
                b = b.header("x-env", v);
            }
            b.body(crate::body::empty()).unwrap().into_parts().0
        };
        assert!(c.matches(&mk("GET", "/p?debug&v=2", Some("prod-us"))));
        assert!(!c.matches(&mk("POST", "/p?debug&v=2", Some("prod-us"))));
        assert!(!c.matches(&mk("GET", "/p?debug&v=2", None)));
        assert!(!c.matches(&mk("GET", "/p?debug&v=2", Some("dev"))));
        assert!(!c.matches(&mk("GET", "/p?v=2", Some("prod")))); // debug absent
        assert!(!c.matches(&mk("GET", "/p?debug&v=1", Some("prod"))));
        // no query on the uri at all
        assert!(!c.matches(&mk("GET", "/p", Some("prod"))));
        // empty conditions match anything
        let c2 = Conditions::default();
        assert!(c2.matches(&mk("DELETE", "/", None)));
    }

    #[test]
    fn empty_header_pattern_is_presence_only() {
        // same rule as query: `""` means "header must be present" —
        // matching an empty value is `re:^$`
        let m = MatchConditions {
            headers: [("x-flag".into(), "".into())].into_iter().collect(),
            ..Default::default()
        };
        let c = Conditions::build(&m).unwrap();
        let mk = |v: Option<&str>| {
            let mut b = http::Request::builder().method("GET").uri("/");
            if let Some(v) = v {
                b = b.header("x-flag", v);
            }
            b.body(crate::body::empty()).unwrap().into_parts().0
        };
        assert!(c.matches(&mk(Some("anything"))));
        assert!(c.matches(&mk(Some(""))));
        assert!(!c.matches(&mk(None)));
    }
}
