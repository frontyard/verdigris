//! Access logging: one [`LogRecord`] per request — fields captured at
//! request time, finished by the response-body wrapper (which also
//! counts streamed bytes and marks client aborts as `499`).

use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use crate::config::model as cfg;

/// Upstream member that served this request — attached to response
/// extensions by the proxy handler, read by the log.
#[derive(Debug, Clone)]
pub struct UpstreamUsed(pub String);

/// One access-log record.
#[derive(Debug)]
pub struct LogRecord {
    req_id: String,
    client_ip: IpAddr,
    method: String,
    host: String,
    path: String,
    proto: String,
    tls: Option<String>,
    route: Option<String>,
    status: u16,
    bytes: u64,
    duration_ms: u128,
    user_agent: String,
    referer: String,
    upstream: Option<String>,
    identity: Option<String>,
    cache: Option<String>,
    /// Metric handles of the matched route; `None` before route match.
    meters: Option<Arc<crate::observe::metrics::RouteMeters>>,
    /// Received request-body bytes — shared with `LimitBody` so the
    /// counter updates as frames arrive; read at finalize time.
    req_bytes: Arc<AtomicU64>,
}

/// Borrowed snapshot used by the metrics emitter — no string clones.
pub struct LogFields<'a> {
    /// HTTP method.
    pub method: &'a str,
    /// Final status (499 when the client aborted mid-body).
    pub status: u16,
    /// Body bytes actually streamed.
    pub bytes: u64,
    /// Request-body bytes received so far.
    pub req_bytes: u64,
    /// Wall-clock duration.
    pub duration_ms: u128,
    /// Matched route's metric handles, when routing happened.
    pub meters: Option<&'a crate::observe::metrics::RouteMeters>,
}

impl LogRecord {
    /// Capture request-side fields.
    pub fn new(
        ctx: &crate::server::service::ConnCtx,
        parts: &http::request::Parts,
        req_id: &super::RequestId,
    ) -> Self {
        Self {
            req_id: req_id.as_str().to_string(),
            client_ip: ctx.remote.ip(),
            method: parts.method.to_string(),
            host: parts
                .headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
                .or_else(|| parts.uri.authority().map(|a| a.to_string()))
                .unwrap_or_default(),
            path: parts.uri.path().to_string(),
            proto: format!("{:?}", parts.version),
            tls: ctx.tls_version.clone(),
            route: None,
            status: 0,
            bytes: 0,
            duration_ms: 0,
            user_agent: parts
                .headers
                .get(http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string(),
            referer: parts
                .headers
                .get(http::header::REFERER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string(),
            upstream: None,
            identity: None,
            cache: None,
            meters: None,
            req_bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Record the authenticated identity (set by auth middleware).
    pub fn set_identity(&mut self, identity: &str) {
        self.identity = Some(identity.to_string());
    }

    /// Record the matched route (for metrics + the log line): its id and
    /// its metric-handle cache.
    pub fn set_route(&mut self, id: &str, meters: Arc<crate::observe::metrics::RouteMeters>) {
        self.route = Some(id.to_string());
        self.meters = Some(meters);
    }

    /// The shared inbound-byte counter — `LimitBody` feeds it while the
    /// request body streams in.
    pub fn req_bytes(&self) -> Arc<AtomicU64> {
        self.req_bytes.clone()
    }

    /// Response-side fields known once the response is assembled —
    /// status, upstream, cache status, declared length.
    pub fn finish_headers(&mut self, resp: &http::Response<crate::body::BoxBody>) {
        self.status = resp.status().as_u16();
        self.upstream = resp.extensions().get::<UpstreamUsed>().map(|u| u.0.clone());
        self.cache = resp
            .headers()
            .get(http::header::HeaderName::from_static("x-cache"))
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        self.bytes = resp
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
    }

    /// Final fields at stream end: duration, actual bytes sent, and a
    /// possibly-overridden status (499 on client abort).
    pub fn finalize(&mut self, started: Instant, status: u16, bytes: u64) {
        self.status = status;
        if bytes > 0 || self.bytes == 0 {
            self.bytes = bytes;
        }
        self.duration_ms = started.elapsed().as_millis();
    }

    /// Metric-facing field snapshot (borrowed — no clones).
    pub fn fields(&self) -> LogFields<'_> {
        LogFields {
            method: &self.method,
            status: self.status,
            bytes: self.bytes,
            req_bytes: self.req_bytes.load(std::sync::atomic::Ordering::Relaxed),
            duration_ms: self.duration_ms,
            meters: self.meters.as_deref(),
        }
    }
}

/// A compiled `field op value` term in a log filter expression.
#[derive(Debug)]
struct Cond {
    field: Field,
    neg: bool,
    op: Op,
    value: String,
    num: Option<u16>,
}

#[derive(Debug, Clone, Copy)]
enum Field {
    Path,
    Host,
    Method,
    Status,
    Upstream,
    Cache,
    Identity,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Op {
    Eq,
    Glob,
    Gt,
    Lt,
}

/// Compiled filter: `cond && cond && ...` — every cond must pass.
#[derive(Debug, Default)]
pub struct Filter(Vec<Cond>);

impl Filter {
    /// Parse `path != "/healthz" && status >= 400`-style expressions.
    /// `=`/`==` exact, `!=`/`<>`, `=~` glob, `!~` anti-glob, `>` `<` `>=`
    /// `<=` ordered (numeric for status, string elsewhere).
    pub fn parse(expr: &str) -> Result<Self, String> {
        let mut conds = Vec::new();
        for term in expr.split("&&") {
            let term = term.trim();
            if term.is_empty() {
                continue;
            }
            conds.push(parse_cond(term)?);
        }
        Ok(Self(conds))
    }

    /// True when the record should be logged.
    fn passes(&self, r: &LogRecord) -> bool {
        let val = |f: Field| -> &str {
            match f {
                Field::Path => &r.path,
                Field::Host => &r.host,
                Field::Method => &r.method,
                Field::Status => "", // handled numerically
                Field::Upstream => r.upstream.as_deref().unwrap_or(""),
                Field::Cache => r.cache.as_deref().unwrap_or(""),
                Field::Identity => r.identity.as_deref().unwrap_or(""),
            }
        };
        self.0.iter().all(|c| {
            let ok = match (c.field, c.op) {
                (Field::Status, Op::Gt) => c.num.is_some_and(|n| r.status > n),
                (Field::Status, Op::Lt) => c.num.is_some_and(|n| r.status < n),
                (Field::Status, Op::Eq) => c.num.is_some_and(|n| r.status == n),
                (Field::Status, Op::Glob) => false,
                (f, Op::Eq) => val(f) == c.value,
                (f, Op::Glob) => crate::handler::static_files::glob_match(&c.value, val(f)),
                (f, Op::Gt) => val(f) > c.value.as_str(),
                (f, Op::Lt) => val(f) < c.value.as_str(),
            };
            ok != c.neg
        })
    }
}

/// Parse one `field op value` term.
fn parse_cond(term: &str) -> Result<Cond, String> {
    // longest operators first so `!=`/`=~`/`!~`/`>=`/`<=` win over `=`
    for (op_str, neg, op) in [
        ("!~", true, Op::Glob),
        ("=~", false, Op::Glob),
        ("!=", true, Op::Eq),
        ("<>", true, Op::Eq),
        (">=", false, Op::Gt),
        ("<=", false, Op::Lt),
        ("==", false, Op::Eq),
        ("=", false, Op::Eq),
        (">", false, Op::Gt),
        ("<", false, Op::Lt),
    ] {
        let Some(pos) = term.find(op_str) else {
            continue;
        };
        let field_str = term[..pos].trim();
        let field = match field_str {
            "path" => Field::Path,
            "host" => Field::Host,
            "method" => Field::Method,
            "status" => Field::Status,
            "upstream" => Field::Upstream,
            "cache" => Field::Cache,
            "identity" => Field::Identity,
            other => return Err(format!("unknown log filter field {other:?}")),
        };
        let mut value = term[pos + op_str.len()..].trim().to_string();
        if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            value = value[1..value.len() - 1].to_string();
        }
        // `>=`/`<=` are inclusive — adjust to strict compares
        let (op, num) = if op_str == ">=" || op_str == "<=" {
            let n: u16 = value
                .parse()
                .map_err(|_| format!("log filter {op_str} needs a number"))?;
            if op_str == ">=" {
                (Op::Gt, Some(n.saturating_sub(1)))
            } else {
                (Op::Lt, Some(n.saturating_add(1)))
            }
        } else {
            (op, value.parse().ok())
        };
        return Ok(Cond {
            field,
            neg,
            op,
            value,
            num,
        });
    }
    Err(format!("malformed log filter term {term:?}"))
}

/// Emits access log records.
pub struct AccessLogger {
    enabled: bool,
    format: cfg::LogFormat,
    filter: Filter,
    sample: f64,
    out: Mutex<Sink>,
    /// File destination retained for SIGUSR1 reopen.
    path: Option<String>,
    /// Per-process salt for the sampling hash — `req_id` can be
    /// client-supplied (`X-Request-Id`), so without a salt a client could
    /// pick IDs that hash above the sample threshold and opt out of
    /// logging.
    sample_salt: u64,
}

enum Sink {
    Stdout,
    File(std::fs::File),
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Stdout => std::io::stdout().write(buf),
            Self::File(f) => f.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Stdout => std::io::stdout().flush(),
            Self::File(f) => f.flush(),
        }
    }
}

impl AccessLogger {
    /// Build from config.
    pub fn build(cfg: &cfg::AccessLog) -> Result<Self, String> {
        let filter = match &cfg.filter {
            Some(f) => Filter::parse(f)?,
            None => Filter::default(),
        };
        let (out, path) = match cfg.output.as_str() {
            "stdout" | "" => (Sink::Stdout, None),
            path => (Sink::File(open_append(path)?), Some(path.to_string())),
        };
        Ok(Self {
            enabled: cfg.enabled,
            format: cfg.format,
            filter,
            sample: cfg.sample.clamp(0.0, 1.0),
            out: Mutex::new(out),
            path,
            sample_salt: uuid::Uuid::new_v4().as_u128() as u64,
        })
    }

    /// Reopen the output file (SIGUSR1 logrotate hook). No-op for stdout.
    pub fn reopen(&self) {
        let Some(path) = &self.path else { return };
        match open_append(path) {
            Ok(f) => {
                if let Ok(mut out) = self.out.lock() {
                    *out = Sink::File(f);
                    tracing::info!(%path, "access log reopened");
                }
            }
            Err(e) => tracing::warn!(%path, error = %e, "access log reopen failed"),
        }
    }

    /// Emit a completed record (filtered/sampled).
    pub fn log(&self, rec: &LogRecord) {
        if !self.enabled || !self.filter.passes(rec) {
            return;
        }
        if self.sample < 1.0 {
            let hash = rec.req_id.bytes().fold(self.sample_salt, |a, b| {
                a.wrapping_mul(31).wrapping_add(b as u64)
            });
            if (hash % 10_000) as f64 / 10_000.0 >= self.sample {
                return;
            }
        }
        let line = match self.format {
            cfg::LogFormat::Json => serde_json::json!({
                "ts": rfc3339_now(),
                "req_id": &rec.req_id,
                "client_ip": rec.client_ip.to_string(),
                "method": &rec.method,
                "host": &rec.host,
                "path": &rec.path,
                "proto": &rec.proto,
                "tls": &rec.tls,
                "route": &rec.route,
                "status": rec.status,
                "bytes": rec.bytes,
                "duration_ms": rec.duration_ms,
                "user_agent": &rec.user_agent,
                "referer": &rec.referer,
                "upstream": &rec.upstream,
                "identity": &rec.identity,
                "cache": &rec.cache,
            })
            .to_string(),
            cfg::LogFormat::Pretty => format!(
                "{} \"{} {}\" {} {}B {}ms {}{}{}{}",
                rec.client_ip,
                rec.method,
                escape(&rec.path),
                rec.status,
                rec.bytes,
                rec.duration_ms,
                rec.upstream
                    .as_deref()
                    .map(|u| format!("upstream={} ", escape(u)))
                    .unwrap_or_default(),
                rec.cache
                    .as_deref()
                    .map(|c| format!("cache={c} "))
                    .unwrap_or_default(),
                escape(&rec.user_agent),
                escape(&rec.referer)
            ),
        };
        if let Ok(mut out) = self.out.lock() {
            let _ = writeln!(out, "{line}");
        }
    }
}

/// Open `path` for appending.
fn open_append(path: &str) -> Result<std::fs::File, String> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("cannot open access log {path}: {e}"))
}

/// Escape ASCII control characters and `"` for the single-line pretty
/// format — a path like `/%0aFORGED` must not inject log lines, and an
/// embedded quote must not break out of the `"method path"` field.
fn escape(s: &str) -> std::borrow::Cow<'_, str> {
    if s.bytes().all(|b| (0x20..0x7f).contains(&b) && b != b'"') {
        return std::borrow::Cow::Borrowed(s);
    }
    std::borrow::Cow::Owned(
        s.chars()
            .flat_map(|c| {
                if (c as u32) < 0x20 || c as u32 == 0x7f {
                    format!("\\x{:02x}", c as u32).chars().collect::<Vec<_>>()
                } else if c == '"' {
                    vec!['\\', '"']
                } else {
                    vec![c]
                }
            })
            .collect(),
    )
}

/// Current UTC timestamp in RFC 3339 format.
fn rfc3339_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_format() {
        let ts = rfc3339_now();
        assert!(ts.contains('T') && ts.ends_with('Z'), "{ts}");
    }

    #[test]
    fn filter_parsing_and_eval() {
        let f = Filter::parse("status >= 400 && path != \"/healthz\"").unwrap();
        assert_eq!(f.0.len(), 2);

        let mut parts = http::Request::builder()
            .method("GET")
            .uri("http://h.test/api")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        parts
            .headers
            .insert(http::header::HOST, http::HeaderValue::from_static("h.test"));
        let ctx = crate::server::service::ConnCtx {
            remote: "127.0.0.1:1".parse().unwrap(),
            tls: false,
            tls_version: None,
            request_counter: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            first_request_done: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            read_gate: crate::server::timeout::DeadlineGate::default(),
        };
        let mut rec = LogRecord::new(
            &ctx,
            &parts,
            &super::super::RequestId::extract(&parts.headers),
        );
        rec.status = 500;
        assert!(f.passes(&rec));
        rec.status = 200;
        assert!(!f.passes(&rec));

        let f = Filter::parse("path =~ \"/api/*\" && cache != HIT").unwrap();
        rec.status = 200;
        rec.path = "/api/x".into();
        rec.cache = Some("MISS".into());
        assert!(f.passes(&rec));
        rec.cache = Some("HIT".into());
        assert!(!f.passes(&rec));

        assert!(Filter::parse("bogus == 1").is_err());
        assert!(Filter::parse("status >= xx").is_err());
    }
}
