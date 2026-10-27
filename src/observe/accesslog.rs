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
    Stderr,
    File(std::fs::File),
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Stdout => std::io::stdout().write(buf),
            Self::Stderr => std::io::stderr().write(buf),
            Self::File(f) => f.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Stdout => std::io::stdout().flush(),
            Self::Stderr => std::io::stderr().flush(),
            Self::File(f) => f.flush(),
        }
    }
}

impl AccessLogger {
    /// Build from config. `mode` gates the file open: [`BuildMode::Check`]
    /// verifies the destination looks writable without creating it.
    pub fn build(cfg: &cfg::AccessLog, mode: crate::BuildMode) -> Result<Self, String> {
        let filter = match &cfg.filter {
            Some(f) => Filter::parse(f)?,
            None => Filter::default(),
        };
        let (out, path) = match cfg.output.as_str() {
            "stdout" | "" => (Sink::Stdout, None),
            "stderr" => (Sink::Stderr, None),
            path if mode.live() => (Sink::File(open_append(path)?), Some(path.to_string())),
            path => {
                check_log_path(path)?;
                (Sink::Stderr, Some(path.to_string()))
            }
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

/// Open `path` for appending, creating the parent directory when it is
/// missing (same treatment the cache directory gets).
pub fn open_append(path: &str) -> Result<std::fs::File, String> {
    if let Some(dir) = std::path::Path::new(path)
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
    {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create log dir {}: {e}", dir.display()))?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("cannot open access log {path}: {e}"))
}

/// A `BuildMode::Check` look at a log output path: the file is never
/// opened or created, but an obviously-bad destination (a directory
/// where the file belongs, or a file standing where a parent directory
/// needs to be created) is an error.
pub fn check_log_path(path: &str) -> Result<(), String> {
    let p = std::path::Path::new(path);
    if p.is_dir() {
        return Err(format!("log output {path} is a directory"));
    }
    let mut dir = p.parent();
    while let Some(d) = dir {
        if d.as_os_str().is_empty() || d.is_dir() {
            return Ok(());
        }
        if d.exists() {
            return Err(format!(
                "log output {path}: {} is not a directory",
                d.display()
            ));
        }
        dir = d.parent();
    }
    Ok(())
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
            conn_guard: crate::server::ConnGuard::for_test("127.0.0.1".parse().unwrap()),
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

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use std::net::IpAddr;

    fn rec() -> LogRecord {
        LogRecord {
            req_id: "r1".into(),
            client_ip: IpAddr::from([127, 0, 0, 1]),
            method: "GET".into(),
            host: "h".into(),
            path: "/p".into(),
            proto: "HTTP/1.1".into(),
            tls: None,
            route: None,
            status: 200,
            bytes: 10,
            duration_ms: 1,
            user_agent: "ua".into(),
            referer: String::new(),
            upstream: None,
            identity: None,
            cache: None,
            meters: None,
            req_bytes: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    #[test]
    fn filter_operators() {
        // each op family on each field kind
        let cases: &[(&str, bool)] = &[
            ("path == \"/p\"", true),
            ("path != \"/p\"", false),
            ("path <> \"/q\"", true),
            ("path =~ \"/p*\"", true),
            ("path !~ \"/q*\"", true),
            ("host = \"h\"", true),
            ("method = \"GET\"", true),
            ("method > \"A\"", true),
            ("method < \"ZZZ\"", true),
            ("status = 200", true),
            ("status > 199", true),
            ("status < 201", true),
            ("status >= 200", true),
            ("status <= 200", true),
            ("status =~ \"2*\"", false), // glob on status is false
            ("upstream = \"u\"", false), // absent → ""
            ("identity != \"\"", false),
        ];
        for (expr, want) in cases {
            let f = Filter::parse(expr).unwrap();
            assert_eq!(f.passes(&rec()), *want, "{expr}");
        }
        // conjunction + errors
        let f = Filter::parse("status >= 400 && path != \"/healthz\"").unwrap();
        assert!(!f.passes(&rec()));
        let mut r = rec();
        r.status = 500;
        assert!(f.passes(&r));
        assert!(Filter::parse("bogus = x").is_err());
        assert!(Filter::parse("status >= abc").is_err());
        // empty filter passes everything
        assert!(Filter::default().passes(&rec()));
        assert!(Filter::parse("").unwrap().passes(&rec()));
    }

    #[test]
    fn logger_build_log_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.log");
        let cfg = crate::config::model::AccessLog {
            enabled: true,
            output: path.to_string_lossy().into(),
            format: crate::config::model::LogFormat::Json,
            ..Default::default()
        };
        let l = AccessLogger::build(&cfg, crate::BuildMode::Live).unwrap();
        l.log(&rec());
        l.reopen(); // swaps the file sink
        l.log(&rec());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"status\":200"));

        // bad filter → build error
        let cfg = crate::config::model::AccessLog {
            filter: Some("bogus = x".into()),
            ..cfg
        };
        assert!(AccessLogger::build(&cfg, crate::BuildMode::Live).is_err());
        // disabled → nothing written
        let cfg = crate::config::model::AccessLog {
            enabled: false,
            output: dir.path().join("b.log").to_string_lossy().into(),
            ..Default::default()
        };
        let l = AccessLogger::build(&cfg, crate::BuildMode::Live).unwrap();
        l.log(&rec());
        // sample=0 → records dropped by the hash gate
        let cfg = crate::config::model::AccessLog {
            sample: 0.0,
            output: "stdout".into(),
            ..Default::default()
        };
        let l = AccessLogger::build(&cfg, crate::BuildMode::Live).unwrap();
        l.log(&rec());
        // pretty format
        let cfg = crate::config::model::AccessLog {
            output: dir.path().join("c.log").to_string_lossy().into(),
            format: crate::config::model::LogFormat::Pretty,
            ..Default::default()
        };
        let l = AccessLogger::build(&cfg, crate::BuildMode::Live).unwrap();
        l.log(&rec());
        assert!(
            std::fs::read_to_string(dir.path().join("c.log"))
                .unwrap()
                .contains("GET")
        );
        // reopen on stdout logger → no-op
        let l = AccessLogger::build(
            &crate::config::model::AccessLog::default(),
            crate::BuildMode::Live,
        )
        .unwrap();
        l.reopen();
    }

    #[test]
    fn escape_and_finalize() {
        assert_eq!(escape("plain/path"), "plain/path");
        assert_eq!(escape("a\"b"), "a\\\"b");
        assert!(escape("a\x01b").contains("\\x01"));
        assert_eq!(escape("uni—dash"), "uni—dash");

        let mut r = rec();
        r.finalize(std::time::Instant::now(), 503, 42);
        assert_eq!(r.status, 503);
        assert_eq!(r.bytes, 42);
        let f = r.fields();
        assert_eq!(f.status, 503);
    }
}
