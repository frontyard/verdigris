//! `static` handler: streams files from a document root with index
//! resolution, directory redirects and listing, SPA and `try_files`
//! fallbacks, precompressed variants, conditional requests, ranges and
//! `Cache-Control` glob rules.
//!
//! The request path is already normalized (no `..`, no duplicate slashes)
//! before it reaches this handler, so `root.join(rel)` cannot escape the
//! document root via path traversal. Symlinks inside the root may point
//! outside it — same default as nginx; confining them would require a
//! canonicalize-and-compare pass per request.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use http::{HeaderName, HeaderValue, Method, StatusCode};

use super::{BuildError, RequestCtx};
use crate::body::{self, BoxBody};
use crate::config::model as cfg;

/// Negotiated encodings for precompressed variants, in server preference
/// order when quality values tie.
const PRECOMPRESSED: &[(&str, &str)] = &[("br", "br"), ("zstd", "zst"), ("gzip", "gz")];

/// Compiled `static` handler.
#[derive(Debug)]
pub struct Static {
    root: Arc<Path>,
    index: Vec<String>,
    listing: bool,
    spa: bool,
    try_files: Vec<String>,
    precompressed: bool,
    cache_control: Vec<(String, String)>,
    error_pages: cfg::ErrorPages,
    mime_overrides: BTreeMap<String, String>,
    /// Matched route prefix stripped from the request path before joining
    /// `root` — `alias` semantics à la Caddy, not nginx `root`.
    strip: String,
}

impl Static {
    /// Build from config. `route_prefix` is the route's `path`/`prefix`
    /// matcher, stripped from request paths before file lookup.
    pub fn build(
        c: &cfg::StaticHandler,
        route_prefix: &str,
        _site: &str,
    ) -> Result<Self, BuildError> {
        if c.root.as_os_str().is_empty() {
            return Err(BuildError::Invalid("static root is empty".into()));
        }
        for name in &c.index {
            if name.contains('/') || name == ".." || name == "." {
                return Err(BuildError::Invalid(format!(
                    "index name {name:?} must be a file name, not a path"
                )));
            }
        }
        // These values land in response headers via `HeaderValue::from_str`
        // per request — reject unparsable ones here rather than panic on
        // every matching request.
        for (ext, v) in &c.mime_types {
            HeaderValue::from_str(v).map_err(|_| {
                BuildError::Invalid(format!("mime_types.{ext}: invalid header value {v:?}"))
            })?;
        }
        for (glob, v) in &c.cache_control {
            HeaderValue::from_str(v).map_err(|_| {
                BuildError::Invalid(format!("cache_control.{glob}: invalid header value {v:?}"))
            })?;
        }
        Ok(Self {
            root: Arc::from(c.root.as_path()),
            index: c.index.clone(),
            listing: c.listing,
            spa: c.spa,
            try_files: c.try_files.clone(),
            precompressed: c.precompressed,
            cache_control: {
                // BTreeMap order is alphabetical — a `"*"` catch-all
                // would sort first and shadow every specific entry.
                // Rank by specificity instead: fewest wildcards, then
                // most literal characters (exact > "*.ext" > "*").
                let mut cc: Vec<_> = c
                    .cache_control
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                cc.sort_by_key(|(g, _)| glob_specificity(g));
                cc
            },
            error_pages: c.error_pages.clone(),
            mime_overrides: c.mime_types.clone(),
            strip: route_prefix.to_string(),
        })
    }

    /// Serve the request.
    pub async fn handle(
        &self,
        req: http::Request<BoxBody>,
        ctx: &RequestCtx,
    ) -> http::Response<BoxBody> {
        let (parts, _body) = req.into_parts();
        match self.respond(&parts, ctx).await {
            Ok(resp) => resp,
            Err(status) => self.error_page(status, &parts.method).await,
        }
    }

    /// The lookup pipeline; `Err(status)` becomes the response (possibly
    /// through a configured error page).
    async fn respond(
        &self,
        parts: &http::request::Parts,
        ctx: &RequestCtx,
    ) -> Result<http::Response<BoxBody>, StatusCode> {
        if !matches!(parts.method, Method::GET | Method::HEAD) {
            let mut resp = crate::server::service::error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            );
            resp.headers_mut()
                .insert(http::header::ALLOW, HeaderValue::from_static("GET, HEAD"));
            return Ok(resp);
        }

        let rel = ctx
            .path
            .strip_prefix(self.strip.as_str())
            .unwrap_or(ctx.path.as_str())
            .trim_start_matches('/');
        let fs_path = self.root.join(rel);
        let meta = std::fs::metadata(&fs_path).ok();

        match meta {
            Some(m) if m.is_dir() => self.serve_dir(parts, ctx, &fs_path).await,
            Some(m) if m.is_file() => self.serve_file(parts, ctx, &fs_path, &m).await,
            _ => {
                // try_files fallbacks, then SPA, then 404
                for tf in &self.try_files {
                    let p = self.root.join(tf.trim_start_matches('/'));
                    if let Ok(m) = std::fs::metadata(&p)
                        && m.is_file()
                    {
                        return self.serve_file(parts, ctx, &p, &m).await;
                    }
                }
                if self.spa
                    && let Some(resp) = self.serve_spa(parts, ctx).await
                {
                    return Ok(resp);
                }
                Err(StatusCode::NOT_FOUND)
            }
        }
    }

    /// Directory request: redirect to the trailing-slash form, then index
    /// files, `try_files`, listing, SPA, 403.
    async fn serve_dir(
        &self,
        parts: &http::request::Parts,
        ctx: &RequestCtx,
        fs_path: &Path,
    ) -> Result<http::Response<BoxBody>, StatusCode> {
        if !ctx.path.ends_with('/') {
            // ctx.path is *decoded* — re-encode so spaces/controls can't
            // corrupt the Location header or its consumers
            let mut location = format!("{}/", crate::proxy::headers::encode_path(&ctx.path));
            if let Some(q) = parts.uri.query() {
                location.push('?');
                location.push_str(q);
            }
            let mut resp = http::Response::new(body::empty());
            *resp.status_mut() = StatusCode::MOVED_PERMANENTLY;
            if let Ok(v) = HeaderValue::from_str(&location) {
                resp.headers_mut().insert(http::header::LOCATION, v);
            }
            return Ok(resp);
        }
        for name in &self.index {
            let p = fs_path.join(name);
            if let Ok(m) = std::fs::metadata(&p)
                && m.is_file()
            {
                return self.serve_file(parts, ctx, &p, &m).await;
            }
        }
        for tf in &self.try_files {
            let p = fs_path.join(tf.trim_start_matches('/'));
            if let Ok(m) = std::fs::metadata(&p)
                && m.is_file()
            {
                return self.serve_file(parts, ctx, &p, &m).await;
            }
        }
        if self.spa
            && let Some(resp) = self.serve_spa(parts, ctx).await
        {
            return Ok(resp);
        }
        if self.listing {
            return self
                .listing(parts, ctx, fs_path)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
        }
        Err(StatusCode::FORBIDDEN)
    }

    /// SPA fallback: the first index file under root.
    async fn serve_spa(
        &self,
        parts: &http::request::Parts,
        ctx: &RequestCtx,
    ) -> Option<http::Response<BoxBody>> {
        let first = self.index.first()?.clone();
        let p = self.root.join(&first);
        let m = std::fs::metadata(&p).ok()?;
        if !m.is_file() {
            return None;
        }
        self.serve_file(parts, ctx, &p, &m).await.ok()
    }

    /// Stream `fs_path` with conditional/range/precompressed handling.
    async fn serve_file(
        &self,
        parts: &http::request::Parts,
        ctx: &RequestCtx,
        fs_path: &Path,
        meta: &std::fs::Metadata,
    ) -> Result<http::Response<BoxBody>, StatusCode> {
        // precompressed variant selection (skipped when a Range is asked
        // for — byte ranges refer to the identity representation)
        let has_range = parts.headers.contains_key(http::header::RANGE);
        let mut variant_path = fs_path.to_path_buf();
        let mut encoding: Option<&'static str> = None;
        let mut variant_meta = meta.clone();
        if self.precompressed
            && !has_range
            && let Some((enc, path, m)) = self.pick_variant(fs_path, parts).await
        {
            encoding = Some(enc);
            variant_path = path;
            variant_meta = m;
        }

        let mtime = variant_meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .unwrap_or_default();
        let etag = format!(
            "\"{:x}-{:x}{}\"",
            mtime.as_nanos() as u64,
            variant_meta.len(),
            encoding.map(|e| format!("-{e}")).unwrap_or_default()
        );

        let headers = ResponseHeaders {
            content_type: self.content_type(fs_path),
            etag: etag.clone(),
            last_modified: httpdate::fmt_http_date(std::time::UNIX_EPOCH + mtime),
            cache_control: self.cache_control(&ctx.path),
            content_encoding: encoding.map(str::to_string),
        };

        // conditional requests (RFC 9110 §13): If-None-Match beats
        // If-Modified-Since for GET/HEAD
        if let Some(inm) = header_str(parts, http::header::IF_NONE_MATCH) {
            if etag_matches(inm, &etag) {
                return Ok(not_modified(headers));
            }
        } else if let Some(ims) = header_str(parts, http::header::IF_MODIFIED_SINCE)
            && let Ok(t) = httpdate::parse_http_date(ims)
            && std::time::UNIX_EPOCH + mtime <= t + std::time::Duration::from_secs(1)
        {
            return Ok(not_modified(headers));
        }

        // ranges
        if let Some(range) = header_str(parts, http::header::RANGE) {
            let if_range_ok = match header_str(parts, http::header::IF_RANGE) {
                Some(v) if v.trim().starts_with('"') => v.trim() == etag,
                Some(v) => httpdate::parse_http_date(v)
                    .map(|t| std::time::UNIX_EPOCH + mtime <= t + std::time::Duration::from_secs(1))
                    .unwrap_or(false),
                None => true,
            };
            if if_range_ok {
                return self
                    .serve_range(parts, &variant_path, &variant_meta, range, headers)
                    .await;
            }
        }
        self.stream(
            parts,
            &variant_path,
            0,
            variant_meta.len(),
            headers,
            StatusCode::OK,
        )
        .await
    }

    /// Parse `Range` and stream the selected window.
    async fn serve_range(
        &self,
        parts: &http::request::Parts,
        path: &Path,
        meta: &std::fs::Metadata,
        range: &str,
        headers: ResponseHeaders,
    ) -> Result<http::Response<BoxBody>, StatusCode> {
        let size = meta.len();
        match parse_range(range, size) {
            RangeResult::One(start, end) => {
                let len = end - start + 1;
                let mut resp = self
                    .stream(
                        parts,
                        path,
                        start,
                        len,
                        headers,
                        StatusCode::PARTIAL_CONTENT,
                    )
                    .await?;
                resp.headers_mut().insert(
                    http::header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes {start}-{end}/{size}")).unwrap(),
                );
                Ok(resp)
            }
            // multiple ranges: MAY be ignored — send the full entity
            RangeResult::Multi => {
                self.stream(parts, path, 0, size, headers, StatusCode::OK)
                    .await
            }
            RangeResult::Invalid => {
                let mut resp = crate::server::service::error_response(
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    "range not satisfiable",
                );
                resp.headers_mut().insert(
                    http::header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes */{size}")).unwrap(),
                );
                Ok(resp)
            }
        }
    }

    /// Open the file and stream `[offset, offset+len)` as the body.
    async fn stream(
        &self,
        parts: &http::request::Parts,
        path: &Path,
        offset: u64,
        len: u64,
        headers: ResponseHeaders,
        status: StatusCode,
    ) -> Result<http::Response<BoxBody>, StatusCode> {
        let file = std::fs::File::open(path).map_err(map_fs_error)?;
        let head_only = parts.method == Method::HEAD;
        let body = if head_only {
            body::empty()
        } else {
            body::file(file, offset, len)
        };
        let mut resp = http::Response::new(body);
        *resp.status_mut() = status;
        let h = resp.headers_mut();
        headers.apply(h, len);
        Ok(resp)
    }

    /// Pick the best available precompressed variant for this request.
    async fn pick_variant(
        &self,
        fs_path: &Path,
        parts: &http::request::Parts,
    ) -> Option<(&'static str, PathBuf, std::fs::Metadata)> {
        let accept = header_str(parts, http::header::ACCEPT_ENCODING)?;
        let mut best: Option<(u16, usize, &'static str, PathBuf, std::fs::Metadata)> = None;
        for (order, &(enc, ext)) in PRECOMPRESSED.iter().enumerate() {
            let q = encoding_quality(accept, enc);
            if q == 0 {
                continue;
            }
            let candidate = appended_extension(fs_path, ext);
            if let Ok(m) = std::fs::metadata(&candidate)
                && m.is_file()
            {
                let better = match &best {
                    None => true,
                    Some((bq, bo, _, _, _)) => q > *bq || (q == *bq && order < *bo),
                };
                if better {
                    best = Some((q, order, enc, candidate, m));
                }
            }
        }
        best.map(|(_, _, enc, p, m)| (enc, p, m))
    }

    /// Content-Type for the ORIGINAL file (extensions like `.gz` never leak).
    fn content_type(&self, fs_path: &Path) -> String {
        if let Some(ext) = fs_path.extension().and_then(|e| e.to_str())
            && let Some(m) = self.mime_overrides.get(ext)
        {
            return m.clone();
        }
        mime_guess::from_path(fs_path)
            .first_raw()
            .unwrap_or("application/octet-stream")
            .to_string()
    }

    /// First matching `cache_control` glob, most specific first.
    fn cache_control(&self, path: &str) -> Option<String> {
        self.cache_control
            .iter()
            .find(|(glob, _)| glob_match(glob, path))
            .map(|(_, v)| v.clone())
    }

    /// Serve a configured error page for `status`, else a plain response.
    async fn error_page(&self, status: StatusCode, method: &Method) -> http::Response<BoxBody> {
        if let Some(p) = self.error_pages.get(status.as_u16()) {
            // error page paths are always relative to `root` — a leading
            // `/` means "from the document root", like `try_files`
            let path = self.root.join(p.to_string_lossy().trim_start_matches('/'));
            if let Ok(m) = std::fs::metadata(&path)
                && m.is_file()
                && let Ok(file) = std::fs::File::open(&path)
            {
                let body = if *method == Method::HEAD {
                    body::empty()
                } else {
                    body::file(file, 0, m.len())
                };
                let mut resp = http::Response::new(body);
                *resp.status_mut() = status;
                let h = resp.headers_mut();
                let ct = mime_guess::from_path(&path)
                    .first_raw()
                    .unwrap_or("text/html")
                    .to_string();
                if let Ok(v) = HeaderValue::from_str(&ct) {
                    h.insert(http::header::CONTENT_TYPE, v);
                }
                h.insert(http::header::CONTENT_LENGTH, HeaderValue::from(m.len()));
                return resp;
            }
        }
        let mut resp = http::Response::new(if *method == Method::HEAD {
            body::empty()
        } else {
            body::full(format!("{status}\n"))
        });
        *resp.status_mut() = status;
        resp
    }

    /// Render an HTML directory listing.
    async fn listing(
        &self,
        parts: &http::request::Parts,
        ctx: &RequestCtx,
        fs_path: &Path,
    ) -> std::io::Result<http::Response<BoxBody>> {
        let mut entries = Vec::new();
        for e in std::fs::read_dir(fs_path)? {
            let e = e?;
            let name = e.file_name().to_string_lossy().to_string();
            let meta = e.metadata().ok();
            entries.push((name, meta));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut html =
            String::from("<!doctype html><html><head><meta charset=utf-8><title>Index of ");
        html.push_str(&html_escape(&ctx.path));
        html.push_str("</title><style>body{font-family:sans-serif;margin:2em}td{padding:2px 1em 2px 0}</style></head><body><h1>Index of ");
        html.push_str(&html_escape(&ctx.path));
        html.push_str("</h1><table>");
        html.push_str("<tr><td><a href=\"../\">../</a></td><td>-</td><td></td></tr>");
        for (name, meta) in &entries {
            let (is_dir, size, mtime) = match meta {
                Some(m) => (
                    m.is_dir(),
                    m.len(),
                    m.modified()
                        .ok()
                        .map(httpdate::fmt_http_date)
                        .unwrap_or_default(),
                ),
                None => (false, 0, String::new()),
            };
            let display = if is_dir {
                format!("{name}/")
            } else {
                name.clone()
            };
            let href = format!("{}{}", uri_escape(&display), if is_dir { "/" } else { "" });
            html.push_str(&format!(
                "<tr><td><a href=\"{href}\">{}</a></td><td>{size}</td><td>{mtime}</td></tr>",
                html_escape(&display),
            ));
        }
        html.push_str("</table></body></html>\n");

        let mut resp = http::Response::new(if parts.method == Method::HEAD {
            body::empty()
        } else {
            body::full(html.clone())
        });
        let h = resp.headers_mut();
        h.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        h.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&html.len().to_string()).unwrap(),
        );
        Ok(resp)
    }
}

/// Response headers shared by all file-serving paths.
struct ResponseHeaders {
    content_type: String,
    etag: String,
    last_modified: String,
    cache_control: Option<String>,
    content_encoding: Option<String>,
}

impl ResponseHeaders {
    fn apply(&self, h: &mut http::HeaderMap, len: u64) {
        h.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_str(&self.content_type).unwrap(),
        );
        h.insert(http::header::CONTENT_LENGTH, HeaderValue::from(len));
        h.insert(
            http::header::ETAG,
            HeaderValue::from_str(&self.etag).unwrap(),
        );
        h.insert(
            http::header::LAST_MODIFIED,
            HeaderValue::from_str(&self.last_modified).unwrap(),
        );
        h.insert(
            http::header::ACCEPT_RANGES,
            HeaderValue::from_static("bytes"),
        );
        if let Some(cc) = &self.cache_control {
            h.insert(
                http::header::CACHE_CONTROL,
                HeaderValue::from_str(cc).unwrap(),
            );
        }
        if let Some(enc) = &self.content_encoding {
            h.insert(
                http::header::CONTENT_ENCODING,
                HeaderValue::from_str(enc).unwrap(),
            );
            h.append(
                http::header::VARY,
                HeaderValue::from_static("Accept-Encoding"),
            );
        }
    }
}

/// A 304 carrying validators.
fn not_modified(headers: ResponseHeaders) -> http::Response<BoxBody> {
    let mut resp = http::Response::new(body::empty());
    *resp.status_mut() = StatusCode::NOT_MODIFIED;
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&headers.etag) {
        h.insert(http::header::ETAG, v);
    }
    if let Ok(v) = HeaderValue::from_str(&headers.last_modified) {
        h.insert(http::header::LAST_MODIFIED, v);
    }
    if let Some(cc) = &headers.cache_control
        && let Ok(v) = HeaderValue::from_str(cc)
    {
        h.insert(http::header::CACHE_CONTROL, v);
    }
    resp
}

fn header_str(parts: &http::request::Parts, name: HeaderName) -> Option<&str> {
    parts.headers.get(name).and_then(|v| v.to_str().ok())
}

/// Weak/strong comparison for If-None-Match (`*` or tag list).
fn etag_matches(inm: &str, etag: &str) -> bool {
    let inm = inm.trim();
    if inm == "*" {
        return true;
    }
    let bare = etag.trim_matches('"');
    inm.split(',').any(|t| {
        let t = t.trim().trim_start_matches("W/").trim_matches('"');
        t == bare
    })
}

enum RangeResult {
    One(u64, u64),
    Multi,
    Invalid,
}

/// Parse a `bytes=` range against `size`. Only single ranges are honoured.
fn parse_range(header: &str, size: u64) -> RangeResult {
    let Some(spec) = header.trim().strip_prefix("bytes=") else {
        return RangeResult::Invalid;
    };
    let mut pieces = spec.split(',');
    let first = pieces.next().unwrap_or_default().trim();
    if pieces.next().is_some() {
        return RangeResult::Multi;
    }
    let Some((a, b)) = first.split_once('-') else {
        return RangeResult::Invalid;
    };
    let (start, end) = if a.is_empty() {
        // suffix range: last N bytes
        let Ok(n) = b.parse::<u64>() else {
            return RangeResult::Invalid;
        };
        if n == 0 {
            return RangeResult::Invalid;
        }
        if n >= size {
            (0, size.saturating_sub(1))
        } else {
            (size - n, size - 1)
        }
    } else {
        let Ok(start) = a.parse::<u64>() else {
            return RangeResult::Invalid;
        };
        let end = if b.is_empty() {
            size.saturating_sub(1)
        } else {
            match b.parse::<u64>() {
                Ok(e) => e.min(size.saturating_sub(1)),
                Err(_) => return RangeResult::Invalid,
            }
        };
        (start, end)
    };
    if start > end || start >= size {
        return RangeResult::Invalid;
    }
    RangeResult::One(start, end)
}

/// The client's quality value for `encoding` in `Accept-Encoding` (0–1000;
/// absent = 0 for file variants — we don't synthesize compressed files).
fn encoding_quality(accept: &str, encoding: &str) -> u16 {
    let mut q = 0u16;
    for item in accept.split(',') {
        let mut it = item.trim().split(';');
        let token = it.next().unwrap_or_default().trim();
        let mut quality = 1000u16;
        for param in it {
            let p = param.trim();
            if let Some(v) = p.strip_prefix("q=")
                && let Ok(f) = v.parse::<f32>()
            {
                quality = (f * 1000.0) as u16;
            }
        }
        if token.eq_ignore_ascii_case(encoding) && quality > q {
            q = quality;
        } else if token == "*" && q == 0 && quality > 0 {
            q = quality.min(999); // wildcard never beats an exact token
        }
    }
    q
}

/// `file` → `file.gz`-style path (append, not replace, the extension).
fn appended_extension(path: &Path, ext: &str) -> PathBuf {
    let mut p = path.to_path_buf().into_os_string();
    p.push(".");
    p.push(ext);
    PathBuf::from(p)
}

/// Map filesystem errors to HTTP statuses.
fn map_fs_error(e: std::io::Error) -> StatusCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
        std::io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Minimal glob matcher: `*` matches any sequence (including `/`).
/// `*.css`, `/assets/*`, `*` are the supported shapes.
pub(crate) fn glob_match(pattern: &str, path: &str) -> bool {
    let mut rest = path;
    let anchored_start = !pattern.starts_with('*');
    let mut first = true;
    for part in pattern.split('*') {
        if part.is_empty() {
            first = false;
            continue;
        }
        match rest.find(part) {
            Some(i) if !anchored_start || !first || i == 0 => rest = &rest[i + part.len()..],
            Some(0) => rest = &rest[part.len()..],
            _ => return false,
        }
        first = false;
    }
    pattern.ends_with('*') || rest.is_empty()
}

/// Specificity rank for `cache_control` globs — sorts ascending so the
/// most specific pattern wins regardless of declaration order: fewest
/// wildcards first, then most literal characters (`"*.css"` beats
/// `"*"`; an exact path has no wildcard and always wins).
fn glob_specificity(pattern: &str) -> (usize, usize) {
    let wildcards = pattern.matches('*').count();
    let literals = pattern.chars().filter(|&c| c != '*').count();
    (wildcards, usize::MAX - literals)
}

/// Escape HTML special chars.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Percent-encode a path segment for use in a link.
fn uri_escape(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_parsing() {
        match parse_range("bytes=0-9", 100) {
            RangeResult::One(0, 9) => {}
            _ => panic!(),
        }
        match parse_range("bytes=10-", 100) {
            RangeResult::One(10, 99) => {}
            _ => panic!(),
        }
        match parse_range("bytes=-20", 100) {
            RangeResult::One(80, 99) => {}
            _ => panic!(),
        }
        match parse_range("bytes=-5000", 100) {
            RangeResult::One(0, 99) => {}
            _ => panic!(),
        }
        match parse_range("bytes=90-50", 100) {
            RangeResult::Invalid => {}
            _ => panic!(),
        }
        match parse_range("bytes=0-1,5-6", 100) {
            RangeResult::Multi => {}
            _ => panic!(),
        }
        match parse_range("items=0-9", 100) {
            RangeResult::Invalid => {}
            _ => panic!(),
        }
    }

    #[test]
    fn etag_weak_and_star() {
        assert!(etag_matches("\"abc-1\"", "\"abc-1\""));
        assert!(etag_matches("W/\"abc-1\"", "\"abc-1\""));
        assert!(etag_matches("*", "\"abc-1\""));
        assert!(etag_matches("\"x\", \"abc-1\"", "\"abc-1\""));
        assert!(!etag_matches("\"other\"", "\"abc-1\""));
    }

    #[test]
    fn accept_encoding_quality() {
        assert_eq!(encoding_quality("br, gzip", "br"), 1000);
        assert_eq!(encoding_quality("br;q=0.5, gzip", "br"), 500);
        assert_eq!(encoding_quality("gzip;q=0", "gzip"), 0);
        assert_eq!(encoding_quality("*", "br"), 999);
        assert_eq!(encoding_quality("identity", "br"), 0);
    }

    #[test]
    fn glob_rules() {
        assert!(glob_match("*.css", "/a/b.css"));
        assert!(glob_match("/assets/*", "/assets/x.css"));
        assert!(!glob_match("/assets/*", "/x.css"));
        assert!(glob_match("*", "/anything"));
        assert!(glob_match("*.js", "app.js"));
        assert!(!glob_match("*.js", "app.css"));
    }
}

#[cfg(test)]
mod handler_tests {
    use super::*;
    use crate::handler::RequestCtx;
    use http_body_util::BodyExt;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn cfg_with(
        root: &std::path::Path,
        f: impl FnOnce(&mut cfg::StaticHandler),
    ) -> cfg::StaticHandler {
        let mut c = cfg::StaticHandler {
            root: root.to_path_buf(),
            ..Default::default()
        };
        f(&mut c);
        c
    }

    fn ctx(path: &str) -> RequestCtx {
        RequestCtx {
            path: path.into(),
            host: "x".into(),
            client_ip: "10.0.0.1".parse().unwrap(),
            peer_ip: "10.0.0.1".parse().unwrap(),
            peer_trusted: false,
            tls: false,
            scheme: "http",
        }
    }

    fn req(method: Method, path: &str) -> http::Request<BoxBody> {
        http::Request::builder()
            .method(method)
            .uri(path)
            .body(crate::body::empty())
            .unwrap()
    }

    async fn body_text(r: http::Response<BoxBody>) -> String {
        String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
    }

    #[tokio::test]
    async fn method_not_allowed_allows_get_head() {
        let d = tmp();
        let s = Static::build(&cfg_with(d.path(), |_| {}), "/", "s").unwrap();
        let r = s.handle(req(Method::POST, "/f.txt"), &ctx("/f.txt")).await;
        assert_eq!(r.status(), 405);
        assert_eq!(r.headers()["allow"], "GET, HEAD");
    }

    #[tokio::test]
    async fn serve_file_with_mime_and_conditionals() {
        let d = tmp();
        std::fs::write(d.path().join("f.txt"), "hello").unwrap();
        let mut c = cfg_with(d.path(), |_| {});
        c.mime_types.insert("txt".into(), "text/x-test".into());
        let s = Static::build(&c, "/", "s").unwrap();

        let r = s.handle(req(Method::GET, "/f.txt"), &ctx("/f.txt")).await;
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["content-type"], "text/x-test");
        let etag = r.headers()["etag"].to_str().unwrap().to_string();
        assert_eq!(body_text(r).await, "hello");

        // If-None-Match hit → 304
        let r2 = http::Request::builder()
            .uri("/f.txt")
            .header("if-none-match", etag.clone())
            .body(crate::body::empty())
            .unwrap();
        let r2 = s.handle(r2, &ctx("/f.txt")).await;
        assert_eq!(r2.status(), 304);

        // If-Modified-Since in the future → 304
        let r3 = http::Request::builder()
            .uri("/f.txt")
            .header("if-modified-since", "Wed, 21 Oct 2099 07:28:00 GMT")
            .body(crate::body::empty())
            .unwrap();
        assert_eq!(s.handle(r3, &ctx("/f.txt")).await.status(), 304);

        // HEAD: headers but empty body
        let r4 = s.handle(req(Method::HEAD, "/f.txt"), &ctx("/f.txt")).await;
        assert_eq!(r4.status(), 200);
        assert!(body_text(r4).await.is_empty());
    }

    #[tokio::test]
    async fn range_requests() {
        let d = tmp();
        std::fs::write(d.path().join("f.bin"), "0123456789").unwrap();
        let s = Static::build(&cfg_with(d.path(), |_| {}), "/", "s").unwrap();

        let with = |hdr: &str| {
            http::Request::builder()
                .uri("/f.bin")
                .header("range", hdr)
                .body(crate::body::empty())
                .unwrap()
        };
        let r = s.handle(with("bytes=0-3"), &ctx("/f.bin")).await;
        assert_eq!(r.status(), 206);
        assert_eq!(r.headers()["content-range"], "bytes 0-3/10");
        assert_eq!(body_text(r).await, "0123");

        // unsatisfiable → 416
        let r = s.handle(with("bytes=50-60"), &ctx("/f.bin")).await;
        assert_eq!(r.status(), 416);

        // If-Range mismatch → full 200
        let r = http::Request::builder()
            .uri("/f.bin")
            .header("range", "bytes=0-3")
            .header("if-range", "\"other\"")
            .body(crate::body::empty())
            .unwrap();
        let r = s.handle(r, &ctx("/f.bin")).await;
        assert_eq!(r.status(), 200);
        assert_eq!(body_text(r).await, "0123456789");
    }

    #[tokio::test]
    async fn directory_index_listing_and_redirect() {
        let d = tmp();
        let sub = d.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("index.html"), "<h1>idx</h1>").unwrap();
        let s = Static::build(&cfg_with(d.path(), |_| {}), "/", "s").unwrap();

        // dir without trailing slash → redirect preserving query
        let r = s.handle(req(Method::GET, "/sub?a=1"), &ctx("/sub")).await;
        assert!(matches!(r.status().as_u16(), 301 | 308));
        assert_eq!(r.headers()["location"], "/sub/?a=1");

        // with trailing slash → serves index.html
        let r = s.handle(req(Method::GET, "/sub/"), &ctx("/sub/")).await;
        assert_eq!(r.status(), 200);
        assert_eq!(body_text(r).await, "<h1>idx</h1>");

        // listing: no index file → html listing
        std::fs::create_dir(d.path().join("ls")).unwrap();
        std::fs::write(d.path().join("ls/a.txt"), "x").unwrap();
        let mut c = cfg_with(d.path(), |_| {});
        c.listing = true;
        let s = Static::build(&c, "/", "s").unwrap();
        let r = s.handle(req(Method::GET, "/ls/"), &ctx("/ls/")).await;
        assert_eq!(r.status(), 200);
        assert!(body_text(r).await.contains("a.txt"));

        // no listing, no index → 403 (dir exists but not listable)
        let s = Static::build(&cfg_with(d.path(), |_| {}), "/", "s").unwrap();
        let r = s.handle(req(Method::GET, "/ls/"), &ctx("/ls/")).await;
        assert_eq!(r.status(), 403);
    }

    #[tokio::test]
    async fn try_files_then_spa_then_404() {
        let d = tmp();
        std::fs::write(d.path().join("app.html"), "app").unwrap();
        std::fs::write(d.path().join("fallback.txt"), "fb").unwrap();

        // try_files hit
        let mut c = cfg_with(d.path(), |c| c.try_files = vec!["/fallback.txt".into()]);
        let s = Static::build(&c, "/", "s").unwrap();
        let r = s
            .handle(req(Method::GET, "/missing"), &ctx("/missing"))
            .await;
        assert_eq!(r.status(), 200);
        assert_eq!(body_text(r).await, "fb");

        // try_files miss + spa → serves index (app.html as the spa fallback)
        c.spa = true;
        c.index = vec!["app.html".into()];
        c.try_files = vec!["/nope".into()];
        let s = Static::build(&c, "/", "s").unwrap();
        let r = s
            .handle(req(Method::GET, "/route/x"), &ctx("/route/x"))
            .await;
        assert_eq!(r.status(), 200);
        assert_eq!(body_text(r).await, "app");

        // plain 404
        let s = Static::build(&cfg_with(d.path(), |_| {}), "/", "s").unwrap();
        let r = s
            .handle(req(Method::GET, "/missing"), &ctx("/missing"))
            .await;
        assert_eq!(r.status(), 404);
    }

    #[tokio::test]
    async fn precompressed_variants() {
        let d = tmp();
        std::fs::write(d.path().join("f.js"), "plain").unwrap();
        std::fs::write(d.path().join("f.js.br"), "brotli").unwrap();
        std::fs::write(d.path().join("f.js.gz"), "gzip").unwrap();
        let s = Static::build(&cfg_with(d.path(), |_| {}), "/", "s").unwrap();

        let accept = |v: &str| {
            http::Request::builder()
                .uri("/f.js")
                .header("accept-encoding", v)
                .body(crate::body::empty())
                .unwrap()
        };
        let r = s.handle(accept("br, gzip"), &ctx("/f.js")).await;
        assert_eq!(r.headers()["content-encoding"], "br");
        assert_eq!(body_text(r).await, "brotli");

        let r = s.handle(accept("gzip"), &ctx("/f.js")).await;
        assert_eq!(r.headers()["content-encoding"], "gzip");
        assert_eq!(body_text(r).await, "gzip");

        let r = s.handle(accept("identity"), &ctx("/f.js")).await;
        assert!(r.headers().get("content-encoding").is_none());
        assert_eq!(body_text(r).await, "plain");
    }

    #[tokio::test]
    async fn error_pages_and_cache_control() {
        let d = tmp();
        std::fs::write(d.path().join("404.html"), "<h1>nope</h1>").unwrap();
        std::fs::write(d.path().join("x.css"), "a{}").unwrap();
        let mut c = cfg_with(d.path(), |c| {
            c.error_pages.exact.insert(404, PathBuf::from("404.html"));
            c.cache_control
                .insert("*.css".into(), "public, max-age=99".into());
        });
        let s = Static::build(&c, "/", "s").unwrap();

        let r = s
            .handle(req(Method::GET, "/missing"), &ctx("/missing"))
            .await;
        assert_eq!(r.status(), 404);
        assert_eq!(body_text(r).await, "<h1>nope</h1>");

        let r = s.handle(req(Method::GET, "/x.css"), &ctx("/x.css")).await;
        assert_eq!(r.headers()["cache-control"], "public, max-age=99");
        let _ = &mut c;
    }

    #[tokio::test]
    async fn cache_control_prefers_specific_glob() {
        // "*" sorts first in the BTreeMap — it must not shadow "*.css"
        let d = tmp();
        std::fs::write(d.path().join("x.css"), "a{}").unwrap();
        let mut c = cfg_with(d.path(), |c| {
            c.cache_control.insert("*".into(), "no-cache".into());
            c.cache_control
                .insert("*.css".into(), "max-age=86400".into());
        });
        let s = Static::build(&c, "/", "s").unwrap();
        let r = s.handle(req(Method::GET, "/x.css"), &ctx("/x.css")).await;
        assert_eq!(r.headers()["cache-control"], "max-age=86400");
        let r = s.handle(req(Method::GET, "/x.png"), &ctx("/x.png")).await;
        assert_eq!(r.status(), 404); // file absent — glob order unaffected
        let _ = &mut c;
    }

    #[test]
    fn build_rejects_bad_config() {
        let d = tmp();
        let c = cfg_with(d.path(), |c| c.root = PathBuf::new());
        assert!(Static::build(&c, "/", "s").is_err());
        let c = cfg_with(d.path(), |c| c.index = vec!["../evil".into()]);
        assert!(Static::build(&c, "/", "s").is_err());
        let c = cfg_with(d.path(), |c| {
            c.mime_types.insert("x".into(), "bad\r\nvalue".into());
        });
        assert!(Static::build(&c, "/", "s").is_err());
        let c = cfg_with(d.path(), |c| {
            c.cache_control.insert("*".into(), "bad\r\nvalue".into());
        });
        assert!(Static::build(&c, "/", "s").is_err());
    }
}
