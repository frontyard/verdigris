//! Response compression: `br`/`zstd`/`gzip` content negotiation plus a
//! streaming encoder over the response body. The body is never buffered
//! — bytes flow `BoxBody → StreamReader → encoder → frames`.

use std::io;
use std::pin::Pin;

use async_compression::Level;
use async_compression::tokio::bufread::{BrotliEncoder, GzipEncoder, ZstdEncoder};
use futures_util::StreamExt;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use tokio::io::AsyncRead;
use tokio_util::io::{ReaderStream, StreamReader};

use crate::body::{self, BoxBody};
use crate::config::model::CompressConfig;
use crate::errors::BoxError;

/// A negotiated compression algorithm (its `Accept-Encoding` token is
/// [`Algo::token`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algo {
    /// Brotli — highest preference.
    Brotli,
    /// Zstandard.
    Zstd,
    /// Gzip.
    Gzip,
}

impl Algo {
    fn token(self) -> &'static str {
        match self {
            Algo::Brotli => "br",
            Algo::Zstd => "zstd",
            Algo::Gzip => "gzip",
        }
    }
}

/// A route's compiled compressor.
pub struct Compress {
    /// Enabled algorithms, sorted by server preference (br > zstd > gzip).
    algos: Vec<Algo>,
    /// Skip bodies with a known `Content-Length` below this.
    min_bytes: u64,
    /// Content-Type allowlist; a `*` suffix is a prefix wildcard.
    types: Vec<String>,
    /// Encoder quality.
    level: Level,
}

/// Request facts needed for the compression decision — captured before
/// the request body is handed to the handler.
pub struct ReqCtx {
    /// HEAD must not be compressed (a compressed HEAD would misreport
    /// `Content-Encoding` against the unencoded entity length).
    pub method_is_head: bool,
    /// A `Range` request — compressing a partial body corrupts offsets.
    pub has_range: bool,
    /// Raw `Accept-Encoding` header value.
    pub accept_encoding: Option<String>,
}

impl Compress {
    /// Compile from route config.
    pub fn build(cfg: &CompressConfig) -> Result<Self, String> {
        let mut algos = Vec::new();
        for name in &cfg.algorithms {
            let a = match name.as_str() {
                "br" | "brotli" => Algo::Brotli,
                "zstd" => Algo::Zstd,
                "gzip" | "gz" => Algo::Gzip,
                other => return Err(format!("unknown compression algorithm {other:?}")),
            };
            if !algos.contains(&a) {
                algos.push(a);
            }
        }
        algos.sort_by_key(|a| match a {
            Algo::Brotli => 0,
            Algo::Zstd => 1,
            Algo::Gzip => 2,
        });
        Ok(Self {
            algos,
            min_bytes: cfg.min_bytes.0,
            types: cfg.types.iter().map(|t| t.to_ascii_lowercase()).collect(),
            level: cfg
                .level
                .map(|l| Level::Precise(l as i32))
                .unwrap_or(Level::Default),
        })
    }

    /// Compress `resp` in place when the request negotiated an encoding
    /// and the response qualifies; otherwise a no-op. Runs last in the
    /// response pipeline so it sees the final `Content-Type`/`Vary`.
    pub fn apply(&self, resp: &mut http::Response<BoxBody>, ctx: &ReqCtx) {
        let Some(algo) = self.decide(resp, ctx) else {
            return;
        };
        let headers = resp.headers_mut();
        headers.insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_static(algo.token()),
        );
        headers.remove(header::CONTENT_LENGTH);
        // A strong ETag describes the exact bytes — transformed bodies
        // must weaken it so caches don't confuse variants.
        if let Some(etag) = headers
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            && !etag.starts_with("W/")
            && let Ok(v) = HeaderValue::from_str(&format!("W/{etag}"))
        {
            headers.insert(header::ETAG, v);
        }
        append_vary(headers, "Accept-Encoding");
        let body = std::mem::replace(resp.body_mut(), body::empty());
        *resp.body_mut() = encode(body, algo, self.level);
    }

    /// All skip rules plus `Accept-Encoding` negotiation.
    fn decide(&self, resp: &http::Response<BoxBody>, ctx: &ReqCtx) -> Option<Algo> {
        if self.algos.is_empty() || ctx.method_is_head || ctx.has_range {
            return None;
        }
        let h = resp.headers();
        if h.contains_key(header::CONTENT_ENCODING)
            || h.contains_key(header::CONTENT_RANGE)
            || body::response_body_forbidden(&http::Method::GET, resp.status())
            || resp.status() == StatusCode::PARTIAL_CONTENT
            || cache_control_has(h, "no-transform")
            || !self.type_allowed(h.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()))
        {
            return None;
        }
        if let Some(cl) = h
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            && cl < self.min_bytes
        {
            return None;
        }
        self.negotiate(ctx.accept_encoding.as_deref())
    }

    /// True when the response's media type is in the allowlist.
    fn type_allowed(&self, content_type: Option<&str>) -> bool {
        let Some(ct) = content_type else {
            return false;
        };
        let mime = ct
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        self.types.iter().any(|pat| {
            if let Some(prefix) = pat.strip_suffix('*') {
                mime.starts_with(prefix)
            } else {
                mime == *pat
            }
        })
    }

    /// Pick the enabled algorithm the client most prefers. Equal
    /// q-values resolve by server preference order.
    fn negotiate(&self, ae: Option<&str>) -> Option<Algo> {
        let ae = ae?;
        // q in thousandths to stay exact.
        let q_for = |token: &str| -> Option<u16> {
            ae.split(',')
                .filter_map(|part| {
                    let mut it = part.splitn(2, ';');
                    if !it.next()?.trim().eq_ignore_ascii_case(token) {
                        return None;
                    }
                    let q = it
                        .next()
                        .and_then(|p| {
                            let p = p.trim();
                            p.strip_prefix("q=").or_else(|| p.strip_prefix("Q="))
                        })
                        .and_then(|v| v.parse::<f32>().ok())
                        .map(|f| (f.clamp(0.0, 1.0) * 1000.0) as u16)
                        .unwrap_or(1000);
                    Some(q)
                })
                .max()
        };
        let mut best: Option<(Algo, u16)> = None;
        for a in &self.algos {
            let Some(q) = q_for(a.token()).or_else(|| q_for("*")) else {
                continue;
            };
            if q > 0 && best.is_none_or(|(_, bq)| q > bq) {
                best = Some((*a, q));
            }
        }
        best.map(|(a, _)| a)
    }
}

/// Wrap `body` in a streaming encoder for `algo`.
fn encode(body: BoxBody, algo: Algo, level: Level) -> BoxBody {
    let data = BodyExt::into_data_stream(body);
    let reader = StreamReader::new(data.map(|r| r.map_err(io::Error::other)));
    let buf = tokio::io::BufReader::with_capacity(8 * 1024, reader);
    let enc: Pin<Box<dyn AsyncRead + Send>> = match algo {
        Algo::Brotli => Box::pin(BrotliEncoder::with_quality(buf, level)),
        Algo::Zstd => Box::pin(ZstdEncoder::with_quality(buf, level)),
        Algo::Gzip => Box::pin(GzipEncoder::with_quality(buf, level)),
    };
    let frames = ReaderStream::new(enc).map(|r| r.map(Frame::data).map_err(BoxError::from));
    body::boxed(StreamBody::new(frames))
}

/// Append `token` to a `Vary` header without duplicating it.
fn append_vary(headers: &mut HeaderMap, token: &str) {
    let existing: Vec<String> = headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|s| s.trim().to_string()))
        .collect();
    if existing.iter().any(|t| t.eq_ignore_ascii_case(token)) || existing.iter().any(|t| t == "*") {
        return;
    }
    let mut merged = existing;
    merged.push(token.to_string());
    if let Ok(v) = HeaderValue::from_str(&merged.join(", ")) {
        headers.remove(header::VARY);
        headers.insert(header::VARY, v);
    }
}

/// True when a `Cache-Control` header contains `token` as a directive.
fn cache_control_has(h: &HeaderMap, token: &str) -> bool {
    h.get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|d| d.trim().eq_ignore_ascii_case(token)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::CompressConfig;

    fn comp() -> Compress {
        Compress::build(&CompressConfig::default()).unwrap()
    }

    fn resp_with(h: &[(&'static str, &'static str)]) -> http::Response<BoxBody> {
        let mut r = http::Response::new(body::full(b"hello world".as_slice()));
        for (k, v) in h {
            r.headers_mut().insert(*k, HeaderValue::from_static(v));
        }
        r
    }

    fn req_ctx(ae: Option<&str>) -> ReqCtx {
        ReqCtx {
            method_is_head: false,
            has_range: false,
            accept_encoding: ae.map(str::to_string),
        }
    }

    #[test]
    fn negotiate_prefers_brotli_on_tie() {
        let c = comp();
        assert_eq!(c.negotiate(Some("gzip, br")), Some(Algo::Brotli));
        assert_eq!(
            c.negotiate(Some("br;q=0.9, zstd;q=0.9")),
            Some(Algo::Brotli)
        );
    }

    #[test]
    fn negotiate_respects_q() {
        let c = comp();
        assert_eq!(c.negotiate(Some("gzip;q=1, br;q=0.5")), Some(Algo::Gzip));
        assert_eq!(
            c.negotiate(Some("br;q=0, gzip;q=0, zstd")),
            Some(Algo::Zstd)
        );
        assert_eq!(c.negotiate(Some("*;q=0.5")), Some(Algo::Brotli));
        assert_eq!(c.negotiate(Some("gzip;q=0, zstd;q=0, br;q=0, *;q=0")), None);
        assert_eq!(c.negotiate(None), None);
        assert_eq!(c.negotiate(Some("identity")), None);
    }

    #[test]
    fn negotiate_respects_enabled_set() {
        let cfg = CompressConfig {
            algorithms: vec!["gzip".into()],
            ..Default::default()
        };
        let c = Compress::build(&cfg).unwrap();
        assert_eq!(c.negotiate(Some("br, gzip")), Some(Algo::Gzip));
        assert_eq!(c.negotiate(Some("br")), None);
        assert_eq!(c.negotiate(Some("br;q=1, *;q=0.5")), Some(Algo::Gzip));
    }

    #[test]
    fn decide_skip_rules() {
        let c = comp();
        let ct = &[("content-type", "text/html")];
        // baseline passes
        assert!(c.decide(&resp_with(ct), &req_ctx(Some("gzip"))).is_some());
        // already encoded (precompressed static short-circuits)
        let encoded = resp_with(&[("content-type", "text/html"), ("content-encoding", "br")]);
        assert!(c.decide(&encoded, &req_ctx(Some("gzip"))).is_none());
        // HEAD
        let mut head = req_ctx(Some("gzip"));
        head.method_is_head = true;
        assert!(c.decide(&resp_with(ct), &head).is_none());
        // range
        let mut ranged = req_ctx(Some("gzip"));
        ranged.has_range = true;
        assert!(c.decide(&resp_with(ct), &ranged).is_none());
        // no-transform
        let nt = resp_with(&[
            ("content-type", "text/html"),
            ("cache-control", "public, no-transform"),
        ]);
        assert!(c.decide(&nt, &req_ctx(Some("gzip"))).is_none());
        // unlisted type
        let png = resp_with(&[("content-type", "image/png")]);
        assert!(c.decide(&png, &req_ctx(Some("gzip"))).is_none());
        // below min_bytes
        let small = resp_with(&[("content-type", "text/html"), ("content-length", "12")]);
        assert!(c.decide(&small, &req_ctx(Some("gzip"))).is_none());
        // no body statuses
        let mut notmod = resp_with(ct);
        *notmod.status_mut() = StatusCode::NOT_MODIFIED;
        assert!(c.decide(&notmod, &req_ctx(Some("gzip"))).is_none());
    }

    #[test]
    fn type_matching() {
        let c = comp();
        assert!(c.type_allowed(Some("text/html; charset=utf-8")));
        assert!(c.type_allowed(Some("Application/JSON")));
        assert!(c.type_allowed(Some("image/svg+xml")));
        assert!(!c.type_allowed(Some("image/png")));
        assert!(!c.type_allowed(None));
    }

    #[tokio::test]
    async fn apply_rewrites_headers_and_encodes() {
        let c = comp();
        let mut resp = resp_with(&[
            ("content-type", "text/plain"),
            ("content-length", "2048"),
            ("etag", "\"abc123\""),
            ("vary", "Origin"),
        ]);
        // enough bytes to pass min_bytes via streaming (no CL check now)
        resp.headers_mut().remove(header::CONTENT_LENGTH);
        c.apply(&mut resp, &req_ctx(Some("gzip, br")));
        let h = resp.headers();
        assert_eq!(h.get(header::CONTENT_ENCODING).unwrap(), "br");
        assert!(h.get(header::CONTENT_LENGTH).is_none());
        assert_eq!(h.get(header::ETAG).unwrap(), "W/\"abc123\"");
        let vary: Vec<&str> = h
            .get_all(header::VARY)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert!(
            vary.iter()
                .any(|v| v.contains("Origin") && v.contains("Accept-Encoding"))
        );
        // decode the body
        use async_compression::tokio::bufread::BrotliDecoder;
        use tokio::io::AsyncReadExt;
        let data = BodyExt::into_data_stream(resp.into_body());
        let reader = StreamReader::new(data.map(|r| r.map_err(io::Error::other)));
        let mut dec = BrotliDecoder::new(reader);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello world");
    }
}
