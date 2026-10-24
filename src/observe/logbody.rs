//! Access-log body wrapper: counts streamed bytes and emits the log
//! record (+ request metrics) exactly once — on end-of-stream, or as
//! `499` when the connection drops mid-body (client abort).

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use http_body::Frame;

use crate::body::BoxBody;
use crate::errors::BoxError;
use crate::observe::LogRecord;

/// Response body that finalizes the access-log record. `UnsyncBoxBody`
/// is `Unpin`, so plain field access suffices.
pub struct AccessLogBody {
    inner: BoxBody,
    rt: Arc<crate::server::Runtime>,
    rec: Option<LogRecord>,
    started: Instant,
    status: u16,
    /// HEAD responses and 101 upgrades drop their body legitimately —
    /// not client aborts.
    graceful_drop_ok: bool,
    /// Declared `content-length` when present — hyper may stop polling a
    /// satisfied fixed-length body, so reaching it means completion.
    expected: Option<u64>,
    bytes: u64,
    finished: bool,
    /// Connection read-deadline gate: the service incremented `active`
    /// when this request started; releasing it here re-arms the
    /// between-requests deadline — and wakes the parked read so it can
    /// actually arm.
    gate: crate::server::timeout::DeadlineGate,
}

/// Wrap `resp`'s body so the record is emitted on completion/abort.
pub fn wrap(
    resp: &mut http::Response<BoxBody>,
    rec: LogRecord,
    rt: Arc<crate::server::Runtime>,
    started: Instant,
    method_is_head: bool,
    gate: crate::server::timeout::DeadlineGate,
) {
    let status = resp.status().as_u16();
    let body = std::mem::replace(resp.body_mut(), crate::body::empty());
    // an already-empty body may be dropped without a poll — that's a
    // completed response, not an abort (same for HEAD and upgrades)
    let graceful = method_is_head
        || status == http::StatusCode::SWITCHING_PROTOCOLS.as_u16()
        || http_body::Body::is_end_stream(&body);
    let expected = resp
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());
    *resp.body_mut() = crate::body::boxed(AccessLogBody {
        inner: body,
        rt,
        rec: Some(rec),
        started,
        status,
        graceful_drop_ok: graceful,
        expected,
        bytes: 0,
        finished: false,
        gate,
    });
}

impl AccessLogBody {
    /// Emit the record once. `status_override` wins when set (499 abort).
    fn finalize(&mut self, status_override: Option<u16>) {
        if self.finished {
            return;
        }
        self.finished = true;
        // response cycle over — between-requests read deadline may arm;
        // wake the parked read since nothing else re-polls it
        self.gate.active.fetch_sub(1, Ordering::Release);
        self.gate.wake_reader();
        if let Some(mut rec) = self.rec.take() {
            let status = status_override.unwrap_or(self.status);
            rec.finalize(self.started, status, self.bytes);
            self.rt.access.log(&rec);
            crate::observe::metrics::request_done(&rec);
        }
    }
}

impl http_body::Body for AccessLogBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let s = self.as_mut().get_mut();
        match Pin::new(&mut s.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    s.bytes += data.len() as u64;
                }
                // hyper may stop polling a satisfied fixed-length body —
                // the end check happens eagerly here like the cache tee
                if s.inner.is_end_stream() || s.expected.is_some_and(|e| s.bytes >= e) {
                    s.finalize(None);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                // mid-stream body error — the client sees truncation
                s.finalize(Some(499));
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                s.finalize(None);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for AccessLogBody {
    fn drop(&mut self) {
        // dropped before the stream finished: a client abort unless the
        // declared bytes all went out or the response kind legitimately
        // drops its body (HEAD, upgrade)
        let done = self.expected.is_some_and(|e| self.bytes >= e);
        let status = if self.graceful_drop_ok || done {
            None
        } else {
            Some(499)
        };
        self.finalize(status);
    }
}
