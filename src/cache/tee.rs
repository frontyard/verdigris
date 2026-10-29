//! Streaming write-through: wraps a handler response body, buffering
//! each frame for the cache while passing it to the client untouched.
//! When the stream ends the buffer is committed via a oneshot; if the
//! body is dropped early (client abort) or exceeds `max_object`, the
//! sender is dropped and nothing is stored.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http_body::Frame;
use pin_project_lite::pin_project;

use crate::body::BoxBody;
use crate::errors::BoxError;

pin_project! {
    /// Body wrapper: tee frames into `buf` up to `limit`, then commit.
    pub struct CacheTee {
        #[pin]
        inner: BoxBody,
        buf: BytesMut,
        limit: u64,
        // expected body length (declared content-length or the body's
        // own exact size hint) — a fixed-length body may never be polled
        // to `Ready(None)` by hyper, so reaching this many buffered bytes
        // is itself end-of-stream.
        expected: Option<u64>,
        tx: Option<tokio::sync::oneshot::Sender<Bytes>>,
    }
}

/// Wrap `inner` so a completed stream is handed to `tx`. `expected` is
/// the declared content-length when known (hyper may not poll a
/// fixed-length body to `Ready(None)`).
pub fn new(
    inner: BoxBody,
    tx: tokio::sync::oneshot::Sender<Bytes>,
    limit: u64,
    expected: Option<u64>,
) -> BoxBody {
    let expected = expected.or_else(|| http_body::Body::size_hint(&inner).exact());
    crate::body::boxed(CacheTee {
        inner,
        buf: BytesMut::new(),
        limit,
        expected,
        tx: Some(tx),
    })
}

impl CacheTee {
    /// Send the collected body to the commit task, once.
    fn commit(buf: &mut BytesMut, tx: &mut Option<tokio::sync::oneshot::Sender<Bytes>>) {
        if let Some(tx) = tx.take() {
            let _ = tx.send(buf.split().freeze());
        }
    }
}

impl http_body::Body for CacheTee {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if this.tx.is_some() {
                    if let Some(data) = frame.data_ref() {
                        this.buf.extend_from_slice(data);
                    }
                    let over = this.buf.len() as u64 > *this.limit;
                    // hyper may stop polling once a fixed-length body is
                    // satisfied — `exact()` bytes received is the end.
                    let complete = this.inner.is_end_stream()
                        || this.expected.is_some_and(|e| this.buf.len() as u64 >= e);
                    if over {
                        // over the storable cap — drop the sender (no store)
                        this.tx.take();
                    } else if complete {
                        Self::commit(this.buf, this.tx);
                    }
                }
                // (trailers are dropped silently — rare and non-essential)
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.tx.take();
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                Self::commit(this.buf, this.tx);
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

#[cfg(test)]
mod tests {
    use super::*;
    use http_body::Body;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn commits_on_exact_completion() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let body = new(crate::body::full("hello"), tx, 100, Some(5));
        let collected = body.collect().await.unwrap().to_bytes();
        assert_eq!(collected.as_ref(), b"hello");
        assert_eq!(rx.await.unwrap().as_ref(), b"hello");
    }

    #[test]
    fn size_hint_delegates_to_inner() {
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let b = new(crate::body::full("hello"), tx, 100, Some(5));
        // a `-> Default` stub returns an unbounded hint — callers that
        // preallocate or compare Content-Length lose the real bound
        assert_eq!(b.size_hint().exact(), Some(5));
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let b = new(crate::body::empty(), tx, 100, None);
        assert_eq!(b.size_hint().exact(), Some(0));
    }

    #[tokio::test]
    async fn commits_without_final_poll_via_expected() {
        // simulate hyper dropping the body after the exact-length frame:
        // poll once (data), then drop — the commit must already have fired
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut body = new(
            crate::body::boxed(http_body_util::StreamBody::new(futures_util::stream::iter(
                vec![Ok::<_, BoxError>(Frame::data(Bytes::from_static(b"hello")))],
            ))),
            tx,
            100,
            Some(5),
        );
        // first poll yields the data frame and commits inline
        let f = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
        assert!(f.unwrap().is_ok());
        assert_eq!(rx.await.unwrap().as_ref(), b"hello");
    }

    #[tokio::test]
    async fn over_limit_stores_nothing() {
        let (tx, rx) = tokio::sync::oneshot::channel::<Bytes>();
        let body = new(crate::body::full("way too long"), tx, 4, None);
        let _ = body.collect().await;
        assert!(rx.await.is_err(), "sender dropped → no commit");
    }

    #[tokio::test]
    async fn early_drop_stores_nothing() {
        let (tx, rx) = tokio::sync::oneshot::channel::<Bytes>();
        let body = new(crate::body::full("partial"), tx, 100, None);
        drop(body); // client aborted before completion
        assert!(rx.await.is_err());
    }

    #[tokio::test]
    async fn upstream_error_drops_commit() {
        let (tx, rx) = tokio::sync::oneshot::channel::<Bytes>();
        let body = new(
            crate::body::boxed(http_body_util::StreamBody::new(futures_util::stream::iter(
                vec![
                    Ok::<_, BoxError>(Frame::data(Bytes::from_static(b"partial"))),
                    Err::<_, BoxError>(BoxError::from("boom")),
                ],
            ))),
            tx,
            100,
            None,
        );
        let mut body = std::pin::pin!(body);
        assert!(
            std::future::poll_fn(|cx| body.as_mut().poll_frame(cx))
                .await
                .unwrap()
                .is_ok()
        );
        assert!(
            std::future::poll_fn(|cx| body.as_mut().poll_frame(cx))
                .await
                .unwrap()
                .is_err()
        );
        assert!(rx.await.is_err());
    }
}
