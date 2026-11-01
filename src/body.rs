//! Body plumbing: a boxed body type uniform across handlers, plus wrappers
//! enforcing per-frame read timeouts and byte limits.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Full};
use pin_project_lite::pin_project;

use crate::errors::BoxError;

/// The body type used for all downstream responses and (once wrapped) for
/// request bodies inside the pipeline. `UnsyncBoxBody` because
/// `hyper::body::Incoming` is `Send` but not `Sync`.
pub type BoxBody = http_body_util::combinators::UnsyncBoxBody<Bytes, BoxError>;

/// An empty body.
pub fn empty() -> BoxBody {
    Full::new(Bytes::new())
        .map_err(|e| match e {})
        .boxed_unsync()
}

/// A body from in-memory bytes.
pub fn full(data: impl Into<Bytes>) -> BoxBody {
    Full::new(data.into())
        .map_err(|e| match e {})
        .boxed_unsync()
}

/// Box an arbitrary body whose error type converts into [`BoxError`].
pub fn boxed<B>(body: B) -> BoxBody
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    body.map_err(Into::into).boxed_unsync()
}

/// File-body frame size.
const FILE_CHUNK: u64 = 64 * 1024;

/// Stream `len` bytes from `file`, reading synchronously inside
/// `poll_frame`. Deliberately not `tokio::fs`: a page-cached `read(2)` is
/// a syscall + memcpy, not an I/O wait — bouncing every chunk through the
/// blocking pool costs ~10x the read itself. Same trade-off nginx makes:
/// a cold-disk stall blocks one worker thread rather than every hot read
/// paying a thread hand-off. Positioned reads (`read_at`) leave the fd
/// offset untouched, so a concurrent truncate can't misalign a range
/// response — it just yields a short body.
struct FileBody {
    file: std::sync::Arc<std::fs::File>,
    pos: u64,
    end: u64,
}

impl Body for FileBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.pos >= this.end {
            return Poll::Ready(None);
        }
        let want = (this.end - this.pos).min(FILE_CHUNK) as usize;
        let mut buf = vec![0u8; want];
        let n = {
            use std::os::unix::fs::FileExt;
            match this.file.read_at(&mut buf, this.pos) {
                Ok(n) => n,
                Err(e) => return Poll::Ready(Some(Err(BoxError::from(e)))),
            }
        };
        if n == 0 {
            return Poll::Ready(Some(Err("file truncated mid-response".into())));
        }
        buf.truncate(n);
        this.pos += n as u64;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(buf)))))
    }

    fn is_end_stream(&self) -> bool {
        self.pos >= self.end
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(self.end - self.pos)
    }
}

/// Same as [`file()`] but shares an already-open fd — the disk cache keeps
/// one `Arc<File>` per object and clones it per hit (an `Arc` bump, not
/// another `open(2)`/`dup(2)`). Deliberately *not* mmap'd here: callers
/// that can cache the map (the disk index) use [`FileMap`]/[`mapped`]
/// directly; per-request map+prefault measurably underperforms `read_at`
/// under TLS (~14.7 vs ~16.3 GB/s on 3MiB bodies) because encryption,
/// not body production, is the bottleneck.
pub fn file_shared(file: std::sync::Arc<std::fs::File>, offset: u64, len: u64) -> BoxBody {
    boxed(FileBody {
        file,
        pos: offset,
        end: offset + len,
    })
}

mod imp {
    /// The crate is `#![deny(unsafe_code)]`; `MmapOptions::map` is the
    /// sole `unsafe` call, scoped to this function.
    ///
    /// SAFETY: the file is opened read-only and the map is never written
    /// through, so the mapping cannot create a data race on our side.
    /// Accepted external-mutation risks (the same contract `sendfile(2)`
    /// gives): a concurrent writer produces torn reads — garbage bytes,
    /// not UB — and truncation of the mapped inode SIGBUSes on access
    /// *even for prefaulted pages* (`MAP_POPULATE` removes lazy-fault
    /// latency, not the hazard). The protection is convention, not the
    /// flag: our own writers never truncate — cache objects are replaced
    /// by atomic rename and unlinked inodes stay valid for existing
    /// maps. Anything else that can write under `disk_path` — a second
    /// verd pointed at it, an admin `truncate(1)` — can kill the
    /// process; keep `disk_path` `0700` and single-tenant.
    #[allow(unsafe_code)]
    pub(super) fn map_file(file: &std::fs::File) -> std::io::Result<memmap2::Mmap> {
        // SAFETY: read-only, prefaulted map of a read-only fd — see doc.
        unsafe { memmap2::MmapOptions::new().populate().map(file) }
    }
}

/// A shared, read-only `mmap` of an immutable file. Cheap to clone;
/// each hit builds `Bytes` views onto page-cache memory without a
/// single syscall. See `imp::map_file` for the safety contract.
#[derive(Clone)]
pub struct FileMap(std::sync::Arc<memmap2::Mmap>);

impl std::fmt::Debug for FileMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileMap")
            .field("len", &self.0.len())
            .finish()
    }
}

impl FileMap {
    /// Map all of `file`, prefaulted.
    pub fn new(file: &std::fs::File) -> std::io::Result<Self> {
        imp::map_file(file).map(|m| Self(std::sync::Arc::new(m)))
    }

    /// Total mapped length in bytes.
    pub fn len(&self) -> u64 {
        self.0.len() as u64
    }

    /// True when the map covers no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// `Bytes::from_owner` needs `AsRef<[u8]>`; `Arc<Mmap>` doesn't implement
/// it, so the map travels in this newtype.
#[derive(Clone)]
struct MapOwner(std::sync::Arc<memmap2::Mmap>);

impl AsRef<[u8]> for MapOwner {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A file body backed by `mmap`: each frame is a `Bytes` view onto
/// page-cache memory — no intermediate `vec` alloc, memset, or `read(2)`
/// syscall. Frames are capped at [`MMAP_FRAME`]: slicing an owned
/// `Bytes` is free, but one giant frame would let the whole body
/// "complete" before hyper's write side could observe a client abort
/// (the 499 path depends on a poll failing mid-stream).
const MMAP_FRAME: u64 = 1024 * 1024;

struct MmapBody {
    map: MapOwner,
    pos: usize,
    end: usize,
}

impl Body for MmapBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.pos >= this.end {
            return Poll::Ready(None);
        }
        let next = this.end.min(this.pos + MMAP_FRAME as usize);
        let data = Bytes::from_owner(this.map.clone()).slice(this.pos..next);
        this.pos = next;
        Poll::Ready(Some(Ok(Frame::data(data))))
    }

    fn is_end_stream(&self) -> bool {
        self.pos >= self.end
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact((self.end - self.pos) as u64)
    }
}

/// A response body serving `len` bytes of `file` starting at `offset`
/// (blocking `std::fs` — see `FileBody`).
pub fn file(file: std::fs::File, offset: u64, len: u64) -> BoxBody {
    file_shared(std::sync::Arc::new(file), offset, len)
}

/// True when the method or status forbids a response body.
pub fn response_body_forbidden(method: &http::Method, status: http::StatusCode) -> bool {
    method == http::Method::HEAD
        || status == http::StatusCode::NO_CONTENT
        || status == http::StatusCode::NOT_MODIFIED
        || status.is_informational()
}

/// Error raised by [`TimeoutBody`] when a frame misses its deadline.
#[derive(Debug)]
pub struct BodyFrameTimeout(pub Duration);

impl std::fmt::Display for BodyFrameTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "body frame did not arrive within {:?}", self.0)
    }
}

impl std::error::Error for BodyFrameTimeout {}

pin_project! {
    /// Wraps a body so each frame must arrive within `frame_timeout`;
    /// exceeding it yields a [`BodyFrameTimeout`] error — protection against
    /// clients that stall mid-body (the body variant of slowloris).
    pub struct TimeoutBody<B> {
        #[pin]
        inner: B,
        frame_timeout: Duration,
        sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    }
}

impl<B> TimeoutBody<B> {
    /// Wrap `body` with a per-frame read deadline.
    pub fn new(inner: B, frame_timeout: Duration) -> Self {
        Self {
            inner,
            frame_timeout,
            sleep: None,
        }
    }
}

impl<B> Body for TimeoutBody<B>
where
    B: Body<Data = Bytes, Error = BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let mut this = self.project();
        if this.frame_timeout.is_zero() {
            return this.inner.as_mut().poll_frame(cx);
        }
        if this.sleep.is_none() {
            *this.sleep = Some(Box::pin(tokio::time::sleep(*this.frame_timeout)));
        }
        if let Some(sleep) = this.sleep.as_mut()
            && sleep.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Some(Err(Box::new(BodyFrameTimeout(*this.frame_timeout)))));
        }
        match this.inner.poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            ready => {
                *this.sleep = None;
                ready
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

pin_project! {
    /// Counts body bytes and fails once `limit` is exceeded. Handlers see a
    /// `BodyLimitExceeded` error; the pipeline maps it to 413.
    pub struct LimitBody<B> {
        #[pin]
        inner: B,
        limit: u64,
        seen: u64,
        // shared counter mirroring `seen` for the inbound-bytes metric
        // (the access log reads it at response finalize)
        count: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    }
}

/// Error raised by [`LimitBody`] when the body exceeds the configured size.
#[derive(Debug)]
pub struct BodyLimitExceeded(pub u64);

impl std::fmt::Display for BodyLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "request body exceeds limit of {} bytes", self.0)
    }
}

impl std::error::Error for BodyLimitExceeded {}

impl<B> LimitBody<B> {
    /// Wrap `body` with a byte `limit`.
    pub fn new(inner: B, limit: u64) -> Self {
        Self {
            inner,
            limit,
            seen: 0,
            count: None,
        }
    }

    /// Wrap with a `limit` and a shared received-bytes counter — one
    /// relaxed atomic add per frame, no extra bookkeeping.
    pub fn counted(
        inner: B,
        limit: u64,
        count: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        Self {
            inner,
            limit,
            seen: 0,
            count: Some(count),
        }
    }
}

impl<B> Body for LimitBody<B>
where
    B: Body<Data = Bytes, Error = BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.project();
        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let n = frame.data_ref().map(|d| d.len() as u64).unwrap_or(0);
                *this.seen += n;
                if let Some(c) = this.count {
                    c.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                }
                if *this.seen > *this.limit {
                    return Poll::Ready(Some(Err(Box::new(BodyLimitExceeded(*this.limit)))));
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

fn mapped_raw(map: std::sync::Arc<memmap2::Mmap>, offset: u64, len: u64) -> BoxBody {
    boxed(MmapBody {
        map: MapOwner(map),
        pos: offset as usize,
        end: (offset + len) as usize,
    })
}

/// A body serving `len` bytes of `map` at `offset` — the zero-syscall
/// hit path for callers that keep one [`FileMap`] per object (the disk
/// cache index).
pub fn mapped(map: &FileMap, offset: u64, len: u64) -> BoxBody {
    mapped_raw(map.0.clone(), offset, len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn full_and_empty() {
        let b = full("abc").collect().await.unwrap().to_bytes();
        assert_eq!(&b[..], b"abc");
        let b = empty().collect().await.unwrap().to_bytes();
        assert!(b.is_empty());
    }

    #[tokio::test]
    async fn file_body_reads_range() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, "0123456789").unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let b = file(f, 2, 4).collect().await.unwrap().to_bytes();
        assert_eq!(&b[..], b"2345");

        // shared-file variant
        let f = std::sync::Arc::new(std::fs::File::open(&path).unwrap());
        let b = file_shared(f, 0, 3).collect().await.unwrap().to_bytes();
        assert_eq!(&b[..], b"012");

        // mmap variant
        let f = std::fs::File::open(&path).unwrap();
        let map = FileMap::new(&f).unwrap();
        assert_eq!(map.len(), 10);
        let b = mapped(&map, 4, 3).collect().await.unwrap().to_bytes();
        assert_eq!(&b[..], b"456");
    }

    #[tokio::test]
    async fn limit_body_enforces_and_counts() {
        let inner = full("0123456789");
        let b = LimitBody::new(inner, 5);
        assert!(b.collect().await.is_err(), "over-limit → error frame");

        // under the limit → passes through, counter shared
        let count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let inner = full("abc");
        let b = LimitBody::counted(inner, 5, count.clone());
        let got = b.collect().await.unwrap().to_bytes();
        assert_eq!(&got[..], b"abc");
        assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn timeout_body_times_out_slow_frames() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, BoxError>>(1);
        let stream =
            futures_util::stream::unfold(
                rx,
                |mut rx| async move { rx.recv().await.map(|f| (f, rx)) },
            );
        let inner = boxed(http_body_util::StreamBody::new(stream));
        let mut b = std::pin::pin!(TimeoutBody::new(inner, Duration::from_millis(30)));
        // first frame arrives promptly
        tx.send(Ok(Frame::data(Bytes::from_static(b"x"))))
            .await
            .unwrap();
        let f = std::future::poll_fn(|cx| b.as_mut().poll_frame(cx)).await;
        assert!(f.unwrap().is_ok());
        // next frame never arrives → timeout error
        let f = std::future::poll_fn(|cx| b.as_mut().poll_frame(cx)).await;
        assert!(f.unwrap().is_err());
    }

    #[test]
    fn body_forbidden_rules() {
        use http::{Method, StatusCode};
        assert!(response_body_forbidden(&Method::HEAD, StatusCode::OK));
        assert!(response_body_forbidden(
            &Method::GET,
            StatusCode::NO_CONTENT
        ));
        assert!(response_body_forbidden(
            &Method::GET,
            StatusCode::NOT_MODIFIED
        ));
        assert!(!response_body_forbidden(&Method::GET, StatusCode::OK));
    }
}
