//! Connection-level read deadlines: `header_read` until the first request
//! on the connection completes, keep-alive `idle` after that. Exceeding the
//! deadline yields an `io::ErrorKind::TimedOut` read error and the
//! connection closes — the socket layer of slowloris protection.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Per-connection read-deadline gate shared between the IO wrapper, the
/// service, and the proxy's upgrade path.
///
/// The deadline exists to kill connections that stall *between* requests
/// (slowloris) — it must never apply while a response is in flight:
/// hyper keeps polling the read side mid-write (`mid_message_detect_eof`)
/// and a client that sends nothing while it downloads would otherwise be
/// cut when `header_read`/`idle` elapses.
#[derive(Clone, Default)]
pub struct DeadlineGate {
    /// In-flight request/response cycles — a count, not a flag, since h2
    /// multiplexes streams on one connection. Non-zero = do not arm.
    /// Incremented when a request enters the pipeline, decremented when
    /// its response body finishes or is dropped.
    pub active: Arc<AtomicUsize>,
    /// Set permanently when the connection becomes an upgrade tunnel:
    /// opaque, long-lived, possibly one-directional traffic — no read
    /// deadline may ever apply again.
    pub off: Arc<AtomicBool>,
    /// The between-requests deadline currently armed on this connection:
    /// `(armed_at, duration)`. Enforced by a watchdog spawn that force-
    /// closes the socket — NOT by re-polling a `Sleep` inside
    /// `poll_read`, because hyper's h1 server path (`mid_message_detect_eof`)
    /// parks the dispatcher on the last io waker: a read that returned
    /// `Pending` while `active > 0` leaves only a socket-readiness waker,
    /// so `poll_read` may never be re-entered after the response ends.
    pub armed: Arc<Mutex<Option<(Instant, Duration)>>>,
    /// The waker from the most recent `poll_read`. When `active` drops
    /// to zero (response finished) or `off` is set (tunnel armed), the
    /// parked connection task must be woken so `poll_read` re-enters and
    /// the deadline can arm — nothing else drives that transition.
    pub read_waker: Arc<Mutex<Option<std::task::Waker>>>,
    /// Armed while a `poll_write`/`poll_flush` stalls (slow-read
    /// protection — `timeouts.send`). `(armed_at, duration)`; cleared on
    /// any write progress. Same watchdog force-close as `armed`.
    pub send_armed: Arc<Mutex<Option<(Instant, Duration)>>>,
}

impl DeadlineGate {
    /// Wake the connection task parked on the read side so `poll_read`
    /// re-enters and re-evaluates the gate/deadline.
    pub fn wake_reader(&self) {
        if let Some(w) = self
            .read_waker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            w.wake();
        }
    }
}

/// Marker placed in request extensions so the proxy's upgrade path can
/// permanently disarm the connection's read deadline before tunnelling.
#[derive(Clone)]
pub struct DeadlineOff(pub DeadlineGate);

/// Marker placed in request extensions: the route's send-inactivity
/// deadline, applied to upgrade-tunnel traffic in both directions — the
/// upstream half of a tunnel isn't wrapped by [`TimeoutIo`], so the
/// tunnel task enforces it via a byte-progress watchdog.
#[derive(Clone, Copy)]
pub struct SendDeadline(pub Duration);

/// An `AsyncRead`/`AsyncWrite` wrapper enforcing read and send deadlines.
/// `Unpin` whenever `T` is, so hyper's `serve_connection` accepts it.
pub struct TimeoutIo<T> {
    inner: T,
    header_read: Duration,
    idle: Duration,
    /// Write-side inactivity deadline: a `poll_write`/`poll_flush` that
    /// stays pending longer than this means the client stopped reading
    /// (slow-read DoS) — the watchdog force-closes the socket.
    send: Duration,
    first_request_done: Arc<AtomicBool>,
    gate: DeadlineGate,
    /// A second handle on the same socket — lets the armed-deadline
    /// watchdog force-close the connection when `poll_read`/`poll_write`
    /// is never re-entered (see `DeadlineGate::armed`). `None` when the
    /// fd duplication failed.
    tcp: Option<Arc<std::net::TcpStream>>,
}

impl<T> TimeoutIo<T> {
    /// Wrap `inner` with phase-aware read deadlines and a send timeout.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        inner: T,
        header_read: Duration,
        idle: Duration,
        send: Duration,
        first_request_done: Arc<AtomicBool>,
        gate: DeadlineGate,
        tcp: Option<Arc<std::net::TcpStream>>,
    ) -> Self {
        Self {
            inner,
            header_read,
            idle,
            send,
            first_request_done,
            gate,
            tcp,
        }
    }

    /// Arm the send-inactivity deadline (idempotent while armed) and
    /// spawn the force-close watchdog when `tcp` is available.
    fn arm_send_deadline(&self) {
        if self.send.is_zero() {
            return;
        }
        let mut armed = self
            .gate
            .send_armed
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // fast path: the deadline already elapsed and we're being polled
        // — report it directly
        if let Some((t, d)) = *armed
            && t.elapsed() >= d
        {
            // leave armed; callers surface the error via the slot
            return;
        }
        if armed.is_none() {
            let dur = self.send;
            *armed = Some((Instant::now(), dur));
            if let Some(tcp) = self.tcp.clone() {
                let send_armed = self.gate.send_armed.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(dur).await;
                    let hit = {
                        let armed = send_armed.lock().unwrap_or_else(|e| e.into_inner());
                        armed.is_some_and(|(t, d)| t.elapsed() >= d)
                    };
                    if hit {
                        let _ = tcp.shutdown(std::net::Shutdown::Both);
                    }
                });
            }
        }
    }

    /// Send-side progress — clear any armed send deadline.
    fn clear_send_deadline(&self) {
        self.gate
            .send_armed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }

    /// Whether the armed send deadline has already elapsed.
    fn send_expired(&self) -> bool {
        self.gate
            .send_armed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some_and(|(t, d)| t.elapsed() >= d)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for TimeoutIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        // freshest waker for the parked-read wake (see `wake_reader`)
        *this
            .gate
            .read_waker
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(cx.waker().clone());
        // gated: a response is in flight or the connection is a tunnel —
        // hyper's read polls here are not "waiting for a request"
        if this.gate.off.load(Ordering::Relaxed) || this.gate.active.load(Ordering::Relaxed) > 0 {
            this.gate
                .armed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        let timeout = if this.first_request_done.load(Ordering::Relaxed) {
            this.idle
        } else {
            this.header_read
        };
        if !timeout.is_zero() {
            let mut armed = this.gate.armed.lock().unwrap_or_else(|e| e.into_inner());
            // fast path: the deadline already elapsed and hyper happens
            // to be polling us — kill the read directly
            if let Some((t, d)) = *armed
                && t.elapsed() >= d
            {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "read deadline exceeded",
                )));
            }
            if armed.is_none() {
                *armed = Some((Instant::now(), timeout));
                // watchdog: if `poll_read` is never re-entered before the
                // deadline (hyper stops polling io while parked
                // mid-message for servers), force-close the socket — the
                // epoll error wakes the connection task and ends it
                if let Some(tcp) = this.tcp.clone() {
                    let gate = this.gate.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(timeout).await;
                        let hit = {
                            let armed = gate.armed.lock().unwrap_or_else(|e| e.into_inner());
                            armed.is_some_and(|(t, d)| t.elapsed() >= d)
                        };
                        if hit {
                            let _ = tcp.shutdown(std::net::Shutdown::Both);
                        }
                    });
                }
            }
        }
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Pending => Poll::Pending,
            ready => {
                // a real read event (bytes, EOF, error) ends this wait
                // window; the next parked poll re-arms as needed
                this.gate
                    .armed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                ready
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for TimeoutIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.send_expired() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "send deadline exceeded",
            )));
        }
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Pending => {
                this.arm_send_deadline();
                Poll::Pending
            }
            ready => {
                this.clear_send_deadline();
                ready
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.send_expired() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "send deadline exceeded",
            )));
        }
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending => {
                this.arm_send_deadline();
                Poll::Pending
            }
            ready => {
                this.clear_send_deadline();
                ready
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Pending => {
                this.arm_send_deadline();
                Poll::Pending
            }
            ready => {
                this.clear_send_deadline();
                ready
            }
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.send_expired() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "send deadline exceeded",
            )));
        }
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Pending => {
                this.arm_send_deadline();
                Poll::Pending
            }
            ready => {
                this.clear_send_deadline();
                ready
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener as StdListener;
    use std::task::Wake;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    /// A waker that counts wakeups, for observing `wake_reader`.
    struct CountWaker(AtomicUsize);

    impl Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn waker() -> (std::task::Waker, Arc<CountWaker>) {
        let c = Arc::new(CountWaker(AtomicUsize::new(0)));
        (std::task::Waker::from(c.clone()), c)
    }

    /// Poll the read side once with a scratch buffer; `Ready` reports the
    /// byte count so callers can distinguish data from EOF/errors.
    fn poll_once<T: AsyncRead + Unpin>(
        io: &mut T,
        w: &std::task::Waker,
    ) -> Poll<io::Result<usize>> {
        let mut data = [0u8; 128];
        let mut buf = ReadBuf::new(&mut data);
        let mut cx = Context::from_waker(w);
        match Pin::new(&mut *io).poll_read(&mut cx, &mut buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn io<T: AsyncRead + Unpin>(inner: T, first_done: bool, gate: &DeadlineGate) -> TimeoutIo<T> {
        TimeoutIo::new(
            inner,
            Duration::from_secs(60),
            Duration::from_secs(90),
            Duration::from_secs(30),
            Arc::new(AtomicBool::new(first_done)),
            gate.clone(),
            None,
        )
    }

    fn armed_dur(gate: &DeadlineGate) -> Option<Duration> {
        gate.armed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(|(_, d)| d)
    }

    #[test]
    fn pending_read_arms_header_deadline() {
        let (_a, b) = duplex(64);
        let gate = DeadlineGate::default();
        let mut t = io(b, false, &gate);
        let (w, _) = waker();
        assert!(poll_once(&mut t, &w).is_pending());
        assert_eq!(armed_dur(&gate), Some(Duration::from_secs(60)));
    }

    #[test]
    fn pending_read_arms_idle_after_first_request() {
        let (_a, b) = duplex(64);
        let gate = DeadlineGate::default();
        let mut t = io(b, true, &gate);
        let (w, _) = waker();
        assert!(poll_once(&mut t, &w).is_pending());
        assert_eq!(armed_dur(&gate), Some(Duration::from_secs(90)));
    }

    #[test]
    fn active_response_gates_and_clears() {
        let (_a, b) = duplex(64);
        let gate = DeadlineGate::default();
        let mut t = io(b, false, &gate);
        let (w, _) = waker();
        assert!(poll_once(&mut t, &w).is_pending());
        assert!(armed_dur(&gate).is_some());
        // a response is now in flight: reads must not arm, and any stale
        // armed entry must be dropped
        gate.active.fetch_add(1, Ordering::Relaxed);
        assert!(poll_once(&mut t, &w).is_pending());
        assert_eq!(armed_dur(&gate), None);
    }

    #[test]
    fn upgrade_gate_never_arms() {
        let (_a, b) = duplex(64);
        let gate = DeadlineGate::default();
        gate.off.store(true, Ordering::Relaxed);
        let mut t = io(b, false, &gate);
        let (w, _) = waker();
        assert!(poll_once(&mut t, &w).is_pending());
        assert_eq!(armed_dur(&gate), None);
    }

    #[tokio::test]
    async fn incoming_bytes_clear_the_arm() {
        let (mut a, b) = duplex(64);
        let gate = DeadlineGate::default();
        let mut t = io(b, false, &gate);
        let (w, _) = waker();
        assert!(poll_once(&mut t, &w).is_pending());
        a.write_all(b"GET /").await.unwrap();
        match poll_once(&mut t, &w) {
            Poll::Ready(Ok(n)) => assert_eq!(n, 5),
            other => panic!("expected data, got {other:?}"),
        }
        assert_eq!(armed_dur(&gate), None);
    }

    #[test]
    fn pending_write_arms_send_deadline() {
        let (_a, b) = duplex(8);
        let gate = DeadlineGate::default();
        let mut t = io(b, false, &gate);
        let (w, _) = waker();
        let mut cx = Context::from_waker(&w);
        // fill the pipe so the next write must stall
        match Pin::new(&mut t).poll_write(&mut cx, &[0u8; 8]) {
            Poll::Ready(Ok(8)) => {}
            other => panic!("fill write failed: {other:?}"),
        }
        match Pin::new(&mut t).poll_write(&mut cx, &[1u8; 4]) {
            Poll::Pending => {}
            other => panic!("expected stalled write, got {other:?}"),
        }
        let d = gate
            .send_armed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(|(_, d)| d);
        assert_eq!(d, Some(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn write_progress_clears_send_deadline() {
        let (mut a, b) = duplex(8);
        let gate = DeadlineGate::default();
        let mut t = io(b, false, &gate);
        let (w, _) = waker();
        let mut cx = Context::from_waker(&w);
        let _ = Pin::new(&mut t).poll_write(&mut cx, &[0u8; 8]);
        assert!(Pin::new(&mut t).poll_write(&mut cx, &[1u8; 4]).is_pending());
        assert!(gate.send_armed.lock().unwrap().is_some());
        // peer reads → the stalled write can now proceed → arm clears
        let mut scratch = [0u8; 8];
        let _ = a.read(&mut scratch).await.unwrap();
        match Pin::new(&mut t).poll_write(&mut cx, &[1u8; 4]) {
            Poll::Ready(Ok(_)) => {}
            other => panic!("expected progress, got {other:?}"),
        }
        assert!(gate.send_armed.lock().unwrap().is_none());
    }

    #[test]
    fn elapsed_send_deadline_errors() {
        let (_a, b) = duplex(64);
        let gate = DeadlineGate::default();
        *gate.send_armed.lock().unwrap() = Some((
            Instant::now() - Duration::from_secs(120),
            Duration::from_secs(60),
        ));
        let mut t = io(b, false, &gate);
        let (w, _) = waker();
        let mut cx = Context::from_waker(&w);
        match Pin::new(&mut t).poll_write(&mut cx, &[1u8; 4]) {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::TimedOut),
            other => panic!("expected TimedOut, got {other:?}"),
        }
    }

    #[test]
    fn elapsed_deadline_errors() {
        let (_a, b) = duplex(64);
        let gate = DeadlineGate::default();
        *gate.armed.lock().unwrap_or_else(|e| e.into_inner()) = Some((
            Instant::now() - Duration::from_secs(120),
            Duration::from_secs(60),
        ));
        let mut t = io(b, false, &gate);
        let (w, _) = waker();
        match poll_once(&mut t, &w) {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::TimedOut),
            other => panic!("expected TimedOut, got {other:?}"),
        }
    }

    #[test]
    fn wake_reader_wakes_parked_task_once() {
        let (_a, b) = duplex(64);
        let gate = DeadlineGate::default();
        let mut t = io(b, false, &gate);
        let (w, count) = waker();
        assert!(poll_once(&mut t, &w).is_pending());
        assert_eq!(count.0.load(Ordering::Relaxed), 0);
        gate.wake_reader();
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
        // the waker was taken: a second wake is a no-op until the next poll
        gate.wake_reader();
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watchdog_force_closes_parked_connection() {
        let listener = StdListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        client.set_nonblocking(true).unwrap();
        server.set_nonblocking(true).unwrap();
        let stream = tokio::net::TcpStream::from_std(client).unwrap();
        let dup = std::os::fd::AsFd::as_fd(&stream)
            .try_clone_to_owned()
            .map(std::net::TcpStream::from)
            .map(Arc::new)
            .unwrap();
        let gate = DeadlineGate::default();
        let mut t = TimeoutIo::new(
            stream,
            Duration::from_millis(60),
            Duration::from_millis(60),
            Duration::from_secs(60),
            Arc::new(AtomicBool::new(false)),
            gate,
            Some(dup),
        );
        // park on a read; nothing is ever sent, so only the watchdog can
        // end this wait
        let mut buf = [0u8; 16];
        let res = tokio::time::timeout(Duration::from_secs(5), t.read(&mut buf)).await;
        match res {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            other => panic!("watchdog did not close the socket: {other:?}"),
        }
    }
}
