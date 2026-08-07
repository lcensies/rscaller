//! Real-fd socket proxy — see `relay.rs`'s module doc for the full
//! rationale (mirrors how `rscfuse` avoids per-syscall interception for
//! files: give the tracee a REAL, locally kernel-backed fd instead of a
//! bare virtual fd number).
//!
//! [`spawn_proxy`] is called once per `socket()`/`accept4()` response that
//! carries a fresh virtual fd from rsbeacon. It creates a `socketpair()`,
//! hands one end back to the caller (to be injected into the tracee via
//! `SyscallController::complete_with_fd`), and spawns a background task
//! that bridges the *other* end to rsbeacon using the exact same
//! `SyscallRequest`/`SyscallResponse` API a directly-intercepted
//! `read`/`write`/`close` would have used — rsbeacon itself needs no
//! changes at all; only who calls it, and how often, changes.
//!
//! Every real byte transfer after this point is an ordinary local
//! `read`/`write`/`close`/`poll`/`fcntl`/`ioctl` on the tracee's end of the
//! socketpair, serviced entirely by the local kernel — never seen by this
//! process again. `connect`/`bind`/`listen`/`setsockopt`/`getsockopt` are
//! the only ops that still need translating and relaying (see
//! `relay.rs::dispatch`); `sendto`/`recvfrom`/`sendmsg`/`recvmsg` work
//! correctly continued locally too (a `socketpair()` end is a real,
//! connected socket — send/recv-family calls need no special casing).

use std::os::fd::{FromRawFd, RawFd};
use std::time::Duration;

use anyhow::{bail, Result};
use rscaller_proto::codec::{read_message, write_message};
use rscaller_proto::types::{SyscallBuf, SyscallRequest, SyscallResponse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

use crate::beacon_conn::{connect_beacon, BeaconConnConfig, BeaconReader, BeaconWriter};

/// Everything [`spawn_proxy`]'s background task needs to reach rsbeacon on
/// its own, independent connections.
#[derive(Clone)]
pub struct ProxyConfig {
    pub beacon_addr: std::net::SocketAddr,
    pub conn: BeaconConnConfig,
}

/// Read/write chunk size for the background proxy loops. Generous relative
/// to a single TCP segment — `sys_read`/`sys_write` just return however
/// many bytes `smoltcp`'s socket buffer actually has, up to this cap.
const CHUNK: usize = 64 * 1024;

/// Sleep between retries when rsbeacon reports `EAGAIN` (no data/space
/// currently available) — keeps a non-blocking-mode socket's proxy loop
/// from hammering rsbeacon in a tight spin; harmless no-op delay for the
/// blocking-mode case, which already waited server-side before EAGAIN.
const RETRY_DELAY: Duration = Duration::from_millis(30);

/// A socketpair created and injected into the tracee, but not yet actively
/// bridging data — see `spawn_proxy`/`start_proxy`.
pub struct PendingProxy {
    local: tokio::net::UnixStream,
    virtual_fd: i64,
    cfg: ProxyConfig,
    /// Set once the outbound (tracee→beacon) direction has read EOF from
    /// the pair AND finished its final write round-trip — i.e. every byte
    /// the tracee wrote is in the beacon kernel's hands. `relay.rs` waits
    /// on this before closing beacon fds at session teardown; without the
    /// wait, a tracee that writes-then-exits (e.g. `cat big >&socket`)
    /// loses whatever was still queued in the pair (~256 KiB observed).
    drained: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl PendingProxy {
    pub fn drained_flag(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.drained.clone()
    }
    pub fn virtual_fd(&self) -> i64 {
        self.virtual_fd
    }
}

/// Creates the socketpair for `virtual_fd` (a fd rsbeacon just allocated,
/// from a `socket()`/`accept4()` response) and returns a raw fd — still
/// open in *this* process — meant to be handed to the tracee via
/// `SyscallController::complete_with_fd`, plus a [`PendingProxy`] to
/// activate later via [`start_proxy`].
///
/// Deliberately does NOT start the background read/write loop yet: for a
/// freshly `socket()`-created (not yet `accept4()`-returned) fd, the
/// connection isn't established — a socket just past `socket()` is
/// `SynSent`/idle, not `Established`, and the corresponding `connect()`
/// call hasn't even been issued yet (it's the tracee's *next* syscall, a
/// separate notification `dispatch` hasn't seen). Starting the proxy's
/// polling loop this early found a genuine rsbeacon-side issue in
/// testing: it hammers `recv_common`/`send_common` (and therefore the
/// same `Mutex<PollState>` `sys_connect`'s own bounded wait loop and the
/// packet-processing poll thread both need) throughout the entire
/// multi-second connect handshake window, badly enough in practice to
/// starve the poll thread and make the handshake itself never complete
/// (`SynSent` forever, `ETIMEDOUT`). Caller (`relay.rs`) holds the
/// `PendingProxy` and calls `start_proxy` only once `connect`/`listen`
/// actually completes (success or failure — either way there's a stable
/// state to monitor, and the proxy is still needed to eventually notice
/// the tracee closing its end and release the virtual fd on rsbeacon).
///
/// The caller owns the returned fd until `complete_with_fd` succeeds; it
/// must be closed locally afterward (the kernel duplicates it into the
/// tracee rather than moving it — this process's own copy is no longer
/// needed once installed there).
pub fn spawn_proxy(virtual_fd: i64, cfg: ProxyConfig) -> Result<(RawFd, PendingProxy)> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if ret != 0 {
        bail!("socketpair: {}", std::io::Error::last_os_error());
    }
    let [rsclient_end, tracee_end] = fds;

    // SAFETY: rsclient_end is a freshly-created, uniquely-owned fd from the
    // socketpair() call above.
    let std_sock = unsafe { std::os::unix::net::UnixStream::from_raw_fd(rsclient_end) };
    std_sock.set_nonblocking(true)?;
    let tokio_sock = match tokio::net::UnixStream::from_std(std_sock) {
        Ok(s) => s,
        Err(e) => {
            unsafe { libc::close(tracee_end) };
            bail!("UnixStream::from_std: {e}");
        }
    };

    let drained = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    Ok((tracee_end, PendingProxy { local: tokio_sock, virtual_fd, cfg, drained }))
}

/// Activates a [`PendingProxy`] — see `spawn_proxy`'s doc for when this
/// should be called.
pub fn start_proxy(pending: PendingProxy) {
    tokio::spawn(proxy_loop(pending.local, pending.virtual_fd, pending.cfg, pending.drained));
}

/// One connection, shared by both directions of a single proxied socket.
/// The wire protocol is strict request-then-response (no pipelining), so
/// the outbound and inbound loops below take turns on it via this mutex
/// rather than each opening their own connection — halves the connection/
/// task/memory overhead per proxied socket for no correctness cost (they
/// were never going to usefully run two round-trips at the exact same
/// instant on a single TCP stream anyway).
struct SharedConn {
    r: BeaconReader,
    w: BeaconWriter,
}

async fn roundtrip(conn: &tokio::sync::Mutex<SharedConn>, req: SyscallRequest) -> Result<SyscallResponse> {
    let mut conn = conn.lock().await;
    write_message(&mut conn.w, &req).await?;
    let resp = read_message::<SyscallResponse, _>(&mut conn.r).await?;
    Ok(resp)
}

async fn proxy_loop(
    local: tokio::net::UnixStream,
    virtual_fd: i64,
    cfg: ProxyConfig,
    drained: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    debug!(virtual_fd, "socket-proxy: proxy_loop starting");
    let (r, w) = match connect_beacon(cfg.beacon_addr, &cfg.conn).await {
        Ok(c) => c,
        Err(e) => {
            warn!(virtual_fd, error = %e, "socket-proxy: connect failed");
            return;
        }
    };
    debug!(virtual_fd, "socket-proxy: connected");
    let conn = std::sync::Arc::new(tokio::sync::Mutex::new(SharedConn { r, w }));

    // Half-close semantics: the tracee may shutdown(WR) (or close its
    // read side of the pair) and STILL expect the response tail — HTTP/2
    // teardown does exactly this (GOAWAY then final frames). So outbound
    // ending must NOT stop the inbound reader: inbound ends on server
    // FIN (ret=0), on EBADF (fd gone), or via `stop` from the inbound
    // side itself. The fd-reuse zombie risk this leaves is bounded by the
    // server's close latency after our shutdown(WR), not unbounded.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    let local_fd = {
        use std::os::unix::io::AsRawFd;
        local.as_raw_fd()
    };
    let (mut local_r, mut local_w) = tokio::io::split(local);

    let outbound = {
        let stop = stop.clone();
        let conn = conn.clone();
        async move {
            let mut buf = vec![0u8; CHUNK];
            loop {
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let n = match local_r.read(&mut buf).await {
                    Ok(0) => {
                        // Read-side EOF: tracee shutdown(WR) or closed.
                        // Disambiguate via poll revents on the pair fd:
                        // POLLRDHUP without POLLHUP = half-close — the
                        // tracee still reads (HTTP/2 teardown does this),
                        // so the inbound reader must stay alive for the
                        // response tail. Full close (POLLHUP, or a reset
                        // below) means nobody will read again — stop
                        // inbound, or it becomes a zombie that can steal
                        // data once the beacon kernel reuses the fd number.
                        // POLLRDHUP must be requested in events or the
                        // kernel never reports it; POLLHUP always is.
                        let mut pfd = libc::pollfd {
                            fd: local_fd,
                            events: libc::POLLRDHUP,
                            revents: 0,
                        };
                        unsafe { libc::poll(&mut pfd, 1, 0) };
                        let half_close = pfd.revents & libc::POLLRDHUP != 0
                            && pfd.revents & libc::POLLHUP == 0;
                        debug!(virtual_fd, half_close, revents = pfd.revents,
                            "socket-proxy: outbound EOF");
                        if !half_close {
                            stop.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                        break;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        debug!(virtual_fd, error = %e, "socket-proxy: local read error");
                        stop.store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                };
            // sendto may report a SHORT write (ret < len) — retry the
            // remaining tail, or the peer sees a truncated stream.
            let mut sent = 0usize;
            while sent < n {
                match roundtrip(&conn, write_req(virtual_fd, &buf[sent..n])).await {
                    Ok(resp) if resp.ret > 0 => {
                        sent += resp.ret as usize;
                    }
                    // Zero-length write: no progress, treat like EAGAIN.
                    Ok(resp) if resp.ret == 0 => {
                        tokio::time::sleep(RETRY_DELAY).await;
                    }
                    // EAGAIN (send buffer full) and ENOTCONN (this write
                    // raced ahead of the tracee's own connect() — same
                    // startup race as the inbound loop's first read, see
                    // its comment) are both retryable, not fatal.
                    Ok(resp)
                        if resp.ret == -(libc::EAGAIN as i64) || resp.ret == -(libc::ENOTCONN as i64) =>
                    {
                        tokio::time::sleep(RETRY_DELAY).await;
                    }
                    Ok(resp) => {
                        debug!(virtual_fd, ret = resp.ret, "socket-proxy: remote write failed, stopping outbound");
                        break;
                    }
                    Err(e) => {
                        warn!(virtual_fd, error = %e, "socket-proxy: outbound roundtrip failed");
                        break;
                    }
                }
            }
            }
            // Outbound ended (tracee closed/shut its write side) — do NOT
            // touch `stop`: inbound may still be delivering the response
            // tail (half-close). Inbound ends on server EOF/EBADF.
            // Everything the tracee wrote is now flushed to the beacon —
            // mark drained so teardown can close safely.
            drained.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    };

    let inbound = async {
        let mut total_read = 0u64;
        let mut total_written = 0u64;
        loop {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let resp = match roundtrip(&conn, read_req(virtual_fd, CHUNK)).await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!(virtual_fd, error = %e, "socket-proxy: inbound roundtrip failed");
                    break;
                }
            };
            debug!(virtual_fd, ret = resp.ret, "socket-proxy: inbound read result");
            if resp.ret == 0 {
                // True remote EOF (peer closed) — nothing more will ever
                // arrive on this socket.
                break;
            }
            if resp.ret < 0 {
                // `ENOTCONN` in particular is expected and common here:
                // this loop starts the instant `socket()` returns, which
                // races ahead of the tracee's own later `connect()` call —
                // there's no connection to read from yet the first several
                // (or, on a slow/absent peer, many) times this runs. Any
                // negative ret is retried after a short delay EXCEPT
                // `EBADF`, which means the fd itself is gone (e.g. this
                // proxy's own `close()` request already ran) — nothing to
                // retry at that point.
                if resp.ret == -(libc::EBADF as i64) {
                    break;
                }
                tokio::time::sleep(RETRY_DELAY).await;
                continue;
            }
            let data = resp
                .out_bufs
                .iter()
                .find(|b| b.arg_idx == 1)
                .map(|b| b.data.as_slice())
                .unwrap_or(&[]);
            // The out buffer is allocated at the full requested size —
            // recvfrom's ret is how much the kernel actually wrote.
            // Writing the whole buffer would inject a zero tail (or stale
            // bytes) into the stream whenever a short read occurs.
            let n = (resp.ret as usize).min(data.len());
            total_read += resp.ret as u64;
            if n < resp.ret as usize {
                warn!(virtual_fd, ret = resp.ret, buf = data.len(), "socket-proxy: SHORT BUFFER, dropping bytes");
            }
            match local_w.write_all(&data[..n]).await {
                Ok(()) => {
                    total_written += n as u64;
                    debug!(virtual_fd, n, total_read, total_written, "socket-proxy: pair write");
                }
                Err(e) => {
                    warn!(virtual_fd, error = %e, total_read, total_written, "socket-proxy: pair write failed");
                    break;
                }
            }
        }
        // Remote EOF/error — outbound has nothing left to do either.
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        // Signal EOF to the tracee's own read() calls.
        let _ = local_w.shutdown().await;
    };

    tokio::join!(outbound, inbound);

    // Both directions have ended (tracee closed its end, remote closed, or
    // an error occurred) — release the virtual fd on rsbeacon. Reuses the
    // same connection; by this point both loops above have returned, so
    // there's no contention on the mutex.
    let _ = roundtrip(&conn, close_req(virtual_fd)).await;
    debug!(virtual_fd, "socket-proxy: closed");
}

/// Uses `sendto`(44)/`recvfrom`(45) rather than plain `write`(1)/`read`(0),
/// with `MSG_DONTWAIT` set — this backgound task always wants an instant
/// EAGAIN-or-data answer (it does its own client-side sleep-and-retry, see
/// `RETRY_DELAY`), regardless of the proxied socket's own persisted
/// blocking mode (which, since the fcntl/ioctl calls that would normally
/// set it never reach rsbeacon for a proxied fd anymore, is whatever it
/// was at `socket()` time — almost always blocking). Without
/// `MSG_DONTWAIT`, a request landing while genuinely nothing is ready
/// would otherwise block a server-side worker thread for the full
/// `IO_TIMEOUT` (rsbeacon's own bounded internal poll loop) — enough,
/// under load, to starve *other* concurrent requests (e.g. the tracee's
/// own in-flight `connect()` on the main relay connection) sharing
/// rsbeacon's tokio runtime. `read`(0)/`write`(1) have no `flags`
/// argument at all to carry `MSG_DONTWAIT`, hence the switch — see the
/// matching comment in `SmoltcpXdpBackend::recv_common`/`send_common`.
/// A `None` destination address is correct: TCP entries never look at it.
fn write_req(virtual_fd: i64, data: &[u8]) -> SyscallRequest {
    SyscallRequest {
        slot_idx: 0,
        number: 44, // sendto
        args: [virtual_fd as u64, 0, data.len() as u64, libc::MSG_DONTWAIT as u64, 0, 0],
        in_bufs: vec![SyscallBuf { arg_idx: 1, data: data.to_vec() }],
        out_sizes: vec![],
    }
}

fn read_req(virtual_fd: i64, cap: usize) -> SyscallRequest {
    SyscallRequest {
        slot_idx: 0,
        number: 45, // recvfrom
        args: [virtual_fd as u64, 0, cap as u64, libc::MSG_DONTWAIT as u64, 0, 0],
        in_bufs: vec![],
        out_sizes: vec![(1, cap as u64)],
    }
}

fn close_req(virtual_fd: i64) -> SyscallRequest {
    SyscallRequest {
        slot_idx: 0,
        number: 3, // close
        args: [virtual_fd as u64, 0, 0, 0, 0, 0],
        in_bufs: vec![],
        out_sizes: vec![],
    }
}

/// Closes `fd` in this process — used by `relay.rs` right after
/// `complete_with_fd` succeeds (the kernel duplicated it into the tracee;
/// this process's own copy is no longer needed).
pub fn close_local(fd: RawFd) {
    unsafe { libc::close(fd) };
}
