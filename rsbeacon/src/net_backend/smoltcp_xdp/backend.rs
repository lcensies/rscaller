//! Socket syscall handlers for the `smoltcp-xdp` network backend — task
//! group 5. Translates intercepted `SyscallRequest`s into operations on
//! `smoltcp` `tcp::Socket`/`udp::Socket`s living in the shared
//! `PollState`'s `SocketSet`, and back into `SyscallResponse`s.
//!
//! ## The TCP "listener" problem
//!
//! Unlike BSD sockets — one `listen()`ing socket that `accept()` spawns
//! new connected sockets out of — a single `smoltcp` `tcp::Socket` that
//! calls `.listen()` transitions *in place* through
//! `Listen -> SynReceived -> Established` for exactly one inbound
//! connection; there is no mechanism to "spawn" additional sockets from
//! it. The standard `smoltcp` idiom (see its own `examples/server.rs`)
//! is a small pool of sockets all independently `.listen()`ing on the
//! same port ("the backlog"): whichever one a SYN happens to land on
//! becomes the accepted connection, and a fresh replacement is immediately
//! `.listen()`ed on the same port to keep the backlog full. This module's
//! [`SocketEntry::TcpListener`] variant implements exactly that pool.
//!
//! ## Deferred/best-effort scope
//!
//! - `sendmsg`(46)/`recvmsg`(47) are never claimed (see
//!   [`SmoltcpXdpBackend::owns_syscall`]) — `ctls::meta` deliberately does
//!   not marshal `struct msghdr`'s nested pointers (nested one level
//!   deeper than this proto's flat `in_bufs`/`out_sizes` model can
//!   express), so a request for either would arrive with no usable
//!   buffer contents regardless of which path forwarded it. Falls
//!   through to the generic passthrough, unchanged from `direct`.
//! - `accept` (bare, nr 43) is likewise never claimed: `shadow.yaml` only
//!   ever forwards `accept4`, and modern glibc's `accept()` always issues
//!   the `accept4` syscall under the hood anyway, so nr 43 is dead in
//!   practice — but `owns_syscall` still declines it explicitly rather
//!   than silently mishandling metadata-less args if it were ever forwarded.
//! - `getsockopt`/`setsockopt` (task 5.5): no pre-existing test/tool
//!   baseline was found to scope this against (see
//!   `openspec/changes/add-beacon-smoltcp-xdp-netstack/tasks.md` task
//!   5.5's revised note), so this implements the options with concrete
//!   behavioral meaning to `smoltcp` (`SO_ERROR`, `TCP_NODELAY`) and
//!   treats every other option as a best-effort no-op success — matching
//!   how most software treats these as advisory and does not hard-fail
//!   when they're silently ignored.
//! - Blocking `connect`/`accept4`/`read`/`write`/`sendto`/`recvfrom` are
//!   bounded poll loops against socket state, per design decision D5 —
//!   documented known limitation, see design.md's Risks section.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};

use rscaller_proto::types::{SyscallBuf, SyscallRequest, SyscallResponse};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint, Ipv4Address};
use tracing::warn;

use super::bpf::XdpProgram;
use super::bridge::PollState;
use super::sockaddr::{encode_sockaddr_in, parse_sockaddr_in, SOCKADDR_IN_LEN};
use crate::net_backend::{NetBackend, SocketTable};

// ── Tunables ─────────────────────────────────────────────────────────────
// Starting points from xdplganger (5s connect timeout / 50ms read poll),
// per design.md D5 / Open Questions — not yet tuned against a real
// workload.

/// Bound on how long `connect()` polls for the handshake to complete
/// (success: `Established`; failure: `Closed`) before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound on how long a blocking `accept4()` polls the listen backlog for
/// an `Established` connection before giving up.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound on how long a blocking `read`/`recvfrom` polls for data, or a
/// blocking `write`/`sendto` polls for send-buffer space, before giving
/// up. Longer than the connect/accept bounds since idle-but-still-open
/// connections legitimately go quiet for a while — see design.md's
/// documented "Blocking RPC semantics" risk for why this can't be a
/// perfect emulation of real indefinite kernel blocking.
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Sleep between poll iterations in all of the above bounded loops.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// First port handed out by [`SmoltcpXdpBackend::alloc_ephemeral_port`].
/// Matches the IANA-registered "dynamic/private" range start.
const EPHEMERAL_PORT_START: u16 = 49152;
/// Number of ports in the ephemeral range (`EPHEMERAL_PORT_START..=65535`).
const EPHEMERAL_PORT_RANGE: u32 = 65536 - EPHEMERAL_PORT_START as u32;

const TCP_BUFFER_SIZE: usize = 65536;
const UDP_PAYLOAD_BUFFER_SIZE: usize = 65536;
const UDP_METADATA_CAPACITY: usize = 32;

/// Number of sockets kept `.listen()`ing in parallel for one `listen()`
/// call's backlog (see module doc). Bounded independent of the caller's
/// requested `backlog` argument to avoid a hostile/huge value allocating
/// unbounded `smoltcp` sockets.
const LISTEN_BACKLOG_MIN: usize = 1;
const LISTEN_BACKLOG_MAX: usize = 16;

// ── Port tracking abstraction ───────────────────────────────────────────

/// Abstracts the four XDP port-tracking operations `SmoltcpXdpBackend`
/// needs, so its socket-handling logic (this module) can be unit-tested
/// against a `smoltcp::phy::Loopback` device without requiring root/
/// `CAP_BPF` to load a real [`XdpProgram`] (see this module's tests).
pub trait PortTracker: Send {
    fn track_tcp(&mut self, port: u16);
    fn untrack_tcp(&mut self, port: u16);
    fn track_udp(&mut self, port: u16);
    fn untrack_udp(&mut self, port: u16);
}

impl PortTracker for XdpProgram {
    fn track_tcp(&mut self, port: u16) {
        if let Err(e) = self.track_tcp_port(port) {
            warn!("failed to track tcp port {port}: {e:#}");
        }
    }

    fn untrack_tcp(&mut self, port: u16) {
        self.untrack_tcp_port(port);
    }

    fn track_udp(&mut self, port: u16) {
        if let Err(e) = self.track_udp_port(port) {
            warn!("failed to track udp port {port}: {e:#}");
        }
    }

    fn untrack_udp(&mut self, port: u16) {
        self.untrack_udp_port(port);
    }
}

// ── Socket table entries ────────────────────────────────────────────────

/// One backend-owned virtual socket's state.
enum SocketEntry {
    /// A freshly `socket()`-created TCP socket: not yet bound, connected,
    /// or listening.
    TcpIdle {
        handle: SocketHandle,
        bound_port: Option<u16>,
        nonblock: bool,
    },
    /// A connecting or connected TCP socket — from a successful
    /// `connect()`, or handed out by `accept4()`.
    Tcp {
        handle: SocketHandle,
        local_port: u16,
        nonblock: bool,
    },
    /// A listening TCP socket. `backlog` holds a pool of `smoltcp` socket
    /// handles each independently `.listen()`ing on `port` — see module
    /// doc for why a single handle can't do this alone.
    TcpListener {
        port: u16,
        backlog: Vec<SocketHandle>,
        nonblock: bool,
    },
    /// A UDP socket. `smoltcp` binds it lazily to an ephemeral port on
    /// first send if it was never explicitly bound.
    Udp {
        handle: SocketHandle,
        local_port: Option<u16>,
        /// Default peer recorded by connect(2). Required by real-world
        /// callers like the glibc resolver, which connect()s a UDP socket
        /// and then sendto()s with a NULL destination — the kernel uses
        /// the connected peer in that case; without it we returned
        /// EDESTADDRREQ and DNS-over-smoltcp silently died.
        peer: Option<(smoltcp::wire::Ipv4Address, u16)>,
        nonblock: bool,
    },
}

impl SocketEntry {
    fn nonblock(&self) -> bool {
        match self {
            SocketEntry::TcpIdle { nonblock, .. }
            | SocketEntry::Tcp { nonblock, .. }
            | SocketEntry::TcpListener { nonblock, .. }
            | SocketEntry::Udp { nonblock, .. } => *nonblock,
        }
    }

    /// Used by `fcntl(fd, F_SETFL, ...)` (see `sys_fcntl`) to toggle
    /// `O_NONBLOCK` after socket creation — e.g. Python's
    /// `socket.setblocking()`/`settimeout()`, which `fcntl` rather than
    /// pass `SOCK_NONBLOCK` to `socket()`/`accept4()` up front.
    fn set_nonblock(&mut self, val: bool) {
        match self {
            SocketEntry::TcpIdle { nonblock, .. }
            | SocketEntry::Tcp { nonblock, .. }
            | SocketEntry::TcpListener { nonblock, .. }
            | SocketEntry::Udp { nonblock, .. } => *nonblock = val,
        }
    }
}

// ── Backend ──────────────────────────────────────────────────────────────

/// The `smoltcp-xdp` [`NetBackend`]: services intercepted socket syscalls
/// against `smoltcp` sockets living in `state`'s shared `SocketSet`,
/// driven by a background poll loop (`bridge::run_poll_loop`) that this
/// struct does not itself own — see `smoltcp_xdp` backend initialization
/// in `main.rs` for how the two are wired together.
pub struct SmoltcpXdpBackend {
    table: SocketTable<SocketEntry>,
    state: Arc<Mutex<PollState>>,
    ports: Mutex<Box<dyn PortTracker>>,
    local_ip: Ipv4Address,
    next_ephemeral: AtomicU32,
}

impl SmoltcpXdpBackend {
    pub fn new(
        state: Arc<Mutex<PollState>>,
        ports: Box<dyn PortTracker>,
        local_ip: Ipv4Address,
    ) -> Self {
        Self {
            table: SocketTable::new(),
            state,
            ports: Mutex::new(ports),
            local_ip,
            next_ephemeral: AtomicU32::new(0),
        }
    }

    fn alloc_ephemeral_port(&self) -> u16 {
        let n = self.next_ephemeral.fetch_add(1, Ordering::Relaxed);
        EPHEMERAL_PORT_START + (n % EPHEMERAL_PORT_RANGE) as u16
    }

    fn new_tcp_handle(&self) -> SocketHandle {
        let rx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_SIZE]);
        let tx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_SIZE]);
        let socket = tcp::Socket::new(rx, tx);
        self.state.lock().expect("PollState mutex poisoned").sockets.add(socket)
    }

    fn new_udp_handle(&self) -> SocketHandle {
        let rx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_METADATA_CAPACITY],
            vec![0u8; UDP_PAYLOAD_BUFFER_SIZE],
        );
        let tx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_METADATA_CAPACITY],
            vec![0u8; UDP_PAYLOAD_BUFFER_SIZE],
        );
        let socket = udp::Socket::new(rx, tx);
        self.state.lock().expect("PollState mutex poisoned").sockets.add(socket)
    }

    /// Resolves a `sockaddr_in`'s address field to the concrete
    /// `IpListenEndpoint` `smoltcp` should bind/listen on: `INADDR_ANY`
    /// (`0.0.0.0`) becomes "any local address" (`addr: None`); our own
    /// interface address is passed through; anything else is not an
    /// address we can ever receive traffic for (single-interface v1
    /// scope, see design.md Non-Goals) and is rejected.
    fn resolve_bind_addr(&self, addr: Ipv4Address, port: u16) -> Result<IpListenEndpoint, i64> {
        if addr == Ipv4Address::UNSPECIFIED {
            Ok(IpListenEndpoint { addr: None, port })
        } else if addr == self.local_ip {
            Ok(IpListenEndpoint {
                addr: Some(IpAddress::Ipv4(addr)),
                port,
            })
        } else {
            Err(-(libc::EADDRNOTAVAIL as i64))
        }
    }

    // ── socket() ─────────────────────────────────────────────────────

    fn sys_socket(&self, req: &SyscallRequest) -> SyscallResponse {
        let domain = req.args[0] as i32;
        let raw_type = req.args[1] as i32;
        let nonblock = raw_type & libc::SOCK_NONBLOCK != 0;
        let sock_type = raw_type & !(libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC);

        if domain != libc::AF_INET {
            return err(req, libc::EAFNOSUPPORT);
        }

        let fd = match sock_type {
            libc::SOCK_STREAM => {
                let handle = self.new_tcp_handle();
                self.table.insert(SocketEntry::TcpIdle {
                    handle,
                    bound_port: None,
                    nonblock,
                })
            }
            libc::SOCK_DGRAM => {
                let handle = self.new_udp_handle();
                self.table.insert(SocketEntry::Udp {
                    handle,
                    local_port: None,
                    peer: None,
                    nonblock,
                })
            }
            _ => return err(req, libc::EPROTONOSUPPORT),
        };

        ok(req, fd)
    }

    // ── bind() ───────────────────────────────────────────────────────

    fn sys_bind(&self, req: &SyscallRequest) -> SyscallResponse {
        let fd = req.args[0] as i64;
        let Some((addr, mut port)) = req
            .in_bufs
            .iter()
            .find(|b| b.arg_idx == 1)
            .and_then(|b| parse_sockaddr_in(&b.data))
        else {
            return err(req, libc::EINVAL);
        };

        let endpoint = match self.resolve_bind_addr(addr, port) {
            Ok(ep) => ep,
            Err(ret) => return SyscallResponse { slot_idx: req.slot_idx, ret, out_bufs: vec![] },
        };

        let result = self.table.with(fd, |entry| -> i64 {
            match entry {
                SocketEntry::TcpIdle { bound_port, .. } => {
                    if port == 0 {
                        port = self.alloc_ephemeral_port();
                    }
                    *bound_port = Some(port);
                    0
                }
                SocketEntry::Udp { handle, local_port, .. } => {
                    if port == 0 {
                        port = self.alloc_ephemeral_port();
                    }
                    let bind_ep = IpListenEndpoint { addr: endpoint.addr, port };
                    let mut state = self.state.lock().expect("PollState mutex poisoned");
                    let sock = state.sockets.get_mut::<udp::Socket>(*handle);
                    match sock.bind(bind_ep) {
                        Ok(()) => {
                            *local_port = Some(port);
                            drop(state);
                            self.ports.lock().expect("ports mutex poisoned").track_udp(port);
                            0
                        }
                        Err(_) => -(libc::EADDRINUSE as i64),
                    }
                }
                // Already bound/connected/listening — bind() on an
                // already-open socket is invalid, matching real bind()'s
                // EINVAL for a socket that's already bound.
                SocketEntry::Tcp { .. } | SocketEntry::TcpListener { .. } => {
                    -(libc::EINVAL as i64)
                }
            }
        });

        match result {
            Some(ret) => SyscallResponse { slot_idx: req.slot_idx, ret, out_bufs: vec![] },
            None => err(req, libc::EBADF),
        }
    }

    // ── listen() ─────────────────────────────────────────────────────

    fn sys_listen(&self, req: &SyscallRequest) -> SyscallResponse {
        let fd = req.args[0] as i64;
        let requested_backlog = (req.args[1] as usize).clamp(LISTEN_BACKLOG_MIN, LISTEN_BACKLOG_MAX);

        // Extract what we need from the current entry, then replace it —
        // done in two steps because building the listener pool needs to
        // allocate additional smoltcp sockets (via `self.new_tcp_handle`,
        // which itself locks `self.state`), which can't happen while
        // `self.table`'s internal lock is held by `with`'s closure.
        let plan = self.table.with(fd, |entry| match entry {
            SocketEntry::TcpIdle { handle, bound_port, nonblock } => {
                Some((*handle, *bound_port, *nonblock))
            }
            _ => None,
        });

        let Some(Some((first_handle, bound_port, nonblock))) = plan else {
            return match plan {
                Some(None) => err(req, libc::EINVAL), // wrong entry kind
                _ => err(req, libc::EBADF),
            };
        };

        let port = bound_port.unwrap_or_else(|| self.alloc_ephemeral_port());

        let mut backlog = Vec::with_capacity(requested_backlog);
        {
            let mut state = self.state.lock().expect("PollState mutex poisoned");
            if state.sockets.get_mut::<tcp::Socket>(first_handle).listen(port).is_err() {
                return err(req, libc::EADDRINUSE);
            }
            backlog.push(first_handle);
        }
        while backlog.len() < requested_backlog {
            let handle = self.new_tcp_handle();
            let mut state = self.state.lock().expect("PollState mutex poisoned");
            // Best-effort: if a replica somehow fails to listen, just
            // don't add it to the pool rather than failing listen()
            // outright — the first handle above already succeeded.
            if state.sockets.get_mut::<tcp::Socket>(handle).listen(port).is_ok() {
                backlog.push(handle);
            }
        }

        self.table.with(fd, |entry| {
            *entry = SocketEntry::TcpListener { port, backlog, nonblock };
        });
        self.ports.lock().expect("ports mutex poisoned").track_tcp(port);

        ok(req, 0)
    }

    // ── connect() ────────────────────────────────────────────────────

    fn sys_connect(&self, req: &SyscallRequest) -> SyscallResponse {
        let fd = req.args[0] as i64;
        let Some((remote_addr, remote_port)) = req
            .in_bufs
            .iter()
            .find(|b| b.arg_idx == 1)
            .and_then(|b| parse_sockaddr_in(&b.data))
        else {
            return err(req, libc::EINVAL);
        };

        // Only meaningful for TCP entries — UDP's "connect" (fixing a
        // default peer for send()/recv() without an explicit address) is
        // handled separately by `sendto`/`recvfrom` always taking an
        // explicit address in this model; a bare UDP connect() just
        // records the peer similarly to bind's ephemeral-port dance.
        enum Plan {
            Tcp { handle: SocketHandle, local_port: u16, nonblock: bool },
            Udp { handle: SocketHandle, needs_port: bool },
            WrongState,
        }

        let plan = self.table.with(fd, |entry| match entry {
            SocketEntry::TcpIdle { handle, bound_port, nonblock } => {
                let local_port = bound_port.unwrap_or_else(|| self.alloc_ephemeral_port());
                Plan::Tcp { handle: *handle, local_port, nonblock: *nonblock }
            }
            SocketEntry::Udp { handle, local_port, .. } => {
                Plan::Udp { handle: *handle, needs_port: local_port.is_none() }
            }
            _ => Plan::WrongState,
        });

        match plan {
            None => err(req, libc::EBADF),
            Some(Plan::WrongState) => err(req, libc::EISCONN),
            Some(Plan::Udp { handle, needs_port }) => {
                let port = if needs_port {
                    let port = self.alloc_ephemeral_port();
                    let mut state = self.state.lock().expect("PollState mutex poisoned");
                    let _ = state
                        .sockets
                        .get_mut::<udp::Socket>(handle)
                        .bind(IpListenEndpoint { addr: None, port });
                    Some(port)
                } else {
                    None
                };
                if let Some(port) = port {
                    self.table.with(fd, |entry| {
                        if let SocketEntry::Udp { local_port, .. } = entry {
                            *local_port = Some(port);
                        }
                    });
                    self.ports.lock().expect("ports mutex poisoned").track_udp(port);
                }
                // Record the default peer so a later sendto()/write() with
                // no explicit destination uses it (kernel UDP semantics).
                self.table.with(fd, |entry| {
                    if let SocketEntry::Udp { peer, .. } = entry {
                        *peer = Some((remote_addr, remote_port));
                    }
                });
                ok(req, 0)
            }
            Some(Plan::Tcp { handle, local_port, nonblock }) => {
                let remote = IpEndpoint::new(IpAddress::Ipv4(remote_addr), remote_port);
                let local = IpListenEndpoint { addr: None, port: local_port };
                let connect_result = {
                    let mut state = self.state.lock().expect("PollState mutex poisoned");
                    let PollState { iface, sockets } = &mut *state;
                    sockets.get_mut::<tcp::Socket>(handle).connect(iface.context(), remote, local)
                };
                tracing::info!(
                    "XDP_DIAG: connect() remote={remote:?} local_port={local_port} result={connect_result:?}"
                );
                if connect_result.is_err() {
                    return err(req, libc::EINVAL);
                }
                self.table.with(fd, |entry| {
                    *entry = SocketEntry::Tcp { handle, local_port, nonblock };
                });
                self.ports.lock().expect("ports mutex poisoned").track_tcp(local_port);

                if nonblock {
                    return err(req, libc::EINPROGRESS);
                }

                let deadline = StdInstant::now() + CONNECT_TIMEOUT;
                let mut last_logged = None;
                loop {
                    let state = {
                        let mut guard = self.state.lock().expect("PollState mutex poisoned");
                        guard.sockets.get_mut::<tcp::Socket>(handle).state()
                    };
                    if last_logged != Some(state) {
                        tracing::info!("XDP_DIAG: connect() poll state={state:?}");
                        last_logged = Some(state);
                    }
                    match state {
                        tcp::State::Established => return ok(req, 0),
                        tcp::State::Closed | tcp::State::TimeWait => {
                            return err(req, libc::ECONNREFUSED)
                        }
                        _ => {}
                    }
                    if StdInstant::now() >= deadline {
                        return err(req, libc::ETIMEDOUT);
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
            }
        }
    }

    // ── accept4() ────────────────────────────────────────────────────

    fn sys_accept4(&self, req: &SyscallRequest) -> SyscallResponse {
        let fd = req.args[0] as i64;
        let flags = req.args[3] as i32;
        let accepted_nonblock = flags & libc::SOCK_NONBLOCK != 0;

        let listener_nonblock = match self.table.with(fd, |e| e.nonblock()) {
            Some(nb) => nb,
            None => return err(req, libc::EBADF),
        };

        let deadline = StdInstant::now() + ACCEPT_TIMEOUT;
        let (accepted_handle, port, peer) = loop {
            let found = self.table.with(fd, |entry| {
                let SocketEntry::TcpListener { port, backlog, .. } = entry else {
                    return Err(());
                };
                let mut state = self.state.lock().expect("PollState mutex poisoned");
                let idx = backlog
                    .iter()
                    .position(|h| state.sockets.get_mut::<tcp::Socket>(*h).state() == tcp::State::Established);
                match idx {
                    Some(i) => {
                        let handle = backlog.remove(i);
                        let peer = state.sockets.get_mut::<tcp::Socket>(handle).remote_endpoint();
                        Ok(Some((handle, *port, peer)))
                    }
                    None => Ok(None),
                }
            });

            match found {
                None => return err(req, libc::EBADF),
                Some(Err(())) => return err(req, libc::EINVAL),
                Some(Ok(Some(result))) => break result,
                Some(Ok(None)) => {}
            }

            if listener_nonblock {
                return err(req, libc::EAGAIN);
            }
            if StdInstant::now() >= deadline {
                return err(req, libc::EAGAIN);
            }
            std::thread::sleep(POLL_INTERVAL);
        };

        // Top up the backlog with a fresh replica so future connections
        // keep getting accepted.
        let replica = self.new_tcp_handle();
        {
            let mut state = self.state.lock().expect("PollState mutex poisoned");
            let _ = state.sockets.get_mut::<tcp::Socket>(replica).listen(port);
        }
        self.table.with(fd, |entry| {
            if let SocketEntry::TcpListener { backlog, .. } = entry {
                backlog.push(replica);
            }
        });

        let new_fd = self.table.insert(SocketEntry::Tcp {
            handle: accepted_handle,
            local_port: port,
            nonblock: accepted_nonblock,
        });

        let mut out_bufs = Vec::new();
        if let Some(peer) = peer {
            let IpAddress::Ipv4(peer_ip) = peer.addr;
            let encoded = encode_sockaddr_in(peer_ip, peer.port);
            if let Some(&(_, addrlen_cap)) = req.out_sizes.iter().find(|&&(i, _)| i == 1) {
                let cap = (addrlen_cap as usize).min(SOCKADDR_IN_LEN);
                out_bufs.push(SyscallBuf { arg_idx: 1, data: encoded[..cap].to_vec() });
            }
            if req.out_sizes.iter().any(|&(i, _)| i == 2) {
                out_bufs.push(SyscallBuf {
                    arg_idx: 2,
                    data: (SOCKADDR_IN_LEN as u32).to_ne_bytes().to_vec(),
                });
            }
        }

        SyscallResponse { slot_idx: req.slot_idx, ret: new_fd, out_bufs }
    }

    // ── read/write/sendto/recvfrom ───────────────────────────────────

    fn sys_read(&self, req: &SyscallRequest) -> SyscallResponse {
        self.recv_common(req, /*from_addr=*/ false)
    }

    fn sys_recvfrom(&self, req: &SyscallRequest) -> SyscallResponse {
        self.recv_common(req, /*from_addr=*/ true)
    }

    fn recv_common(&self, req: &SyscallRequest, want_addr: bool) -> SyscallResponse {
        let fd = req.args[0] as i64;
        let cap = req
            .out_sizes
            .iter()
            .find(|&&(i, _)| i == 1)
            .map(|&(_, sz)| sz as usize)
            .unwrap_or(0);

        // `flags` (args[3]) is only a real argument for recvfrom/recvmsg —
        // read(2)/write(2) (the `want_addr == false` case, `sys_read`) have
        // no such parameter, so args[3] there is an arbitrary leftover
        // register value, not a real flags word; checking it in that case
        // would risk misreading MSG_DONTWAIT out of noise. `MSG_DONTWAIT`
        // requests non-blocking behavior for *this call only*, regardless
        // of the fd's own persisted blocking mode (`SocketEntry::nonblock`)
        // — this is what lets rsclient's `socket_proxy` background task
        // poll a socket without ever blocking a server-side worker thread
        // for the full `IO_TIMEOUT`, independent of whatever blocking mode
        // the tracee itself asked for at `socket()`/later via `fcntl`/
        // `ioctl` (which, for a proxied real fd, never reaches rsbeacon at
        // all anymore — see `rsclient::socket_proxy`'s module doc).
        let want_dontwait = want_addr && (req.args[3] as i32 & libc::MSG_DONTWAIT != 0);

        let nonblock = match self.table.with(fd, |e| e.nonblock()) {
            Some(nb) => nb || want_dontwait,
            None => return err(req, libc::EBADF),
        };

        let deadline = StdInstant::now() + IO_TIMEOUT;
        loop {
            let outcome = self.table.with(fd, |entry| -> Option<(i64, Vec<u8>, Option<IpEndpoint>)> {
                let mut state = self.state.lock().expect("PollState mutex poisoned");
                match entry {
                    SocketEntry::Tcp { handle, .. } => {
                        let sock = state.sockets.get_mut::<tcp::Socket>(*handle);
                        // Still establishing the connection: `may_recv()`
                        // returns `false` for these states too, which
                        // would otherwise be indistinguishable from "peer
                        // closed" below — not ready yet, not closed. Only
                        // ever actually reachable when a caller issues a
                        // read on a socket before its own connect() has
                        // finished (rsclient's socket-proxy background
                        // task does exactly this deliberately, racing
                        // ahead of the tracee's connect() call — see its
                        // module doc).
                        if matches!(sock.state(), tcp::State::SynSent | tcp::State::SynReceived | tcp::State::Listen)
                        {
                            return None;
                        }
                        if !sock.may_recv() {
                            return Some((0, Vec::new(), None)); // peer closed: EOF
                        }
                        if !sock.can_recv() {
                            return None;
                        }
                        let mut buf = vec![0u8; cap];
                        match sock.recv_slice(&mut buf) {
                            Ok(n) => {
                                buf.truncate(n);
                                Some((n as i64, buf, None))
                            }
                            Err(_) => Some((-(libc::ECONNRESET as i64), Vec::new(), None)),
                        }
                    }
                    SocketEntry::Udp { handle, .. } => {
                        let sock = state.sockets.get_mut::<udp::Socket>(*handle);
                        if !sock.can_recv() {
                            return None;
                        }
                        let mut buf = vec![0u8; cap];
                        match sock.recv_slice(&mut buf) {
                            Ok((n, meta)) => {
                                buf.truncate(n);
                                Some((n as i64, buf, Some(meta.endpoint)))
                            }
                            Err(_) => Some((0, Vec::new(), None)),
                        }
                    }
                    _ => Some((-(libc::ENOTCONN as i64), Vec::new(), None)),
                }
            });

            match outcome {
                None => return err(req, libc::EBADF),
                Some(Some((ret, data, peer))) => {
                    let mut out_bufs = vec![SyscallBuf { arg_idx: 1, data }];
                    if want_addr {
                        if let Some(IpAddress::Ipv4(addr)) = peer.map(|p| p.addr) {
                            let port = peer.map(|p| p.port).unwrap_or(0);
                            let encoded = encode_sockaddr_in(addr, port);
                            if let Some(&(_, addrlen_cap)) = req.out_sizes.iter().find(|&&(i, _)| i == 4) {
                                let c = (addrlen_cap as usize).min(SOCKADDR_IN_LEN);
                                out_bufs.push(SyscallBuf { arg_idx: 4, data: encoded[..c].to_vec() });
                            }
                            if req.out_sizes.iter().any(|&(i, _)| i == 5) {
                                out_bufs.push(SyscallBuf {
                                    arg_idx: 5,
                                    data: (SOCKADDR_IN_LEN as u32).to_ne_bytes().to_vec(),
                                });
                            }
                        }
                    }
                    return SyscallResponse { slot_idx: req.slot_idx, ret, out_bufs };
                }
                Some(None) => {}
            }

            if nonblock {
                return err(req, libc::EAGAIN);
            }
            if StdInstant::now() >= deadline {
                return err(req, libc::EAGAIN);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn sys_write(&self, req: &SyscallRequest) -> SyscallResponse {
        self.send_common(req, /*dest_arg_idx=*/ None)
    }

    fn sys_sendto(&self, req: &SyscallRequest) -> SyscallResponse {
        self.send_common(req, Some(4))
    }

    fn send_common(&self, req: &SyscallRequest, dest_arg_idx: Option<u8>) -> SyscallResponse {
        let fd = req.args[0] as i64;
        let Some(data) = req.in_bufs.iter().find(|b| b.arg_idx == 1).map(|b| b.data.clone()) else {
            return err(req, libc::EINVAL);
        };
        let dest = dest_arg_idx.and_then(|idx| {
            req.in_bufs.iter().find(|b| b.arg_idx == idx).and_then(|b| parse_sockaddr_in(&b.data))
        });
        // No explicit destination → fall back to the connect(2)ed peer,
        // like the kernel does for UDP sendto(NULL)/write().
        let dest = match dest {
            Some(_) => dest,
            None => self
                .table
                .with(fd, |e| match e {
                    SocketEntry::Udp { peer, .. } => *peer,
                    _ => None,
                })
                .flatten(),
        };

        // See the matching comment in `recv_common`: args[3] (`flags`) is
        // only meaningful for the sendto variant (`dest_arg_idx.is_some()`)
        // — plain write(2) has no such argument.
        let want_dontwait = dest_arg_idx.is_some() && (req.args[3] as i32 & libc::MSG_DONTWAIT != 0);

        let nonblock = match self.table.with(fd, |e| e.nonblock()) {
            Some(nb) => nb || want_dontwait,
            None => return err(req, libc::EBADF),
        };

        let deadline = StdInstant::now() + IO_TIMEOUT;
        loop {
            let outcome = self.table.with(fd, |entry| -> Result<Option<i64>, i64> {
                match entry {
                    SocketEntry::Tcp { handle, .. } => {
                        let mut state = self.state.lock().expect("PollState mutex poisoned");
                        let sock = state.sockets.get_mut::<tcp::Socket>(*handle);
                        // See the matching comment in `recv_common`: still
                        // connecting is not the same as closed.
                        if matches!(sock.state(), tcp::State::SynSent | tcp::State::SynReceived | tcp::State::Listen)
                        {
                            return Ok(None);
                        }
                        if !sock.may_send() {
                            return Err(-(libc::EPIPE as i64));
                        }
                        if !sock.can_send() {
                            return Ok(None);
                        }
                        match sock.send_slice(&data) {
                            Ok(n) => Ok(Some(n as i64)),
                            Err(_) => Err(-(libc::ECONNRESET as i64)),
                        }
                    }
                    SocketEntry::Udp { handle, local_port, .. } => {
                        let Some((addr, port)) = dest else {
                            return Err(-(libc::EDESTADDRREQ as i64));
                        };
                        // A UDP socket that has never been bound/connected
                        // gets an ephemeral local port auto-assigned on
                        // its first send, exactly like a real kernel UDP
                        // socket does — otherwise `smoltcp` rejects the
                        // send with `Unaddressable` (`endpoint.port == 0`).
                        if local_port.is_none() {
                            let eph = self.alloc_ephemeral_port();
                            let bound = {
                                let mut state = self.state.lock().expect("PollState mutex poisoned");
                                state
                                    .sockets
                                    .get_mut::<udp::Socket>(*handle)
                                    .bind(IpListenEndpoint { addr: None, port: eph })
                                    .is_ok()
                            };
                            if bound {
                                *local_port = Some(eph);
                                self.ports.lock().expect("ports mutex poisoned").track_udp(eph);
                            }
                        }
                        let mut state = self.state.lock().expect("PollState mutex poisoned");
                        let sock = state.sockets.get_mut::<udp::Socket>(*handle);
                        if !sock.can_send() {
                            return Ok(None);
                        }
                        let ep = IpEndpoint::new(IpAddress::Ipv4(addr), port);
                        match sock.send_slice(&data, ep) {
                            Ok(()) => Ok(Some(data.len() as i64)),
                            Err(_) => Err(-(libc::ENOBUFS as i64)),
                        }
                    }
                    _ => Err(-(libc::ENOTCONN as i64)),
                }
            });

            match outcome {
                None => return err(req, libc::EBADF),
                Some(Err(ret)) => return SyscallResponse { slot_idx: req.slot_idx, ret, out_bufs: vec![] },
                Some(Ok(Some(n))) => return ok(req, n),
                Some(Ok(None)) => {}
            }

            if nonblock {
                return err(req, libc::EAGAIN);
            }
            if StdInstant::now() >= deadline {
                return err(req, libc::EAGAIN);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    // ── getsockopt/setsockopt ────────────────────────────────────────

    fn sys_setsockopt(&self, req: &SyscallRequest) -> SyscallResponse {
        let fd = req.args[0] as i64;
        let level = req.args[1] as i32;
        let optname = req.args[2] as i32;
        let optval = req.in_bufs.iter().find(|b| b.arg_idx == 3).map(|b| b.data.as_slice());

        let result = self.table.with(fd, |entry| -> i64 {
            if level == libc::IPPROTO_TCP && optname == libc::TCP_NODELAY {
                if let SocketEntry::Tcp { handle, .. } | SocketEntry::TcpIdle { handle, .. } = entry {
                    if let Some(val) = optval.and_then(as_i32) {
                        let mut state = self.state.lock().expect("PollState mutex poisoned");
                        state
                            .sockets
                            .get_mut::<tcp::Socket>(*handle)
                            .set_nagle_enabled(val == 0);
                    }
                }
            }
            // Every other option: best-effort no-op success — see module
            // doc for why.
            0
        });

        match result {
            Some(ret) => SyscallResponse { slot_idx: req.slot_idx, ret, out_bufs: vec![] },
            None => err(req, libc::EBADF),
        }
    }

    fn sys_getsockopt(&self, req: &SyscallRequest) -> SyscallResponse {
        let fd = req.args[0] as i64;
        let level = req.args[1] as i32;
        let optname = req.args[2] as i32;
        let cap = req
            .out_sizes
            .iter()
            .find(|&&(i, _)| i == 3)
            .map(|&(_, sz)| sz as usize)
            .unwrap_or(4);

        let value: Option<i32> = self.table.with(fd, |entry| -> i32 {
            if level == libc::SOL_SOCKET && optname == libc::SO_ERROR {
                // Only a socket that has actually attempted a connect()
                // (i.e. transitioned out of `TcpIdle`) can have a
                // pending error to report — a fresh `TcpIdle` socket's
                // `smoltcp` state happens to also read `Closed` (that's
                // simply its initial state), which must NOT be confused
                // with "connection refused".
                let handle = match entry {
                    SocketEntry::Tcp { handle, .. } => Some(*handle),
                    _ => None,
                };
                if let Some(handle) = handle {
                    let mut state = self.state.lock().expect("PollState mutex poisoned");
                    return match state.sockets.get_mut::<tcp::Socket>(handle).state() {
                        tcp::State::Closed | tcp::State::TimeWait => libc::ECONNREFUSED,
                        _ => 0,
                    };
                }
            }
            0
        });

        let Some(value) = value else {
            return err(req, libc::EBADF);
        };

        let mut buf = value.to_ne_bytes().to_vec();
        buf.truncate(cap.min(4));
        let mut out_bufs = vec![SyscallBuf { arg_idx: 3, data: buf }];
        if req.out_sizes.iter().any(|&(i, _)| i == 4) {
            out_bufs.push(SyscallBuf { arg_idx: 4, data: 4u32.to_ne_bytes().to_vec() });
        }
        SyscallResponse { slot_idx: req.slot_idx, ret: 0, out_bufs }
    }

    // ── shutdown / getsockname / getpeername ───────────────────────────

    /// Builds the sockaddr_in OUT response shared by getsockname and
    /// getpeername (arg 1 = addr, arg 2 = addrlen*).
    fn sockaddr_out_resp(&self, req: &SyscallRequest, addr: Ipv4Address, port: u16) -> SyscallResponse {
        let encoded = encode_sockaddr_in(addr, port);
        let capped = match req.out_sizes.iter().find(|&&(i, _)| i == 1) {
            Some(&(_, cap)) => encoded[..(cap as usize).min(SOCKADDR_IN_LEN)].to_vec(),
            None => encoded.to_vec(),
        };
        SyscallResponse {
            slot_idx: req.slot_idx,
            ret: 0,
            out_bufs: vec![
                SyscallBuf { arg_idx: 1, data: capped },
                SyscallBuf { arg_idx: 2, data: (SOCKADDR_IN_LEN as u32).to_ne_bytes().to_vec() },
            ],
        }
    }

    fn sys_getsockname(&self, req: &SyscallRequest) -> SyscallResponse {
        let fd = req.args[0] as i64;
        let local = self.table.with(fd, |entry| match entry {
            SocketEntry::Tcp { handle, .. } => {
                let mut state = self.state.lock().expect("PollState mutex poisoned");
                state
                    .sockets
                    .get::<tcp::Socket>(*handle)
                    .local_endpoint()
                    .map(|ep| ep.port)
            }
            SocketEntry::TcpListener { port, .. } => Some(*port),
            SocketEntry::TcpIdle { bound_port, .. } => *bound_port,
            SocketEntry::Udp { local_port, .. } => *local_port,
        });
        match local.flatten() {
            // glibc's getaddrinfo rfc3484 sort probe asserts the family —
            // always answer a well-formed AF_INET sockaddr.
            Some(port) => self.sockaddr_out_resp(req, self.local_ip, port),
            None => self.sockaddr_out_resp(req, Ipv4Address::UNSPECIFIED, 0),
        }
    }

    fn sys_getpeername(&self, req: &SyscallRequest) -> SyscallResponse {
        let fd = req.args[0] as i64;
        let peer = self.table.with(fd, |entry| match entry {
            SocketEntry::Tcp { handle, .. } => {
                let mut state = self.state.lock().expect("PollState mutex poisoned");
                state
                    .sockets
                    .get::<tcp::Socket>(*handle)
                    .remote_endpoint()
                    .and_then(|ep| match ep.addr {
                        IpAddress::Ipv4(a) => Some((a, ep.port)),
                        _ => None,
                    })
            }
            SocketEntry::Udp { peer, .. } => *peer,
            _ => None,
        });
        match peer.flatten() {
            Some((addr, port)) => self.sockaddr_out_resp(req, addr, port),
            None => err(req, libc::ENOTCONN),
        }
    }

    /// shutdown(fd, how) — smoltcp TCP has only full close(); any `how`
    /// closes the send side (FIN), which is what relay teardown paths use
    /// it for. UDP: success iff a peer is connected (kernel semantics),
    /// no wire effect.
    fn sys_shutdown(&self, req: &SyscallRequest) -> SyscallResponse {
        let fd = req.args[0] as i64;
        let outcome = self.table.with(fd, |entry| match entry {
            SocketEntry::Tcp { handle, .. } => {
                let mut state = self.state.lock().expect("PollState mutex poisoned");
                state.sockets.get_mut::<tcp::Socket>(*handle).close();
                Some(())
            }
            SocketEntry::Udp { peer, .. } => {
                if peer.is_some() {
                    Some(())
                } else {
                    None
                }
            }
            _ => None,
        });
        match outcome {
            Some(Some(())) => ok(req, 0),
            Some(None) => err(req, libc::ENOTCONN),
            None => err(req, libc::EBADF),
        }
    }

    // ── fcntl() ──────────────────────────────────────────────────────
    /// `fcntl(fd, cmd, arg)` for a beacon-owned virtual fd. Only
    /// `F_GETFL`/`F_SETFL` have concrete meaning for a socket in this
    /// backend (toggling/reading `O_NONBLOCK` — see `SocketEntry::nonblock`);
    /// every other command is a best-effort no-op success, same scope
    /// decision as `sys_setsockopt` (module doc / task 5.5): no baseline
    /// found to scope real `flock`/`F_DUPFD`-style behavior against, and
    /// most software treats an ignored fcntl as advisory rather than fatal.
    fn sys_fcntl(&self, req: &SyscallRequest) -> SyscallResponse {
        let fd = req.args[0] as i64;
        let cmd = req.args[1] as i32;
        let arg = req.args[2] as i32;

        let ret = self.table.with(fd, |entry| -> i64 {
            match cmd {
                libc::F_GETFL => {
                    (libc::O_RDWR | if entry.nonblock() { libc::O_NONBLOCK } else { 0 }) as i64
                }
                libc::F_SETFL => {
                    entry.set_nonblock(arg & libc::O_NONBLOCK != 0);
                    0
                }
                _ => 0,
            }
        });

        match ret {
            Some(ret) => SyscallResponse { slot_idx: req.slot_idx, ret, out_bufs: vec![] },
            None => err(req, libc::EBADF),
        }
    }

    // ── ioctl() ──────────────────────────────────────────────────────

    /// `ioctl(fd, request, argp)` for a beacon-owned virtual fd. Only
    /// `FIONBIO` has concrete meaning here (toggle `O_NONBLOCK` — see
    /// `SocketEntry::nonblock`; this, not `fcntl(F_SETFL)`, is what
    /// CPython's `socket.settimeout()`/`setblocking()` actually issues on
    /// modern Linux, confirmed via `strace`). Every other request is a
    /// best-effort no-op success, same scope decision as `sys_setsockopt`/
    /// `sys_fcntl`.
    fn sys_ioctl(&self, req: &SyscallRequest) -> SyscallResponse {
        let fd = req.args[0] as i64;
        let request = req.args[1];
        let argp = req.in_bufs.iter().find(|b| b.arg_idx == 2).map(|b| b.data.as_slice());

        let ret = self.table.with(fd, |entry| -> i64 {
            if request == libc::FIONBIO as u64 {
                if let Some(val) = argp.and_then(as_i32) {
                    entry.set_nonblock(val != 0);
                }
            }
            0
        });

        let Some(ret) = ret else {
            return err(req, libc::EBADF);
        };

        // Echo the input value back on the same 4-byte buffer (`InOut` in
        // `ctls::meta`) — correct no-op for `FIONBIO` (caller doesn't read
        // it back), and the right shape if a future `FIONREAD`-style
        // request needs to actually report a value out of `argp`.
        let out_bufs = match argp {
            Some(bytes) => vec![SyscallBuf { arg_idx: 2, data: bytes.to_vec() }],
            None => vec![],
        };
        SyscallResponse { slot_idx: req.slot_idx, ret, out_bufs }
    }

    // ── close() ──────────────────────────────────────────────────────

    fn sys_close(&self, req: &SyscallRequest) -> SyscallResponse {
        let fd = req.args[0] as i64;
        let Some(entry) = self.table.remove(fd) else {
            return err(req, libc::EBADF);
        };

        let mut ports = self.ports.lock().expect("ports mutex poisoned");
        let mut state = self.state.lock().expect("PollState mutex poisoned");
        match entry {
            SocketEntry::TcpIdle { handle, .. } => {
                state.sockets.get_mut::<tcp::Socket>(handle).abort();
            }
            SocketEntry::Tcp { handle, local_port, .. } => {
                state.sockets.get_mut::<tcp::Socket>(handle).close();
                ports.untrack_tcp(local_port);
            }
            SocketEntry::TcpListener { port, backlog, .. } => {
                for handle in backlog {
                    state.sockets.get_mut::<tcp::Socket>(handle).abort();
                }
                ports.untrack_tcp(port);
            }
            SocketEntry::Udp { handle, local_port, .. } => {
                state.sockets.get_mut::<udp::Socket>(handle).close();
                if let Some(port) = local_port {
                    ports.untrack_udp(port);
                }
            }
        }

        ok(req, 0)
    }

    // ── poll()/ppoll() ───────────────────────────────────────────────

    /// Parses `req`'s `struct pollfd[nfds]` array (arg 0) and returns it
    /// only if every entry's fd is a virtual fd tracked by this backend —
    /// mixed real/virtual-fd polling in one call is out of scope (see
    /// module doc); callers fall back to the generic passthrough in that
    /// case, per `owns_syscall`'s contract for `FD_GENERIC_SYSCALL_NRS`.
    fn parse_owned_pollfds(&self, req: &SyscallRequest) -> Option<Vec<(i32, i16)>> {
        let raw = &req.in_bufs.iter().find(|b| b.arg_idx == 0)?.data;
        if raw.is_empty() || raw.len() % 8 != 0 {
            return None;
        }
        let mut fds = Vec::with_capacity(raw.len() / 8);
        for chunk in raw.chunks_exact(8) {
            let fd = i32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let events = i16::from_ne_bytes([chunk[4], chunk[5]]);
            if !SocketTable::<SocketEntry>::is_virtual_fd(fd as i64) || !self.table.contains(fd as i64) {
                return None;
            }
            fds.push((fd, events));
        }
        Some(fds)
    }

    fn sys_poll(&self, req: &SyscallRequest) -> SyscallResponse {
        let Some(fds) = self.parse_owned_pollfds(req) else {
            return err(req, libc::EINVAL);
        };

        let mut out = Vec::with_capacity(fds.len() * 8);
        for (fd, events) in fds {
            let revents = self.table.with(fd as i64, |entry| -> i16 {
                let mut state = self.state.lock().expect("PollState mutex poisoned");
                let mut r = 0i16;
                match entry {
                    SocketEntry::Tcp { handle, .. } => {
                        let sock = state.sockets.get_mut::<tcp::Socket>(*handle);
                        if events & libc::POLLIN as i16 != 0 && (sock.can_recv() || !sock.may_recv()) {
                            r |= libc::POLLIN as i16;
                        }
                        if events & libc::POLLOUT as i16 != 0 && sock.can_send() {
                            r |= libc::POLLOUT as i16;
                        }
                        if matches!(sock.state(), tcp::State::Closed | tcp::State::TimeWait) {
                            r |= libc::POLLHUP as i16;
                        }
                    }
                    SocketEntry::TcpListener { backlog, .. } => {
                        if events & libc::POLLIN as i16 != 0
                            && backlog
                                .iter()
                                .any(|h| state.sockets.get_mut::<tcp::Socket>(*h).state() == tcp::State::Established)
                        {
                            r |= libc::POLLIN as i16;
                        }
                    }
                    SocketEntry::Udp { handle, .. } => {
                        let sock = state.sockets.get_mut::<udp::Socket>(*handle);
                        if events & libc::POLLIN as i16 != 0 && sock.can_recv() {
                            r |= libc::POLLIN as i16;
                        }
                        if events & libc::POLLOUT as i16 != 0 && sock.can_send() {
                            r |= libc::POLLOUT as i16;
                        }
                    }
                    SocketEntry::TcpIdle { .. } => {}
                }
                r
            }).unwrap_or(libc::POLLNVAL as i16);
            out.extend_from_slice(&fd.to_ne_bytes());
            out.extend_from_slice(&events.to_ne_bytes());
            out.extend_from_slice(&revents.to_ne_bytes());
        }

        let nready = out.chunks_exact(8).filter(|c| i16::from_ne_bytes([c[6], c[7]]) != 0).count();
        SyscallResponse {
            slot_idx: req.slot_idx,
            ret: nready as i64,
            out_bufs: vec![SyscallBuf { arg_idx: 0, data: out }],
        }
    }
}

fn as_i32(bytes: &[u8]) -> Option<i32> {
    if bytes.len() < 4 {
        return None;
    }
    Some(i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn ok(req: &SyscallRequest, ret: i64) -> SyscallResponse {
    SyscallResponse { slot_idx: req.slot_idx, ret, out_bufs: vec![] }
}

fn err(req: &SyscallRequest, errno: i32) -> SyscallResponse {
    SyscallResponse { slot_idx: req.slot_idx, ret: -(errno as i64), out_bufs: vec![] }
}

impl NetBackend for SmoltcpXdpBackend {
    fn name(&self) -> &'static str {
        "smoltcp-xdp"
    }

    fn owns_syscall(&self, req: &SyscallRequest) -> bool {
        match req.number {
            // See module doc: msghdr's nested pointers aren't marshaled
            // by `ctls::meta`, and bare `accept` is never forwarded by
            // any current profile — never claim either.
            46 | 47 | 43 => false,
            // `socket(domain, type, protocol)` — only ever claim AF_INET.
            // Claiming unconditionally meant `socket(AF_NETLINK, ...)` (e.g.
            // `ip addr`/`ip link`, which go through rtnetlink) or
            // `socket(AF_UNIX, ...)` got handed to `sys_socket`, which
            // already rejects non-AF_INET with EAFNOSUPPORT — but that's
            // the *wrong* answer for those: the real kernel would have
            // succeeded, so the caller must fall through to the generic
            // passthrough (`direct` behavior) instead of being told the
            // domain doesn't exist. `sys_socket`'s own check stays too, as
            // a second line of defense (e.g. if `owns_syscall` and
            // `handle` are ever called out of step in a future refactor).
            41 => req.args[0] as i32 == libc::AF_INET,
            42 | 49 | 50 | 44 | 45 | 54 | 55 | 288 => true,
            // fd-carrying socket ops: claim only fds this backend owns —
            // otherwise the raw virtual fd would reach the beacon kernel
            // (EBADF at best). Missing 51 here crashed glibc's
            // getaddrinfo rfc3484 sort probe with a fatal assert.
            48 | 51 | 52 => {
                let fd = req.args[0] as i64;
                SocketTable::<SocketEntry>::is_virtual_fd(fd) && self.table.contains(fd)
            }
            0 | 1 | 3 | 72 | 16 => {
                let fd = req.args[0] as i64;
                SocketTable::<SocketEntry>::is_virtual_fd(fd) && self.table.contains(fd)
            }
            7 | 271 => self.parse_owned_pollfds(req).is_some(),
            _ => false,
        }
    }

    fn handle(&self, req: &SyscallRequest) -> SyscallResponse {
        match req.number {
            41 => self.sys_socket(req),
            49 => self.sys_bind(req),
            50 => self.sys_listen(req),
            42 => self.sys_connect(req),
            288 => self.sys_accept4(req),
            0 => self.sys_read(req),
            1 => self.sys_write(req),
            44 => self.sys_sendto(req),
            45 => self.sys_recvfrom(req),
            54 => self.sys_setsockopt(req),
            55 => self.sys_getsockopt(req),
            48 => self.sys_shutdown(req),
            51 => self.sys_getsockname(req),
            52 => self.sys_getpeername(req),
            3 => self.sys_close(req),
            72 => self.sys_fcntl(req),
            16 => self.sys_ioctl(req),
            7 | 271 => self.sys_poll(req),
            other => unreachable!(
                "owns_syscall claimed nr={other} but handle() has no case for it"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::iface::{Config, Interface, SocketSet};
    use smoltcp::phy::{Loopback, Medium};
    use smoltcp::time::Instant;
    use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr};
    use std::sync::atomic::AtomicBool;

    const TEST_IP: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);
    const TEST_MAC: EthernetAddress = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

    #[derive(Default)]
    struct NullPortTracker;
    impl PortTracker for NullPortTracker {
        fn track_tcp(&mut self, _port: u16) {}
        fn untrack_tcp(&mut self, _port: u16) {}
        fn track_udp(&mut self, _port: u16) {}
        fn untrack_udp(&mut self, _port: u16) {}
    }

    /// Builds a `SmoltcpXdpBackend` bound to a `Loopback` device (self-
    /// talk: connecting to `TEST_IP` from `TEST_IP` delivers packets back
    /// to this same interface), with a background thread driving the
    /// poll loop — the exact same `bridge::run_poll_loop` production
    /// code runs against, just with `Loopback` standing in for a real
    /// AF_XDP socket. Returns the backend and a guard that stops the
    /// poll thread on drop.
    struct TestHarness {
        backend: SmoltcpXdpBackend,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for TestHarness {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    fn harness() -> TestHarness {
        let mut device = Loopback::new(Medium::Ethernet);
        let config = Config::new(HardwareAddress::Ethernet(TEST_MAC));
        let mut iface = Interface::new(config, &mut device, Instant::now());
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(IpAddress::Ipv4(TEST_IP), 24)).unwrap();
        });
        let state = Arc::new(Mutex::new(PollState {
            iface,
            sockets: SocketSet::new(vec![]),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let state = state.clone();
            let stop = stop.clone();
            std::thread::spawn(move || super::super::bridge::run_poll_loop(state, device, stop))
        };
        let backend = SmoltcpXdpBackend::new(state, Box::new(NullPortTracker), TEST_IP);
        TestHarness { backend, stop, thread: Some(thread) }
    }

    fn req(nr: u64, args: [u64; 6]) -> SyscallRequest {
        SyscallRequest { slot_idx: 0, number: nr, args, in_bufs: vec![], out_sizes: vec![] }
    }

    fn sockaddr_buf(arg_idx: u8, addr: Ipv4Address, port: u16) -> SyscallBuf {
        SyscallBuf { arg_idx, data: encode_sockaddr_in(addr, port).to_vec() }
    }

    #[test]
    fn socket_returns_virtual_fd_for_tcp_and_udp() {
        let h = harness();
        let tcp_resp = h.backend.sys_socket(&req(41, [libc::AF_INET as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0]));
        assert!(SocketTable::<()>::is_virtual_fd(tcp_resp.ret));
        let udp_resp = h.backend.sys_socket(&req(41, [libc::AF_INET as u64, libc::SOCK_DGRAM as u64, 0, 0, 0, 0]));
        assert!(SocketTable::<()>::is_virtual_fd(udp_resp.ret));
        assert_ne!(tcp_resp.ret, udp_resp.ret);
    }

    #[test]
    fn socket_rejects_non_af_inet() {
        let h = harness();
        let resp = h.backend.sys_socket(&req(41, [libc::AF_INET6 as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0]));
        assert_eq!(resp.ret, -(libc::EAFNOSUPPORT as i64));
    }

    #[test]
    fn owns_syscall_claims_socket_syscalls_unconditionally() {
        let h = harness();
        // socket(41) is domain-gated (see below) — needs a real AF_INET
        // domain arg, unlike the other syscalls here which don't inspect
        // their args at the `owns_syscall` stage.
        assert!(h.backend.owns_syscall(&req(41, [libc::AF_INET as u64, 0, 0, 0, 0, 0])));
        for nr in [42u64, 49, 50, 44, 45, 54, 55, 288] {
            assert!(h.backend.owns_syscall(&req(nr, [0; 6])), "nr={nr}");
        }
    }

    #[test]
    fn owns_syscall_declines_socket_for_non_af_inet_domains() {
        let h = harness();
        // AF_NETLINK (rtnetlink — `ip addr`/`ip link`) and AF_UNIX must
        // fall through to the real kernel via the generic passthrough,
        // not be claimed and hard-failed with EAFNOSUPPORT.
        for domain in [libc::AF_NETLINK, libc::AF_UNIX, libc::AF_INET6] {
            assert!(
                !h.backend.owns_syscall(&req(41, [domain as u64, 0, 0, 0, 0, 0])),
                "domain={domain} must not be claimed"
            );
        }
    }

    #[test]
    fn owns_syscall_declines_sendmsg_recvmsg_and_bare_accept() {
        let h = harness();
        for nr in [46u64, 47, 43] {
            assert!(!h.backend.owns_syscall(&req(nr, [0; 6])), "nr={nr}");
        }
    }

    #[test]
    fn owns_syscall_fd_generic_requires_tracked_virtual_fd() {
        let h = harness();
        // Untracked / real fd numbers must never be claimed.
        for nr in [0u64, 1, 3, 72, 16] {
            assert!(!h.backend.owns_syscall(&req(nr, [0; 6])), "real fd, nr={nr}");
            assert!(!h.backend.owns_syscall(&req(nr, [1u64 << 30, 0, 0, 0, 0, 0])), "untracked virtual fd, nr={nr}");
        }
        let resp = h.backend.sys_socket(&req(41, [libc::AF_INET as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0]));
        let fd = resp.ret as u64;
        for nr in [0u64, 1, 3, 72, 16] {
            assert!(h.backend.owns_syscall(&req(nr, [fd, 0, 0, 0, 0, 0])), "tracked virtual fd, nr={nr}");
        }
    }

    #[test]
    fn fcntl_getfl_setfl_toggle_nonblock_on_virtual_fd() {
        let h = harness();
        let resp = h.backend.sys_socket(&req(41, [libc::AF_INET as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0]));
        let fd = resp.ret as u64;

        // Freshly created blocking socket: F_GETFL must not report O_NONBLOCK.
        let getfl = h.backend.sys_fcntl(&req(72, [fd, libc::F_GETFL as u64, 0, 0, 0, 0]));
        assert_eq!(getfl.ret & libc::O_NONBLOCK as i64, 0);

        // F_SETFL with O_NONBLOCK actually flips the socket's tracked mode.
        let setfl = h.backend.sys_fcntl(&req(
            72,
            [fd, libc::F_SETFL as u64, libc::O_NONBLOCK as u64, 0, 0, 0],
        ));
        assert_eq!(setfl.ret, 0);
        let getfl2 = h.backend.sys_fcntl(&req(72, [fd, libc::F_GETFL as u64, 0, 0, 0, 0]));
        assert_ne!(getfl2.ret & libc::O_NONBLOCK as i64, 0);

        // An untracked fd is EBADF, matching the real kernel — note fd is
        // deliberately not just `1 << 30` (VIRTUAL_FD_BASE), since that's
        // exactly the value `fd` above already holds (the first fd this
        // fresh table hands out).
        let bad = h.backend.sys_fcntl(&req(72, [(1u64 << 30) + 999, libc::F_GETFL as u64, 0, 0, 0, 0]));
        assert_eq!(bad.ret, -(libc::EBADF as i64));
    }

    #[test]
    fn ioctl_fionbio_toggles_nonblock_matching_settimeout_on_modern_python() {
        // Regression test for the real end-to-end finding: CPython's
        // `socket.settimeout()`/`setblocking()` issues `ioctl(fd, FIONBIO,
        // &val)`, not `fcntl(fd, F_SETFL, ...)` — confirmed via `strace` on
        // Python 3.14. Without this, a forwarded socket's `settimeout()`
        // fails with EBADF (the real kernel rejecting our virtual fd).
        let h = harness();
        let resp = h.backend.sys_socket(&req(41, [libc::AF_INET as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0]));
        let fd = resp.ret as u64;

        let set_nonblock = |val: i32| SyscallRequest {
            slot_idx: 0,
            number: 16,
            args: [fd, libc::FIONBIO as u64, 0, 0, 0, 0],
            in_bufs: vec![SyscallBuf { arg_idx: 2, data: val.to_ne_bytes().to_vec() }],
            out_sizes: vec![],
        };

        assert!(!h.backend.table.with(fd as i64, |e| e.nonblock()).unwrap());

        let resp = h.backend.sys_ioctl(&set_nonblock(1));
        assert_eq!(resp.ret, 0);
        assert!(h.backend.table.with(fd as i64, |e| e.nonblock()).unwrap());

        let resp = h.backend.sys_ioctl(&set_nonblock(0));
        assert_eq!(resp.ret, 0);
        assert!(!h.backend.table.with(fd as i64, |e| e.nonblock()).unwrap());

        // An untracked fd is EBADF.
        let bad = h.backend.sys_ioctl(&SyscallRequest {
            slot_idx: 0,
            number: 16,
            args: [(1u64 << 30) + 999, libc::FIONBIO as u64, 0, 0, 0, 0],
            in_bufs: vec![SyscallBuf { arg_idx: 2, data: 1i32.to_ne_bytes().to_vec() }],
            out_sizes: vec![],
        });
        assert_eq!(bad.ret, -(libc::EBADF as i64));
    }

    #[test]
    fn bind_rejects_foreign_address() {
        let h = harness();
        let resp = h.backend.sys_socket(&req(41, [libc::AF_INET as u64, libc::SOCK_DGRAM as u64, 0, 0, 0, 0]));
        let fd = resp.ret as u64;
        let mut bind_req = req(49, [fd, 0, 16, 0, 0, 0]);
        bind_req.in_bufs.push(sockaddr_buf(1, Ipv4Address::new(8, 8, 8, 8), 5353));
        let resp = h.backend.sys_bind(&bind_req);
        assert_eq!(resp.ret, -(libc::EADDRNOTAVAIL as i64));
    }

    #[test]
    fn udp_bind_then_close_untracks_port() {
        let h = harness();
        let sock_resp = h.backend.sys_socket(&req(41, [libc::AF_INET as u64, libc::SOCK_DGRAM as u64, 0, 0, 0, 0]));
        let fd = sock_resp.ret as u64;
        let mut bind_req = req(49, [fd, 0, 16, 0, 0, 0]);
        bind_req.in_bufs.push(sockaddr_buf(1, Ipv4Address::UNSPECIFIED, 9999));
        let resp = h.backend.sys_bind(&bind_req);
        assert_eq!(resp.ret, 0);
        assert!(h.backend.table.contains(fd as i64));

        let resp = h.backend.sys_close(&req(3, [fd, 0, 0, 0, 0, 0]));
        assert_eq!(resp.ret, 0);
        assert!(!h.backend.table.contains(fd as i64));
    }

    #[test]
    fn close_unknown_fd_returns_ebadf() {
        let h = harness();
        let resp = h.backend.sys_close(&req(3, [(1u64 << 30) + 999, 0, 0, 0, 0, 0]));
        assert_eq!(resp.ret, -(libc::EBADF as i64));
    }

    /// Full end-to-end happy path over the loopback device: listen,
    /// connect (self-connect to our own interface address), accept,
    /// write from the client, read on the accepted server socket, then
    /// close both ends. Exercises tasks 5.1-5.6 together.
    #[test]
    fn tcp_listen_connect_accept_read_write_close_roundtrip() {
        let h = harness();
        let backend = &h.backend;

        // Server: socket -> bind -> listen.
        let listen_fd = backend
            .sys_socket(&req(41, [libc::AF_INET as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0]))
            .ret as u64;
        let mut bind_req = req(49, [listen_fd, 0, 16, 0, 0, 0]);
        bind_req.in_bufs.push(sockaddr_buf(1, Ipv4Address::UNSPECIFIED, 7878));
        assert_eq!(backend.sys_bind(&bind_req).ret, 0);
        assert_eq!(backend.sys_listen(&req(50, [listen_fd, 4, 0, 0, 0, 0])).ret, 0);

        // Client: socket -> connect (blocking, self-connect over loopback).
        let client_fd = backend
            .sys_socket(&req(41, [libc::AF_INET as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0]))
            .ret as u64;
        let mut connect_req = req(42, [client_fd, 0, 16, 0, 0, 0]);
        connect_req.in_bufs.push(sockaddr_buf(1, TEST_IP, 7878));
        let connect_resp = backend.sys_connect(&connect_req);
        assert_eq!(connect_resp.ret, 0, "connect should succeed over loopback");

        // Server: accept the pending connection.
        let accept_resp = backend.sys_accept4(&req(288, [listen_fd, 0, 0, 0, 0, 0]));
        assert!(accept_resp.ret >= 0, "accept4 should return a new fd, got {}", accept_resp.ret);
        let accepted_fd = accept_resp.ret as u64;

        // Client writes, server reads.
        let mut write_req = req(1, [client_fd, 0, 5, 0, 0, 0]);
        write_req.in_bufs.push(SyscallBuf { arg_idx: 1, data: b"hello".to_vec() });
        let write_resp = backend.sys_write(&write_req);
        assert_eq!(write_resp.ret, 5);

        let mut read_req = req(0, [accepted_fd, 0, 64, 0, 0, 0]);
        read_req.out_sizes.push((1, 64));
        let read_resp = backend.sys_read(&read_req);
        assert_eq!(read_resp.ret, 5);
        assert_eq!(read_resp.out_bufs[0].data, b"hello");

        // Clean up.
        assert_eq!(backend.sys_close(&req(3, [client_fd, 0, 0, 0, 0, 0])).ret, 0);
        assert_eq!(backend.sys_close(&req(3, [accepted_fd, 0, 0, 0, 0, 0])).ret, 0);
        assert_eq!(backend.sys_close(&req(3, [listen_fd, 0, 0, 0, 0, 0])).ret, 0);
    }

    #[test]
    fn udp_send_recv_roundtrip_over_loopback() {
        let h = harness();
        let backend = &h.backend;

        let server_fd = backend
            .sys_socket(&req(41, [libc::AF_INET as u64, libc::SOCK_DGRAM as u64, 0, 0, 0, 0]))
            .ret as u64;
        let mut bind_req = req(49, [server_fd, 0, 16, 0, 0, 0]);
        bind_req.in_bufs.push(sockaddr_buf(1, Ipv4Address::UNSPECIFIED, 6000));
        assert_eq!(backend.sys_bind(&bind_req).ret, 0);

        let client_fd = backend
            .sys_socket(&req(41, [libc::AF_INET as u64, libc::SOCK_DGRAM as u64, 0, 0, 0, 0]))
            .ret as u64;

        let mut sendto_req = req(44, [client_fd, 0, 3, 0, 0, 16]);
        sendto_req.in_bufs.push(SyscallBuf { arg_idx: 1, data: b"hey".to_vec() });
        sendto_req.in_bufs.push(sockaddr_buf(4, TEST_IP, 6000));
        let send_resp = backend.sys_sendto(&sendto_req);
        assert_eq!(send_resp.ret, 3, "sendto failed: ret={}", send_resp.ret);

        let mut recvfrom_req = req(45, [server_fd, 0, 64, 0, 0, 0]);
        recvfrom_req.out_sizes.push((1, 64));
        recvfrom_req.out_sizes.push((4, SOCKADDR_IN_LEN as u64));
        recvfrom_req.out_sizes.push((5, 4));
        let recv_resp = backend.sys_recvfrom(&recvfrom_req);
        assert_eq!(recv_resp.ret, 3);
        assert_eq!(recv_resp.out_bufs.iter().find(|b| b.arg_idx == 1).unwrap().data, b"hey");

        assert_eq!(backend.sys_close(&req(3, [server_fd, 0, 0, 0, 0, 0])).ret, 0);
        assert_eq!(backend.sys_close(&req(3, [client_fd, 0, 0, 0, 0, 0])).ret, 0);
    }

    #[test]
    fn nonblocking_read_returns_eagain_immediately_with_no_data() {
        let h = harness();
        let backend = &h.backend;
        let fd = backend
            .sys_socket(&req(41, [
                libc::AF_INET as u64,
                (libc::SOCK_DGRAM | libc::SOCK_NONBLOCK) as u64,
                0,
                0,
                0,
                0,
            ]))
            .ret as u64;
        let mut bind_req = req(49, [fd, 0, 16, 0, 0, 0]);
        bind_req.in_bufs.push(sockaddr_buf(1, Ipv4Address::UNSPECIFIED, 6001));
        assert_eq!(backend.sys_bind(&bind_req).ret, 0);

        let start = StdInstant::now();
        let mut read_req = req(45, [fd, 0, 64, 0, 0, 0]);
        read_req.out_sizes.push((1, 64));
        let resp = backend.sys_recvfrom(&read_req);
        assert_eq!(resp.ret, -(libc::EAGAIN as i64));
        assert!(start.elapsed() < Duration::from_secs(1), "nonblocking read must not poll-wait");
    }

    #[test]
    fn setsockopt_tcp_nodelay_and_getsockopt_so_error() {
        let h = harness();
        let backend = &h.backend;
        let fd = backend
            .sys_socket(&req(41, [libc::AF_INET as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0]))
            .ret as u64;

        let mut setopt_req = req(54, [fd, libc::IPPROTO_TCP as u64, libc::TCP_NODELAY as u64, 0, 4, 0]);
        setopt_req.in_bufs.push(SyscallBuf { arg_idx: 3, data: 1i32.to_ne_bytes().to_vec() });
        assert_eq!(backend.sys_setsockopt(&setopt_req).ret, 0);

        let mut getopt_req = req(55, [fd, libc::SOL_SOCKET as u64, libc::SO_ERROR as u64, 0, 0, 0]);
        getopt_req.out_sizes.push((3, 4));
        let resp = backend.sys_getsockopt(&getopt_req);
        assert_eq!(resp.ret, 0);
        let val = i32::from_ne_bytes(resp.out_bufs[0].data[..4].try_into().unwrap());
        assert_eq!(val, 0, "freshly created socket should report no pending error");
    }

    fn pollfd_bytes(fd: i32, events: i16) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8);
        buf.extend_from_slice(&fd.to_ne_bytes());
        buf.extend_from_slice(&events.to_ne_bytes());
        buf.extend_from_slice(&0i16.to_ne_bytes()); // revents, filled by us
        buf
    }

    fn pollfd_revents(data: &[u8], idx: usize) -> i16 {
        let entry = &data[idx * 8..idx * 8 + 8];
        i16::from_ne_bytes([entry[6], entry[7]])
    }

    #[test]
    fn owns_syscall_declines_poll_with_any_untracked_fd() {
        let h = harness();
        let backend = &h.backend;
        let fd = backend
            .sys_socket(&req(41, [libc::AF_INET as u64, libc::SOCK_DGRAM as u64, 0, 0, 0, 0]))
            .ret;

        // All-tracked: claimed.
        let mut all_tracked = req(7, [0, 1, 0, 0, 0, 0]);
        all_tracked.in_bufs.push(SyscallBuf {
            arg_idx: 0,
            data: pollfd_bytes(fd as i32, libc::POLLIN as i16),
        });
        assert!(backend.owns_syscall(&all_tracked));

        // Mixed real + virtual: declined (falls through to passthrough).
        let mut mixed = req(7, [0, 2, 0, 0, 0, 0]);
        mixed.in_bufs.push(SyscallBuf {
            arg_idx: 0,
            data: [pollfd_bytes(fd as i32, libc::POLLIN as i16), pollfd_bytes(0, libc::POLLIN as i16)].concat(),
        });
        assert!(!backend.owns_syscall(&mixed));
    }

    #[test]
    fn poll_reports_pollin_for_readable_udp_socket() {
        let h = harness();
        let backend = &h.backend;

        let server_fd = backend
            .sys_socket(&req(41, [libc::AF_INET as u64, libc::SOCK_DGRAM as u64, 0, 0, 0, 0]))
            .ret as u64;
        let mut bind_req = req(49, [server_fd, 0, 16, 0, 0, 0]);
        bind_req.in_bufs.push(sockaddr_buf(1, Ipv4Address::UNSPECIFIED, 6100));
        assert_eq!(backend.sys_bind(&bind_req).ret, 0);

        let client_fd = backend
            .sys_socket(&req(41, [libc::AF_INET as u64, libc::SOCK_DGRAM as u64, 0, 0, 0, 0]))
            .ret as u64;
        let mut sendto_req = req(44, [client_fd, 0, 2, 0, 0, 16]);
        sendto_req.in_bufs.push(SyscallBuf { arg_idx: 1, data: b"hi".to_vec() });
        sendto_req.in_bufs.push(sockaddr_buf(4, TEST_IP, 6100));
        assert_eq!(backend.sys_sendto(&sendto_req).ret, 2);

        // Give the poll loop a moment to actually deliver the datagram.
        let deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            let mut poll_req = req(7, [0, 1, 0, 0, 0, 0]);
            poll_req.in_bufs.push(SyscallBuf {
                arg_idx: 0,
                data: pollfd_bytes(server_fd as i32, libc::POLLIN as i16),
            });
            assert!(backend.owns_syscall(&poll_req));
            let resp = backend.sys_poll(&poll_req);
            if resp.ret == 1 {
                assert_eq!(pollfd_revents(&resp.out_bufs[0].data, 0) & libc::POLLIN as i16, libc::POLLIN as i16);
                break;
            }
            assert!(StdInstant::now() < deadline, "datagram never became readable via poll()");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
