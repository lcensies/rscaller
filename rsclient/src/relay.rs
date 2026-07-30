//! Generic relay loop — controller-agnostic.
//!
//! [`Relay`] receives [`Notification`]s from any [`SyscallController`] backend,
//! optionally applies a network destination filter ([`NetFilter`]), forwards
//! matching notifications to rsbeacon as [`SyscallRequest`]s, and signals
//! completion back to the controller.
//!
//! Non-matching network syscalls (connect/sendto to addresses outside the
//! filter) are continued locally via [`SyscallController::continue_syscall`].
//!
//! # Real-fd socket proxying (`socket`/`accept4`)
//!
//! When [`Relay::with_socket_proxy`] is configured (seccomp backend only —
//! see `socket_proxy.rs`'s module doc for the full rationale), a
//! `socket()`/`accept4()` response carrying a fresh virtual fd from
//! rsbeacon is NOT completed with that bare virtual fd number directly.
//! Instead:
//! - [`socket_proxy::spawn_proxy`] creates a `socketpair()` and a
//!   background task bridging one end to rsbeacon (over its own
//!   connections, using the same request/response API unchanged);
//! - the other end is injected into the tracee via
//!   [`SyscallController::complete_with_fd`] (`SECCOMP_IOCTL_NOTIF_ADDFD`);
//! - the resulting real fd (as installed in the tracee) is recorded in
//!   `proxy_fds`, mapping it back to the virtual fd rsbeacon actually
//!   understands.
//!
//! `dispatch` consults `proxy_fds` for every later syscall whose `args[0]`
//! is an fd: `connect`/`bind`/`listen`/`setsockopt`/`getsockopt` get that
//! arg translated back to the virtual fd before relaying (control-plane
//! ops rsbeacon must actually service); `sendto`/`recvfrom`/`sendmsg`/
//! `recvmsg` are continued locally instead (a `socketpair()` end is a
//! real, connected socket — send/recv-family calls work correctly against
//! it without any relay at all). `read`/`write`/`close`/`poll`/`ppoll`/
//! `fcntl`/`ioctl` never reach `dispatch` in the first place for these fds
//! — they're real, small, local fd numbers, below `VIRTUAL_FD_BASE`, so the
//! seccomp BPF filter's existing fd-range gating (`shadow.yaml`'s
//! `fd_range: virtual` rule) already excludes them automatically, with no
//! changes needed there at all.
//!
//! If a controller doesn't support `complete_with_fd` (kmod — see that
//! trait method's doc) or `with_socket_proxy` was never configured,
//! `socket`/`accept4` fall back to the historical behavior: complete with
//! the bare virtual fd, unchanged.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Result};
use ctls::{Notification, SyscallController};
use rscaller_proto::codec::{read_message, write_message};
use rscaller_proto::types::{SyscallBuf, SyscallRequest, SyscallResponse};
use crate::beacon_conn::BeaconConnConfig;
use crate::kmod::KmodSyscall;
use crate::socket_proxy::{self, PendingProxy, ProxyConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, warn};

const EINVAL: i64 = 22;

// ---------------------------------------------------------------------------
// Network filter
// ---------------------------------------------------------------------------

/// IPv4 subnet + optional port list filter.
///
/// Built from `--filter-net` / `--filter-ports` CLI args.
/// `passes()` returns `true` if the syscall should be forwarded to rsbeacon.
#[derive(Clone, Debug)]
pub struct NetFilter {
    /// Ordered routing policy: each rule is (subnet_addr_be, subnet_mask_be, port_opt, direction).
    /// First match wins. If no match, fall back to `default_direction`.
    pub routes: Vec<(u32, u32, Option<u16>, NetRouteDirection)>,
    /// Default direction when no routes match. Always LOCAL unless explicitly configured.
    pub default_direction: NetRouteDirection,
}

impl Default for NetFilter {
    fn default() -> Self {
        Self {
            routes: vec![],
            default_direction: NetRouteDirection::Local,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NetRouteDirection {
    Local,
    Remote,
}

impl NetFilter {
    /// Create from routing policy (from YAML ForwardFilter::net_routes).
    /// Routes are represented as tuples internally for performance.
    pub fn from_yaml_routes(routes_yaml: Vec<(String, Option<u16>, String)>) -> Result<Self> {
        let mut routes = Vec::new();
        for (subnet, port, direction_str) in routes_yaml {
            let (addr_be, mask_be) = parse_cidr(&subnet)?;
            let direction = match direction_str.to_uppercase().as_str() {
                "LOCAL" => NetRouteDirection::Local,
                "REMOTE" => NetRouteDirection::Remote,
                _ => bail!("invalid direction '{}', expected 'LOCAL' or 'REMOTE'", direction_str),
            };
            routes.push((addr_be, mask_be, port, direction));
        }
        Ok(Self {
            routes,
            default_direction: NetRouteDirection::Local,
        })
    }

    /// Parse from CLI strings (legacy, simple allow-list).
    ///
    /// Format: `--route "subnet[:port]=direction"` e.g. `"192.168.1.0/24=remote"`.
    pub fn from_cli(route_strs: Vec<String>) -> Result<Self> {
        let mut routes = Vec::new();
        for route_str in route_strs {
            let (subnet_port, direction_str) = route_str
                .rsplit_once('=')
                .ok_or_else(|| anyhow::anyhow!("route missing '=': '{}'", route_str))?;

            let direction = match direction_str.to_lowercase().as_str() {
                "local" => NetRouteDirection::Local,
                "remote" => NetRouteDirection::Remote,
                _ => bail!("invalid direction '{}' in route '{}', expected 'local' or 'remote'", direction_str, route_str),
            };

            let (subnet, port) = if let Some((s, p)) = subnet_port.rsplit_once(':') {
                let port = p.parse::<u16>()
                    .map_err(|e| anyhow::anyhow!("bad port '{}' in route '{}': {}", p, route_str, e))?;
                (s, Some(port))
            } else {
                (subnet_port, None)
            };

            let (addr_be, mask_be) = parse_cidr(subnet)?;
            routes.push((addr_be, mask_be, port, direction));
        }
        Ok(Self {
            routes,
            default_direction: NetRouteDirection::Local,
        })
    }

    /// Route a syscall: returns the direction (LOCAL or REMOTE).
    ///
    /// For connect (42) and sendto (44) with a valid sockaddr: matches against routing rules.
    /// For all other syscalls: returns LOCAL (no routing needed, not network operations).
    ///
    /// `sa_bytes`: the raw sockaddr bytes already read from tracee memory
    /// (i.e. `in_data` for connect arg 1, sendto arg 4).
    pub fn route(&self, nr: u64, sa_bytes: Option<&[u8]>) -> NetRouteDirection {
        // Only route connect and sendto.
        if nr != 42 && nr != 44 {
            return NetRouteDirection::Local;
        }

        // If no sockaddr data, default to LOCAL.
        let Some(sa) = sa_bytes else {
            return NetRouteDirection::Local;
        };

        // Parse sockaddr_in: u16 family + u16 port_be + u32 addr_be
        if sa.len() < 8 {
            return NetRouteDirection::Local;
        }
        let family = u16::from_ne_bytes([sa[0], sa[1]]);
        if family != libc::AF_INET as u16 {
            return NetRouteDirection::Local; // non-IPv4 → local
        }
        let port_be = u16::from_be_bytes([sa[2], sa[3]]);
        let addr_be = u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]);

        // Check routes in order; first match wins.
        for (route_addr, route_mask, route_port, direction) in &self.routes {
            // Subnet match
            if (addr_be & route_mask) != (route_addr & route_mask) {
                continue;
            }
            // Port match (if specified in the route)
            if let Some(rp) = route_port {
                if port_be != *rp {
                    continue;
                }
            }
            return *direction;
        }

        // No match → use default direction (LOCAL by default, configurable)
        self.default_direction
    }
}

fn parse_cidr(s: &str) -> Result<(u32, u32)> {
    let (addr_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("FILTER_NET missing '/': '{}'", s))?;
    let addr: Ipv4Addr = addr_str
        .parse()
        .map_err(|e| anyhow::anyhow!("bad FILTER_NET addr '{}': {}", addr_str, e))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|e| anyhow::anyhow!("bad FILTER_NET prefix '{}': {}", prefix_str, e))?;
    if prefix > 32 {
        anyhow::bail!("FILTER_NET prefix > 32: {}", prefix);
    }
    let addr_be = u32::from_be_bytes(addr.octets());
    let mask_be: u32 = if prefix == 0 { 0 } else { !((1u32 << (32 - prefix)) - 1) };
    Ok((addr_be, mask_be))
}

// ---------------------------------------------------------------------------
// CgroupFilter — local-cgroup exclusion for signal syscalls
// ---------------------------------------------------------------------------

/// Excludes signal syscalls from forwarding when the target PID is a member
/// of the per-session local cgroup (i.e. a locally-spawned child process).
///
/// This keeps `kill %job` / `kill <local_pid>` working correctly inside an
/// interactive shell while still forwarding signals to beacon processes.
#[derive(Clone, Debug, Default)]
pub struct CgroupFilter {
    /// Absolute path to the per-session cgroup, e.g.
    /// `/sys/fs/cgroup/rscaller/session-<hex>`.
    pub cgroup_path: String,
    /// Syscall numbers gated by this filter (kill=62, tkill=200, tgkill=234).
    pub gated_nrs: Vec<u32>,
}

impl CgroupFilter {
    pub fn new(cgroup_path: String, gated_nrs: Vec<u32>) -> Self {
        Self { cgroup_path, gated_nrs }
    }

    /// Returns true if the syscall should be continued locally (target is in
    /// the local cgroup), false if it should be forwarded to beacon.
    pub fn is_local(&self, nr: u64, args: &[u64; 6]) -> bool {
        if !self.gated_nrs.contains(&(nr as u32)) {
            return false;
        }
        let target_pid = match nr {
            62 | 200 => args[0] as i64,  // kill(pid,sig) / tkill(tid,sig)
            234 => args[1] as i64,        // tgkill(tgid,tid,sig) — tid is arg 1
            _ => return false,
        };
        if target_pid <= 0 {
            return false;
        }
        pid_in_cgroup(target_pid as u32, &self.cgroup_path)
    }
}

/// Check whether `pid` is a member of the cgroup rooted at `cgroup_path`.
///
/// Reads `/proc/<pid>/cgroup` (cgroup v2 format: `0::/relative/path`)
/// and checks if the relative path starts with the session cgroup's
/// relative path (everything after `/sys/fs/cgroup`).
fn pid_in_cgroup(pid: u32, cgroup_path: &str) -> bool {
    // Strip the cgroup v2 mount prefix to get the relative path.
    // e.g. /sys/fs/cgroup/rscaller/session-abc → /rscaller/session-abc
    let rel = cgroup_path
        .strip_prefix("/sys/fs/cgroup")
        .unwrap_or(cgroup_path);

    let proc_cgroup_path = format!("/proc/{pid}/cgroup");
    let Ok(content) = std::fs::read_to_string(&proc_cgroup_path) else {
        return false; // PID doesn't exist locally → not in local cgroup
    };

    // cgroup v2 line format: "0::<path>"
    content.lines().any(|line| {
        if let Some(path) = line.strip_prefix("0::") {
            // Check exact match or sub-cgroup membership.
            path == rel || path.starts_with(&format!("{rel}/"))
        } else {
            false
        }
    })
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

pub struct Relay<C, R, W>
where
    C: SyscallController,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub controller: C,
    pub beacon_reader: R,
    pub beacon_writer: W,
    pub filter: NetFilter,
    pub cgroup_filter: Option<CgroupFilter>,
    /// Set via `with_socket_proxy` — enables the real-fd proxy path for
    /// `socket`/`accept4` (see module doc). `None` = historical behavior
    /// (complete with the bare virtual fd).
    proxy_cfg: Option<ProxyConfig>,
    /// Real fd (as installed in the tracee) → virtual fd (as rsbeacon
    /// knows it), for every socket currently proxied via `proxy_cfg`.
    proxy_fds: HashMap<i32, i64>,
    /// Real fd → not-yet-started background proxy, for a socket that's
    /// been created (and had its real fd injected) but hasn't yet had its
    /// `connect`/`listen` complete — see `socket_proxy::spawn_proxy`'s doc
    /// for why starting the proxy is deferred that long.
    pending_proxies: HashMap<i32, PendingProxy>,
}

impl<C, R, W> Relay<C, R, W>
where
    C: SyscallController,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub fn new(controller: C, beacon_reader: R, beacon_writer: W) -> Self {
        Self {
            controller,
            beacon_reader,
            beacon_writer,
            filter: NetFilter::default(),
            cgroup_filter: None,
            proxy_cfg: None,
            proxy_fds: HashMap::new(),
            pending_proxies: HashMap::new(),
        }
    }

    pub fn with_filter(mut self, filter: NetFilter) -> Self {
        self.filter = filter;
        self
    }

    pub fn with_cgroup_filter(mut self, filter: Option<CgroupFilter>) -> Self {
        self.cgroup_filter = filter;
        self
    }

    /// Enables the real-fd proxy path for `socket`/`accept4` responses
    /// (see module doc). `beacon_addr`/`use_tls`/`ca_pem` are used by
    /// `socket_proxy`'s background tasks to open their own additional
    /// connections to rsbeacon, independent of `beacon_reader`/
    /// `beacon_writer` (this relay's own control-plane connection).
    pub fn with_socket_proxy(mut self, beacon_addr: SocketAddr, use_tls: bool, ca_pem: Option<Vec<u8>>) -> Self {
        self.proxy_cfg = Some(ProxyConfig { beacon_addr, conn: BeaconConnConfig { use_tls, ca_pem } });
        self
    }

    pub async fn run(&mut self) -> Result<()> {
        let result = self.run_inner().await;
        self.shutdown_proxies().await;
        result
    }

    async fn run_inner(&mut self) -> Result<()> {
        loop {
            let notif = match self.controller.recv().await? {
                Some(n) => n,
                None => return Ok(()),
            };

            if let Err(e) = self.dispatch(notif).await {
                warn!(error = %e, "dispatch error");
            }
        }
    }

    /// Releases every virtual fd the real-fd socket proxy (see module
    /// doc) still has open once the relay loop ends for any reason — most
    /// importantly, the tracee exiting (killed, crashed, or simply
    /// finished) before its own background proxy task(s) noticed (via EOF
    /// on their end of the socketpair) and cleaned up on their own.
    ///
    /// Without this, an abruptly-terminated tracee leaks its proxied
    /// sockets on rsbeacon forever: `tokio::spawn`ed tasks are simply
    /// dropped (not gracefully awaited) when the runtime shuts down at
    /// process exit, so a background proxy mid-retry never gets to send
    /// its own `close`. Found the hard way in testing — rapid repeated
    /// test runs left prior connections fully ESTABLISHED (on the peer,
    /// from rsbeacon's side) at ephemeral source ports smoltcp's allocator
    /// deterministically reissues from the same starting value on every
    /// `rsbeacon` restart, silently blocking every later connection
    /// attempt from ever completing its handshake.
    async fn shutdown_proxies(&mut self) {
        let virtual_fds: Vec<i64> = self.proxy_fds.values().copied().collect();
        for virtual_fd in virtual_fds {
            let req = SyscallRequest {
                slot_idx: 0,
                number: 3, // close
                args: [virtual_fd as u64, 0, 0, 0, 0, 0],
                in_bufs: vec![],
                out_sizes: vec![],
            };
            if let Err(e) = write_message(&mut self.beacon_writer, &req).await {
                warn!(virtual_fd, error = %e, "socket-proxy: shutdown close request failed");
                continue;
            }
            // A background proxy task may have already raced this same
            // close through independently — either order is fine, the
            // second one just gets a harmless EBADF.
            let _ = read_message::<SyscallResponse, _>(&mut self.beacon_reader).await;
        }
        self.proxy_fds.clear();
        // Drops each `PendingProxy`'s socketpair end — nothing else to do
        // for these specifically, their virtual fd is already covered by
        // `proxy_fds` above (inserted there before ever becoming pending).
        self.pending_proxies.clear();
    }

    async fn dispatch(&mut self, mut notif: Notification) -> Result<()> {
        let id = notif.id;
        let nr = notif.nr;
        // Captured before any fd-translation below overwrites `args[0]` —
        // used after the beacon response comes back, to know which real
        // fd's pending proxy (if any) to start (see
        // `socket_proxy::spawn_proxy`'s doc).
        let orig_real_fd = notif.args[0] as i32;

        // ── Beacon PID offset stripping for signal syscalls ───────────────
        // When merged-proc mode is active, the ghost shell uses virtual PIDs
        // (real_beacon_pid + BEACON_PID_OFFSET) to address beacon processes.
        // Strip the offset before forwarding so the beacon sees the real PID.
        const BEACON_PID_OFFSET: i64 = 10_000_000;
        if matches!(nr, 62 | 200 | 234) {
            let target = match nr {
                62 | 200 => notif.args[0] as i64,  // kill(pid,sig) / tkill(tid,sig)
                234      => notif.args[1] as i64,   // tgkill(tgid,tid,sig)
                _        => 0,
            };
            if target > BEACON_PID_OFFSET {
                let stripped = (target - BEACON_PID_OFFSET) as u64;
                debug!(id, nr, orig_pid = target, real_pid = stripped, "stripped beacon PID offset");
                match nr {
                    62 | 200 => notif.args[0] = stripped,
                    234      => notif.args[1] = stripped,
                    _        => {}
                }
            }
        }

        // ── Network routing ───────────────────────────────────────────────
        // For connect(42): sockaddr is arg 1.
        // For sendto(44):  sockaddr is arg 4 (may be null for connected sockets).
        let sa_bytes: Option<&[u8]> = match nr {
            42 => notif.in_data.iter().find(|b| b.arg_idx == 1).map(|b| b.data.as_slice()),
            44 => notif.in_data.iter().find(|b| b.arg_idx == 4).map(|b| b.data.as_slice()),
            _ => None,
        };

        match self.filter.route(nr, sa_bytes) {
            NetRouteDirection::Local => {
                debug!(id, nr, "net routing: LOCAL");
                self.controller.continue_syscall(id).await?;
                return Ok(());
            }
            NetRouteDirection::Remote => {
                // Fall through to beacon forwarding below
            }
        }

        // ── Cgroup filter — local-process signal exclusion ────────────────
        if let Some(ref cf) = self.cgroup_filter {
            if cf.is_local(nr, &notif.args) {
                debug!(id, nr, pid = notif.args[0], "cgroup filter: signal target is local, continuing");
                self.controller.continue_syscall(id).await?;
                return Ok(());
            }
        }

        // ── Real-fd socket proxy — translate or continue locally ──────────
        // See module doc.
        //
        // `poll`/`ppoll` are special: `args[0]` is a POINTER to the
        // `struct pollfd[]` array, not an fd — the client-side seccomp BPF
        // filter can't dereference it (classic BPF has no such op), so it
        // always intercepts poll/ppoll regardless of which real fds are
        // inside the array (a pointer value is virtually always >=
        // VIRTUAL_FD_BASE, which is what the filter's fd-range check
        // actually sees). Once every fd a proxied socket ever hands to the
        // tracee is real (this whole mechanism's point), the array will
        // never contain anything rsbeacon needs to see — so if EVERY fd in
        // it is a known real-proxy fd, continue locally; the real kernel
        // already reports the correct readiness (our background proxy
        // task is what's actually keeping the socketpair's buffers
        // truthful). A mixed or all-unknown array falls through to the
        // existing behavior unchanged (rsbeacon's own `parse_owned_pollfds`
        // requires every fd to be virtual-and-tracked to claim it either).
        if matches!(nr, 7 | 271) {
            if let Some(raw) = notif.in_data.iter().find(|b| b.arg_idx == 0).map(|b| &b.data) {
                if !raw.is_empty() && raw.len() % 8 == 0 {
                    let all_proxied = raw
                        .chunks_exact(8)
                        .all(|c| self.proxy_fds.contains_key(&i32::from_ne_bytes([c[0], c[1], c[2], c[3]])));
                    if all_proxied {
                        debug!(id, nr, "socket-proxy: continuing poll/ppoll locally (all fds real)");
                        self.controller.continue_syscall(id).await?;
                        return Ok(());
                    }
                }
            }
        } else if let Some(&virtual_fd) = self.proxy_fds.get(&(notif.args[0] as i32)) {
            match nr {
                // send/recv-family: a socketpair() end is a real, connected
                // socket — the local kernel handles these correctly on its
                // own, delivering to/from the background proxy's own end.
                44 | 45 | 46 | 47 => {
                    debug!(id, nr, virtual_fd, "socket-proxy: continuing send/recv locally");
                    self.controller.continue_syscall(id).await?;
                    return Ok(());
                }
                // Control-plane ops: rsbeacon must actually service these
                // against the virtual fd — translate before relaying.
                42 | 49 | 50 | 54 | 55 | 288 => {
                    debug!(id, nr, real_fd = notif.args[0], virtual_fd, "socket-proxy: translating fd");
                    notif.args[0] = virtual_fd as u64;
                }
                _ => {}
            }
        }

        // ── Forward to beacon ─────────────────────────────────────────────
        debug!(id, nr, pid = notif.pid, "dispatching to beacon");

        let req = notification_to_request(&notif);

        if let Err(e) = write_message(&mut self.beacon_writer, &req).await {
            warn!(error = %e, "send to beacon failed");
            self.controller.complete(id, -EINVAL, &[], &notif.args).await?;
            return Err(e);
        }

        let resp = match tokio::time::timeout(
            Duration::from_secs(30),
            read_message::<SyscallResponse, _>(&mut self.beacon_reader),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                warn!(error = %e, id, "beacon response error");
                self.controller.complete(id, -EINVAL, &[], &notif.args).await?;
                return Err(e);
            }
            Err(_) => {
                warn!(id, "beacon response timeout");
                self.controller.complete(id, -EINVAL, &[], &notif.args).await?;
                return Err(anyhow::anyhow!("beacon response timeout"));
            }
        };

        debug!(id = resp.slot_idx, ret = resp.ret, "beacon response");

        // ── socket()/accept4() success: real-fd proxy instead of a bare
        //    virtual fd, when configured (see module doc). ────────────────
        if matches!(nr, 41 | 288) && resp.ret >= 0 {
            if let Some(ref proxy_cfg) = self.proxy_cfg {
                // accept4()'s fd is already an established connection —
                // start monitoring it right away. socket()'s fd isn't
                // connected/listening yet — deferred (see
                // `try_proxy_new_fd`/`spawn_proxy`).
                let start_immediately = nr == 288;
                match self.try_proxy_new_fd(id, resp.ret, proxy_cfg.clone(), start_immediately).await {
                    Ok(true) => return Ok(()), // already completed via complete_with_fd
                    Ok(false) => {} // spawn/addfd failed — fall through to plain complete()
                    Err(e) => return Err(e),
                }
            }
        }

        // `connect`/`listen` reaching a stable state (success or failure)
        // on a fd with a deferred proxy: start it now — see
        // `socket_proxy::spawn_proxy`'s doc for why it couldn't start any
        // earlier.
        if matches!(nr, 42 | 50) {
            self.start_pending_proxy(orig_real_fd);
        }

        let out_bufs: Vec<(u8, Vec<u8>)> = resp
            .out_bufs
            .into_iter()
            .map(|b| (b.arg_idx, b.data))
            .collect();
        self.controller
            .complete(resp.slot_idx, resp.ret, &out_bufs, &notif.args)
            .await?;
        Ok(())
    }

    /// Attempts the real-fd proxy path for a fresh virtual fd (`virtual_fd`,
    /// from a successful `socket()`/`accept4()` response): spawns the
    /// background proxy, injects the real end into the tracee via
    /// `complete_with_fd`, and records the mapping.
    ///
    /// Returns `Ok(true)` if the notification was completed this way —
    /// caller must not call `complete` again. Returns `Ok(false)` if
    /// `complete_with_fd` isn't supported by this controller or the proxy
    /// couldn't be set up (already logged) — caller should fall back to a
    /// plain `complete(id, virtual_fd, ...)`.
    async fn try_proxy_new_fd(
        &mut self,
        id: u64,
        virtual_fd: i64,
        proxy_cfg: ProxyConfig,
        start_immediately: bool,
    ) -> Result<bool> {
        let (local_fd, pending) = match socket_proxy::spawn_proxy(virtual_fd, proxy_cfg) {
            Ok(v) => v,
            Err(e) => {
                warn!(virtual_fd, error = %e, "socket-proxy: spawn_proxy failed, falling back to virtual fd");
                return Ok(false);
            }
        };

        match self.controller.complete_with_fd(id, local_fd).await {
            Ok(installed_fd) => {
                // The kernel duplicated local_fd into the tracee — this
                // process's own copy is no longer needed.
                socket_proxy::close_local(local_fd);
                self.proxy_fds.insert(installed_fd, virtual_fd);
                if start_immediately {
                    // `accept4()` result: already an established
                    // connection, no `connect`/`listen` to wait for.
                    socket_proxy::start_proxy(pending);
                } else {
                    // `socket()` result: not started yet — see
                    // `spawn_proxy`'s doc. `dispatch` starts it once
                    // `connect`/`listen` for this fd completes.
                    self.pending_proxies.insert(installed_fd, pending);
                }
                debug!(virtual_fd, installed_fd, start_immediately, "socket-proxy: fd injected into tracee");
                Ok(true)
            }
            Err(e) => {
                // Controller doesn't support complete_with_fd (e.g. kmod)
                // or the ioctl itself failed — close our end; `pending`
                // (and the socketpair end it owns) is dropped here,
                // nothing left to clean up.
                warn!(virtual_fd, error = %e, "socket-proxy: complete_with_fd failed, falling back to virtual fd");
                socket_proxy::close_local(local_fd);
                Ok(false)
            }
        }
    }

    /// Starts the background proxy for `real_fd` if one is pending — see
    /// `socket_proxy::spawn_proxy`'s doc for why starting is deferred
    /// until now. No-op if `real_fd` has no pending proxy (not a proxied
    /// fd at all, or already started).
    fn start_pending_proxy(&mut self, real_fd: i32) {
        if let Some(pending) = self.pending_proxies.remove(&real_fd) {
            socket_proxy::start_proxy(pending);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn notification_to_request(n: &Notification) -> SyscallRequest {
    let in_bufs: Vec<SyscallBuf> = n
        .in_data
        .iter()
        .map(|b| SyscallBuf { arg_idx: b.arg_idx, data: b.data.clone() })
        .collect();

    SyscallRequest {
        slot_idx: n.id,
        number: n.nr,
        args: n.args,
        in_bufs,
        out_sizes: n.out_sizes.clone(),
    }
}
pub fn kmod_syscall_to_request(slot_idx: u64, sc: &KmodSyscall) -> SyscallRequest {
    let mut args = [0u64; 6];
    for (i, p) in sc.param_bufs.iter().enumerate() {
        args[i] = unsafe { p.ulong_type };
    }
    SyscallRequest {
         slot_idx,
        number: sc.number as u64,
        args,
        in_bufs: vec![],
        out_sizes: vec![],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netfilter_empty_routes_defaults_to_local() {
        let filter = NetFilter::from_cli(vec![]).unwrap();
        
        // connect() with any address should default to LOCAL
        let sa = sockaddr_in_bytes(std::net::Ipv4Addr::new(192, 168, 1, 100), 443);
        assert_eq!(filter.route(42, Some(&sa)), NetRouteDirection::Local);
        
        // sendto() with any address should default to LOCAL
        assert_eq!(filter.route(44, Some(&sa)), NetRouteDirection::Local);
    }

    #[test]
    fn test_netfilter_single_remote_route() {
        let filter = NetFilter::from_cli(vec![
            "192.168.1.0/24=remote".to_string(),
        ]).unwrap();
        
        // 192.168.1.100 matches /24 → REMOTE
        let sa = sockaddr_in_bytes(std::net::Ipv4Addr::new(192, 168, 1, 100), 443);
        assert_eq!(filter.route(42, Some(&sa)), NetRouteDirection::Remote);
        
        // 192.168.2.100 doesn't match /24 → LOCAL (default)
        let sa = sockaddr_in_bytes(std::net::Ipv4Addr::new(192, 168, 2, 100), 443);
        assert_eq!(filter.route(42, Some(&sa)), NetRouteDirection::Local);
    }

    #[test]
    fn test_netfilter_port_specific_route() {
        // Test: different rules for same subnet, different ports
        let target_ip = std::net::Ipv4Addr::new(192, 0, 2, 1);
        
        let filter = NetFilter::from_cli(vec![
            format!("{}/32:443=local", target_ip),
            format!("{}/32:22=remote", target_ip),
        ]).unwrap();
        
        assert_eq!(filter.routes.len(), 2);
        
        // Test port 443 (first rule) → LOCAL
        let sa = sockaddr_in_bytes(target_ip, 443);
        assert_eq!(filter.route(42, Some(&sa)), NetRouteDirection::Local);
        
        // Test port 22 (second rule) → REMOTE
        let sa = sockaddr_in_bytes(target_ip, 22);
        assert_eq!(filter.route(42, Some(&sa)), NetRouteDirection::Remote);
        
        // Test port 8080 (no matching port rule) → LOCAL (default)
        let sa = sockaddr_in_bytes(target_ip, 8080);
        assert_eq!(filter.route(42, Some(&sa)), NetRouteDirection::Local);
    }

    #[test]
    fn test_netfilter_first_match_wins() {
        // Overlapping subnets: /24 before /32
        let filter = NetFilter::from_cli(vec![
            "192.168.1.0/24=remote".to_string(),
            "192.168.1.100/32=local".to_string(),  // Never reached
        ]).unwrap();
        
        // 192.168.1.100 matches /24 first → REMOTE (not /32)
        let sa = sockaddr_in_bytes(std::net::Ipv4Addr::new(192, 168, 1, 100), 443);
        assert_eq!(filter.route(42, Some(&sa)), NetRouteDirection::Remote);
    }

    #[test]
    fn test_netfilter_default_route() {
        let filter = NetFilter::from_cli(vec![
            "192.168.1.0/24=remote".to_string(),
            "0.0.0.0/0=local".to_string(),  // Catch-all
        ]).unwrap();
        
        // In range → REMOTE
        let sa = sockaddr_in_bytes(std::net::Ipv4Addr::new(192, 168, 1, 1), 80);
        assert_eq!(filter.route(42, Some(&sa)), NetRouteDirection::Remote);
        
        // Out of range → caught by 0.0.0.0/0 → LOCAL
        let sa = sockaddr_in_bytes(std::net::Ipv4Addr::new(10, 0, 0, 1), 80);
        assert_eq!(filter.route(42, Some(&sa)), NetRouteDirection::Local);
    }

    #[test]
    fn test_netfilter_non_connect_syscalls_always_local() {
        let filter = NetFilter::from_cli(vec![
            "0.0.0.0/0=remote".to_string(),  // Even everything
        ]).unwrap();
        
        let sa = sockaddr_in_bytes(std::net::Ipv4Addr::new(192, 168, 1, 1), 80);
        
        // read(0) → always LOCAL (not connect or sendto)
        assert_eq!(filter.route(0, Some(&sa)), NetRouteDirection::Local);
        
        // write(1) → always LOCAL
        assert_eq!(filter.route(1, Some(&sa)), NetRouteDirection::Local);
        
        // Only 42 (connect) and 44 (sendto) are routed
        assert_eq!(filter.route(42, Some(&sa)), NetRouteDirection::Remote);
        assert_eq!(filter.route(44, Some(&sa)), NetRouteDirection::Remote);
    }

    #[test]
    fn test_netfilter_no_sockaddr_defaults_to_local() {
        let filter = NetFilter::from_cli(vec![
            "0.0.0.0/0=remote".to_string(),
        ]).unwrap();
        
        // connect() with no sockaddr → LOCAL
        assert_eq!(filter.route(42, None), NetRouteDirection::Local);
    }

    #[test]
    fn test_netfilter_parse_error_missing_equals() {
        let result = NetFilter::from_cli(vec![
            "192.168.1.0/24remote".to_string(),  // missing '='
        ]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing '='"));
    }

    #[test]
    fn test_netfilter_parse_error_invalid_direction() {
        let result = NetFilter::from_cli(vec![
            "192.168.1.0/24=forward".to_string(),  // invalid direction
        ]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid direction"));
    }

    /// Helper: construct a sockaddr_in buffer for testing.
    fn sockaddr_in_bytes(addr: std::net::Ipv4Addr, port: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 16];
        buf[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        buf[2..4].copy_from_slice(&port.to_be_bytes());
        // addr.octets() is [a, b, c, d]; write directly as network byte order
        buf[4..8].copy_from_slice(&addr.octets());
        buf
    }
}

