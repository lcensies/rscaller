//! Pluggable network-syscall execution backend for rsbeacon.
//!
//! rsbeacon executes every syscall it receives from rsclient via a generic
//! `libc::syscall()` passthrough (see `crate::executor`). This module adds a
//! seam in front of that passthrough for the small set of socket-related
//! syscall numbers, so an alternate [`NetBackend`] implementation can
//! service them through a different network stack entirely (see the
//! `smoltcp_xdp` submodule) instead of the beacon host's kernel.
//!
//! All other syscall numbers are completely unaffected by backend
//! selection — they always go through the existing generic path in
//! `executor.rs`.

use rscaller_proto::types::{SyscallRequest, SyscallResponse};

pub mod direct;
pub mod smoltcp_xdp;
pub mod socket_table;

pub use socket_table::SocketTable;

/// Syscall numbers that are always socket-specific: a [`NetBackend`] may
/// claim these outright (subject to its own logic in [`NetBackend::owns_syscall`]).
///
/// Numbers are x86-64 Linux syscall numbers, matching the ABI kmod/rsclient
/// already use to build [`SyscallRequest`].
pub const SOCKET_SYSCALL_NRS: &[u64] = &[
    41,  // socket
    42,  // connect
    43,  // accept
    49,  // bind
    50,  // listen
    44,  // sendto
    45,  // recvfrom
    46,  // sendmsg
    47,  // recvmsg
    54,  // setsockopt
    55,  // getsockopt
    288, // accept4
];

/// Syscall numbers that operate on *any* file descriptor, not just sockets.
/// A [`NetBackend`] must only claim these when the fd in `args[0]` is one it
/// already owns (tracked in its own socket table) — otherwise it must defer
/// to the existing generic passthrough so non-socket fds are unaffected.
pub const FD_GENERIC_SYSCALL_NRS: &[u64] = &[
    0,   // read
    1,   // write
    3,   // close
    7,   // poll
    271, // ppoll
    72,  // fcntl
    16,  // ioctl
];

/// Returns true if `nr` is one of the syscall numbers that *could* be
/// serviced by a network backend (either always-socket or fd-generic).
/// This is just the union of the two lists above — actual ownership for
/// fd-generic numbers still depends on [`NetBackend::owns_syscall`].
pub fn is_backend_candidate(nr: u64) -> bool {
    SOCKET_SYSCALL_NRS.contains(&nr) || FD_GENERIC_SYSCALL_NRS.contains(&nr)
}

/// A pluggable execution strategy for socket-related syscalls received by
/// rsbeacon.
///
/// Implementations must be safe to share across all connection-handling
/// tasks (rsbeacon spawns one Tokio task per client connection, all of
/// which call into the same backend instance).
pub trait NetBackend: Send + Sync {
    /// Human-readable backend name, used in logs and CLI error messages.
    fn name(&self) -> &'static str;

    /// Returns true if this backend wants to handle `req` itself, i.e. the
    /// caller (`executor::execute_syscall`) must call [`NetBackend::handle`]
    /// instead of falling through to the generic `libc::syscall` passthrough.
    ///
    /// Implementations MUST return `false` for any syscall number not in
    /// [`SOCKET_SYSCALL_NRS`] or [`FD_GENERIC_SYSCALL_NRS`], and for
    /// fd-generic numbers MUST return `false` unless `req.args[0]` is a
    /// virtual fd currently tracked by this backend.
    fn owns_syscall(&self, req: &SyscallRequest) -> bool;

    /// Execute a syscall this backend claimed via [`NetBackend::owns_syscall`].
    /// Only ever called after `owns_syscall(req)` returned `true` for the
    /// same request.
    fn handle(&self, req: &SyscallRequest) -> SyscallResponse;
}
