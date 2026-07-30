//! The `direct` network backend: today's rsbeacon behavior, made explicit.
//!
//! `DirectBackend` never claims any syscall — [`NetBackend::owns_syscall`]
//! always returns `false`, so every request (including all socket-related
//! ones) falls through to the existing generic `libc::syscall` passthrough
//! in `crate::executor::execute_syscall`. This is intentional: it keeps
//! `--netstack direct` (the default) behaviorally identical to rsbeacon's
//! behavior before the `NetBackend` abstraction was introduced — there is
//! exactly one code path executing socket syscalls when this backend is
//! active, not a parallel shadow implementation that could subtly diverge.
use rscaller_proto::types::{SyscallRequest, SyscallResponse};

use super::NetBackend;

#[derive(Debug, Default)]
pub struct DirectBackend;

impl DirectBackend {
    pub fn new() -> Self {
        Self
    }
}

impl NetBackend for DirectBackend {
    fn name(&self) -> &'static str {
        "direct"
    }

    fn owns_syscall(&self, _req: &SyscallRequest) -> bool {
        // Never claim anything: every syscall goes through the existing
        // generic libc::syscall passthrough, exactly as before this
        // change was introduced.
        false
    }

    fn handle(&self, _req: &SyscallRequest) -> SyscallResponse {
        // Unreachable in practice: execute_syscall only calls `handle`
        // when `owns_syscall` returned true, which DirectBackend never does.
        unreachable!(
            "DirectBackend::handle called despite owns_syscall always returning false"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_req(number: u64) -> SyscallRequest {
        SyscallRequest {
            slot_idx: 0,
            number,
            args: [0; 6],
            in_bufs: vec![],
            out_sizes: vec![],
        }
    }

    #[test]
    fn never_owns_socket_syscalls() {
        let backend = DirectBackend::new();
        for &nr in super::super::SOCKET_SYSCALL_NRS {
            assert!(!backend.owns_syscall(&sample_req(nr)), "nr={nr}");
        }
    }

    #[test]
    fn never_owns_fd_generic_syscalls() {
        let backend = DirectBackend::new();
        for &nr in super::super::FD_GENERIC_SYSCALL_NRS {
            assert!(!backend.owns_syscall(&sample_req(nr)), "nr={nr}");
        }
    }

    #[test]
    fn never_owns_arbitrary_syscall() {
        let backend = DirectBackend::new();
        assert!(!backend.owns_syscall(&sample_req(2))); // open
    }
}
