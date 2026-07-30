use rscaller_proto::types::{SyscallBuf, SyscallRequest, SyscallResponse};
use tracing::{debug, warn};

use crate::net_backend::NetBackend;

/// Syscalls blocked from remote execution.
/// Extend as needed — beacon is meant for a throwaway VM, so list is minimal.
const BLOCKED_SYSCALLS: &[u64] = &[
    169, // reboot
    175, // init_module
    176, // delete_module
    155, // pivot_root
    166, // umount2
    60,  // exit       — let the originating process exit locally
    231, // exit_group — let the originating process exit locally
    // Process lifecycle — kmod skips these, but block as safety net:
    // forwarding execve would replace the beacon process itself.
    56,  // clone
    57,  // fork
    58,  // vfork
    59,  // execve
    322, // execveat
    435, // clone3
];

/// Executes `req`, first giving the active `NetBackend` a chance to claim
/// it (see `crate::net_backend`). Syscall numbers not claimed by the
/// backend — which, with the default `direct` backend, is *every* syscall
/// number — fall through to the generic `libc::syscall` passthrough below,
/// unchanged from rsbeacon's behavior before the `NetBackend` abstraction
/// was introduced.
pub fn execute_syscall(req: &SyscallRequest, backend: &dyn NetBackend) -> SyscallResponse {
    if backend.owns_syscall(req) {
        return backend.handle(req);
    }

    execute_syscall_direct(req)
}

/// The generic syscall passthrough: executes `req` via `libc::syscall`
/// against the beacon host's real kernel. This is rsbeacon's entire
/// behavior prior to the `NetBackend` abstraction, and remains the sole
/// execution path for any syscall number the active backend does not
/// claim.
fn execute_syscall_direct(req: &SyscallRequest) -> SyscallResponse {
    let num = req.number;
    let mut args = req.args;

    debug!("execute_syscall: num={} in_bufs={} out_sizes={}", num, req.in_bufs.len(), req.out_sizes.len());
    for ib in &req.in_bufs {
        debug!("  in_buf arg_idx={} data_len={} data={:?}", ib.arg_idx, ib.data.len(), String::from_utf8_lossy(&ib.data));
    }

    if BLOCKED_SYSCALLS.contains(&num) {
        warn!("Blocked syscall {}", num);
        return SyscallResponse {
            slot_idx: req.slot_idx,
            ret: -(libc::EPERM as i64),
            out_bufs: Vec::new(),
        };
    }

    // Allocate local buffers for pointer params.  Each Vec<u8> is kept alive
    // in `local_bufs` until after `libc::syscall` returns; raw pointers into
    // each Vec are stashed in `args[i]` so the syscall sees beacon-local
    // addresses rather than the originating process's userspace pointers.
    let mut local_bufs: Vec<(u8, Vec<u8>)> = Vec::with_capacity(
        req.in_bufs.len() + req.out_sizes.len(),
    );

    // IN / INOUT: seed the buffer with incoming data and (for INOUT) extend
    // it to the output size if larger.
    for sb in &req.in_bufs {
        let mut buf = sb.data.clone();
        if let Some(&(_, out_sz)) = req.out_sizes.iter().find(|&&(i, _)| i == sb.arg_idx) {
            if (out_sz as usize) > buf.len() {
                buf.resize(out_sz as usize, 0);
            }
        }
        local_bufs.push((sb.arg_idx, buf));
    }

    // OUT-only: allocate a zeroed buffer of the requested size.
    for &(arg_idx, size) in &req.out_sizes {
        if req.in_bufs.iter().any(|b| b.arg_idx == arg_idx) {
            continue;
        }
        local_bufs.push((arg_idx, vec![0u8; size as usize]));
    }

    // Now that local_bufs will not be mutated/resized further, take stable
    // pointers and overwrite the corresponding args entries.
    for (arg_idx, buf) in local_bufs.iter_mut() {
        args[*arg_idx as usize] = buf.as_mut_ptr() as u64;
    }

    debug!("Executing syscall {} with args {:?}", num, args);

    // Safety: intentionally executing arbitrary syscalls as directed by rsclient.
    // The beacon is designed to run on a disposable VM.
    let ret = unsafe {
        libc::syscall(
            num as libc::c_long,
            args[0] as libc::c_long,
            args[1] as libc::c_long,
            args[2] as libc::c_long,
            args[3] as libc::c_long,
            args[4] as libc::c_long,
            args[5] as libc::c_long,
        )
    };

    debug!("Syscall {} returned {} (errno={})", num, ret, unsafe { *libc::__errno_location() });

    // Collect OUT/INOUT results from the local buffers (must happen before
    // local_bufs is dropped so the raw pointers we passed remain valid for
    // the entire libc::syscall lifetime above).
    let out_bufs: Vec<SyscallBuf> = req
        .out_sizes
        .iter()
        .filter_map(|&(arg_idx, _)| {
            local_bufs
                .iter()
                .find(|(i, _)| *i == arg_idx)
                .map(|(_, buf)| SyscallBuf {
                    arg_idx,
                    data: buf.clone(),
                })
        })
        .collect();

    SyscallResponse {
        slot_idx: req.slot_idx,
        ret: ret as i64,
        out_bufs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_backend::direct::DirectBackend;

    /// `execute_syscall` with the `direct` backend must behave identically
    /// to calling the generic passthrough directly — this is the
    /// behavioral-parity guarantee from design decision D1: `direct` is not
    /// a reimplementation, it's the same code path with zero interception.
    #[test]
    fn direct_backend_matches_generic_passthrough_for_getpid() {
        let backend = DirectBackend::new();
        let req = SyscallRequest {
            slot_idx: 7,
            number: libc::SYS_getpid as u64,
            args: [0; 6],
            in_bufs: vec![],
            out_sizes: vec![],
        };

        let via_backend = execute_syscall(&req, &backend);
        let via_direct = execute_syscall_direct(&req);

        assert_eq!(via_backend.ret, via_direct.ret);
        assert_eq!(via_backend.slot_idx, req.slot_idx);
        // Both should return the real pid of this test process.
        assert_eq!(via_backend.ret, std::process::id() as i64);
    }

    /// A socket-related syscall number, when serviced through the `direct`
    /// backend, must still go through the exact same generic passthrough —
    /// there is no shadow/alternate code path for socket syscalls when
    /// `--netstack direct` is selected.
    #[test]
    fn direct_backend_does_not_intercept_socket_syscalls() {
        let backend = DirectBackend::new();
        // socket(AF_INET, SOCK_DGRAM, 0) — harmless, closes itself via drop
        // of the fd being lost is fine for this test (short-lived process).
        let req = SyscallRequest {
            slot_idx: 1,
            number: libc::SYS_socket as u64,
            args: [libc::AF_INET as u64, libc::SOCK_DGRAM as u64, 0, 0, 0, 0],
            in_bufs: vec![],
            out_sizes: vec![],
        };

        let via_backend = execute_syscall(&req, &backend);
        // A real fd (>= 0) proves this actually executed via libc::syscall
        // against the real kernel, not some backend-internal virtual fd.
        assert!(
            via_backend.ret >= 0,
            "expected a real kernel fd, got {}",
            via_backend.ret
        );
        // Clean up the fd we just created.
        unsafe {
            libc::close(via_backend.ret as i32);
        }
    }

    #[test]
    fn blocked_syscalls_still_return_eperm_through_backend() {
        let backend = DirectBackend::new();
        let req = SyscallRequest {
            slot_idx: 0,
            number: 169, // reboot
            args: [0; 6],
            in_bufs: vec![],
            out_sizes: vec![],
        };
        let resp = execute_syscall(&req, &backend);
        assert_eq!(resp.ret, -(libc::EPERM as i64));
    }
}
