use rscaller_proto::types::{SyscallBuf, SyscallRequest, SyscallResponse};
use tracing::{debug, warn};

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

pub fn execute_syscall(req: &SyscallRequest) -> SyscallResponse {
    let num = req.number;
    let mut args = req.args;

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

    debug!("Syscall {} returned {}", num, ret);

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
