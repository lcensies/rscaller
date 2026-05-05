use rscaller_proto::types::{SyscallRequest, SyscallResponse};
use tracing::{debug, warn};

/// Syscalls blocked from remote execution.
/// Extend as needed — beacon is meant for a throwaway VM, so list is minimal.
const BLOCKED_SYSCALLS: &[u64] = &[
    169, // reboot
    175, // init_module
    176, // delete_module
    155, // pivot_root
    166, // umount2
];

pub fn execute_syscall(req: &SyscallRequest) -> SyscallResponse {
    let num = req.number;
    let args = req.args;

    if BLOCKED_SYSCALLS.contains(&num) {
        warn!("Blocked syscall {}", num);
        return SyscallResponse {
            slot_idx: req.slot_idx,
            ret: -(libc::EPERM as i64),
        };
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

    SyscallResponse {
        slot_idx: req.slot_idx,
        ret: ret as i64,
    }
}
