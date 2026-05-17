use serde::{Deserialize, Serialize};

/// A single pointer-argument buffer payload.
///
/// For IN/INOUT params, `data` contains bytes copied from the process's
/// userspace memory by kmod (via copy_from_user).  For OUT params returning
/// from the beacon, `data` contains the bytes the syscall wrote into the
/// beacon-side buffer; kmod will copy_to_user them back into the originating
/// process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallBuf {
    pub arg_idx: u8,
    pub data: Vec<u8>,
}

/// A request to execute a raw syscall on the beacon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallRequest {
    /// Slot index for correlating requests/responses.
    pub slot_idx: u64,
    /// Linux syscall number.
    pub number: u64,
    /// Up to 6 syscall arguments.
    pub args: [u64; 6],
    /// Contents of IN/INOUT pointer params (copied from the process's memory by kmod).
    pub in_bufs: Vec<SyscallBuf>,
    /// `(arg_idx, size)` for OUT/INOUT pointer params — beacon must allocate
    /// a local buffer of `size` bytes and return its post-syscall contents.
    pub out_sizes: Vec<(u8, u64)>,
}

/// The result of executing a syscall on the beacon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallResponse {
    /// Matches the slot_idx from the request.
    pub slot_idx: u64,
    /// Raw return value from libc::syscall().
    pub ret: i64,
    /// OUT/INOUT buffer contents after syscall execution, for copy_to_user.
    pub out_bufs: Vec<SyscallBuf>,
}
