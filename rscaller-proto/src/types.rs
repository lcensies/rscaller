use serde::{Deserialize, Serialize};

/// A request to execute a raw syscall on the beacon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallRequest {
    /// Slot index for correlating requests/responses.
    pub slot_idx: u64,
    /// Linux syscall number.
    pub number: u64,
    /// Up to 6 syscall arguments.
    pub args: [u64; 6],
}

/// The result of executing a syscall on the beacon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallResponse {
    /// Matches the slot_idx from the request.
    pub slot_idx: u64,
    /// Raw return value from libc::syscall().
    pub ret: i64,
}
