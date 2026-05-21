//! Shared notification type delivered by every controller backend.

/// Up to 6 syscall arguments (matches Linux ABI).
pub type SyscallArgs = [u64; 6];

/// A single intercepted syscall notification from a controller backend.
///
/// The relay translates this into a `SyscallRequest` and sends it to rsbeacon.
/// `id` must be echoed back in `SyscallController::complete`.
#[derive(Debug, Clone)]
pub struct Notification {
    /// Opaque controller-specific ID used to correlate `complete` calls.
    /// kmod: ring-buffer slot index.  seccomp: `seccomp_notif.id` cookie.
    pub id: u64,

    /// Linux syscall number.
    pub nr: u64,

    /// Raw syscall arguments (up to 6).
    pub args: SyscallArgs,

    /// PID of the process whose syscall was intercepted.
    /// 0 if the backend does not provide this.
    pub pid: u32,

    /// Pre-copied IN/INOUT pointer-argument buffers.
    ///
    /// kmod fills these via `copy_from_user`.
    /// seccomp fills these via `process_vm_readv` using the metadata table.
    pub in_data: Vec<InBuf>,

    /// `(arg_idx, size)` pairs for OUT/INOUT pointer args that rsbeacon
    /// must allocate and return after the syscall executes.
    ///
    /// Populated from `meta::ParamMeta` for both backends.
    pub out_sizes: Vec<(u8, u64)>,
}

/// An already-copied input buffer attached to a notification.
#[derive(Debug, Clone)]
pub struct InBuf {
    /// Which argument index (0–5) holds the pointer.
    pub arg_idx: u8,
    /// The bytes at that pointer in the tracee's address space.
    pub data: Vec<u8>,
}
