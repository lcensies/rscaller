use std::mem;

/// Mirror of the C `SyscallParam` union from kmod/types.h.
/// All variants overlap at offset 0; size = 8 bytes (largest member).
#[repr(C)]
#[derive(Clone, Copy)]
pub union SyscallParam {
    pub long_type: i64,
    pub ulong_type: u64,
    pub int_type: i32,
    pub uint_type: u32,
    /// Pointer fields stored as raw u64 to avoid fat-pointer issues.
    pub char_ptr_type: u64,
    pub void_ptr_type: u64,
}

impl Default for SyscallParam {
    fn default() -> Self {
        // Safety: all-zero bytes are valid for this union.
        unsafe { mem::zeroed() }
    }
}

impl std::fmt::Debug for SyscallParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Always print as u64 — safe for a union of integer / pointer types.
        write!(f, "SyscallParam(0x{:016x})", unsafe { self.ulong_type })
    }
}

/// Mirror of the C `Syscall` struct from kmod/types.h.
///
/// Layout (64-bit):
///   int number   (4) + int n_params (4) + int ret (4) + pad (4) + 6×u64 (48) = 64 bytes
///
/// The explicit `_pad` field matches the natural alignment padding the C compiler
/// inserts before the 8-byte-aligned `SyscallParam` array.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KmodSyscall {
    pub number: i32,
    pub n_params: i32,
    pub ret: i32,
    pub _pad: i32,
    pub param_bufs: [SyscallParam; 6],
}

impl Default for KmodSyscall {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

/// Mirror of the C `MemoryQueue` struct from kmod/buffer.h.
///
/// NOTE: The kmod's `MemoryQueue` must NOT include `struct completion` fields
/// inside this struct — those must live in a separate module-level array in the
/// kmod so that the mmap'd region only contains the data portion.
#[repr(C)]
pub struct MemoryQueue {
    pub size: i32,
    pub max_size: i32,
    pub tail_idx: i32,
    pub head_idx: i32,
    pub nodes: [KmodSyscall; 10],
}

/// Mirror of the C `ControlBuffer` struct.
///
/// Layout:
///   kernel_to_user: MemoryQueue (kmod writes, rsclient reads)
///   user_to_kernel: MemoryQueue (reserved / not yet used)
#[repr(C)]
pub struct ControlBuffer {
    pub kernel_to_user: MemoryQueue,
    pub user_to_kernel: MemoryQueue,
}

// ---------------------------------------------------------------------------
// Compile-time layout assertions
// ---------------------------------------------------------------------------
const _: () = {
    assert!(mem::size_of::<SyscallParam>() == 8);
    // 4+4+4+4 + 6*8 = 64
    assert!(mem::size_of::<KmodSyscall>() == 64);
};
