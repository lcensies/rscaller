//! Raw Linux AF_XDP ABI — mirrors kernel `uapi/linux/if_xdp.h` structs and
//! constants directly, the same way `xdplganger/pkg/xdp/types.go` does for
//! Go. Using hand-rolled constants/structs avoids depending on a
//! libbpf/libxdp binding for the socket/ring/UMEM path (see design decision
//! D3 in `openspec/changes/add-beacon-smoltcp-xdp-netstack/design.md`).

#![allow(dead_code)]

use std::mem::size_of;

pub const AF_XDP: i32 = 44;
pub const SOL_XDP: i32 = 283;

// setsockopt() option names (SOL_XDP level).
pub const XDP_MMAP_OFFSETS: i32 = 1;
pub const XDP_RX_RING: i32 = 2;
pub const XDP_TX_RING: i32 = 3;
pub const XDP_UMEM_REG: i32 = 4;
pub const XDP_UMEM_FILL_RING: i32 = 5;
pub const XDP_UMEM_COMPLETION_RING: i32 = 6;

// bind() flags (struct sockaddr_xdp.flags).
pub const XDP_SHARED_UMEM: u16 = 1 << 0;
pub const XDP_COPY: u16 = 1 << 1; // force copy mode — portable across all drivers, incl. veth
pub const XDP_ZEROCOPY: u16 = 1 << 2; // requires driver support; unsupported/unvalidated in v1
pub const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

// mmap() page offsets for each ring (see kernel net/xdp/xsk.c).
pub const XDP_PGOFF_RX_RING: i64 = 0;
pub const XDP_PGOFF_TX_RING: i64 = 0x8000_0000;
pub const XDP_UMEM_PGOFF_FILL_RING: i64 = 0x1_0000_0000;
pub const XDP_UMEM_PGOFF_COMPLETION_RING: i64 = 0x1_8000_0000;

// UMEM / ring sizing. Matches xdplganger's defaults (portable, no huge
// tuning) — see design Non-Goals re: multi-queue/zero-copy scope.
pub const NUM_FRAMES: u64 = 4096;
pub const FRAME_SIZE: u64 = 2048;
pub const RING_SIZE: u32 = 2048; // entries per ring; must be a power of two
pub const HEADROOM: u64 = 0;

/// Mirrors `struct xdp_umem_reg`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UmemReg {
    pub addr: u64,
    pub len: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
    _pad: u32,
}

impl UmemReg {
    pub fn new(addr: u64, len: u64, chunk_size: u32, headroom: u32) -> Self {
        Self {
            addr,
            len,
            chunk_size,
            headroom,
            flags: 0,
            _pad: 0,
        }
    }
}

/// Mirrors `struct xdp_ring_offset`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RingOffset {
    pub producer: u64,
    pub consumer: u64,
    pub desc: u64,
    pub flags: u64,
}

/// Mirrors `struct xdp_mmap_offsets`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MmapOffsets {
    pub rx: RingOffset,
    pub tx: RingOffset,
    pub fr: RingOffset, // fill ring
    pub cr: RingOffset, // completion ring
}

/// Mirrors `struct xdp_desc` (RX/TX ring entry).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Desc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

pub const DESC_SIZE: usize = size_of::<Desc>();

/// Mirrors `struct sockaddr_xdp`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SockaddrXdp {
    pub family: u16,
    pub flags: u16,
    pub ifindex: u32,
    pub queue_id: u32,
    pub shared_umem_fd: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These sizes must exactly match the kernel's uapi struct layout —
    /// wrong sizes here silently corrupt every setsockopt/bind/mmap call.
    #[test]
    fn struct_sizes_match_kernel_abi() {
        assert_eq!(size_of::<UmemReg>(), 32);
        assert_eq!(size_of::<RingOffset>(), 32);
        assert_eq!(size_of::<MmapOffsets>(), 32 * 4);
        assert_eq!(size_of::<Desc>(), 16);
        assert_eq!(size_of::<SockaddrXdp>(), 16);
    }

    #[test]
    fn ring_size_is_power_of_two() {
        assert!(RING_SIZE.is_power_of_two());
    }
}
