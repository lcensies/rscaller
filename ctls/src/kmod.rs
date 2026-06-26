//! Kmod controller backend.
//!
//! Wraps the existing `/proc/rscaller` mmap ring-buffer mechanism.
//! The shared-memory layout is defined by the kernel module in `kmod/buffer.h`
//! and mirrored here in [`KmodLayout`].
//!
//! # Historical note
//! Earlier revisions used `remap_pfn_range` + `vm_insert_page`; those
//! experiments are visible in git history pre-v4.4.  The current kmod
//! uses `remap_pfn_range` without `VM_IO` (normal RAM pages on 6.x kernels).

use std::fs::File;
use std::io::Write;
use std::mem;

use anyhow::Result;
use async_trait::async_trait;
use memmap2::MmapMut;
use tracing::debug;

use crate::{Notification, SyscallController};
use crate::notification::InBuf;

// ---------------------------------------------------------------------------
// C struct mirrors (must match kmod/buffer.h exactly)
// ---------------------------------------------------------------------------

const QUEUE_SIZE: usize = 10;
const MAX_PARAM_BUF: usize = 4096;
const MAX_PARAMS: usize = 6;

pub const PARAM_DIR_IN: u32 = 0;
pub const PARAM_DIR_OUT: u32 = 1;
pub const PARAM_DIR_INOUT: u32 = 2;

/// Mirror of C `SyscallParam` union.
#[repr(C)]
#[derive(Clone, Copy)]
pub union SyscallParam {
    pub long_type: i64,
    pub ulong_type: u64,
}

impl std::fmt::Debug for SyscallParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SyscallParam(0x{:016x})", unsafe { self.ulong_type })
    }
}

impl Default for SyscallParam {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

/// Mirror of C `Syscall` struct.
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

/// Mirror of C `MemoryQueue`.
#[repr(C)]
pub struct MemoryQueue {
    pub size: i32,
    pub max_size: i32,
    pub tail_idx: i32,
    pub head_idx: i32,
    pub nodes: [KmodSyscall; 10],
}

/// Mirror of C `ParamBuf`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ParamBuf {
    pub user_ptr: u64,
    pub size: u32,
    pub direction: u32,
    pub data: [u8; MAX_PARAM_BUF],
}

impl Default for ParamBuf {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

/// Mirror of C `SlotBufs`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SlotBufs {
    pub params: [ParamBuf; MAX_PARAMS],
}

/// Mirror of C `ControlBuffer` — the mmap'd region.
#[repr(C)]
pub struct ControlBuffer {
    pub kernel_to_user: MemoryQueue,
    pub user_to_kernel: MemoryQueue,
    pub bufs: [SlotBufs; QUEUE_SIZE],
}

// Compile-time size sanity.
const _: () = {
    assert!(mem::size_of::<SyscallParam>() == 8);
    assert!(mem::size_of::<KmodSyscall>() == 64);
    assert!(mem::size_of::<ParamBuf>() == 4112);
    assert!(mem::size_of::<SlotBufs>() == 24672);
};

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

/// Kmod-based syscall controller.
///
/// Opens `/proc/rscaller`, mmaps the `ControlBuffer`, polls the
/// `kernel_to_user` ring buffer for new entries, and signals completion
/// by writing `DONE <slot> <retval>` to the proc file.
pub struct KmodController {
    mmap: MmapMut,
    proc_file: File,
}

impl KmodController {
    /// Open `/proc/rscaller` (or a custom path) and set up the mmap.
    pub fn open(proc_path: &str) -> Result<Self> {
        use std::fs::OpenOptions;
        use memmap2::MmapOptions;

        let proc_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(proc_path)?;

        let mmap = unsafe {
            MmapOptions::new()
                .len(mem::size_of::<ControlBuffer>())
                .map_mut(&proc_file)?
        };

        Ok(Self { mmap, proc_file })
    }

    /// Send a `TARGET <name>` command to the kmod.
    pub fn set_target_name(&mut self, name: &str) -> Result<()> {
        self.write_cmd(&format!("TARGET {}\n", name))
    }

    /// Write a raw newline-terminated command string to the kmod proc file.
    pub fn write_cmd(&mut self, cmd: &str) -> Result<()> {
        self.proc_file.write_all(cmd.as_bytes())?;
        Ok(())
    }

    fn ctl(&mut self) -> &mut ControlBuffer {
        unsafe { &mut *(self.mmap.as_mut_ptr() as *mut ControlBuffer) }
    }

    /// Non-blocking pop from the ring buffer.
    fn pop(&mut self) -> Option<(usize, KmodSyscall)> {
        let cb = self.ctl();
        let q = &mut cb.kernel_to_user;

        if q.size == 0 {
            return None;
        }

        let slot = q.head_idx as usize % QUEUE_SIZE;
        let sc = q.nodes[slot];

        if sc.n_params == 0 {
            return None; // not yet filled
        }

        q.head_idx = (q.head_idx + 1) % QUEUE_SIZE as i32;
        q.size -= 1;

        if sc.n_params < 0 {
            return self.pop(); // cancelled slot — drain
        }

        Some((slot, sc))
    }

    /// Read IN/INOUT buffers from a slot.
    fn read_in_bufs(&mut self, slot: usize, n_params: usize) -> Vec<InBuf> {
        let cb = self.ctl();
        let mut bufs = Vec::new();
        let slot_bufs = &cb.bufs[slot];
        for i in 0..n_params {
            let pb = &slot_bufs.params[i];
            if (pb.direction == PARAM_DIR_IN || pb.direction == PARAM_DIR_INOUT)
                && pb.size > 0
                && pb.user_ptr != 0
            {
                let len = pb.size as usize;
                bufs.push(InBuf {
                    arg_idx: i as u8,
                    data: pb.data[..len].to_vec(),
                });
            }
        }
        bufs
    }

    /// Read OUT/INOUT (arg_idx, size) pairs from a slot.
    fn read_out_sizes(&mut self, slot: usize, n_params: usize) -> Vec<(u8, u64)> {
        let cb = self.ctl();
        let mut sizes = Vec::new();
        let slot_bufs = &cb.bufs[slot];
        for i in 0..n_params {
            let pb = &slot_bufs.params[i];
            if (pb.direction == PARAM_DIR_OUT || pb.direction == PARAM_DIR_INOUT)
                && pb.user_ptr != 0
            {
                sizes.push((i as u8, pb.size as u64));
            }
        }
        sizes
    }
}

#[async_trait]
impl SyscallController for KmodController {
    async fn recv(&mut self) -> Result<Option<Notification>> {
        loop {
            if let Some((slot, sc)) = self.pop() {
                let n = sc.n_params as usize;
                let in_data = self.read_in_bufs(slot, n);
                let out_sizes = self.read_out_sizes(slot, n);
                let mut args = [0u64; 6];
                for (i, p) in sc.param_bufs.iter().enumerate() {
                    args[i] = unsafe { p.ulong_type };
                }
                debug!(slot, syscall = sc.number, n_params = n, "kmod notification");
                return Ok(Some(Notification {
                    id: slot as u64,
                    nr: sc.number as u64,
                    args,
                    pid: 0,
                    in_data,
                    out_sizes,
                }));
            }
            // Yield to avoid busy-spinning — kmod has no epoll/eventfd yet.
            tokio::task::yield_now().await;
        }
    }

    async fn complete(
        &mut self,
        id: u64,
        retval: i64,
        out_bufs: &[(u8, Vec<u8>)],
        _original_args: &crate::SyscallArgs,
    ) -> Result<()> {
        // Write OUT buffer data into the shared mmap ParamBuf slots so the
        // kmod can copy_to_user them back into the tracee.
        let slot = id as usize % QUEUE_SIZE;
        let cb = self.ctl();
        let slot_bufs = &mut cb.bufs[slot];
        for (arg_idx, data) in out_bufs {
            let idx = *arg_idx as usize;
            if idx >= MAX_PARAMS { continue; }
            let pb = &mut slot_bufs.params[idx];
            let n = data.len().min(pb.data.len());
            pb.data[..n].copy_from_slice(&data[..n]);
            pb.size = n as u32;
        }

        let msg = format!("DONE {} {}\n", id, retval);
        self.proc_file.write_all(msg.as_bytes())?;
        Ok(())
    }
}
