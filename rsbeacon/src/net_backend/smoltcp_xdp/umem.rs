//! UMEM: the shared memory region that backs all AF_XDP frame I/O, plus the
//! fill/completion rings that hand frames to and reclaim frames from the
//! kernel. Ported from `xdplganger/pkg/xdp/umem.go`.

use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use super::xdp_abi::*;

/// A memory-mapped AF_XDP ring (fill or completion; RX/TX use
/// [`super::xdp_socket::DescRing`] instead since their entries are
/// [`Desc`] rather than a bare `u64` frame address).
pub struct FrameRing {
    mmap_ptr: *mut u8,
    mmap_len: usize,
    producer: *const AtomicU32,
    consumer: *const AtomicU32,
    descs: *mut u64,
    mask: u32,
}

// The ring lives in a kernel-shared mmap; access is synchronized via the
// acquire/release atomics on producer/consumer exactly as the AF_XDP ABI
// requires, so it is safe to move/share across threads.
unsafe impl Send for FrameRing {}
unsafe impl Sync for FrameRing {}

impl FrameRing {
    fn producer(&self) -> &AtomicU32 {
        unsafe { &*self.producer }
    }

    fn consumer(&self) -> &AtomicU32 {
        unsafe { &*self.consumer }
    }

    fn desc_at(&self, idx: u32) -> *mut u64 {
        unsafe { self.descs.add((idx & self.mask) as usize) }
    }

    /// Current producer index, for a caller (e.g. `XdpSocket::reclaim_rx`)
    /// that wants to push new entries onto this ring from the outside
    /// (used for the fill ring, whose producer is advanced by the RX
    /// consumer rather than by `Umem` itself).
    pub(super) fn producer_for_reclaim(&self) -> u32 {
        self.producer().load(Ordering::Acquire)
    }

    /// Writes a frame address at `idx` (masked) into this ring's
    /// descriptor array. Used for the fill ring reclaim path.
    pub(super) fn set_desc(&self, idx: u32, addr: u64) {
        unsafe {
            *self.desc_at(idx) = addr;
        }
    }

    /// Publishes a new producer index (release ordering, per the AF_XDP
    /// ring ABI).
    pub(super) fn producer_for_reclaim_store(&self, new_prod: u32) {
        self.producer().store(new_prod, Ordering::Release);
    }
}

impl Drop for FrameRing {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.mmap_ptr as *mut libc::c_void, self.mmap_len);
        }
    }
}

/// Owns the mmap'd frame buffer and the fill/completion rings for one
/// AF_XDP socket.
pub struct Umem {
    buf_ptr: *mut u8,
    buf_len: usize,
    pub fill: FrameRing,
    pub completion: FrameRing,
    free_frames: Mutex<Vec<u64>>,
}

unsafe impl Send for Umem {}
unsafe impl Sync for Umem {}

impl Drop for Umem {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.buf_ptr as *mut libc::c_void, self.buf_len);
        }
    }
}

fn setsockopt_raw<T>(fd: RawFd, level: i32, name: i32, val: &T) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            val as *const T as *const libc::c_void,
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn setsockopt_int(fd: RawFd, level: i32, name: i32, val: i32) -> io::Result<()> {
    setsockopt_raw(fd, level, name, &val)
}

pub fn get_mmap_offsets(fd: RawFd) -> io::Result<MmapOffsets> {
    let mut off = MmapOffsets::default();
    let mut len = std::mem::size_of::<MmapOffsets>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_MMAP_OFFSETS,
            &mut off as *mut MmapOffsets as *mut libc::c_void,
            &mut len,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(off)
    }
}

fn mmap_ring(fd: RawFd, pgoff: i64, size: usize) -> io::Result<*mut u8> {
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            fd,
            pgoff,
        )
    };
    if ptr == libc::MAP_FAILED {
        Err(io::Error::last_os_error())
    } else {
        Ok(ptr as *mut u8)
    }
}

impl Umem {
    /// Allocates the frame buffer and registers it with the kernel via
    /// `setsockopt(XDP_UMEM_REG)`. `fd` must already be an `AF_XDP` socket.
    pub fn new(fd: RawFd) -> io::Result<Self> {
        let size = (NUM_FRAMES * FRAME_SIZE) as usize;

        // Try huge pages first (matches xdplganger); fall back to regular
        // pages if unavailable (e.g. no hugetlbfs reservation).
        let mut ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
        }
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        let reg = UmemReg::new(ptr as u64, size as u64, FRAME_SIZE as u32, HEADROOM as u32);
        if let Err(e) = setsockopt_raw(fd, SOL_XDP, XDP_UMEM_REG, &reg) {
            unsafe {
                libc::munmap(ptr, size);
            }
            return Err(e);
        }

        setsockopt_int(fd, SOL_XDP, XDP_UMEM_FILL_RING, RING_SIZE as i32).map_err(|e| {
            unsafe {
                libc::munmap(ptr, size);
            }
            e
        })?;
        setsockopt_int(fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, RING_SIZE as i32).map_err(|e| {
            unsafe {
                libc::munmap(ptr, size);
            }
            e
        })?;

        let offsets = get_mmap_offsets(fd).map_err(|e| {
            unsafe {
                libc::munmap(ptr, size);
            }
            e
        })?;

        let fill = Self::setup_frame_ring(fd, XDP_UMEM_PGOFF_FILL_RING, &offsets.fr).map_err(|e| {
            unsafe {
                libc::munmap(ptr, size);
            }
            e
        })?;
        let completion =
            Self::setup_frame_ring(fd, XDP_UMEM_PGOFF_COMPLETION_RING, &offsets.cr).map_err(
                |e| {
                    unsafe {
                        libc::munmap(ptr, size);
                    }
                    e
                },
            )?;

        // Every frame is initially free.
        let mut free_frames = Vec::with_capacity(NUM_FRAMES as usize);
        for i in 0..NUM_FRAMES {
            free_frames.push(i * FRAME_SIZE);
        }

        Ok(Self {
            buf_ptr: ptr as *mut u8,
            buf_len: size,
            fill,
            completion,
            free_frames: Mutex::new(free_frames),
        })
    }

    fn setup_frame_ring(fd: RawFd, pgoff: i64, off: &RingOffset) -> io::Result<FrameRing> {
        let size = off.desc as usize + RING_SIZE as usize * 8;
        let mmap_ptr = mmap_ring(fd, pgoff, size)?;
        unsafe {
            Ok(FrameRing {
                mmap_ptr,
                mmap_len: size,
                producer: mmap_ptr.add(off.producer as usize) as *const AtomicU32,
                consumer: mmap_ptr.add(off.consumer as usize) as *const AtomicU32,
                descs: mmap_ptr.add(off.desc as usize) as *mut u64,
                mask: RING_SIZE - 1,
            })
        }
    }

    /// Takes a free frame address from the pool, if any is available.
    pub fn alloc_frame(&self) -> Option<u64> {
        self.free_frames.lock().unwrap().pop()
    }

    /// Returns a frame address to the pool.
    pub fn free_frame(&self, addr: u64) {
        self.free_frames.lock().unwrap().push(addr);
    }

    /// Fills the fill ring with up to `n` free frame addresses so the
    /// kernel has buffers ready for incoming packets.
    pub fn populate_fill(&self, n: usize) {
        let prod = self.fill.producer().load(Ordering::Acquire);
        let mut added = 0u32;
        for i in 0..n as u32 {
            let Some(addr) = self.alloc_frame() else {
                break;
            };
            unsafe {
                *self.fill.desc_at(prod + i) = addr;
            }
            added += 1;
        }
        self.fill.producer().store(prod + added, Ordering::Release);
    }

    /// Recycles TX-completed frames back into the free pool.
    pub fn drain_completion(&self) {
        let prod = self.completion.producer().load(Ordering::Acquire);
        let cons = self.completion.consumer().load(Ordering::Acquire);
        let n = prod.wrapping_sub(cons);
        for i in 0..n {
            let addr = unsafe { *self.completion.desc_at(cons + i) };
            self.free_frame(addr);
        }
        self.completion
            .consumer()
            .store(cons.wrapping_add(n), Ordering::Release);
    }

    /// Returns a mutable view into the UMEM buffer for the frame at `addr`,
    /// `length` bytes long, past the configured headroom.
    ///
    /// # Safety
    /// Caller must ensure `addr` is a valid, currently-owned frame offset
    /// (from `alloc_frame` or a just-consumed RX descriptor) and that
    /// `HEADROOM + length` does not exceed `FRAME_SIZE`, and that no other
    /// live reference to the same frame region exists concurrently.
    pub unsafe fn frame_slice_mut(&self, addr: u64, length: usize) -> &mut [u8] {
        let off = addr as usize + HEADROOM as usize;
        std::slice::from_raw_parts_mut(self.buf_ptr.add(off), length)
    }

    /// Read-only view, same addressing as [`Umem::frame_slice_mut`].
    ///
    /// # Safety
    /// Same requirements as [`Umem::frame_slice_mut`], minus exclusivity.
    pub unsafe fn frame_slice(&self, addr: u64, length: usize) -> &[u8] {
        let off = addr as usize + HEADROOM as usize;
        std::slice::from_raw_parts(self.buf_ptr.add(off), length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setsockopt_int_helper_compiles_and_rejects_bad_fd() {
        // fd -1 is never valid; this just exercises the error path without
        // needing a real AF_XDP socket (which requires root).
        let err = setsockopt_int(-1, SOL_XDP, XDP_UMEM_FILL_RING, 1).unwrap_err();
        assert!(err.raw_os_error().is_some());
    }

    #[test]
    fn get_mmap_offsets_rejects_bad_fd() {
        assert!(get_mmap_offsets(-1).is_err());
    }
}
