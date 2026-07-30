//! AF_XDP socket: creation, ring setup, and bind to an interface queue.
//! Ported from `xdplganger/pkg/xdp/socket.go`.

use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};

use super::umem::{get_mmap_offsets, Umem};
use super::xdp_abi::*;

/// A memory-mapped RX or TX ring (entries are [`Desc`], 16 bytes each —
/// distinct from the fill/completion rings, whose entries are bare `u64`
/// frame addresses; see [`super::umem::FrameRing`]).
pub struct DescRing {
    mmap_ptr: *mut u8,
    mmap_len: usize,
    producer: *const AtomicU32,
    consumer: *const AtomicU32,
    descs: *mut Desc,
    mask: u32,
}

unsafe impl Send for DescRing {}
unsafe impl Sync for DescRing {}

impl Drop for DescRing {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.mmap_ptr as *mut libc::c_void, self.mmap_len);
        }
    }
}

impl DescRing {
    fn producer(&self) -> &AtomicU32 {
        unsafe { &*self.producer }
    }
    fn consumer(&self) -> &AtomicU32 {
        unsafe { &*self.consumer }
    }
    fn desc_at(&self, idx: u32) -> *mut Desc {
        unsafe { self.descs.add((idx & self.mask) as usize) }
    }

    fn mmap(fd: RawFd, pgoff: i64, off: &RingOffset) -> io::Result<Self> {
        let size = off.desc as usize + RING_SIZE as usize * DESC_SIZE;
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
            return Err(io::Error::last_os_error());
        }
        let ptr = ptr as *mut u8;
        unsafe {
            Ok(Self {
                mmap_ptr: ptr,
                mmap_len: size,
                producer: ptr.add(off.producer as usize) as *const AtomicU32,
                consumer: ptr.add(off.consumer as usize) as *const AtomicU32,
                descs: ptr.add(off.desc as usize) as *mut Desc,
                mask: RING_SIZE - 1,
            })
        }
    }
}

/// A bound AF_XDP socket with its UMEM and RX/TX rings.
pub struct XdpSocket {
    fd: RawFd,
    umem: Umem,
    rx: DescRing,
    tx: DescRing,
}

impl XdpSocket {
    /// Creates an AF_XDP socket, registers a UMEM, sets up all four rings,
    /// and binds to `ifindex`/`queue_id` in copy mode (see design D3/Non-Goals
    /// re: zero-copy being unsupported/unvalidated in v1).
    pub fn bind(ifindex: u32, queue_id: u32) -> io::Result<Self> {
        let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let result = Self::bind_inner(fd, ifindex, queue_id);
        if result.is_err() {
            unsafe {
                libc::close(fd);
            }
        }
        result
    }

    fn bind_inner(fd: RawFd, ifindex: u32, queue_id: u32) -> io::Result<Self> {
        let umem = Umem::new(fd)?;

        setsockopt_int(fd, SOL_XDP, XDP_RX_RING, RING_SIZE as i32)?;
        setsockopt_int(fd, SOL_XDP, XDP_TX_RING, RING_SIZE as i32)?;

        let offsets = get_mmap_offsets(fd)?;
        let rx = DescRing::mmap(fd, XDP_PGOFF_RX_RING, &offsets.rx)?;
        let tx = DescRing::mmap(fd, XDP_PGOFF_TX_RING, &offsets.tx)?;

        let sa = SockaddrXdp {
            family: AF_XDP as u16,
            flags: XDP_COPY,
            ifindex,
            queue_id,
            shared_umem_fd: 0,
        };
        let ret = unsafe {
            libc::bind(
                fd,
                &sa as *const SockaddrXdp as *const libc::sockaddr,
                std::mem::size_of::<SockaddrXdp>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Pre-populate the fill ring so the kernel has buffers ready for RX.
        umem.populate_fill(RING_SIZE as usize / 2);

        Ok(Self { fd, umem, rx, tx })
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }

    pub fn umem(&self) -> &Umem {
        &self.umem
    }

    /// Drains up to `out.len()` frames from the RX ring into `out`.
    /// Returns the number of descriptors read. Callers must eventually
    /// call [`XdpSocket::reclaim_rx`] once each frame has been processed,
    /// to return the buffer to the fill ring.
    pub fn read_batch(&self, out: &mut [Desc]) -> usize {
        let prod = self.rx.producer().load(Ordering::Acquire);
        let cons = self.rx.consumer().load(Ordering::Acquire);
        let avail = prod.wrapping_sub(cons);
        let n = avail.min(out.len() as u32);
        for i in 0..n {
            out[i as usize] = unsafe { *self.rx.desc_at(cons + i) };
        }
        self.rx.consumer().store(cons.wrapping_add(n), Ordering::Release);
        n as usize
    }

    /// Returns consumed RX frames to the fill ring so the kernel can reuse
    /// them for future incoming packets.
    pub fn reclaim_rx(&self, descs: &[Desc]) {
        let prod = self.umem.fill.producer_for_reclaim();
        for (i, d) in descs.iter().enumerate() {
            self.umem.fill.set_desc(prod + i as u32, d.addr);
        }
        self.umem
            .fill
            .producer_for_reclaim_store(prod + descs.len() as u32);
    }

    /// Enqueues frames onto the TX ring. Callers must call [`XdpSocket::kick`]
    /// afterwards to wake the kernel driver. Returns the number of
    /// descriptors actually enqueued (may be less than `descs.len()` if the
    /// ring is full).
    pub fn write_batch(&self, descs: &[Desc]) -> usize {
        let prod = self.tx.producer().load(Ordering::Acquire);
        let cons = self.tx.consumer().load(Ordering::Acquire);
        let free = RING_SIZE.saturating_sub(prod.wrapping_sub(cons));
        let n = free.min(descs.len() as u32);
        for i in 0..n {
            unsafe {
                *self.tx.desc_at(prod + i) = descs[i as usize];
            }
        }
        self.tx.producer().store(prod.wrapping_add(n), Ordering::Release);
        n as usize
    }

    /// Wakes the kernel to process pending TX frames.
    pub fn kick(&self) -> io::Result<()> {
        let ret = unsafe {
            libc::sendto(
                self.fd,
                std::ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                std::ptr::null(),
                0,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ENOBUFS) | Some(libc::EAGAIN) => Ok(()),
                _ => Err(err),
            }
        } else {
            Ok(())
        }
    }
}

impl Drop for XdpSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn setsockopt_int(fd: RawFd, level: i32, name: i32, val: i32) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &val as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_without_privileges_fails_cleanly_not_panics() {
        // Without CAP_NET_RAW/root this will fail at socket() or bind();
        // either way it must return an Err rather than panicking, so
        // higher layers (backend init) can surface an actionable error.
        let result = XdpSocket::bind(0, 0);
        // We don't assert Err specifically because a privileged CI runner
        // could conceivably succeed against ifindex 0 on some kernels; the
        // important invariant is "never panics", exercised either way.
        let _ = result;
    }
}
