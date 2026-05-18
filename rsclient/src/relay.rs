use std::fs::File;
use std::io::Write;
use std::time::Duration;

use anyhow::Result;
use memmap2::MmapMut;
use rscaller_proto::codec::{read_message, write_message};
use rscaller_proto::types::{SyscallBuf, SyscallRequest, SyscallResponse};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use crate::kmod::{ControlBuffer, KmodSyscall, PARAM_DIR_IN, PARAM_DIR_INOUT, PARAM_DIR_OUT};

const QUEUE_SIZE: usize = 10;

pub struct Relay<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> {
    mmap: MmapMut,
    proc_file: File,
    beacon_reader: R,
    beacon_writer: W,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> Relay<R, W> {
    pub fn new(mmap: MmapMut, proc_file: File, beacon_reader: R, beacon_writer: W) -> Self {
        Self {
            mmap,
            proc_file,
            beacon_reader,
            beacon_writer,
        }
    }

    /// Returns a mutable reference to the `ControlBuffer` mapped at the start of the mmap.
    ///
    /// # Safety
    /// Caller must ensure:
    /// - `mmap` covers at least `size_of::<ControlBuffer>()` bytes.
    /// - No other thread/process aliases this memory concurrently (the kmod
    ///   synchronises via its own spinlock; we are the only reader here).
    fn ctl_buffer(&mut self) -> &mut ControlBuffer {
        unsafe { &mut *(self.mmap.as_mut_ptr() as *mut ControlBuffer) }
    }

    /// Pop one `KmodSyscall` from the `kernel_to_user` ring buffer.
    ///
    /// Returns `Some((slot_idx, syscall))` or `None` if the queue is empty.
    ///
    /// `slot_idx` is the ring-buffer position of the consumed entry — used
    /// when writing the `DONE` completion back to the kmod.
    pub fn pop_syscall(&mut self) -> Option<(usize, KmodSyscall)> {
        let cb = self.ctl_buffer();
        let q = &mut cb.kernel_to_user;

        if q.size == 0 {
            return None;
        }

        let slot = q.head_idx as usize % QUEUE_SIZE;
        let syscall = q.nodes[slot];

        // n_params==0 means the kmod submitted the placeholder but hasn't filled
        // params yet — wait until the real entry is written.
        if syscall.n_params == 0 {
            return None;
        }

        q.head_idx = (q.head_idx + 1) % QUEUE_SIZE as i32;
        q.size -= 1;

        // n_params<0: kmod cancelled this slot — drain without processing.
        if syscall.n_params < 0 {
            return self.pop_syscall();
        }

        Some((slot, syscall))
    }

    /// Collect IN/INOUT pointer buffers from the per-slot ParamBuf array.
    pub fn read_in_bufs(&mut self, slot: usize, n_params: usize) -> Vec<SyscallBuf> {
        let cb = self.ctl_buffer();
        let mut bufs = Vec::new();
        let slot_bufs = &cb.bufs[slot];
        for i in 0..n_params {
            let pb = &slot_bufs.params[i];
            debug!(slot, param = i, direction = pb.direction, size = pb.size, user_ptr = pb.user_ptr, "param_buf");
            if pb.direction == PARAM_DIR_IN || pb.direction == PARAM_DIR_INOUT {
                if pb.size > 0 && pb.user_ptr != 0 {
                    let len = pb.size as usize;
                    bufs.push(SyscallBuf {
                        arg_idx: i as u8,
                        data: pb.data[..len].to_vec(),
                    });
                }
            }
        }
        bufs
    }

    /// Collect (arg_idx, size) entries for OUT/INOUT pointer buffers so the
    /// beacon knows what to allocate.
    pub fn read_out_sizes(&mut self, slot: usize, n_params: usize) -> Vec<(u8, u64)> {
        let cb = self.ctl_buffer();
        let mut sizes = Vec::new();
        let slot_bufs = &cb.bufs[slot];
        for i in 0..n_params {
            let pb = &slot_bufs.params[i];
            if pb.direction == PARAM_DIR_OUT || pb.direction == PARAM_DIR_INOUT {
                if pb.user_ptr != 0 {
                    sizes.push((i as u8, pb.size as u64));
                }
            }
        }
        sizes
    }

    /// Write beacon-returned OUT/INOUT buffer contents back into the shared
    /// `ParamBuf.data` so the kmod can copy_to_user them.
    pub fn write_out_bufs(&mut self, slot: usize, out_bufs: &[SyscallBuf]) {
        let cb = self.ctl_buffer();
        let slot_bufs = &mut cb.bufs[slot];
        for sb in out_bufs {
            let idx = sb.arg_idx as usize;
            if idx >= slot_bufs.params.len() {
                continue;
            }
            let pb = &mut slot_bufs.params[idx];
            let n = sb.data.len().min(pb.data.len());
            pb.data[..n].copy_from_slice(&sb.data[..n]);
            pb.size = n as u32;
        }
    }

    /// Write `"DONE {slot_idx} {retval}\n"` to `/proc/rscaller` so the kmod
    /// can wake the blocked process and deliver the return value.
    pub fn signal_done(&mut self, slot_idx: u32, retval: i64) -> Result<()> {
        let msg = format!("DONE {} {}\n", slot_idx, retval);
        self.proc_file.write_all(msg.as_bytes())?;
        Ok(())
    }

    /// Convert a `KmodSyscall` into a `SyscallRequest` suitable for sending
    /// over the wire to rsbeacon.
    pub fn to_request(slot_idx: u32, sc: &KmodSyscall) -> SyscallRequest {
        let mut args = [0u64; 6];
        for (i, param) in sc.param_bufs.iter().enumerate() {
            // Safety: all union variants are integer/pointer-width types;
            // reading as ulong_type (u64) is always safe.
            args[i] = unsafe { param.ulong_type };
        }
        SyscallRequest {
            slot_idx: slot_idx as u64,
            number: sc.number as u64,
            args,
            in_bufs: Vec::new(),
            out_sizes: Vec::new(),
        }
    }

    /// Main relay loop.
    ///
    /// Polls the `kernel_to_user` ring buffer for incoming syscall intercepts,
    /// forwards each one to rsbeacon, awaits the response, then signals
    /// completion back to the kmod.
    pub async fn run(&mut self) -> Result<()> {
        info!("Relay started");

        loop {
            match self.pop_syscall() {
                Some((slot, sc)) => {
                    debug!(
                        slot,
                        syscall = sc.number,
                        n_params = sc.n_params,
                        "dispatching syscall to beacon"
                    );

                    let n_params = sc.n_params as usize;
                    let in_bufs = self.read_in_bufs(slot, n_params);
                    let out_sizes = self.read_out_sizes(slot, n_params);

                    let mut req = Self::to_request(slot as u32, &sc);
                    req.in_bufs = in_bufs;
                    req.out_sizes = out_sizes;

                    if let Err(e) = write_message(&mut self.beacon_writer, &req).await {
                        warn!(error = %e, "failed to send request to beacon");
                        // Signal an error return so the kernel process is not stuck.
                        self.signal_done(slot as u32, -EINVAL)?;
                        continue;
                    }

                    let resp_result = tokio::time::timeout(
                        Duration::from_secs(30),
                        read_message::<SyscallResponse, _>(&mut self.beacon_reader),
                    ).await;
                    match resp_result {
                        Ok(Ok(resp)) => {
                            debug!(
                                slot = resp.slot_idx,
                                ret = resp.ret,
                                "beacon response received"
                            );
                            self.write_out_bufs(resp.slot_idx as usize, &resp.out_bufs);
                            self.signal_done(resp.slot_idx as u32, resp.ret)?;
                        }
                        Ok(Err(e)) => {
                            warn!(error = %e, "failed to read response from beacon");
                            self.signal_done(slot as u32, -EINVAL)?;
                            return Err(e);
                        }
                        Err(_) => {
                            warn!(slot, "beacon response timeout — signaling EINVAL");
                            self.signal_done(slot as u32, -EINVAL)?;
                            return Err(anyhow::anyhow!("beacon response timeout"));
                        }
                    }
                }
                None => {
                    tokio::task::yield_now().await;
                }
            }
        }
    }
}

/// EINVAL (22) — used as fallback error return when beacon connection fails.
/// Negated when passed to `signal_done` so the kernel sees -EINVAL.
const EINVAL: i64 = 22;
