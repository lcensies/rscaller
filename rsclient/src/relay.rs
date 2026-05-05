use std::fs::File;
use std::io::Write;
use std::time::Duration;

use anyhow::Result;
use memmap2::MmapMut;
use rscaller_proto::codec::{read_message, write_message};
use rscaller_proto::types::{SyscallRequest, SyscallResponse};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use crate::kmod::{ControlBuffer, KmodSyscall};

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

        q.head_idx = (q.head_idx + 1) % QUEUE_SIZE as i32;
        q.size -= 1;

        Some((slot, syscall))
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

                    let req = Self::to_request(slot as u32, &sc);

                    if let Err(e) = write_message(&mut self.beacon_writer, &req).await {
                        warn!(error = %e, "failed to send request to beacon");
                        // Signal an error return so the kernel process is not stuck.
                        self.signal_done(slot as u32, -EINVAL)?;
                        continue;
                    }

                    match read_message::<SyscallResponse, _>(&mut self.beacon_reader).await {
                        Ok(resp) => {
                            debug!(
                                slot = resp.slot_idx,
                                ret = resp.ret,
                                "beacon response received"
                            );
                            self.signal_done(resp.slot_idx as u32, resp.ret)?;
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to read response from beacon");
                            self.signal_done(slot as u32, -EINVAL)?;
                        }
                    }
                }
                None => {
                    // Queue is empty — yield the async executor so we don't
                    // spin-burn the CPU.
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }
    }
}

/// EINVAL (22) — used as fallback error return when beacon connection fails.
/// Negated when passed to `signal_done` so the kernel sees -EINVAL.
const EINVAL: i64 = 22;
