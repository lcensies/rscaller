//! Seccomp-unotify controller backend.
//!
//! Uses `SECCOMP_RET_USER_NOTIF` to intercept syscalls from a supervised
//! process without any kernel module.  The notify fd is obtained by calling
//! `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, ...)`.
//!
//! # Architecture overview
//!
//! 1. `rsc` (the launcher) installs a BPF filter with `SECCOMP_RET_USER_NOTIF`
//!    for the target syscalls and calls `SECCOMP_GET_NOTIF_SIZES` to get a
//!    notify fd.  It passes this fd to `rsclient` (e.g. via an inherited fd or
//!    an env-var `RSCALLER_NOTIF_FD`).
//! 2. `rsclient` constructs a `SeccompController` from that fd.
//! 3. The relay calls `recv()` which does `ioctl(SECCOMP_IOCTL_NOTIF_RECV)` on
//!    the fd, blocking until a syscall is intercepted.
//! 4. After getting the response from rsbeacon, the relay calls `complete()`
//!    which does `ioctl(SECCOMP_IOCTL_NOTIF_SEND)` to inject the return value
//!    and resume the traced process.
//!
//! # Reading pointer arguments from the tracee
//!
//! Unlike the kmod (which copies args via `copy_from_user` into the shared
//! buffer), seccomp-unotify only delivers raw register values.  For syscalls
//! that take pointer arguments (e.g. `openat`, `read`), the relay must read
//! the data with `process_vm_readv(2)` using the tracee's PID from
//! [`Notification::pid`].  This is the caller's responsibility.
//!
//! # Kernel version
//! `SECCOMP_RET_USER_NOTIF` is available since Linux 5.0.
//! `SECCOMP_IOCTL_NOTIF_ADDFD` (fd injection) requires Linux 5.9.

use std::os::fd::AsRawFd;
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use std::mem;

use anyhow::{bail, Result};
use async_trait::async_trait;
use libc::{c_long, syscall, SYS_seccomp};
use tracing::debug;

use crate::meta::{build_table, read_tracee_mem, resolve_size, write_tracee_mem, Dir};
use crate::notification::InBuf;
use crate::{Notification, SyscallController};

// ---------------------------------------------------------------------------
// Raw C struct definitions (must match linux/seccomp.h)
// ---------------------------------------------------------------------------

/// `struct seccomp_data` from linux/seccomp.h
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

/// `struct seccomp_notif` from linux/seccomp.h
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

/// `struct seccomp_notif_resp` from linux/seccomp.h
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

// Compile-time layout assertions.
const _: () = {
    assert!(mem::size_of::<SeccompData>() == 64);
    assert!(mem::size_of::<SeccompNotif>() == 80);
    assert!(mem::size_of::<SeccompNotifResp>() == 24);
};

// ---------------------------------------------------------------------------
// ioctl numbers (computed from linux/ioctl.h macros)
//
// _IOWR(type, nr, size) = (3<<30) | ((size)<<16) | ((type)<<8) | (nr)
// _IOW(type, nr, size)  = (1<<30) | ((size)<<16) | ((type)<<8) | (nr)
// SECCOMP_IOC_MAGIC = '!' = 0x21
// ---------------------------------------------------------------------------
const SECCOMP_IOC_MAGIC: u32 = b'!' as u32;

const fn iowr(nr: u32, size: usize) -> libc::c_ulong {
    ((3u64 << 30) | ((size as u64) << 16) | ((SECCOMP_IOC_MAGIC as u64) << 8) | nr as u64)
        as libc::c_ulong
}

#[allow(dead_code)]
const fn iow(nr: u32, size: usize) -> libc::c_ulong {
    ((1u64 << 30) | ((size as u64) << 16) | ((SECCOMP_IOC_MAGIC as u64) << 8) | nr as u64)
        as libc::c_ulong
}

const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong =
    iowr(0, mem::size_of::<SeccompNotif>());
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong =
    iowr(1, mem::size_of::<SeccompNotifResp>());
#[allow(dead_code)]
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong =
    iow(2, mem::size_of::<u64>());

// ---------------------------------------------------------------------------
// seccomp(2) syscall wrappers
// ---------------------------------------------------------------------------

/// BPF filter flag: the call returns a new listener fd.
const SECCOMP_FILTER_FLAG_NEW_LISTENER: u32 = 1 << 3;

/// Install a seccomp BPF filter and return the listener fd.
///
/// The filter must set `SECCOMP_RET_USER_NOTIF` for every syscall number you
/// want to intercept.  Syscalls not matched fall through to
/// `SECCOMP_RET_ALLOW` (or whatever default the filter specifies).
///
/// # Safety
/// `prog` must point to a valid `sock_fprog`.
pub unsafe fn seccomp_install_filter(prog: *const libc::sock_fprog) -> Result<OwnedFd> {
    let fd = syscall(
        SYS_seccomp,
        libc::SECCOMP_SET_MODE_FILTER as c_long,
        SECCOMP_FILTER_FLAG_NEW_LISTENER as c_long,
        prog as c_long,
    );
    if fd < 0 {
        bail!(
            "seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(OwnedFd::from_raw_fd(fd as RawFd))
}

// BPF constants shared by both filter builders below.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc00000;

// offsetof(struct seccomp_data, nr) == 0
const OFFSET_NR: u32 = 0;

/// offsetof(struct seccomp_data, args[i]) == 16 + 8*i. Each `args[i]` is a
/// 64-bit value but classic BPF can only load 32-bit words, so a full
/// comparison needs both halves. x86-64 is little-endian: the low 32 bits
/// live at the base offset, the high 32 bits 4 bytes further in.
fn offset_arg_lo(i: u8) -> u32 {
    16 + 8 * i as u32
}
fn offset_arg_hi(i: u8) -> u32 {
    offset_arg_lo(i) + 4
}

fn ld_abs(offset: u32) -> libc::sock_filter {
    libc::sock_filter { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: offset }
}
fn jeq(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt, jf, k }
}
fn jgt(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code: BPF_JMP | BPF_JGT | BPF_K, jt, jf, k }
}
fn jge(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code: BPF_JMP | BPF_JGE | BPF_K, jt, jf, k }
}
fn ret(k: u32) -> libc::sock_filter {
    libc::sock_filter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k }
}

/// Build a BPF filter with `SECCOMP_RET_USER_NOTIF` for the given syscall
/// numbers, allowing all others (equivalent to the pre-fd-gating filter —
/// kept for callers/tests that don't need the fd-range distinction).
pub fn build_filter(syscall_nrs: &[u32]) -> (Vec<libc::sock_filter>, libc::sock_fprog) {
    build_filter_fd_gated(syscall_nrs, &[])
}

/// Build a BPF filter with two categories of intercepted syscalls:
///
/// - `always_nrs`: `SECCOMP_RET_USER_NOTIF` unconditionally (e.g. `socket`,
///   `connect`, `bind` — there's no meaningful "real fd" for these to fall
///   back to).
/// - `fd_gated_nrs`: `SECCOMP_RET_USER_NOTIF` only if `args[0]` (the fd
///   argument — true for `read`/`write`/`close`/`poll`/`ppoll`, the only
///   syscalls this is meant for) is `>= VIRTUAL_FD_BASE`
///   (`rscaller_proto::types::VIRTUAL_FD_BASE`); otherwise `SECCOMP_RET_ALLOW`
///   (runs against the tracee's real kernel, untouched). This is what lets
///   a profile intercept `read`/`write`/`close` on rsbeacon-backend-owned
///   virtual fds *without* round-tripping every ordinary file/pipe/real-
///   socket read or write through rsbeacon too.
///
/// Any syscall number present in both lists is treated as fd-gated (the
/// `always_nrs` JEQ for it would be unreachable dead code, so callers
/// should not do this, but it's not unsound — just wasteful).
///
/// Returns `(instructions, sock_fprog)` — keep `instructions` alive as long
/// as the `sock_fprog` is used.
pub fn build_filter_fd_gated(
    always_nrs: &[u32],
    fd_gated_nrs: &[u32],
) -> (Vec<libc::sock_filter>, libc::sock_fprog) {
    let threshold = rscaller_proto::types::VIRTUAL_FD_BASE as u64;
    let threshold_lo = (threshold & 0xffff_ffff) as u32;
    debug_assert_eq!(
        threshold >> 32,
        0,
        "VIRTUAL_FD_BASE must fit in 32 bits for this filter's high-word fast path"
    );

    // Program layout (all jumps forward-only, as required by classic BPF):
    //
    //   0:                LD nr
    //   1..=A:            JEQ always_nrs[i] -> NOTIF                  (fall through)
    //   A+1..=A+F:        JEQ fd_gated_nrs[i] -> FDCHECK               (fall through)
    //   A+F+1:            RET ALLOW                        [ALLOW1]
    //   A+F+2:            LD args[0] hi                    [FDCHECK]
    //   A+F+3:            JGT 0 -> NOTIF                              (fall through)
    //   A+F+4:            LD args[0] lo
    //   A+F+5:            JGE threshold_lo -> NOTIF                   (fall through)
    //   A+F+6:            RET ALLOW                        [ALLOW2]
    //   A+F+7:            RET NOTIF                        [NOTIF]
    let a = always_nrs.len();
    let f = fd_gated_nrs.len();
    // Instruction index (0-based) of the shared FDCHECK block's first
    // instruction and of the final RET NOTIF — computed once, up front, so
    // every JEQ/JGT/JGE below can compute its own forward-relative jt.
    let idx_fdcheck = 1 + a + f + 1; // skip LD, all JEQs, and ALLOW1
    let idx_notif = idx_fdcheck + 5; // FDCHECK block is 5 instructions long

    let mut insns: Vec<libc::sock_filter> = Vec::with_capacity(idx_notif + 1);

    insns.push(ld_abs(OFFSET_NR)); // 0

    for &nr in always_nrs {
        let here = insns.len();
        let jt = (idx_notif - (here + 1)) as u8;
        insns.push(jeq(nr, jt, 0));
    }
    for &nr in fd_gated_nrs {
        let here = insns.len();
        let jt = (idx_fdcheck - (here + 1)) as u8;
        insns.push(jeq(nr, jt, 0));
    }

    debug_assert_eq!(insns.len(), 1 + a + f);
    insns.push(ret(SECCOMP_RET_ALLOW)); // ALLOW1, idx = 1+a+f

    debug_assert_eq!(insns.len(), idx_fdcheck);
    insns.push(ld_abs(offset_arg_hi(0)));
    {
        let here = insns.len();
        let jt = (idx_notif - (here + 1)) as u8;
        insns.push(jgt(0, jt, 0));
    }
    insns.push(ld_abs(offset_arg_lo(0)));
    {
        let here = insns.len();
        let jt = (idx_notif - (here + 1)) as u8;
        insns.push(jge(threshold_lo, jt, 0));
    }
    insns.push(ret(SECCOMP_RET_ALLOW)); // ALLOW2

    debug_assert_eq!(insns.len(), idx_notif);
    insns.push(ret(SECCOMP_RET_USER_NOTIF)); // NOTIF

    let prog = libc::sock_fprog {
        len: insns.len() as u16,
        filter: insns.as_mut_ptr(),
    };

    (insns, prog)
}

// ---------------------------------------------------------------------------
// Metadata-driven pointer-arg filling
// ---------------------------------------------------------------------------

/// Use the syscall metadata table to populate `in_data` (via `process_vm_readv`)
/// and `out_sizes` for a given notification.
///
/// Called immediately after `SECCOMP_IOCTL_NOTIF_RECV` returns while the
/// tracee is still blocked — the pointers in `args` are still valid.
fn fill_from_meta(nr: u64, args: &[u64; 6], pid: u32) -> (Vec<InBuf>, Vec<(u8, u64)>) {
    use std::sync::OnceLock;
    use std::collections::HashMap;
    use crate::meta::SyscallMeta;

    static TABLE: OnceLock<HashMap<u64, SyscallMeta>> = OnceLock::new();
    let table = TABLE.get_or_init(build_table);

    let Some(meta) = table.get(&nr) else {
        return (Vec::new(), Vec::new());
    };

    let mut in_data = Vec::new();
    let mut out_sizes = Vec::new();

    for param in &meta.ptr_params {
        let ptr = args[param.idx as usize];
        if ptr == 0 {
            continue;
        }
        let size = resolve_size(param, args, pid);
        if size == 0 {
            continue;
        }

        match param.dir {
            Dir::In | Dir::InOut => {
                // Read bytes from tracee address space.
                if let Some(data) = read_tracee_mem(pid, ptr, size) {
                    in_data.push(InBuf { arg_idx: param.idx, data });
                }
                // InOut also needs an out_sizes entry.
                if param.dir == Dir::InOut {
                    out_sizes.push((param.idx, size as u64));
                }
            }
            Dir::Out => {
                out_sizes.push((param.idx, size as u64));
            }
        }
    }

    (in_data, out_sizes)
}

// `read_tracee_mem`/`write_tracee_mem` now live in `meta.rs` (imported
// above) — `resolve_size`'s `Size::FromPtrU32` variant needs the same
// `process_vm_readv` capability, so both live next to the metadata table
// that drives them.

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

/// Seccomp-unotify syscall controller.
///
/// Constructed from an already-opened seccomp notify fd.  The fd is obtained
/// by the launcher (`rsc`) via [`seccomp_install_filter`] and passed to
/// `rsclient` (e.g. via an inherited fd or `RSCALLER_NOTIF_FD` env var).
pub struct SeccompController {
    fd: RawFd,
    _owned: OwnedFd,
    /// PID of the last tracee that delivered a notification.
    /// Used by `complete` to write OUT buffers back via `process_vm_writev`.
    tracee_pid: u32,
}

impl SeccompController {
    /// Wrap an existing seccomp notify fd.
    ///
    /// Takes ownership of the fd — it will be closed when this struct is dropped.
    pub fn from_fd(fd: OwnedFd) -> Self {
        let raw = fd.as_raw_fd();
        Self { fd: raw, _owned: fd, tracee_pid: 0 }
    }

    /// Open a notify fd from the integer in `RSCALLER_NOTIF_FD` env var.
    ///
    /// `rsc` sets this before `exec`-ing `rsclient`.
    pub fn from_env() -> Result<Self> {
        let fd_str = std::env::var("RSCALLER_NOTIF_FD")
            .map_err(|_| anyhow::anyhow!("RSCALLER_NOTIF_FD not set"))?;
        let raw: RawFd = fd_str
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("RSCALLER_NOTIF_FD is not a valid fd integer"))?;
        // SAFETY: caller must ensure this fd is valid and not aliased elsewhere.
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self::from_fd(owned))
    }

    /// Check if a notification id is still valid (process has not exited/exec'd).
    #[allow(dead_code)]
    fn id_valid(&self, id: u64) -> bool {
        let mut id_val = id;
        let ret = unsafe {
            libc::ioctl(
                self.fd,
                SECCOMP_IOCTL_NOTIF_ID_VALID,
                &mut id_val as *mut u64,
            )
        };
        ret == 0
    }
}

#[async_trait]
impl SyscallController for SeccompController {
    async fn recv(&mut self) -> Result<Option<Notification>> {
        // SECCOMP_IOCTL_NOTIF_RECV blocks until a notification is available.
        // We run it in a spawn_blocking thread so we don't block the async runtime.
        let fd = self.fd;
        let notif = tokio::task::spawn_blocking(move || -> Result<Option<SeccompNotif>> {
            let mut n: SeccompNotif = unsafe { mem::zeroed() };
            let ret = unsafe {
                libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &mut n as *mut SeccompNotif)
            };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                // ENOENT = process exited while we were waiting
                if err.raw_os_error() == Some(libc::ENOENT) {
                    return Ok(None);
                }
                return Err(anyhow::anyhow!("SECCOMP_IOCTL_NOTIF_RECV: {}", err));
            }
            Ok(Some(n))
        })
        .await??;

        let Some(n) = notif else {
            return Ok(None);
        };

        debug!(
            id = n.id,
            pid = n.pid,
            nr = n.data.nr,
            "seccomp notification"
        );

        let nr = n.data.nr as u64;
        let args = n.data.args;
        let pid = n.pid;
        self.tracee_pid = pid;
        let (in_data, out_sizes) = fill_from_meta(nr, &args, pid);

        Ok(Some(Notification {
            id: n.id,
            nr,
            args,
            pid,
            in_data,
            out_sizes,
        }))
    }

    async fn complete(
        &mut self,
        id: u64,
        retval: i64,
        out_bufs: &[(u8, Vec<u8>)],
        original_args: &crate::SyscallArgs,
    ) -> Result<()> {
        // Write OUT buffer data back into the tracee's address space via
        // process_vm_writev before resuming it.
        // We need the tracee PID — stash it alongside the fd.
        let pid = self.tracee_pid;
        for (arg_idx, data) in out_bufs {
            let addr = original_args[*arg_idx as usize];
            if addr == 0 || data.is_empty() { continue; }
            write_tracee_mem(pid, addr, data);
        }

        let fd = self.fd;
        let resp = SeccompNotifResp {
            id,
            val: if retval < 0 { 0 } else { retval },
            error: if retval < 0 { retval as i32 } else { 0 },
            flags: 0,
        };

        let ret = unsafe {
            libc::ioctl(
                fd,
                SECCOMP_IOCTL_NOTIF_SEND,
                &resp as *const SeccompNotifResp,
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(());
            }
            bail!("SECCOMP_IOCTL_NOTIF_SEND id={}: {}", id, err);
        }

        Ok(())
    }

    async fn continue_syscall(&mut self, id: u64) -> Result<()> {
        // SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1: kernel runs the syscall itself.
        const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
        let fd = self.fd;
        let resp = SeccompNotifResp {
            id,
            val: 0,
            error: 0,
            flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        };
        let ret = unsafe {
            libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp as *const SeccompNotifResp)
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(());
            }
            bail!("continue_syscall SECCOMP_IOCTL_NOTIF_SEND id={}: {}", id, err);
        }
        Ok(())
    }
}

#[cfg(test)]
mod filter_tests {
    use super::*;

    /// Minimal classic BPF interpreter for exactly the instruction subset
    /// `build_filter_fd_gated` emits (`LD_ABS W`, `JEQ`/`JGT`/`JGE K`,
    /// `RET K`), run against a `SeccompData`-shaped byte buffer. Lets us
    /// validate the generated jump math without an actual `seccomp(2)`
    /// syscall (which needs a real kernel + no_new_privs/CAP_SYS_ADMIN).
    fn run_filter(insns: &[libc::sock_filter], data: &SeccompData) -> u32 {
        let bytes = data_to_bytes(data);
        let mut pc = 0usize;
        let mut acc: u32 = 0;
        loop {
            let ins = insns[pc];
            let class = ins.code & 0x07;
            match class {
                0x00 => {
                    // LD | W | ABS — the only load form we ever generate.
                    let off = ins.k as usize;
                    acc = u32::from_ne_bytes(bytes[off..off + 4].try_into().unwrap());
                    pc += 1;
                }
                0x05 => {
                    let op = ins.code & 0xf0;
                    let taken = match op {
                        0x10 => acc == ins.k,
                        0x20 => acc > ins.k,
                        0x30 => acc >= ins.k,
                        _ => panic!("unsupported jmp op in test interpreter: {op:#x}"),
                    };
                    pc = if taken {
                        pc + 1 + ins.jt as usize
                    } else {
                        pc + 1 + ins.jf as usize
                    };
                }
                0x06 => return ins.k,
                _ => panic!("unsupported bpf class in test interpreter: {class:#x}"),
            }
        }
    }

    fn data_to_bytes(d: &SeccompData) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(&d.nr.to_ne_bytes());
        buf[4..8].copy_from_slice(&d.arch.to_ne_bytes());
        buf[8..16].copy_from_slice(&d.instruction_pointer.to_ne_bytes());
        for i in 0..6 {
            buf[16 + 8 * i..16 + 8 * i + 8].copy_from_slice(&d.args[i].to_ne_bytes());
        }
        buf
    }

    fn data_for(nr: i32, args: [u64; 6]) -> SeccompData {
        SeccompData { nr, arch: 0, instruction_pointer: 0, args }
    }

    #[test]
    fn always_list_notifies_regardless_of_fd() {
        let (insns, _prog) = build_filter_fd_gated(&[41, 42], &[0, 1, 3]);
        let d = data_for(41, [0; 6]);
        assert_eq!(run_filter(&insns, &d), SECCOMP_RET_USER_NOTIF);
    }

    #[test]
    fn fd_gated_low_fd_is_allowed() {
        let (insns, _prog) = build_filter_fd_gated(&[41], &[0, 1, 3]);
        let mut args = [0u64; 6];
        args[0] = 3; // an ordinary low fd
        let d = data_for(1 /* write */, args);
        assert_eq!(run_filter(&insns, &d), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn fd_gated_high_fd_notifies() {
        let (insns, _prog) = build_filter_fd_gated(&[41], &[0, 1, 3]);
        let mut args = [0u64; 6];
        args[0] = rscaller_proto::types::VIRTUAL_FD_BASE as u64 + 5;
        let d = data_for(1, args);
        assert_eq!(run_filter(&insns, &d), SECCOMP_RET_USER_NOTIF);
    }

    #[test]
    fn fd_gated_exact_threshold_notifies() {
        let (insns, _prog) = build_filter_fd_gated(&[], &[0]);
        let mut args = [0u64; 6];
        args[0] = rscaller_proto::types::VIRTUAL_FD_BASE as u64;
        let d = data_for(0, args);
        assert_eq!(run_filter(&insns, &d), SECCOMP_RET_USER_NOTIF);
    }

    #[test]
    fn fd_gated_just_below_threshold_is_allowed() {
        let (insns, _prog) = build_filter_fd_gated(&[], &[0]);
        let mut args = [0u64; 6];
        args[0] = rscaller_proto::types::VIRTUAL_FD_BASE as u64 - 1;
        let d = data_for(0, args);
        assert_eq!(run_filter(&insns, &d), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn fd_gated_high_word_nonzero_notifies() {
        // Value far beyond 32 bits must still trigger the high-word check.
        let (insns, _prog) = build_filter_fd_gated(&[], &[0]);
        let mut args = [0u64; 6];
        args[0] = 1u64 << 40;
        let d = data_for(0, args);
        assert_eq!(run_filter(&insns, &d), SECCOMP_RET_USER_NOTIF);
    }

    #[test]
    fn unrelated_syscall_is_allowed() {
        let (insns, _prog) = build_filter_fd_gated(&[41, 42], &[0, 1, 3]);
        let d = data_for(2 /* open, in neither list */, [0; 6]);
        assert_eq!(run_filter(&insns, &d), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn every_always_and_fd_gated_syscall_individually() {
        let always = [41u32, 42, 44, 45, 49, 50, 54, 55, 288];
        let fd_gated = [0u32, 1, 3, 7, 271];
        let (insns, _prog) = build_filter_fd_gated(&always, &fd_gated);
        for &nr in &always {
            let d = data_for(nr as i32, [0; 6]);
            assert_eq!(run_filter(&insns, &d), SECCOMP_RET_USER_NOTIF, "nr={nr}");
        }
        for &nr in &fd_gated {
            let mut args = [0u64; 6];
            args[0] = rscaller_proto::types::VIRTUAL_FD_BASE as u64 + 1;
            let d = data_for(nr as i32, args);
            assert_eq!(run_filter(&insns, &d), SECCOMP_RET_USER_NOTIF, "nr={nr} (high fd)");
            args[0] = 5;
            let d = data_for(nr as i32, args);
            assert_eq!(run_filter(&insns, &d), SECCOMP_RET_ALLOW, "nr={nr} (low fd)");
        }
    }

    #[test]
    fn plain_build_filter_still_notifies_unconditionally() {
        let (insns, _prog) = build_filter(&[59]);
        let d = data_for(59, [0; 6]);
        assert_eq!(run_filter(&insns, &d), SECCOMP_RET_USER_NOTIF);
        let d2 = data_for(60, [0; 6]);
        assert_eq!(run_filter(&insns, &d2), SECCOMP_RET_ALLOW);
    }
}
