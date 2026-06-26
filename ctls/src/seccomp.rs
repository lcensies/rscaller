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

use crate::meta::{build_table, resolve_size, Dir};
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

/// Build a minimal BPF filter that traps the given syscall numbers with
/// `SECCOMP_RET_USER_NOTIF` and allows all others.
///
/// Returns `(instructions, sock_fprog)` — keep `instructions` alive as long
/// as the `sock_fprog` is used.
pub fn build_filter(syscall_nrs: &[u32]) -> (Vec<libc::sock_filter>, libc::sock_fprog) {
    // BPF constants
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
    const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc00000;

    // offsetof(seccomp_data, nr) == 0
    const OFFSET_NR: u32 = 0;

    let mut insns: Vec<libc::sock_filter> = Vec::new();

    // Load syscall nr into accumulator.
    insns.push(libc::sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: OFFSET_NR,
    });

    // For each intercepted syscall: JEQ nr → USER_NOTIF (jump to ret_notif)
    // The jump offset calculation: after we push all JEQ instructions and the
    // RET_ALLOW, we'll jump to RET_USER_NOTIF.  We arrange it as:
    //   [load] [jeq_0] [jeq_1] ... [jeq_N] [ret_allow] [ret_notif]
    //
    // jeq_i: if equal, jump forward (N - i) instructions to ret_notif
    //        else fall through to next jeq.
    let n = syscall_nrs.len();
    for (i, &nr) in syscall_nrs.iter().enumerate() {
        // jt = jump if equal; jf = 0 (fall through)
        let jt = (n - i) as u8; // skip remaining jeqs + ret_allow
        insns.push(libc::sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt,
            jf: 0,
            k: nr,
        });
    }

    // Default: allow.
    insns.push(libc::sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    // Target for matched syscalls.
    insns.push(libc::sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_USER_NOTIF,
    });

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
        let size = resolve_size(param, args);
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

/// Write `data` into `pid`'s virtual address `addr` using `process_vm_writev`.
/// Silently ignores failures (process may have exited).
fn write_tracee_mem(pid: u32, addr: u64, data: &[u8]) {
    let local = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: data.len(),
    };
    unsafe {
        libc::process_vm_writev(
            pid as libc::pid_t,
            &local as *const libc::iovec,
            1,
            &remote as *const libc::iovec,
            1,
            0,
        );
    }
}

/// Read `len` bytes from `pid`'s virtual address `addr` using `process_vm_readv`.
/// Returns `None` on failure (e.g. process exited, bad pointer).
fn read_tracee_mem(pid: u32, addr: u64, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };
    let ret = unsafe {
        libc::process_vm_readv(
            pid as libc::pid_t,
            &local as *const libc::iovec,
            1,
            &remote as *const libc::iovec,
            1,
            0,
        )
    };
    if ret < 0 {
        None
    } else {
        buf.truncate(ret as usize);
        Some(buf)
    }
}

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
