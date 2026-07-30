//! `ctls` — syscall interception controller abstraction.
//!
//! Each *controller* backend captures syscalls from a running process and
//! presents them through a uniform [`SyscallController`] interface.  The
//! relay loop is backend-agnostic: it just calls [`SyscallController::recv`]
//! to get the next notification and [`SyscallController::complete`] to inject
//! the return value.
//!
//! # Backends
//!
//! | Feature flag | Module            | Mechanism                                    |
//! |--------------|-------------------|----------------------------------------------|
//! | `kmod`       | [`kmod`]          | Shared-memory ring buffer via `/proc/rscaller` mmap |
//! | `seccomp`    | [`seccomp`]       | `SECCOMP_RET_USER_NOTIF` notify fd           |
//!
//! Older mmap/text_poke experiments live in git history (pre-v4.4).

pub mod meta;
pub mod notification;
#[cfg(feature = "kmod")]
pub mod kmod;
#[cfg(feature = "seccomp")]
pub mod seccomp;

pub use notification::{Notification, SyscallArgs};

use anyhow::Result;
use async_trait::async_trait;
use std::os::unix::io::RawFd;

/// The controller interface every backend must implement.
///
/// A controller owns the channel to the intercepted process.  The relay calls
/// [`recv`] in a loop and [`complete`] once it has a return value from the
/// beacon.
#[async_trait]
pub trait SyscallController: Send {
    /// Wait for the next intercepted syscall notification.
    ///
    /// Blocks (async) until a notification is available.  Returns `None` if
    /// the controller has been shut down or the process has exited.
    async fn recv(&mut self) -> Result<Option<Notification>>;

    /// Inject the syscall result back into the intercepted process.
    ///
    /// - `id` must match [`Notification::id`].
    /// - `retval` is the raw i64 return value (negative errno on error).
    /// - `out_bufs` is the list of OUT buffer payloads from rsbeacon.
    ///   Each `(arg_idx, data)` pair must be written into the tracee's address
    ///   space at `original_args[arg_idx]` before the process is resumed.
    ///   For the kmod backend the kmod handles this via `copy_to_user`; the
    ///   data was already placed in the shared mmap by the relay.
    ///   For the seccomp backend the relay writes it via `process_vm_writev`.
    /// - `original_args` is the `args` field from the original `Notification`,
    ///   needed by the seccomp backend to find the tracee's pointer addresses.
    async fn complete(
        &mut self,
        id: u64,
        retval: i64,
        out_bufs: &[(u8, Vec<u8>)],
        original_args: &SyscallArgs,
    ) -> Result<()>;

    /// Resume the intercepted syscall locally — let the kernel execute it as
    /// if it were never intercepted.
    ///
    /// For the seccomp backend this sends `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
    /// For the kmod backend there is no equivalent; the default impl returns
    /// an error so callers know forwarding is required.
    async fn continue_syscall(&mut self, id: u64) -> Result<()> {
        let _ = id;
        anyhow::bail!("continue_syscall not supported by this controller backend")
    }

    /// Complete a notification by injecting `local_fd` — an fd valid in
    /// THIS process (the controller/relay), e.g. one half of a
    /// `socketpair()` — into the tracee's own fd table, using the newly
    /// installed fd number as the syscall's return value.
    ///
    /// Only meaningful for syscalls that return a *new* fd (`socket`,
    /// `accept4`): it lets a real, locally-backed fd stand in for what
    /// used to be a bare virtual fd number, so every later `read`/`write`/
    /// `close`/`poll`/`fcntl`/`ioctl` on it is an ordinary local syscall —
    /// never seen by this controller again — while a background task on
    /// the *other* half of the pair relays actual bytes to/from rsbeacon
    /// using the existing per-syscall request/response API, unchanged.
    ///
    /// For the seccomp backend this is `SECCOMP_IOCTL_NOTIF_ADDFD` with
    /// `SECCOMP_ADDFD_FLAG_SEND` (Linux 5.9+), which atomically injects the
    /// fd *and* completes/resumes the notification with it as the return
    /// value. The kmod backend has no equivalent (and doesn't need one —
    /// see `AGENTS.md`'s "shadow fd" note); the default impl returns an
    /// error so callers know to fall back to a plain `complete(id, retval,
    /// ...)` with the original (virtual fd) value instead.
    ///
    /// Returns the fd number as installed in the *tracee's* fd table
    /// (usually different from `local_fd`, which is a number in the
    /// caller's own table).
    async fn complete_with_fd(&mut self, id: u64, local_fd: RawFd) -> Result<RawFd> {
        let _ = (id, local_fd);
        anyhow::bail!("complete_with_fd not supported by this controller backend")
    }
}
