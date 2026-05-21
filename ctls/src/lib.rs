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
}
