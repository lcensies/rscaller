//! Virtual file descriptor table shared by network backends that need to
//! track fds not backed by a real kernel fd (e.g. `smoltcp-xdp`'s sockets,
//! which are serviced entirely in userspace against a `smoltcp` interface).
//!
//! rsbeacon fully controls fd allocation on its side of the RPC — the
//! `SyscallResponse::ret` for a `socket()` call is whatever fd number
//! rsbeacon chooses to hand back, and rsclient/kmod use exactly that number
//! for subsequent syscalls. `SocketTable` allocates fds from a high range
//! so they can never collide with any real kernel fd the beacon process
//! itself has open (stdio, listening sockets, log files, ...).

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

/// First virtual fd handed out. Chosen well above any realistic real-fd
/// count for the beacon process itself. Re-exported from `rscaller-proto`
/// since the client-side seccomp filter (`ctls`/`rsc`) must agree on the
/// exact same value — see that constant's doc comment for why.
pub use rscaller_proto::types::VIRTUAL_FD_BASE;

/// A generic, thread-safe table mapping virtual fds to backend-defined
/// socket entries of type `E`.
pub struct SocketTable<E> {
    next_fd: AtomicI64,
    entries: Mutex<HashMap<i64, E>>,
}

impl<E> Default for SocketTable<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E> SocketTable<E> {
    pub fn new() -> Self {
        Self {
            next_fd: AtomicI64::new(VIRTUAL_FD_BASE),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if `fd` is a value this table could have allocated
    /// (i.e. it's in the virtual fd range). Cheap check that does not
    /// require locking `entries` — useful for a fast-path `owns_syscall`
    /// rejection before taking the lock to check actual membership.
    pub fn is_virtual_fd(fd: i64) -> bool {
        fd >= VIRTUAL_FD_BASE
    }

    /// Allocates a new virtual fd, inserts `entry` for it, and returns the
    /// fd.
    pub fn insert(&self, entry: E) -> i64 {
        let fd = self.next_fd.fetch_add(1, Ordering::Relaxed);
        self.entries.lock().unwrap().insert(fd, entry);
        fd
    }

    /// Returns true if `fd` is currently tracked.
    pub fn contains(&self, fd: i64) -> bool {
        self.entries.lock().unwrap().contains_key(&fd)
    }

    /// Runs `f` against the entry for `fd`, if present.
    pub fn with<R>(&self, fd: i64, f: impl FnOnce(&mut E) -> R) -> Option<R> {
        self.entries.lock().unwrap().get_mut(&fd).map(f)
    }

    /// Removes and returns the entry for `fd`, if present.
    pub fn remove(&self, fd: i64) -> Option<E> {
        self.entries.lock().unwrap().remove(&fd)
    }

    /// Number of currently tracked entries. Mostly useful for tests/metrics.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_fds_in_virtual_range_and_increasing() {
        let table: SocketTable<&'static str> = SocketTable::new();
        let fd1 = table.insert("a");
        let fd2 = table.insert("b");
        assert!(SocketTable::<&'static str>::is_virtual_fd(fd1));
        assert!(SocketTable::<&'static str>::is_virtual_fd(fd2));
        assert!(fd2 > fd1);
    }

    #[test]
    fn contains_and_remove() {
        let table: SocketTable<&'static str> = SocketTable::new();
        let fd = table.insert("entry");
        assert!(table.contains(fd));
        assert_eq!(table.len(), 1);
        let removed = table.remove(fd);
        assert_eq!(removed, Some("entry"));
        assert!(!table.contains(fd));
        assert!(table.is_empty());
    }

    #[test]
    fn with_mutates_entry_in_place() {
        let table: SocketTable<i32> = SocketTable::new();
        let fd = table.insert(1);
        table.with(fd, |v| *v += 41);
        table.with(fd, |v| assert_eq!(*v, 42));
    }

    #[test]
    fn real_fds_are_never_virtual() {
        for real_fd in 0i64..3 {
            assert!(!SocketTable::<()>::is_virtual_fd(real_fd));
        }
    }

    #[test]
    fn missing_fd_is_not_contained() {
        let table: SocketTable<()> = SocketTable::new();
        assert!(!table.contains(VIRTUAL_FD_BASE));
        assert!(table.with(VIRTUAL_FD_BASE, |_| ()).is_none());
        assert!(table.remove(VIRTUAL_FD_BASE).is_none());
    }
}
