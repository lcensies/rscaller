# Syscall Capture Methods: Design Decisions & Trade-offs

## Overview

Rscaller intercepts and forwards syscalls from a tracee process to a remote `rsbeacon` network backend. This document traces the evolution of capture mechanisms for **both networking and filesystem I/O**, the trade-offs of each approach, and the path forward.

Both layers faced a similar progression: bare kmod → seccomp-unotify with virtual fds → FUSE daemon. The filesystem path completed the transition earlier; the network path is still in transition.

---

## Method 1: Bare kmod (khook-based)

**Status:** Removed — replaced by seccomp-unotify.

### Design

- **Hook layer:** Linux kernel module (khook library) patches `x64_sys_call` at runtime.
- **Forwarding:** Every flagged syscall writes to a shared ring buffer (`global_ctl_buffer`), **blocks the kernel thread** waiting for a response from rsclient.
- **Response path:** rsclient reads buffer, calls rsbeacon, writes response back to buffer, kernel thread resumes.

### Strengths

- ✅ **Transparent fd semantics:** Kernel sees all syscalls as normal; epoll/select/dup/fork all work natively without special handling.
- ✅ **No fd translation:** Virtual fd number returned = kernel's own fd number, no extra table needed.
- ✅ **Simple failure mode:** If a syscall isn't gated, it runs normally (default-allow).

### Weaknesses

- ❌ **Thread blocking latency:** Every syscall stalls a kernel thread waiting for rsbeacon response. On high-latency or remote beacons (50–200ms RTT), threads pile up in wait-queues.
- ❌ **Memory pressure:** Thousands of threads blocked in kernel = memory overhead, context-switch thrashing.
- ❌ **Signal safety:** Threads blocked in kmod don't handle signals cleanly; graceful shutdown is difficult.
- ❌ **Maintenance burden:** Kernel module maintenance (version compatibility, architecture-specific code, crash risk).
- ❌ **Deployment friction:** Requires root, kernel headers, compilation on target system.

### Why it was replaced

Latency and operational burden became unbearable with remote beacons. Seccomp-unotify offered a userspace-friendly alternative.

---

## Method 2: Seccomp-unotify (current)

**Status:** Active — primary capture mechanism for both network and filesystem.

### Design

- **Hook layer:** Pure userspace seccomp-unotify (no kmod).
- **Forwarding:** Seccomp filter in userspace traps flagged syscalls into a notification queue.
- **Response path:** rsclient's dispatch loop reads notifications, relays to rsbeacon (or handles locally), sends responses back to kernel.

### Strengths

- ✅ **No kmod maintenance:** Pure userspace, no kernel headers, no compilation, portable.
- ✅ **Async-friendly:** rsclient can be async (tokio); no threads blocked in kernel.
- ✅ **Fine-grained control:** Seccomp BPF filter gates syscalls at the syscall level and fd-number level (e.g., only forward virtual fds).
- ✅ **Lower latency on average:** Userspace dispatch loop doesn't tie up kernel threads; can batch responses.

### Weaknesses

- ❌ **Virtual fd problem (network & filesystem):** Returning a virtual fd (bare number) doesn't work with kernel features that expect real `struct file` objects.
- ❌ **Dispatch loop serialization:** One process-wide serial dispatch loop → multi-threaded apps doing concurrent I/O get serialized through it.
- ❌ **Complexity in relay:** To handle epoll/select (network) or native fs syscalls (filesystem), need parallel mechanisms.

---

## Method 3: Virtual FD Table (Network & Filesystem)

**Status:** Attempted in early seccomp-unotify design; abandoned for both layers.

### Design

- **Fd model:** `socket()`/`open()` returns a bare virtual fd number (e.g., 1073741824).
- **Syscall handling:** Every syscall on that fd (read/write/close/poll/ioctl/fcntl) must be trapped and relayed to rsbeacon.
- **Kernel role:** Kernel has no knowledge of the fd; every operation requires a syscall trap and userspace round-trip.

### Strengths

- ✅ **Minimal complexity:** No background tasks, no injection, just a HashMap lookup.
- ✅ **Simple fallback:** Ungated syscalls just return EBADF (fd doesn't exist in kernel).

### Weaknesses (both network & filesystem)

- ❌ **epoll/select broken:** Kernel's epoll machinery can't mark a virtual fd ready because it has no `struct file` object.
- ❌ **fd passing via SCM_RIGHTS broken:** Can't send a virtual fd number over a Unix socket; receiving end sees garbage.
- ❌ **dup/fork/execve broken:** Kernel can't automatically duplicate or inherit a virtual fd.
- ❌ **io_uring, mmap(fd), other kernel primitives:** All fail — they expect real fds.
- ❌ **Ungated syscall collision risk:** Virtual fd number collides with a real fd the app opened independently → syscalls silently operate on the wrong object.
- ❌ **Enumeration problem:** Can't enumerate every possible syscall + fd combination; apps always find an ungated path.

### Example failures

**Network:** 
```python
import socket
s = socket.socket()
s.settimeout(1.0)  # Calls ioctl(FIONBIO), not fcntl(F_SETFL)
s.connect(("host", 80))  # If ioctl isn't in gate list, fails silently
```

**Filesystem:**
```c
// Virtual fd 1073741824 represents /home/user/secret.txt
int fd = 1073741824;
epoll_add(epfd, fd, ...);  // App expects to wait on file readiness
epoll_wait(epfd, ...);     // Blocks forever — kernel has no fd to poll
```

---

## Method 4: Real-FD ADDFD (SECCOMP_IOCTL_NOTIF_ADDFD)

**Status:** Implemented and working; but introduces parallel mechanism.

### Design

- **Fd injection:** `socket()` syscall returns a real kernel fd (socketpair end) via `SECCOMP_IOCTL_NOTIF_ADDFD`.
- **Control-plane:** connect/bind/listen/setsockopt/getsockopt are relayed to rsbeacon via dispatch loop.
- **Data-plane:** read/write/poll/epoll are handled by the kernel on the real socketpair fd (no relay).
- **Bridge:** Background tokio task per socket proxies the other socketpair end to rsbeacon.

### Strengths

- ✅ **epoll/select work:** Real fd is real `struct file`; kernel's epoll machinery works natively.
- ✅ **dup/fork/SCM_RIGHTS work:** Kernel treats it as a normal fd; all standard operations work.
- ✅ **Low latency on data-plane:** read/write don't trap to seccomp; they're local syscalls to the socketpair (kernel buffers data).
- ✅ **Multi-threaded friendly:** No dispatch-loop serialization on the hot path; each thread operates on its own fd independently.

### Weaknesses

- ❌ **Complexity:** 561 new LOC (socket_proxy.rs + relay.rs changes).
- ❌ **Four bugs found during implementation:**
  1. Proxy task started immediately at `socket()`, raced ahead of tracee's own `connect()` → called `recv()` on `SynSent` socket.
  2. `recv_common()`/`send_common()` misclassified "still connecting" as "closed" → wrong error code.
  3. No way to poll rsbeacon without blocking its worker → added `MSG_DONTWAIT` flag support.
  4. Resource leak on abrupt tracee exit → spawned proxy tasks not awaited, stale TCP sockets on rsbeacon → fixed with `shutdown_proxies()` sweep.
- ❌ **Two separate mechanisms:** Sockets use ADDFD + background tasks; files/proc use FUSE. Inconsistent architecture.
- ❌ **Fd translation overhead:** Relay loop maintains `proxy_fds` HashMap to map real_fd ↔ virtual_fd for control-plane calls.
- ❌ **Deferred-start state machine:** `PendingProxy` struct tracks whether to start proxy immediately (accept4) or defer (socket/connect) → another source of races.

### Why ADDFD was chosen over FUSE for sockets

At the time, extending rscfuse to handle sockets seemed heavier than injecting real fds. ADDFD appeared simpler. In hindsight, this was a premature optimization — the bugs and fragility suggest FUSE would've been cleaner.

---

## Method 5a: FUSE for Filesystem I/O (Completed)

**Status:** Completed and stable. Filesystem forwarding now uses rscfuse.

### Design (Filesystem)

- **Forwarding daemon:** rscfuse (separate userspace daemon) handles all filesystem operations.
- **Mount mechanism:** `/proc`, `/sys`, `/etc/`, and remote paths are mounted via FUSE at startup.
- **Kernel integration:** Apps see real `struct file` objects backed by FUSE; epoll/select/dup/fork all work natively.
- **Async delegation:** rscfuse daemon uses tokio to forward I/O operations to rsbeacon asynchronously.

### How it solved the virtual-fd problem

1. **Real fs objects:** FUSE inodes are real VFS `struct inode` objects with wait-queues. Kernel's epoll/select can poll them.
2. **Proven pattern:** Started with /proc forwarding; extended to /etc and arbitrary remote paths.
3. **No fd translation:** Apps just open paths; kernel returns real fds backed by FUSE. No virtual number trickery.
4. **True async:** rscfuse daemon runs independently; doesn't block rsclient's dispatch loop.

### Why FUSE worked for filesystem

The filesystem use case was amenable to FUSE from the start:
- **Coarser-grained ops:** open/close/read/write/stat are already syscalls; one more context switch to FUSE daemon is acceptable.
- **Fewer per-byte operations:** Large read/write calls amortize FUSE overhead.
- **Natural daemon pattern:** Filesystems have always been kernel ↔ userspace daemons (NFS, SMB, fuse).

---

## Method 5b: FUSE for Network I/O (Proposed Future)

**Status:** Proposed; not yet implemented. Should replace ADDFD for sockets.

### Design

- **Single forwarding mechanism:** Both files and sockets go through rscfuse FUSE daemon.
- **Socket inode type:** `/dev/rsock/<handle>` FUSE-backed inodes represent remote sockets.
- **Readiness signaling:** rsbeacon writes to an eventfd when socket state changes; rscfuse daemon's eventfd reader triggers `wake_up()` on the inode's wait-queue.
- **Kernel integration:** Apps see real `struct file` objects backed by FUSE; epoll/select/dup/fork all work natively without special handling.

### Strengths (Network)

- ✅ **Unified forwarding:** All I/O (files, sockets, /proc) goes through same FUSE daemon — consistent architecture.
- ✅ **Simpler rsclient:** No fd translation table (`proxy_fds` HashMap), no deferred-start state machine (`PendingProxy`), no shutdown sweep. Just route socket syscalls to FUSE mount.
- ✅ **Fewer bugs:** No ADDFD-specific race conditions; kernel's VFS layer handles all fd semantics.
- ✅ **Proven codebase:** rscfuse already handles /proc, /sys, /etc correctly; reuse same patterns for sockets.
- ✅ **No kernel-thread blocking:** FUSE daemon runs async in userspace; no threads pile up waiting for rsbeacon.
- ✅ **Net negative complexity:** ~200 LOC in rscfuse, remove 294 LOC socket_proxy.rs + 150 LOC from relay.rs = **-244 LOC total**.
- ✅ **Signal-based readiness:** eventfd in FUSE daemon's loop, rsbeacon writes it when socket state changes, FUSE daemon wakes kernel's epoll. No busy-loop, nanosecond latency.

### Weaknesses (Network)

- ⚠️ **Extra context switch:** FUSE daemon instead of inline socketpair tasks. But rscfuse already runs for /proc; one more inode type is negligible cost.
- ⚠️ **FUSE syscall overhead per op:** Each socket op (send/recv/connect/etc) goes through kernel's FUSE layer. But kernel's FUSE is heavily optimized; microsecond-level overhead per call.
- ⚠️ **Indirection on readiness:** rsbeacon signals rscfuse via eventfd → rscfuse wakes kernel. One extra hop, but nanosecond-level compared to network latency to rsbeacon.

### Why FUSE is the better path (both layers)

1. **Architectural consistency:** Everything forwarded to rsbeacon uses the same mechanism — both filesystem and network.
2. **Proven pattern:** rscfuse already validates FUSE for filesystem forwarding; sockets extend the same proven code.
3. **Fewer bug surface areas:** No per-socket state machines; no fd translation tables; kernel's VFS handles all semantics.
4. **Better separation of concerns:** rsclient = seccomp dispatch, rscfuse = I/O forwarding.
5. **Simpler for new developers:** One forwarding pattern to understand, not ADDFD for network + FUSE for files.
6. **Network performance comparable:** Data-plane latency is dominated by network RTT to rsbeacon (10–200ms), not FUSE overhead (microseconds).

---

## Comparison Table

| Feature | Bare kmod | Seccomp + Virtual FD | ADDFD | FUSE (proposed) |
|---|---|---|---|---|
| **Mechanism** | khook patch | unotify trap | unotify + fd inject | unotify + FUSE |
| **Kernel blocking** | Yes (threads stall) | No | No | No |
| **epoll/select** | ✅ Works | ❌ Broken | ✅ Works | ✅ Works |
| **dup/fork** | ✅ Works | ❌ Broken | ✅ Works | ✅ Works |
| **SCM_RIGHTS** | ✅ Works | ❌ Broken | ✅ Works | ✅ Works |
| **Complexity (LOC)** | ~850 (kmod) | ~0 (just dispatch) | ~561 (added) | ~200 (added) - 294 (removed) |
| **Bug surface area** | Low | High (enumeration) | Medium (4 found) | Low (proven FUSE) |
| **Multi-threaded perf** | ⚠️ Fair (blocked threads) | ❌ Poor (serialized dispatch) | ✅ Good (real fds) | ✅ Good (FUSE daemon) |
| **Single-threaded perf** | ✅ Good (direct kernel) | ⚠️ Fair (one RTT per op) | ⚠️ Fair (async proxy) | ⚠️ Fair (FUSE overhead) |
| **Maintainability** | ❌ Kmod burden | ✅ Userspace | ⚠️ Complex async state | ✅ Proven pattern |
| **Consistency** | N/A | N/A | ❌ Two mechanisms | ✅ One mechanism |

---

## Decision: Current State

**Seccomp-unotify** is the primary capture mechanism for both layers (July 2026).

- **Sockets (network):** ADDFD real-fd proxy (works, but complex) — 561 LOC added, 4 bugs found and fixed.
- **Files/proc (filesystem):** FUSE (rscfuse daemon) — stable, proven, 2100 LOC in rscfuse.
- **Asymmetry:** Two different forwarding mechanisms for similar problems.

### Evolution summary

Both layers followed the same path:
1. **Bare kmod (khook)** → removed due to thread-blocking latency and maintenance burden.
2. **Virtual-fd table** → attempted but broken (no epoll/select/dup support).
3. **FUSE** → chosen for filesystem layer, proven successful, simple to maintain.
4. **ADDFD** → chosen for network layer as a "faster" alternative; adds complexity without solving the fundamental problem.

The filesystem layer reached the correct solution (FUSE) earlier. The network layer should follow the same path.

---

## Next Step: Unify Network with Filesystem via FUSE

**Recommended future work:** Replace ADDFD socket handling with FUSE socket inodes, completing the unification that began with the filesystem layer.

**Scope:**
1. Extend rscfuse with socket inode type (200–300 LOC) — follow the same patterns used for `/proc`.
2. Add eventfd-based readiness signaling from rsbeacon to rscfuse (100 LOC) — when socket state changes, rsbeacon writes to eventfd; FUSE daemon wakes kernel.
3. Simplify relay.rs: route socket syscalls to `/dev/rsock` FUSE mount (remove `proxy_fds` HashMap, `PendingProxy` state machine, `shutdown_proxies()` sweep).
4. Delete socket_proxy.rs entirely (−294 LOC).
5. Retest with same test suite.

**Expected outcome:**
- **Fewer LOC:** −244 net (200 + 100 added, 544 removed).
- **Fewer bugs:** No ADDFD-specific race conditions; kernel's VFS layer handles all fd semantics (proven by filesystem layer).
- **Unified I/O forwarding pattern:** Everything goes through rscfuse, both files and sockets.
- **Easier to maintain and extend:** New developers understand one pattern, not two.
- **Same or better performance:** FUSE is already in the critical path for /proc; sockets add minimal overhead (nanoseconds per op vs network RTT to rsbeacon in the 10–200ms range).

---

## References

- `rsclient/src/relay.rs`: Seccomp dispatch loop, ADDFD socket handling.
- `rsclient/src/socket_proxy.rs`: Real-fd ADDFD proxy implementation (candidate for removal).
- `rscfuse/src/`: FUSE daemon, proven pattern for I/O forwarding.
- `rsc/profiles/shadow.yaml`: Mount profile defining what's forwarded vs local.
