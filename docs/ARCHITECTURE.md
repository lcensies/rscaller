# rscaller Architecture

## Overview

rscaller intercepts syscalls from a target process on a local machine and
forwards them to **rsbeacon** running on a remote machine (typically a
disposable VM or microVM).  The intercepted process's syscalls are executed
on the remote machine and results are returned, creating a transparent
remote execution environment.

```
Local machine                          Remote machine
─────────────────────────────────      ────────────────
 target process
   │ syscall (e.g. openat)
   ▼
 [controller backend]                  rsbeacon
   │ SyscallNotification               │ executor
   ▼                                   │
 rsclient ─── TCP/TLS ──────────────▶  │ execute syscall locally
   │◀─────── SyscallResponse ─────────  │
   │                                   │
   ▼
 inject retval → target process
```

## Crate Layout

| Crate              | Role                                                         |
|--------------------|--------------------------------------------------------------|
| `ctls`             | Controller abstraction: `SyscallController` trait + backends |
| `rscaller-proto`   | Wire protocol: `SyscallRequest`, `SyscallResponse`, codec    |
| `rsclient`         | Relay process: connects controller to rsbeacon               |
| `rsc`              | Launcher: sets up the controller, starts the target binary   |
| `rsbeacon`         | Remote executor: receives requests, executes syscalls        |
| `rscfuse`          | FUSE filesystem library (embedded in `rsc` as `rsc fuse`)    |
| `qemu-vdw-core`    | QEMU relay: libvirt VM provisioning + guest-agent exec       |
| `tools/codegen`    | Generates syscall parameter metadata from tracefs            |

(`rscaller-run/`, `rscaller-runner/` are legacy, not workspace members.)

## Controller Abstraction (`ctls`)

All interception backends implement the `SyscallController` trait:

```rust
#[async_trait]
pub trait SyscallController: Send {
    /// Block until a syscall is intercepted; return None if tracee exited.
    async fn recv(&mut self) -> Result<Option<Notification>>;

    /// Inject the return value and resume the blocked process.
    async fn complete(&mut self, id: u64, retval: i64) -> Result<()>;
}
```

A `Notification` carries: syscall number, 6 raw args, tracee PID, and
any pre-copied IN-parameter buffers (kmod only).

### Backend: `SeccompController` (primary, no kernel module)

- Mechanism: `SECCOMP_RET_USER_NOTIF` (Linux 5.0+)
- Filter installed by `rsc` in the child before `execve`
- Notify fd duplicated from the child into parent `rsc` via
  `pidfd_open`/`pidfd_getfd` (SCM_RIGHTS would deadlock: `sendmsg` is itself
  intercepted by the filter), then inherited by `rsclient` via `execve`
- `recv()` calls `SECCOMP_IOCTL_NOTIF_RECV` (blocks in `spawn_blocking`)
- `complete()` calls `SECCOMP_IOCTL_NOTIF_SEND`
- For pointer args: relay must use `process_vm_readv(2)` on the tracee PID
  (the kmod copied these automatically; seccomp does not)
- No kernel crashes, no CR0.WP/PKS/CET issues, no `text_poke` needed

### Backend: `KmodController` (legacy/fallback)

- Mechanism: shared-memory ring buffer via `/proc/rscaller` mmap
- kmod hooks syscalls via khook (function trampolining)
- Filter: cgroup inode or binary-path based
- `recv()` polls the `kernel_to_user` ring buffer (busy-wait + yield)
- `complete()` writes `DONE <slot> <retval>` to `/proc/rscaller`
- IN-parameter buffers copied by `copy_from_user` in the kmod

See `kmod/buffer.h` for the shared-memory layout.

**Historical note**: earlier versions used `remap_pfn_range` + `vm_insert_page`
for the mmap.  Those experiments are in git history (pre-v4.4 commits).
The current kmod uses `remap_pfn_range` without `VM_IO` to handle normal
RAM pages on Linux 6.x.

## Data Flow (seccomp backend)

```
rsc --ctl seccomp -- /bin/ls /tmp
  │
  ├─ fork()
  │    ├─ child: prctl(NO_NEW_PRIVS) → seccomp(NEW_LISTENER, BPF) → execve(target)
  │    │                  target's syscalls → blocked by kernel → notify fd queued
  │    │
   │    └─ parent: duplicate notify_fd from child via pidfd_getfd
   │               execve(rsclient --ctl seccomp --notif-fd <fd> --beacon ...)
  │
  └─ rsclient (loop):
       ctl.recv()        → SECCOMP_IOCTL_NOTIF_RECV   (blocks until syscall)
       write_message()   → SyscallRequest over TCP/TLS
       read_message()    → SyscallResponse
       ctl.complete()    → SECCOMP_IOCTL_NOTIF_SEND   (injects retval, resumes tracee)
```

## Data Flow (kmod backend)

```
rsclient --ctl kmod --beacon ...
  │
  ├─ open /proc/rscaller (keeps kmod active)
  ├─ mmap ControlBuffer (kernel_to_user ring + param bufs)
  │
  └─ loop:
       ctl.recv()        → poll kernel_to_user ring buffer
       write_message()   → SyscallRequest over TCP/TLS
       read_message()    → SyscallResponse
       ctl.complete()    → write "DONE <slot> <ret>" to /proc/rscaller

rsc --ctl kmod -- <binary>
  │ fork → child in dedicated cgroup → exec binary
  └─ kmod filters by cgroup inode
```

## Wire Protocol

Messages are length-prefixed (4-byte LE `u32`) bincode-serialized structs.

```
SyscallRequest {
    slot_idx: u64,     // opaque ID (echoed back in response)
    number:   u64,     // Linux syscall number
    args:     [u64;6], // raw register arguments
    in_bufs:  Vec<SyscallBuf>,      // pre-copied IN pointer data (kmod only)
    out_sizes: Vec<(u8, u64)>,      // (arg_idx, size) for OUT allocations
}

SyscallResponse {
    slot_idx: u64,
    ret:      i64,           // raw return value (negative = -errno)
    out_bufs: Vec<SyscallBuf>, // OUT/INOUT buffer contents post-syscall
}
```

Transport: TCP with optional TLS (rustls).  Pass `--encryption none` to
skip TLS for development/testing.

## Syscall Division of Responsibility

| Syscall category                        | Handled by       |
|-----------------------------------------|------------------|
| `open`, `stat`, `read`, `write`, `close` | **rscfuse** — FUSE mount at `/rsc/<target>/` transparently proxies to rsbeacon |
| `kill`, `bpf`, other non-path ops       | **seccomp filter** — forwarded directly to rsbeacon |
| Everything else                          | Local (not intercepted) |

The seccomp filter is profile-driven: each mount profile's `forward:` list
names the syscalls to intercept (resolved via `syscall_nr()`, generated by
`rsc/build.rs` from `<asm/unistd_64.h>`). Path-bearing syscalls are routed
through the FUSE mount instead of being forwarded.

## seccomp vs kmod: Trade-offs

| Dimension          | seccomp-unotify        | kmod                          |
|--------------------|------------------------|-------------------------------|
| Kernel crashes     | None (kernel-managed)  | Possible (text patching)      |
| Kernel version     | 5.0+                   | 5.4+ (khook + proc_ops)       |
| Overhead           | Only intercepted calls | Every call filtered in kernel |
| Pointer args       | `process_vm_readv`     | `copy_from_user` in kmod      |
| Setup              | `rsc` launcher         | `insmod` + rsclient           |
| Privileges         | `NO_NEW_PRIVS` (safe)  | `CAP_SYS_ADMIN` (root)        |
| Stability          | Stable ABI             | Fragile (PKS/CET/text_poke)   |

## Adding a New Backend

1. Create `ctls/src/<name>.rs`
2. Implement `SyscallController` for your struct
3. Add `[features]` entry in `ctls/Cargo.toml`
4. Add CLI option in `rsclient/src/main.rs` and `rsc/src/main.rs`
