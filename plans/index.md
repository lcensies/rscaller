# rscaller — Feature Roadmap

## Status legend
- ✅ Done / merged to master
- 🟡 Partial / blocked
- ❌ Not started

---

## 1. Core forwarding (✅ done)

Syscall interception via khook, forwarding to rsbeacon over TCP, rsclient relay.
TLS transport, codegen pipeline, proto/codec — all merged to master.

---

## 2. microVM support (🟡 blocked — see plans/microvm.md)

Goal: `rscaller-run --microvm` launches ephemeral Firecracker/QEMU microVM,
boots rsbeacon inside, tears down after run.

**Blocked on**: FC networking config + rootfs glibc/musl mismatch.
See `plans/microvm.md` for full status and fix plan.

---

## 3. Per-process remote execution via `rsc` wrapper (❌ not started)

Goal: `RSC_REMOTE=1 ./binary` — or `rsc ./binary` — forwards all syscalls
of that specific process to rsbeacon, without touching other processes.

**Approach**: cgroup-inode filter mode in kmod.
- `rsc` binary: fork → create dedicated cgroup → move self into it →
  stat cgroup dir inode → write inode to `/proc/rscaller` param → exec target.
- kmod: third filter mode — `target_cgroup_ino` param, check
  `task_dfl_cgroup()->kn->id` in `filter_binary()`.

**Branch**: `feature/cgroup-filter` exists but is empty (based on old ecf3577).
Needs to be implemented fresh on top of master.

**Files to create/modify**:
- `rsc/` — new Cargo crate (`rsc/Cargo.toml`, `rsc/src/main.rs`)
- `Cargo.toml` — add `rsc` to workspace members
- `kmod/main.c` — add `target_cgroup_ino` param + filter branch

---

## 4. FUSE daemon — rscfuse (🟡 merged, untested)

Goal: mount `/rsc/<target>/` as a FUSE filesystem backed by rsbeacon,
so any open/read/write on paths under that mount goes remote.

**Status**: implementation merged (7 .rs files, ~1358 lines).
Shadow-fd + anon_inode approach in kmod was reverted; rscfuse uses pure
FUSE (no kmod changes needed).

**TODO**:
- End-to-end test: mount rscfuse, open a file through it, verify rsbeacon
  receives the request and returns data.
- Fix build: `rscfuse` excluded from deploy (needs `libfuse-dev` on host).
  Either add to deploy or document manual build step.

---

## 5. End-to-end integration tests (❌ not started)

- `make test-remote` covers basic forwarding.
- Missing: microVM boot test, rscfuse mount test, `rsc` wrapper test.

---

## Priority order (ASAP)

1. **Fix forwarding regression** — verify `make test-remote` still passes on master.
2. **rscfuse e2e test** — mount + file access via FUSE.
3. **`rsc` wrapper + cgroup filter** — implement on master, test.
4. **microVM** — unblock networking, then test FC boot + beacon reachability.
