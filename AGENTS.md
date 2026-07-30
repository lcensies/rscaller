# rscaller — Agent & Developer Notes

## Kernel Compatibility

### proc_ops (5.6+)
`struct proc_ops` replaces `struct file_operations` for proc files starting in Linux 5.6.
Field names are prefixed `proc_` (e.g. `.proc_read`, `.proc_write`, `.proc_mmap`).
Guarded in `main.c` with `#ifdef HAVE_PROC_OPS` (defined when `LINUX_VERSION_CODE >= 5.6.0`).

### vm_flags_set / vm_flags_clear (6.3+)
`vma->vm_flags` became `const` in Linux 6.3 — direct `|=` assignment is a compile error.
Use `vm_flags_set(vma, flags)` / `vm_flags_clear(vma, flags)` on 6.3+.
Compat shim defined in `main.c` for kernels < 6.3.
**Note:** In Linux 6.15+ these helpers are GPL-only exports. Non-GPL modules on 6.15+ must use `vm_flags_reset()` instead.

### vm_insert_page (2.6.15+)
Safe to use on all supported kernels. Used in `rscaller_dev_mmap_new` instead of
`remap_pfn_range` because `remap_pfn_range` rejects normal RAM (struct-page-backed) PFNs
on Linux 6.x without additional setup.

### mmap size check
`mmap(len)` is rounded up to `PAGE_SIZE` by the kernel before reaching the driver's mmap
handler. Always compare against `PAGE_ALIGN(sizeof(ControlBuffer))`, not bare `sizeof`.

### sys_call_table write protection (5.4+)
On kernels ≥ 5.4, clearing CR0.WP is no longer sufficient to write to the sys_call_table —
kernels with PKS (Protection Key Supervisor) or CET enforce page-level write protection
independently of the WP bit, and `set_memory_rw` (even when looked up dynamically) may not
lift PKS protection either.  The reliable cross-version technique is a **vmap alias**: get
the physical page(s) backing the target address, `vmap()` them with `PAGE_KERNEL`
(read-write), write through the alias, then `vunmap()`.  This bypasses all protections on
the original mapping.  Keep `set_memory_rw` + CR0.WP fallback paths in `sct_set_rw/ro` for
kernels where vmap is unavailable or overkill.
**General rule:** prefer kernel-version-gated code over a single approach that silently
fails on newer kernels. Add a `LINUX_VERSION_CODE` guard any time a kernel API, struct
field, or memory-protection mechanism differs across supported versions. For GPL-only
symbols, prefer dynamic lookup via `lookup_kallsym()` over direct linking.

### khook_release timeout
The upstream khook `khook_release()` loops forever if `use_count > 0` (e.g. a process was
killed mid-syscall). Our fork (`lib/khook`) adds a 10-iteration / 10-second timeout with a
forced `atomic_set(&p->use_count, 0)` to prevent the module from getting stuck in
"Unloading" state permanently.

## Test Script Notes

### BECOME_PASS
`make test-remote` / `make deploy-remote` require sudo on the remote VM.
Set `BECOME_PASS=ubuntu` in `.env` or pass as env var. `.env` is gitignored.

### CLIENT variable
`make test-remote CLIENT=dev-vm-rscaller-2` runs rsclient on a separate VM.
rsclient must have access to `/proc/rscaller`, which only exists on the kmod host (REMOTE).
Currently CLIENT and REMOTE should be the same machine unless a remote /proc mount is configured.

### Cleanup order
Always kill rsclient before rmmod. If rsclient is killed mid-syscall (while inside the
khook stub), `use_count` leaks and rmmod hangs. The test script enforces:
`pkill -9 rsclient → sleep 0.5 → rmmod`.

## Standard Deploy & Test Workflow

### Two-VM topology
- **dev-vm-1** — rsc client (build host): full Rust workspace built here via `deploy.sh`
- **dev-vm-2** — beacon host: receives only the `rsbeacon` binary (scp'd from dev-vm-1)

### Dependency: `libfuse3-dev`
`deploy.sh` installs `libfuse3-dev` on dev-vm-1 automatically. rscfuse is now a library
embedded in `rsc` (invoked as `rsc fuse`); no separate rscfuse binary is deployed.

### Dependency: XDP/eBPF toolchain (`clang`, `libbpf-dev`, `libelf-dev`, `bpftool`)
Required by the `smoltcp-xdp` rsbeacon network backend (compiling `bpf/*.c` to BPF
bytecode and loading/inspecting XDP programs). Installed by `scripts/bootstrap.sh`'s
`PKGS` array — **never `apt-get install` these by hand on a dev VM**; add the package to
`bootstrap.sh` instead so provisioning stays idempotent and reproducible from a clean VM.

### Never hand-install packages on dev VMs — fix the harness instead
If a dev VM is missing a system package (build tool, library, etc.), **do not**
`ssh dev-vm-N "sudo apt-get install ..."` ad hoc. Add the package to
`scripts/bootstrap.sh`'s `PKGS` array (it already diffs against `dpkg -s` and only
installs what's missing, so it's safe/idempotent to re-run) and re-run bootstrap. This
keeps VM state reproducible from a fresh snapshot/clone instead of accumulating
undocumented manual changes that `vm-reset` would silently wipe out.

### Normal iteration (code changed, want to test)
```
make test-evasion-clean        # vm-reset → deploy-all → run tests (canonical)
```
Or step by step:
```
make vm-reset                  # purge stale snapshots + fresh deploy to both VMs
make test-evasion NO_DEPLOY=1  # run tests, skip redundant deploy
```

### After a crashed test run (stale `pytest-clean` snapshot blocks re-run)
```
make vm-clean                  # delete pytest-clean snapshots from both VMs
make test-evasion-clean        # full clean run
```

### Just re-run tests without rebuilding
```
make test-evasion NO_DEPLOY=1
```

### Key Makefile targets
| Target | What it does |
|---|---|
| `make deploy` | rsync source + build workspace on dev-vm-1 (installs libfuse3-dev) |
| `make deploy-beacon` | deploy + scp rsbeacon to dev-vm-2 |
| `make vm-clean` | delete stale `pytest-clean` snapshots from both VMs |
| `make vm-reset` | vm-clean + start VMs + deploy-beacon |
| `make test-evasion` | run evasion tests (deploy by default, `NO_DEPLOY=1` to skip) |
| `make test-evasion-clean` | vm-reset + test-evasion (most reliable, use after changes) |

### VM snapshot strategy (used by pytest fixtures)
- Both `client_snapshotted` and `beacon_snapshotted` fixtures **revert to a persistent
  `baseline` snapshot** at the start of each test — no new snapshot is created per-test.
- `vm-reset` reverts **both** VMs to their `baseline` snapshots before deploying, so tests
  always start from clean state.
- `VM_SNAPSHOT` and `BEACON_SNAPSHOT` both default to `baseline`.
- **Never run tests against a dirty VM state** — always start with `make vm-reset` or
  `make test-evasion-clean` after code changes.

### FUSE reads on /proc files — known pitfall
`/proc` files report `st_size=0`. The Linux kernel short-circuits `read()` when the cached
inode size is 0, even with `FOPEN_DIRECT_IO`. Fix in `rscfuse/src/stat.rs`: regular files
with `st_size=0` get a 4 MiB sentinel size so the kernel issues reads; actual EOF is
signalled when the read handler returns 0 bytes.

## Shell / Tmux Workflow

- **Use tmux panes for all long-running commands** (deploy, build, SSH). Never use
  `run_in_background` Bash for blocking operations — use `tmux send-keys` instead.
- Pane map (session `rscaller`):
  - `1.1` — Claude Code session (llm-redactor-exec) — do not run commands here
  - `1.2` — SSH to dev-vm-rscaller (192.168.122.115), cwd `/home/ubuntu/rscaller`
  - `1.3` — SSH to dev-vm-rscaller-clone (192.168.122.168)
- Deploy: `tmux send-keys -t rscaller:1.2 "BECOME_PASS=ubuntu bash ~/rscaller/scripts/deploy.sh 2>&1 | tee /tmp/deploy.log" Enter`
- Check: `tmux capture-pane -t rscaller:1.2 -p | tail -30`

## VM Notes

- rmmod while rsclient is connected crashes the VM — reboot, then re-insmod
- VM IP can change on reboot — verify with `hostname -I` in pane 1.2 and update `~/.ssh/config`
- rsbeacon accumulates CLOSE-WAIT sockets if rsclient reconnects repeatedly; kill and restart rsbeacon to clear
- Forwarding LOCAL-path syscalls to rsbeacon breaks it (fd number collisions destroy rsbeacon epoll fd)

## Remote FS Architecture

- `/rsc/<target>/path` prefix: kmod intercepts path syscalls, strips prefix, forwards to rsbeacon
- Shadow fds: `anon_inode_getfd`-backed fds that proxy read/write/close to rsbeacon's remote fd
- Target name: written to `/proc/rscaller` as `TARGET <name>` by rsclient on startup
- **Only forward to rsbeacon for `/rsc/` paths or shadow fds** — everything else KHOOK_ORIGIN
