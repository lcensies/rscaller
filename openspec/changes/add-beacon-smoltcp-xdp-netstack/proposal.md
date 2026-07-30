## Why

Today rsbeacon executes every forwarded syscall — including all socket
syscalls (`socket`, `connect`, `bind`, `listen`, `accept4`, `sendto`,
`recvfrom`, `sendmsg`, `recvmsg`, `getsockopt`, `setsockopt`) — via a single
generic `libc::syscall()` passthrough in `executor.rs`. The beacon host's
real kernel TCP/IP stack always terminates the connection, which means the
beacon's own kernel-level network fingerprint (TCP stack behavior, socket
options, `/proc/net/*` state, conntrack entries, etc.) is always exposed to
whatever it talks to. There is no way to run network operations through an
independent, swappable userspace network stack that only touches the wire
via a raw AF_XDP socket — the pattern proven by the `xdplganger` reference
project (gVisor netstack bridged to AF_XDP). We want the same capability in
rscaller, built on `smoltcp` instead of gVisor, and wired in as a selectable
rsbeacon backend rather than a hardcoded behavior.

## What Changes

- Add a `NetBackend` abstraction in rsbeacon that intercepts the ~10
  socket-related syscall numbers before they reach the existing generic
  `libc::syscall` passthrough in `executor.rs`; all other syscall numbers
  (file, process, etc.) continue unchanged through the existing path.
- Add a `direct` backend that is exactly today's implicit behavior
  (`libc::syscall` passthrough) — this becomes the explicit default so
  current behavior is preserved with no config changes required.
- Add a new `smoltcp-xdp` backend that:
  - Creates and binds one AF_XDP socket (UMEM + fill/completion/RX/TX
    rings) on a configured interface/queue, requiring the beacon process
    to run as root / with `CAP_NET_ADMIN` and `CAP_BPF` (or root).
  - Loads and attaches a minimal XDP eBPF program that redirects frames
    matching intercepted TCP ports (and all ICMP) into an `XSKMAP`,
    leaving all other traffic on the interface untouched (`XDP_PASS`).
  - Bridges the AF_XDP rings to a `smoltcp::iface::Interface` via a
    `smoltcp::phy::Device` implementation (RX/TX tokens over UMEM frames),
    mirroring the `txLoop`/`rxLoop` bridge pattern in `xdplganger`'s
    `pkg/interceptor/netstack.go`.
  - Implements the intercepted socket syscalls (`socket`, `bind`,
    `connect`, `listen`, `accept4`, read/write/send/recv variants,
    `getsockopt`/`setsockopt`, `close`) as thin adapters over
    `smoltcp::socket::tcp::Socket` / `udp::Socket`, tracked in a per-fd
    socket table keyed by the beacon's virtual fd space.
  - Registers/deregisters locally-used TCP ports into the XDP program's
    port map on connect/bind so inbound return traffic for the userspace
    stack is redirected correctly while unrelated traffic on the shared
    interface keeps flowing to the host kernel.
- Add a `--netstack <direct|smoltcp-xdp>` CLI flag to rsbeacon (following
  the existing `--transport`/`--encryption` flat-CLI-flag convention — no
  config-file infrastructure exists today and none is introduced), plus
  backend-specific flags (`--xdp-iface`, `--xdp-queue`, `--xdp-dst-mac`,
  `--xdp-mode copy|zerocopy`) consumed only when `--netstack smoltcp-xdp`
  is selected.
- Thread the new flags through `rscaller-run`'s microVM `/init` script
  generation (`rscaller-run/src/microvm.rs`) so the smoltcp-xdp backend
  can actually be selected in the two-VM deploy topology, not just when
  invoking rsbeacon manually.
- **BREAKING**: none. `rscaller-proto`'s `SyscallRequest`/`SyscallResponse`
  wire format is unchanged — the new backend is purely a beacon-local
  execution detail behind the existing generic syscall RPC. No changes are
  required to kmod, rsclient, or the local-side interception/filtering
  (`FILTER_NET`/`NetFilter`), which already forward socket syscalls
  generically today.

## Capabilities

### New Capabilities
- `beacon-net-backend`: Pluggable network-syscall execution backend
  abstraction in rsbeacon, with a `direct` (passthrough) implementation
  preserving current behavior and a backend selection mechanism
  (CLI flag) that other backends plug into.
- `beacon-smoltcp-xdp-backend`: The `smoltcp-xdp` backend itself — AF_XDP
  socket/UMEM setup, XDP eBPF program load/attach and port-map
  management, and the smoltcp `phy::Device` bridge that services
  intercepted socket syscalls through a userspace TCP/IP stack instead of
  the beacon host's kernel stack.

### Modified Capabilities
- none (no existing specs in this repository; this change establishes the
  first capabilities in the `openspec/specs/` tree).

## Impact

- **Affected code**: `rsbeacon/src/executor.rs` (dispatch split for
  socket syscall numbers), `rsbeacon/src/main.rs` (new CLI flags),
  new modules `rsbeacon/src/net_backend/{mod.rs, direct.rs, smoltcp_xdp/
  {mod.rs, xdp_socket.rs, umem.rs, bpf.rs, bridge.rs, socket_table.rs}}`,
  `rscaller-run/src/microvm.rs` (init script flag threading).
- **New dependencies**: `smoltcp` (userspace TCP/IP stack), a small
  hand-rolled AF_XDP ABI layer (UMEM/ring mmap + `bind(AF_XDP)`, modeled
  on `xdplganger/pkg/xdp/*.go` but in Rust — no suitable maintained Rust
  AF_XDP crate is assumed available, so this may be implemented directly
  via `libc`/`nix` raw syscalls), and an eBPF loader (e.g. `aya` or raw
  `bpf(2)` syscalls) plus a small XDP C program compiled to an embedded
  `.o`, modeled on `xdplganger/bpf/xdp_prog.c`.
- **Privilege requirements**: the `smoltcp-xdp` backend requires the
  rsbeacon process to run as root (or with `CAP_NET_ADMIN` + `CAP_BPF`/
  `CAP_SYS_ADMIN` depending on kernel version) to create the AF_XDP
  socket and load/attach the XDP program. The `direct` backend has no
  additional privilege requirements beyond what rsbeacon needs today.
- **Deployment**: two-VM topology docs (`AGENTS.md`) and `deploy.sh`/
  Makefile invocations of rsbeacon need to note the root requirement and
  new flags when `smoltcp-xdp` is selected.
- **Out of scope for this change**: IPv6 support, zero-copy XDP mode
  validation on all NIC drivers, and multi-queue scaling (one XDP socket
  per interface/queue, matching `xdplganger`'s current limitation) are
  explicitly deferred; the initial `smoltcp-xdp` backend targets a single
  interface/queue with copy-mode XDP, matching `xdplganger`'s portable
  default.
