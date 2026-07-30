## Context

rsbeacon (`rsbeacon/src/{main.rs,server.rs,executor.rs}`) is a generic
remote-syscall executor. It receives a `SyscallRequest { number, args[6],
in_bufs, out_sizes }` (defined in `rscaller-proto/src/types.rs`) over a
TCP/TLS/UDS transport and executes it via a single call:

```rust
let ret = unsafe { libc::syscall(num as libc::c_long, args[0] as libc::c_long, ...); };
```

Nothing distinguishes socket syscalls (`socket`=41, `connect`=42,
`bind`=49, `accept4`=288, `sendto`=44, `recvfrom`=45, `sendmsg`=46,
`recvmsg`=47, `getsockopt`=55, `setsockopt`=54, plus `read`/`write`/`close`/
`poll`/`ppoll` shared with file fds) from any other syscall. The beacon
host's kernel always terminates the actual connection.

The local-side interception (kmod `SyscallSignature` dispatch table,
`FILTER_NET`/`NetFilter` CIDR+port gating in `rsclient/src/relay.rs`) is
**out of scope** — it already forwards socket syscalls generically and
requires no changes. This design is scoped entirely to rsbeacon's
execution side.

Reference implementation: `xdplganger` (`/home/esc2/repos/darthevader/
xdplganger`), a Go project that bridges a gVisor `tcpip.Stack` to an
AF_XDP socket via a `channel.Endpoint` (`pkg/interceptor/netstack.go`) and
a hand-rolled, CGo-free AF_XDP ABI layer (`pkg/xdp/{umem,socket,types}.go`)
plus a minimal XDP eBPF program (`bpf/xdp_prog.c`) that redirects only
tracked TCP ports + all ICMP into an `XSKMAP`, `XDP_PASS`-ing everything
else. This design ports that architecture to Rust, substituting `smoltcp`
for gVisor's netstack.

## Goals / Non-Goals

**Goals:**
- Introduce a `NetBackend` trait in rsbeacon that intercepts the ~10
  socket-related syscall numbers ahead of the existing generic
  `libc::syscall` dispatch, leaving all other syscall numbers unaffected.
- Ship a `direct` backend that is byte-for-byte today's behavior (default,
  zero config change required for existing deployments).
- Ship a `smoltcp-xdp` backend: AF_XDP socket + UMEM, XDP program
  load/attach with a port-keyed `XSKMAP`, and a `smoltcp::phy::Device`
  bridge driving `smoltcp` TCP/UDP sockets, so intercepted connections
  never touch the beacon host's kernel TCP/IP stack.
- Make the backend selectable via a CLI flag on rsbeacon
  (`--netstack direct|smoltcp-xdp`), following the existing flat-CLI-flag
  configuration convention (`--transport`, `--encryption`) — no config
  file infrastructure is introduced.
- Thread the new flags through `rscaller-run`'s microVM init-script
  generation so the backend is selectable in the standard deploy path.

**Non-Goals:**
- IPv6 support (v1 targets IPv4 + TCP/UDP/ICMP, matching xdplganger).
- Zero-copy XDP mode validation across NIC drivers — v1 always binds
  copy-mode (`XDP_COPY`), matching xdplganger's portable default;
  zero-copy is a config option but unsupported/unvalidated initially.
- Multi-queue scaling — v1 is one XDP socket per interface/single queue.
- Changes to `rscaller-proto` wire format, kmod, or rsclient/local
  filtering — the new backend is entirely a beacon-local execution
  detail behind the existing generic `SyscallRequest`/`SyscallResponse`
  RPC.
- A raw-socket/UDP-direct-frame fast path (xdplganger's non-netstack UDP
  mode) — v1 routes all intercepted protocols (TCP, UDP, ICMP) through
  the smoltcp `Interface`, for a single consistent code path. A raw-frame
  fast path can be added later if UDP latency through smoltcp proves
  insufficient.

## Decisions

### D1: Backend selection via `NetBackend` trait, dispatched by syscall number in `execute_syscall`

`executor.rs::execute_syscall` gets a set of intercepted syscall numbers
(`SOCKET_SYSCALL_NRS: &[u64]`). Before the existing `libc::syscall` call,
check membership; if the active backend is non-`direct` and the number is
in the set, dispatch to `NetBackend::handle(req) -> SyscallResponse`
instead. `read`/`write`/`close`/`poll`/`ppoll` are ambiguous (they operate
on any fd, not just sockets) — the backend's per-fd socket table decides:
if `fd` is not tracked as a backend-owned socket, fall through to the
existing `libc::syscall` path unchanged. This keeps `direct` mode's
behavior provably identical to today (the trait's `direct` impl **is**
the existing `libc::syscall` call, so there is exactly one behavioral
code path when `--netstack direct` is selected — no shadow logic that
could diverge).

```rust
pub trait NetBackend: Send + Sync {
    /// Returns true if this backend wants to handle this syscall number.
    fn owns_syscall(&self, req: &SyscallRequest, table: &SocketTable) -> bool;
    fn handle(&self, req: &SyscallRequest, table: &mut SocketTable) -> SyscallResponse;
}
```

Alternatives considered: a full syscall-emulation layer that intercepts
*every* syscall through the trait (rejected — needlessly re-implements
the passthrough for non-socket syscalls, increasing risk of subtly
changing `direct`'s behavior); dispatch by fd-type registry only, no
syscall-number filter (rejected — `socket()` itself has no fd yet, must
be dispatched by syscall number first to allocate the virtual fd).

### D2: Per-fd virtual socket table owned by the backend, not the kernel

rsbeacon already virtualizes nothing about fds today — `socket()` returns
a real kernel fd, and all subsequent ops use it directly. Once
`smoltcp-xdp` is active, `socket(AF_INET, SOCK_STREAM, ...)` must instead
allocate a **virtual fd** (an integer not backed by a real kernel fd) so
that later `connect`/`read`/`write`/`close` on that fd route to the
smoltcp socket instead of the kernel. `SocketTable` maps
`virtual_fd -> SmoltcpSocketHandle` (a `smoltcp::iface::SocketHandle`
plus cached local/peer addr and protocol). Virtual fds are allocated from
a high range (e.g. starting at `1 << 30`) to avoid colliding with real
fds the same beacon process may hold open, and `owns_syscall` for
fd-taking syscalls checks table membership rather than fd numeric value
alone.

Alternatives considered: reusing real kernel fd numbers by opening a
`memfd`/`eventfd` placeholder per virtual socket so the fd "looks real"
(rejected — adds a syscall per socket for no behavioral benefit, since
rsbeacon fully controls fd allocation on its own side of the RPC and the
client only ever sees the fd number that rsbeacon assigned in the
`SyscallResponse`, per the proto in `rscaller-proto/src/types.rs`).

### D3: AF_XDP layer implemented directly (no CGo-equivalent dependency), modeled on `xdplganger/pkg/xdp`

Rust has no single dominant, well-maintained `libbpf`-free AF_XDP crate
that matches the copy-mode-first, portable approach used by xdplganger.
Rather than depend on a heavier `xsk-rs`(libbpf/libxdp-bound, requires
system libbpf) or an unmaintained crate, port `pkg/xdp/{types.go, umem.go,
socket.go}` directly to Rust using `libc`/`nix` raw syscalls: `socket
(AF_XDP=44, SOCK_RAW, 0)`, `setsockopt(SOL_XDP=283, XDP_UMEM_REG, ...)`,
`mmap` at the kernel's magic ring offsets
(`XDP_PGOFF_RX_RING`/`XDP_UMEM_PGOFF_FILL_RING`/etc.), and `bind(2)` with a
raw `sockaddr_xdp`. This mirrors xdplganger's approach of not depending on
libbpf for the socket/ring/UMEM path (only the XDP *program* load path
optionally uses an eBPF loader — see D4). Ring producer/consumer indices
use the same acquire/release atomics pattern as the kernel ABI requires
(`AtomicU32` with `Acquire`/`Release` ordering in Rust in place of Go's
manual `atomic.Load/Store`).

Alternatives considered: `xsk-rs` (rejected for v1 — pulls in a libbpf/
libxdp system dependency, and its high-level socket abstraction doesn't
map as directly onto the txLoop/rxLoop bridge model being ported from
xdplganger; may be revisited later as a v2 simplification once the direct
port is proven).

### D4: XDP eBPF program load/attach via a minimal loader, program logic ported from `xdplganger/bpf/xdp_prog.c`

The kernel-side XDP program is unchanged in spirit from xdplganger, with
two deliberate extensions: parse Ethernet→{ARP, IPv4→{TCP,UDP,ICMP}} with
bounds checks; redirect ARP always, ICMP always, TCP only if `dest_port`
is present in a `tcp_ports` `BPF_MAP_TYPE_HASH` (u16 port → u8 marker),
and UDP only if `dest_port` is present in a separate `udp_ports` map of
the same shape; everything else `XDP_PASS`. **Divergence from
xdplganger**: its own `xdp_prog.c` only redirects ICMP+TCP — no UDP
branch, and no ARP redirect either (its gVisor bridge needed the
gateway's MAC resolved upfront rather than via live ARP — see D5/D6 —
so it never needed ARP traffic in userspace at all). This design's Goals
explicitly include working `smoltcp` UDP sockets, so a `udp_ports` map
and matching redirect branch were added on top of the ported logic; it
is *not* shared with `tcp_ports` because TCP and UDP port numbers are
independent namespaces (tracking TCP port 53 must not cause UDP DNS
traffic on port 53 to be redirected too). The ARP redirect branch was
**found necessary during integration testing** (task 8.x), not part of
the original port: D6 has `smoltcp::iface::Interface` resolve neighbor
MACs itself via its own ARP requests sent over the AF_XDP-backed
`XdpDevice`, which only works if ingress ARP (both requests targeting
smoltcp's own address and replies to its own outgoing requests) actually
reaches the AF_XDP socket — without this branch every ARP frame was
`XDP_PASS`-ed to the host kernel instead, so smoltcp's neighbor cache
never populated and **no outbound traffic of any kind (TCP connect, UDP
send, or even an ICMP echo reply — which itself must resolve the
request's source IP to a destination MAC before replying) was ever
actually transmitted**, despite RX/UMEM/ring plumbing all working
correctly. See the Risks section below for the trade-off this
introduces. Maps:
`xsks_map` (`BPF_MAP_TYPE_XSKMAP`) keyed by RX queue index → the beacon's
AF_XDP socket fd. The `.o` is compiled ahead-of-time (clang `-target bpf`,
checked into the repo like xdplganger does) and embedded via
`include_bytes!`. Loading/attaching uses a small Rust eBPF loader
(candidate: `aya` — pure-Rust, no libbpf dependency, consistent with D3's
"avoid libbpf" preference) to parse the ELF, create maps, load the
program, and `AttachXDP` to the configured interface. Port map
updates (`TCPPortAdd`/`TCPPortRemove` and their UDP equivalents, called
from the backend on connect/bind/listen and close) use `aya`'s map API
rather than hand-rolled `bpf(2)` syscalls (Go's raw-syscall choice there
was likely incidental, not a hard requirement — `aya` gives equivalent
perf).

Alternatives considered: hand-rolled `bpf(2)` syscalls for map
update/load like xdplganger's `bpf.go` (rejected for the loader path
itself — `aya`'s ELF/program loading saves significant, error-prone code
— but map read/update syscalls may still go direct via `aya::maps::HashMap`
which is itself a thin `bpf(2)` wrapper, so this is not a meaningful
divergence).

### D5: smoltcp bridge — `phy::Device` over UMEM frames, `SocketSet` driving intercepted sockets

A `XdpDevice` struct implements `smoltcp::phy::Device`:
- `receive()` — pops available RX ring descriptors (batched, akin to
  xdplganger's `rxLoop` `ReadBatch`), validates EtherType==IPv4 (or ARP,
  for the interface's own ARP resolution) and, for IPv4, destination MAC
  match; returns an `RxToken` wrapping the UMEM frame region minus the
  14-byte Ethernet header consumed internally by smoltcp's `EthernetII`
  medium — actually simplest to keep `Medium::Ethernet` in smoltcp (unlike
  gVisor's `channel.Endpoint` which strips Ethernet, smoltcp's own
  `Interface` natively speaks Ethernet framing, so no manual header
  strip/prepend is needed — this is a **simplification** over xdplganger's
  gVisor bridge, which had to hand-build Ethernet frames because
  `channel.Endpoint` operates at IP layer only).
- `transmit()` — allocates a UMEM TX frame, returns a `TxToken`; on
  `consume()`, the closure writes the full Ethernet frame smoltcp
  produces directly into the UMEM frame, pushes the TX descriptor, and
  kicks the socket (`sendto(..., MSG_DONTWAIT)`), matching xdplganger's
  `sendRaw`.
- Frame recycling: consumed RX descriptors are returned to the fill ring;
  completed TX descriptors are returned to the UMEM free list —
  same bookkeeping as xdplganger's `ReclaimRX`/completion-ring drain.

One `smoltcp::iface::Interface` + `SocketSet` per backend instance (single
interface/queue for v1, per Non-Goals). Each virtual fd's `TcpSocket`/
`UdpSocket` is added to the shared `SocketSet` on `socket()`, configured
on `bind`/`connect`/`listen`, and driven by calling `iface.poll()` in a
background thread that also services the AF_XDP rings — analogous to
xdplganger's `txLoop`/`rxLoop` goroutines, collapsed into a single poll
loop since smoltcp's model is single-threaded-poll-driven rather than
gVisor's async endpoint model. Blocking semantics for `SyscallRequest`
handlers (`connect`, `accept4`, blocking `read`/`write`) are implemented
as a bounded poll loop against socket state (connected/readable/writable)
similar to xdplganger's 5s connect timeout / 50ms read poll interval,
since the RPC executor has no way to block a client's syscall
indefinitely on the wire without risking client-side timeouts — exact
timeout values are an Open Question (see below).

Alternatives considered: `smoltcp::phy::Medium::Ip` (skip Ethernet,
build frames manually like xdplganger did for gVisor) — rejected because
it reintroduces manual Ethernet header handling that smoltcp's native
Ethernet medium already provides for free; only worth it if a future
zero-copy optimization needs to avoid a copy, which is not a v1 concern.

### D6: Port tracking and interface addressing

For a `smoltcp-xdp`-backed TCP socket, the backend calls into the XDP
loader to add the local port to `tcp_ports` on successful `listen()` and
on successful `connect()`; on `close()` (or connection teardown) it
removes it. **Divergence from xdplganger**: its own `trackPort`/
`untrackPort` are only ever called from the outbound-`connect()` path —
there is no equivalent call from a listen handler, so inbound listening
sockets are never actually reachable through its XDP redirect (bind()
there only reserves the port in gVisor's own stack). Since this design's
Goals explicitly include `bind()`/`listen()`/`accept4()` as supported
syscalls, tracking is also done at `listen()` time here, so inbound TCP
servers work. UDP sockets follow the same pattern against the separate
`udp_ports` map: tracked on successful `bind()` (and on `connect()`, for
the ephemeral local port an unbound UDP socket is assigned), untracked
on `close()`. The interface's own IPv4 address (+ CIDR prefix), own MAC,
and default-route gateway IPv4 are either passed explicitly via
`--xdp-*` flags or auto-detected — address/prefix/MAC via `SIOCGIFADDR`/
`SIOCGIFNETMASK`/`SIOCGIFHWADDR` ioctls, the gateway IPv4 from
`/proc/net/route` — at startup (matching xdplganger's `firstIPv4`/
route-detection fallback). **Finding, narrows this decision's original
scope**: the gateway's *MAC* (as opposed to its IPv4) is deliberately
**not** auto-detected/wired into backend construction, despite
`/proc/net/arp`-based `gateway_mac()` detection being fully implemented
in `addr_detect.rs` (with an ARP-priming ping fallback, as originally
planned) — implementation turned up that `smoltcp::iface::Interface`
(`Medium::Ethernet`) resolves neighbor MACs, including the gateway's,
itself via its own ARP requests sent over the `XdpDevice`, and this
project's smoltcp version (0.13.1) exposes no public API to pre-seed
its neighbor cache with a value anyway. This only reproduces xdplganger's
own need for upfront gateway-MAC knowledge because its gVisor
`channel.Endpoint` has no ARP of its own — it required hand-built
Ethernet frames with a resolved destination MAC (see D5) — which does
not apply here. `gateway_mac()` is kept (tested, `#[allow(dead_code)]`d)
for potential future use (e.g. a startup connectivity diagnostic) but no
`--xdp-dst-mac` flag exists to feed it, since there is nothing for it to
functionally feed.

## Risks / Trade-offs

- [Risk] AF_XDP + XDP program load requires root/`CAP_NET_ADMIN`+`CAP_BPF`
  on the beacon host — a strictly higher privilege bar than today's
  `direct` backend, and a change to the deploy/threat model documented in
  AGENTS.md/README. → Mitigation: `direct` remains the default; the
  privilege requirement is fail-fast and clearly logged at startup
  (backend init fails immediately with an actionable error rather than
  degrading silently to `direct`), and deploy docs are updated to call
  out the requirement explicitly.
- [Risk] Hand-rolled AF_XDP ABI in Rust (D3) re-implements low-level ring
  /UMEM logic that's easy to get subtly wrong (torn reads, missing
  memory barriers) — xdplganger's Go version had the same risk but is a
  proven reference to diff against. → Mitigation: port structure and
  constants 1:1 from `xdplganger/pkg/xdp/*.go` where possible, add a
  focused unit/integration test (veth pair, like xdplganger's
  `tests/integration_test.go`) exercising the ring lifecycle before
  building socket-level logic on top.
- [Risk] Shared interface: a misconfigured `tcp_ports` map or a bug in
  the XDP program's parsing could incorrectly redirect unrelated traffic
  away from the host kernel, breaking other services on the same NIC.
  → Mitigation: default-deny XDP program logic (only ICMP + explicitly
  tracked TCP ports redirect, everything else `XDP_PASS`, exactly as in
  xdplganger); ports are only tracked while an active smoltcp socket owns
  them and removed promptly on close/error.
- [Risk] Blocking RPC semantics over poll loops (D5) may not perfectly
  match kernel blocking behavior (e.g. `SO_RCVTIMEO`, signal
  interruption) — could surface as subtly different `errno`/timing
  behavior to the intercepted target process vs. real kernel sockets.
  → Mitigation: document as a known limitation; keep `direct` as the
  reference/fallback backend for cases needing exact kernel semantics.
- [Trade-off] v1 scope explicitly excludes IPv6, zero-copy, and
  multi-queue — narrows the initial implementation surface at the cost
  of not yet matching xdplganger's full feature set (which itself is
  IPv4/TCP+UDP+ICMP/single-queue only, so parity is actually maintained,
  not reduced).
- [Risk] **ARP redirect (D4) starves the host kernel's own neighbor
  cache on the shared interface** — found the hard way during
  integration testing (task 8.x): `XDP_REDIRECT` is exclusive (a frame
  goes to *either* the kernel *or* the AF_XDP socket, never both), so
  once ARP is redirected to smoltcp (required for D6's neighbor
  resolution to work at all — see D4), the kernel stops seeing *any*
  ingress ARP on that interface. This is *not* limited to "new"
  resolutions as originally assumed while writing D4/D6: Linux
  periodically revalidates even already-`REACHABLE` neighbor-cache
  entries (stale timeout + NUD unicast reachability probes), and once
  that revalidation can no longer complete, the kernel loses the
  ability to reach that peer at all — including a peer it already had
  an established TCP connection with (observed directly: an active SSH
  session into a `smoltcp-xdp`-active VM died after roughly a minute).
  **This means `smoltcp-xdp` must not be attached to an interface that
  also carries the host's own management/control traffic** (SSH, the
  rsbeacon RPC control-plane listener itself is fine since that's a
  normal kernel-mode socket — the risk is specifically the *interface*
  the operator manages the box through). → Mitigation: deploy docs
  (task 9.1) must call this out explicitly as a hard requirement, not
  just a suggestion — dedicate `--xdp-iface` to an interface with no
  other required kernel-side traffic (a second NIC, or a dedicated
  bridge/veth leg), never the same interface as the box's own SSH
  management path. No code-level fix exists within XDP's redirect
  model (dual kernel+userspace delivery of the same frame is not a
  supported primitive); this is a fundamental consequence of D4/D6's
  design, not a bug to fix later.

## Migration Plan

- No migration for existing deployments: default `--netstack direct`
  preserves current behavior exactly (D1).
- Rollout is opt-in per beacon instance via CLI flag; `rscaller-run`'s
  microVM init-script generation gets the new flags but keeps `direct`
  as its own default unless explicitly configured otherwise.
- Rollback: switch `--netstack` back to `direct` (or omit the flag) and
  restart rsbeacon — no persistent state to clean up beyond removing any
  stale `tcp_ports` XDP map entries, which are process-lifetime-scoped
  (the eBPF program/maps are unloaded on backend/process shutdown).

## Open Questions

- Exact poll/timeout intervals for blocking `connect`/`read`/`accept4`
  emulation over the RPC — start from xdplganger's values (5s connect,
  50ms read poll) and tune based on integration testing.
- Whether `aya` (D4) or a hand-rolled minimal ELF/`bpf(2)` loader is
  ultimately preferable — `aya` is the working assumption pending a
  spike to confirm it supports the exact `XSKMAP` + `AttachXDP` flow
  needed without pulling in unwanted transitive dependencies.
- Whether UDP should get a raw-frame fast path bypassing smoltcp (as
  xdplganger does) in a later iteration, if smoltcp's UDP path proves
  too slow for the target workload.
- How `rscaller-run` should surface backend selection to the operator
  (new top-level CLI flag vs. env var) — deferred to task breakdown.
