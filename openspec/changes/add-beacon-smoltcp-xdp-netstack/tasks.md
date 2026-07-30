## 1. Backend abstraction and `direct` backend

- [x] 1.1 Define `NetBackend` trait (`owns_syscall`, `handle`) and
      `SOCKET_SYSCALL_NRS` constant in a new `rsbeacon/src/net_backend/mod.rs`
- [x] 1.2 Implement `SocketTable` (virtual fd allocation starting at a
      high range, entry type covering both TCP/UDP smoltcp handles)
- [x] 1.3 Implement the `direct` backend (`rsbeacon/src/net_backend/direct.rs`)
      as a thin wrapper that always defers to the existing
      `libc::syscall` path — verify byte-for-byte behavioral equivalence
      with today's `executor.rs` for all intercepted syscall numbers
- [x] 1.4 Wire `execute_syscall` in `rsbeacon/src/executor.rs` to check
      the active backend's `owns_syscall` before falling through to the
      existing generic `libc::syscall` dispatch
- [x] 1.5 Add `--netstack <direct|smoltcp-xdp>` CLI flag to
      `rsbeacon/src/main.rs`, defaulting to `direct`, rejecting unknown
      values with an actionable error
- [x] 1.6 Add backend initialization to `main.rs` startup path: fail fast
      (non-zero exit, actionable log) if the selected backend fails to
      initialize, before accepting any client connections

## 2. AF_XDP socket + UMEM layer

- [x] 2.1 Port AF_XDP ABI constants/structs from
      `xdplganger/pkg/xdp/types.go` to Rust
      (`rsbeacon/src/net_backend/smoltcp_xdp/xdp_abi.rs`): `AF_XDP`,
      `SOL_XDP`, ring/umem sockopt constants, `UmemReg`, `Desc`,
      `SockaddrXdp`
- [x] 2.2 Implement UMEM setup (`umem.rs`): mmap frame buffer (try
      `MAP_HUGETLB`, fall back to regular pages), `setsockopt(XDP_UMEM_REG)`,
      fill/completion ring mmap + setup, free-frame list
- [x] 2.3 Implement AF_XDP socket (`xdp_socket.rs`): `socket(AF_XDP, ...)`,
      RX/TX ring size sockopts, RX/TX ring mmap, `bind(2)` with
      `SockaddrXdp` in copy mode, `ReadBatch`/`WriteBatch`/`Kick`
      following the kernel ring producer/consumer ABI with correct
      acquire/release atomics
- [ ] 2.4 Write a focused ring-lifecycle test against a veth pair
      (mirroring `xdplganger/tests/integration_test.go`) validating
      UMEM registration, bind, and a raw frame round-trip before any
      socket-syscall logic is built on top

## 3. XDP eBPF program and loader

- [x] 3.1 Port `xdplganger/bpf/xdp_prog.c` logic to a Rust-buildable XDP
      C program (or confirm the existing `.c` can be reused as-is):
      parse Ethernet→IPv4→{TCP,UDP,ICMP}, redirect ICMP + tracked TCP
      ports + tracked UDP ports into `xsks_map`, `XDP_PASS` everything
      else. NOTE: xdplganger's own program only redirects TCP+ICMP, not
      UDP — the UDP branch and `udp_ports` map are an addition on top of
      that reference, required because this design's Goals (unlike
      xdplganger's) include working `smoltcp` UDP sockets. Uses a
      separate `udp_ports` map (not shared with `tcp_ports`) since TCP
      and UDP ports are independent namespaces.
- [x] 3.2 Compile the program to an embedded `.o` (checked into the repo,
      built via a `build.rs` or documented manual clang invocation)
- [x] 3.3 Spike and confirm `aya` supports the required `XSKMAP` +
      `AttachXDP` + hash-map-update flow without unwanted transitive
      dependencies (resolves the design's Open Question); fall back to a
      minimal hand-rolled ELF/`bpf(2)` loader if not
- [x] 3.4 Implement program load/attach (`bpf.rs`): load the embedded
      `.o`, create/attach `xsks_map`, `tcp_ports` and `udp_ports` maps,
      `AttachXDP` to the configured interface, register the AF_XDP
      socket fd into `xsks_map` at the configured queue index
- [x] 3.5 Implement `TcpPortAdd`/`TcpPortRemove` and
      `UdpPortAdd`/`UdpPortRemove` map update helpers
- [x] 3.6 Unload/detach the XDP program and close map fds cleanly on
      backend/process shutdown

## 4. smoltcp bridge

- [x] 4.1 Implement `XdpDevice: smoltcp::phy::Device` (`bridge.rs`):
      `receive()` pops RX descriptors (EtherType/dest-MAC validated),
      `transmit()` allocates a UMEM TX frame and, inside the TX callback,
      writes the frame and kicks the socket
- [x] 4.2 Implement RX descriptor recycling (return to fill ring) and TX
      completion draining (return frames to the UMEM free list)
- [x] 4.3 Construct the `smoltcp::iface::Interface` with `Medium::Ethernet`,
      configured/auto-detected IPv4 address, and default route
- [x] 4.4 Implement the poll loop: drive `iface.poll()` against the
      shared `SocketSet` on a background thread/task, servicing AF_XDP
      RX/TX on every iteration

## 5. Socket syscall handlers (`smoltcp-xdp` backend)

- [x] 5.1 Implement `socket()`: allocate a virtual fd, create the
      corresponding `smoltcp` `TcpSocket`/`UdpSocket` in the shared
      `SocketSet`, insert into `SocketTable`
- [x] 5.2 Implement `bind()`/`listen()`/`connect()` against the
      `smoltcp` socket, including a bounded poll loop for `connect`
      completion (start from xdplganger's 5s timeout, tune per design
      Open Questions). `listen()` uses a small pool of `smoltcp` sockets
      all independently `.listen()`ing on the same port (see
      `backend.rs` module doc for why a single `smoltcp` TCP socket
      can't fill BSD's listen+accept role alone) — bounded to 1-16
      sockets regardless of the caller's requested backlog
- [x] 5.3 Implement `accept4()` for listening TCP sockets, allocating a
      new virtual fd for the accepted connection, and topping up the
      listen backlog pool with a fresh replica afterward. Bare `accept`
      (nr 43, no metadata in `ctls::meta` and never forwarded by
      `shadow.yaml`) is deliberately never claimed
- [x] 5.4 Implement `read`/`write`/`sendto`/`recvfrom` for backend-owned
      fds, with a bounded poll loop for blocking reads (start from
      xdplganger's 50ms poll interval). **Scope decision**: `sendmsg`(46)/
      `recvmsg`(47) are never claimed — `ctls::meta` deliberately does
      not marshal `struct msghdr`'s nested pointers (documented there),
      so a request for either arrives with no usable buffer contents
      regardless of transport; falls through to the generic passthrough
      unchanged from `direct`
- [x] 5.5 Implement `getsockopt`/`setsockopt`. **Scope decision**: no
      pre-existing test/tool baseline was actually found in the
      repository to scope this against (searched thoroughly — see PR
      discussion), so this implements the two options with concrete
      behavioral meaning against a `smoltcp` socket (`SO_ERROR`,
      `TCP_NODELAY`) and treats every other `level`/`optname` as a
      best-effort no-op success (setsockopt) / zeroed-value success
      (getsockopt) — matching how most software treats these as
      advisory and does not hard-fail when they're silently ignored
- [x] 5.6 Implement `close()`: close the `smoltcp` socket, untrack any
      bound TCP/UDP port (see task 6), remove the `SocketTable` entry
- [x] 5.7 Ensure `read`/`write`/`close`/`poll`/`ppoll` correctly fall
      through to the existing generic `libc::syscall` path when the fd
      is not present in `SocketTable`. For `poll`/`ppoll` specifically,
      ownership requires *every* fd in the `struct pollfd[]` array to be
      backend-tracked — a single call mixing real and virtual fds is out
      of scope and falls through in its entirety (documented limitation
      in `backend.rs` module doc)

## 6. Port tracking and addressing

- [x] 6.1 Call `TcpPortAdd` on successful TCP `listen()`/`connect()`,
      `TcpPortRemove` on close/connection teardown (task 5.6). Note:
      unlike xdplganger (which only tracks ports for outbound
      `connect()`), also track at `listen()` time so inbound TCP
      listeners work — untracked at `close()` for the listening socket.
      Similarly call `UdpPortAdd` on successful UDP `bind()`/`connect()`
      (the latter for the ephemeral local port an unbound UDP socket
      gets on first send), `UdpPortRemove` on close. Implemented via the
      `backend::PortTracker` trait (abstracts `XdpProgram`'s four
      tracking methods so `backend.rs`'s socket-handling logic is
      unit-testable against a `smoltcp::phy::Loopback` device without
      requiring root/`CAP_BPF`)
- [x] 6.2 Implement interface IPv4 auto-detection (`SIOCGIFADDR`/
      `SIOCGIFNETMASK` ioctls for the local address + CIDR prefix,
      `/proc/net/route` for the default-route gateway IPv4) used when not
      explicitly configured. `addr_detect::InterfaceInfoProvider` also
      grew a `local_mac()` method (`SIOCGIFHWADDR`) — always
      auto-detected, no CLI override, since the interface's own hardware
      address (needed for the `smoltcp::iface::Interface`'s source MAC
      and the `XdpDevice` RX destination-MAC filter) is unambiguous and
      locally knowable, unlike the gateway's MAC (6.3)
- [x] 6.3 Implement default-route gateway MAC auto-detection
      (`/proc/net/arp`, with optional ARP-priming ping fallback).
      **Scope finding, changes this task's original framing**: confirmed
      `smoltcp::iface::Interface` (`Medium::Ethernet`, this project's
      smoltcp version 0.13.1) resolves neighbor MACs — including the
      default gateway's — itself via its own ARP requests sent over the
      `XdpDevice`, and exposes no public API to pre-seed its neighbor
      cache. Unlike `xdplganger` (whose gVisor `channel.Endpoint`
      required the gateway's MAC upfront to hand-build outgoing Ethernet
      frames itself, since gVisor's endpoint has no ARP of its own — see
      design D5), this design's smoltcp bridge genuinely does not need
      gateway-MAC auto-detection for correctness. `gateway_mac()` is
      still implemented and unit-tested in `addr_detect.rs` (kept for
      potential future use, e.g. a startup connectivity diagnostic,
      `#[allow(dead_code)]`d in the meantime) but is **not** called from
      backend construction (task 6.4) — see that task's note. Only the
      *gateway IPv4* half of the original xdplganger-modeled behavior
      (`default_route()`, giving the default route's gateway IP, not its
      MAC) is actually wired in, since `Interface`'s own default-route
      table genuinely needs that value.
- [x] 6.4 Add `--xdp-iface`, `--xdp-queue`, `--xdp-mode copy|zerocopy`
      CLI flags to `rsbeacon/src/main.rs`, consumed only when
      `--netstack smoltcp-xdp` is selected; `zerocopy` is rejected with
      an actionable error (v1 only ever binds `XDP_COPY`, per design
      Non-Goals — `XdpSocket::bind` has no zerocopy code path to silently
      fall back to). Also added `--xdp-ip`/`--xdp-prefix`/`--xdp-gateway`
      overrides for the addressing 6.2 auto-detects (no `--xdp-dst-mac`
      flag — dropped along with 6.3's gateway-MAC wiring, since there's
      nothing to feed it into). Backend construction itself
      (`XdpProgram::load_and_attach` → `XdpSocket::bind` →
      `xsks_map` registration → `XdpDevice`/`Interface`/`PollState` →
      spawning `run_poll_loop` on a background thread →
      `SmoltcpXdpBackend::new`) lives in a new
      `net_backend/smoltcp_xdp/init.rs` (`pub fn init(XdpConfig) -> Result<Arc<dyn NetBackend>>`),
      not `main.rs` — `main.rs`'s `init_smoltcp_xdp_backend` only
      validates flags (`--xdp-iface` required, `--xdp-mode` must be
      `copy`, `--xdp-ip`/`--xdp-gateway` parse as valid IPv4) and turns
      them into an `XdpConfig`, keeping the CLI entrypoint free of
      `XdpProgram`/`XdpSocket`/`XdpDevice`/`PollState` wiring details.
      Manually verified end-to-end without root: missing `--xdp-iface`,
      `--xdp-mode zerocopy`, an invalid `--xdp-ip`, and an unknown
      `--xdp-iface` all fail fast with actionable errors before any
      privileged operation; a real interface (`lo`) correctly
      auto-detects its address/prefix/MAC and gateway, and only then
      fails (cleanly, `EPERM`) at the actually-privileged
      `XdpProgram::load_and_attach` step, confirming the whole
      non-privileged config-resolution path is correct.

## 7. Deploy integration

- [ ] 7.1 Thread `--netstack` and `--xdp-*` flags through
      `rscaller-run/src/microvm.rs`'s `/init` script generation, keeping
      `direct` as `rscaller-run`'s own default. **Deferred**: this
      project's current deploy/test path is the two-VM topology (7.2),
      not the microVM image path — revisit when/if that path is actually
      in use.
- [x] 7.2 Update Makefile-driven manual rsbeacon invocations (two-VM
      topology) to support passing the new flags through:
      - `tests/remote/conftest.py`: new `--netstack`/`--xdp-iface`/
        `--xdp-queue` pytest options (default `direct`/none/`0`, matching
        `rsbeacon`'s own defaults), threaded through the
        `rsbeacon_on_beacon` fixture's command line. Fails fast
        (`pytest.fail`, before ever starting rsbeacon) if `--netstack
        smoltcp-xdp` is selected without `--xdp-iface`.
      - `scripts/poc.sh`: same three flags added (`--netstack`/
        `--xdp-iface`/`--xdp-queue`, env-var overridable like the
        script's existing `--beacon`/`--port`/etc.), validated before
        starting rsbeacon, and echoed in the "Print plan" banner.
      - `Makefile`: `NETSTACK`/`XDP_IFACE`/`XDP_QUEUE` variables (empty/
        `direct`-default, matching `rsbeacon`'s CLI), threaded into
        `test-evasion`'s pytest invocation; `poc`/`poc-notracee` need no
        recipe change since GNU Make auto-exports command-line variable
        overrides to recipe subprocesses and `poc.sh` already reads
        these three as env vars with matching defaults — verified via
        `make -n test-evasion NETSTACK=smoltcp-xdp XDP_IFACE=enp1s0` and
        `make -n poc NETSTACK=smoltcp-xdp XDP_IFACE=enp1s0`.
      - `deploy.sh` itself needed no change: it only rsyncs + builds, it
        never invokes rsbeacon with any flags at all.

## 8. Testing

- [ ] 8.1 Unit tests for `SocketTable` virtual fd allocation/lookup/removal
- [ ] 8.2 Integration test: `direct` backend behavioral parity check
      against pre-change rsbeacon for a sample of socket syscalls
- [ ] 8.3 Integration test (veth pair, root required, following the
      `test-evasion`-style VM/pytest fixtures pattern where practical):
      TCP connect/send/recv/close end-to-end through `smoltcp-xdp`
- [ ] 8.4 Integration test: UDP send/recv end-to-end through `smoltcp-xdp`
- [ ] 8.5 Integration test: untracked traffic on the shared interface is
      unaffected (XDP_PASS verification, e.g. concurrent SSH/ping to the
      interface while `smoltcp-xdp` is active)
- [ ] 8.6 Integration test: backend fails to start without root/required
      capabilities, with an actionable error and non-zero exit

## 9. Documentation

- [ ] 9.1 Update `AGENTS.md`/`README.md` with the new `--netstack` flag,
      privilege requirements for `smoltcp-xdp`, and deploy notes
- [ ] 9.2 Document the `NetBackend` trait and how to add a future backend
      (mirroring the existing "Adding a New Backend" pattern documented
      for `ctls` in `ARCHITECTURE.md`)
