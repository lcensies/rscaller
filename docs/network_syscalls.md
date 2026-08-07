# Network syscalls — handling matrix & decisions

Every socket-related syscall, and what each relay layer does with it.
Layers, in order of appearance:

1. **seccomp profile** (`rsc/profiles/relay.yaml`) — whether the syscall is
   intercepted at all. Two rules: `network` (explicit nr list, default
   REMOTE) and `socket-fd-ops` (fd-gated to the virtual range).
2. **rsclient route/translate** (`rsclient/src/relay.rs`) — `route()`:
   connect/sendto-with-sockaddr → REMOTE; AF_UNIX/non-INET socket() → LOCAL;
   sockaddr-less ops → `default_direction`. Proxied fds: translate arm
   (42|48|49|50|51|52|54|55|288) swaps the pair fd for the beacon virtual fd;
   everything else on a proxied fd continues LOCALLY on the socketpair.
3. **socket proxy** (`rsclient/src/socket_proxy.rs`) — data plane: a local
   AF_UNIX SOCK_STREAM pair per beacon socket; kernel does the data copies
   that seccomp can't.
4. **ctls meta** (`ctls/src/meta.rs`) — pointer marshaling table used by the
   direct executor. No entry ⇒ pointers can't cross ⇒ syscall must not be
   forwarded with pointer args.
5. **rsbeacon direct executor** — executes on the beacon kernel with meta
   marshaling; `-errno` on failure.
6. **smoltcp backend** (`rsbeacon/src/net_backend/smoltcp_xdp/backend.rs`) —
   `owns_syscall()` must claim AND `handle()` must implement; a claim gap
   means the raw (virtual) fd reaches the beacon kernel → EBADF/garbage.

## Socket API proper

| nr | name | profile | rsclient | meta | direct exec | smoltcp | status / decision |
|---|---|---|---|---|---|---|---|
| 41 | socket | ✔ network | AF_INET(6)→REMOTE, else LOCAL | ✔ | ✔ | ✔ AF_INET only; INET6 kernel-falls to beacon netstack (smoltcp is v4-only) | OK |
| 42 | connect | ✔ | REMOTE (addr drives route) | ✔ | ✔ | ✔ (UDP peer recorded since the EDESTADDRREQ fix) | OK |
| 43 | accept | — | — | — | — | declined by design | OK: profiles use accept4; bare accept never forwarded |
| 44 | sendto | ✔ | REMOTE; NULL-addr on connected UDP uses stored peer | ✔ | ✔ | ✔ | OK |
| 45 | recvfrom | ✔ | REMOTE | ✔ | ✔ | ✔ | OK |
| 46 | sendmsg | ✔ | proxied fd → LOCAL on pair (not in translate arm) | ✘ (nested iovec pointers — seccomp can't chase tracee memory) | n/a | declined | OK for TCP (pair is a stream). **Must never be forwarded raw.** |
| 47 | recvmsg | ✔ | same as 46 | ✘ | n/a | declined | OK as above |
| 48 | shutdown | ✔ | translate arm ✔ | ✔ | ✔ | **✘ GAP** — reaches beacon kernel with virtual fd → EBADF | **FIX: own+implement in smoltcp backend (TCP close_send, UDP mark)** |
| 49 | bind | ✔ | translate ✔ | ✔ | ✔ | ✔ | OK |
| 50 | listen | ✔ | translate ✔ | ✔ | ✔ | ✔ | OK |
| 51 | getsockname | ✔ | translate ✔ | ✔ | ✔ | **✘ GAP** — same fallthrough → **this is the rfc3484_sort crash** (glibc's getaddrinfo sort probe getsockname()s a relayed UDP socket, gets garbage family, glibc aborts) | **FIX: return xdp-ip + local port / stored peer** |
| 52 | getpeername | ✔ | translate ✔ | ✔ | ✔ | **✘ GAP** — same | **FIX: TCP remote ep / UDP connected peer** |
| 53 | socketpair | — | LOCAL | — | — | — | OK: host-local IPC, never leaves |
| 54 | setsockopt | ✔ | translate ✔ | ✔ | ✔ | ✔ | OK |
| 55 | getsockopt | ✔ | translate ✔ | ✔ | ✔ | ✔ | OK |
| 288 | accept4 | ✔ | translate ✔; result gets proxy spawned immediately | ✔ | ✔ | ✔ | OK |
| 307 | sendmmsg | — | LOCAL on pair | ✘ | n/a | n/a | **Boundary loss on stream pair** (A+AAAA merge — the DNS flake). Workaround shipped: `options single-request`. **Proper fix: SOCK_DGRAM pair for UDP sockets — kernel preserves one datagram per mmsghdr element** |
| 299 | recvmmsg | — | LOCAL on pair | ✘ | n/a | n/a | Same story as 307; fixed by the same dgram pair |
| 102 | socketcall | — | — | — | — | — | N/A: i386 only, absent on x86-64 |

## Fd-generic syscalls on socket fds

With the proxy ON (default), the tracee's fd is a local pair fd — these run
on the LOCAL kernel and behave correctly by construction. The
`socket-fd-ops` rule (fd ≥ VIRTUAL_FD_BASE) only matters for the
`RSC_SOCKET_PROXY=0` bare-virtual-fd mode.

| nr | name | proxy mode | bare-fd mode | decision |
|---|---|---|---|---|
| 0 | read | local (pair) | fd-gated → beacon, translated | OK |
| 1 | write | local (pair) | same | OK (50 MiB md5-verified after drain fix) |
| 3 | close | local (pair EOF → proxy cleanup; drain-wait at teardown) | fd-gated → beacon | OK after drain fix |
| 7 | poll | local; relay only forwards when ALL fds are beacon-virtual | owned by smoltcp for owned pollfds | OK |
| 271 | ppoll | same as poll | same | OK |
| 23 / 270 | select / pselect6 | local on pair | not gated → local on real fd → **wrong** | Accepted gap: bare-fd mode is debug-only |
| 72 | fcntl | local (pair) | fd-gated → beacon (O_NONBLOCK mirrored) | OK |
| 16 | ioctl | local (pair) | fd-gated → beacon `sys_ioctl` | OK |
| 32/33/292 | dup* | local; dup of an injected fd yields another fd on the same pair — relay never sees the new number, ops stay local → correct | **broken** (dup of virtual fd unknown to beacon) | Accepted gap: bare-fd mode is debug-only |
| 232/233 | epoll_ctl/epoll_wait | local on pair | broken (same reason as dup) | Accepted gap, same |
| 19/20 | readv/writev | local on pair | not gated | OK in proxy mode |
| 40/275 | sendfile/splice | local on pair | not gated | OK in proxy mode |
| 425/426 | io_uring_* | not intercepted | — | Out of scope: whole ring would need virtualizing. No current payload uses it |

## Action items (gap fixes)

1. **smoltcp: own+implement 48/51/52** — the rfc3484_sort abort. getaddrinfo
   on any relayed connection does a getsockname probe; today that fd hits
   the beacon kernel raw and returns garbage/EBADF. (getsockname: iface IP +
   bound port; getpeername: TCP remote / UDP stored peer; shutdown: TCP
   close_send, UDP no-op-success.)
2. **SOCK_DGRAM socketpair for UDP tracee sockets** — removes the
   datagram-boundary class of bugs (sendmmsg/recvmmsg merge/split) and lets
   the `single-request` resolv.conf hack be dropped.
3. Keep 46/47 and 307/299 OUT of any forwarded list forever unless a
   ptrace-style memory reader is added — the mmsghdr/iovec arrays live in
   tracee memory; blind forwarding produced the merged-datagram corruption.
