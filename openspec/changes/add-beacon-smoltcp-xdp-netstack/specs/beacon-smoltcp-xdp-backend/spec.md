## ADDED Requirements

### Requirement: smoltcp-xdp backend routes socket operations through a userspace netstack
When the `smoltcp-xdp` network backend is active, rsbeacon SHALL service
intercepted socket-related syscalls (`socket`, `bind`, `connect`,
`listen`, `accept4`, send/receive variants, `getsockopt`/`setsockopt`,
and `read`/`write`/`close` on backend-owned fds) through a `smoltcp`
userspace TCP/IP stack, instead of the beacon host's kernel network
stack, for IPv4 TCP and UDP traffic.

#### Scenario: TCP connect is serviced by smoltcp, not the host kernel
- **WHEN** a `connect` syscall for an `AF_INET`/`SOCK_STREAM` socket is
  received while the `smoltcp-xdp` backend is active
- **THEN** the connection is established through a `smoltcp` TCP socket
  and its packets are transmitted/received exclusively via the backend's
  AF_XDP socket, without the beacon host's kernel TCP/IP stack
  processing the connection

#### Scenario: UDP socket operations are serviced by smoltcp
- **WHEN** `sendto`/`recvfrom` syscalls for an `AF_INET`/`SOCK_DGRAM`
  socket are received while the `smoltcp-xdp` backend is active
- **THEN** the datagrams are sent/received through a `smoltcp` UDP
  socket via the backend's AF_XDP socket

### Requirement: Virtual socket table tracks backend-owned file descriptors
The `smoltcp-xdp` backend SHALL allocate a virtual file descriptor for
each `socket()` call it services and maintain a socket table mapping
each virtual fd to its corresponding `smoltcp` socket handle, so that
subsequent syscalls referencing that fd are routed to the backend.

#### Scenario: Virtual fd is returned from socket()
- **WHEN** a `socket(AF_INET, SOCK_STREAM, ...)` or
  `socket(AF_INET, SOCK_DGRAM, ...)` syscall is serviced by the
  `smoltcp-xdp` backend
- **THEN** the returned fd is a virtual fd tracked in the backend's
  socket table, distinct from any real kernel fd the beacon process
  holds open

#### Scenario: close() releases the virtual socket
- **WHEN** a `close` syscall is received for a virtual fd present in the
  socket table
- **THEN** the backend closes the corresponding `smoltcp` socket,
  removes any associated tracked TCP port, and removes the entry from
  the socket table

### Requirement: AF_XDP socket and UMEM setup
The `smoltcp-xdp` backend SHALL create and bind an AF_XDP socket with an
associated UMEM (fill, completion, RX, and TX rings) on the configured
network interface and queue at backend initialization time.

#### Scenario: AF_XDP socket created on configured interface
- **WHEN** the `smoltcp-xdp` backend initializes with a configured
  interface name and queue ID
- **THEN** it creates a UMEM, registers it via the AF_XDP socket, sets up
  fill/completion/RX/TX rings, and binds the socket to that interface and
  queue in copy mode

#### Scenario: Backend fails to initialize without required privileges
- **WHEN** the `smoltcp-xdp` backend attempts to create the AF_XDP
  socket or load the XDP program without sufficient privileges
  (root or `CAP_NET_ADMIN`/`CAP_BPF`)
- **THEN** initialization fails with an actionable error and rsbeacon
  does not start (per the fail-fast requirement in `beacon-net-backend`)

### Requirement: XDP program redirects only tracked traffic
The `smoltcp-xdp` backend SHALL load and attach an XDP eBPF program to
the configured interface that redirects only ICMP packets, TCP packets
whose destination port is in a tracked TCP-ports map, and UDP packets
whose destination port is in a tracked UDP-ports map, into the backend's
AF_XDP socket, passing all other traffic through to the host kernel's
normal network stack unaffected. TCP and UDP ports are tracked in two
separate maps, since they are independent port namespaces.

#### Scenario: Untracked traffic is unaffected
- **WHEN** a packet arrives on the configured interface whose protocol
  is not ICMP and, for TCP/UDP, whose destination port is not in the
  corresponding tracked-ports map
- **THEN** the XDP program passes the packet through to the host
  kernel's normal network stack (`XDP_PASS`)

#### Scenario: Tracked TCP port traffic is redirected
- **WHEN** a TCP packet arrives on the configured interface whose
  destination port is present in the tracked TCP-ports map
- **THEN** the XDP program redirects the packet into the backend's
  AF_XDP socket via the `XSKMAP`

#### Scenario: Tracked UDP port traffic is redirected
- **WHEN** a UDP packet arrives on the configured interface whose
  destination port is present in the tracked UDP-ports map
- **THEN** the XDP program redirects the packet into the backend's
  AF_XDP socket via the `XSKMAP`

### Requirement: Port tracking follows socket lifecycle
The `smoltcp-xdp` backend SHALL add a TCP socket's local port to the XDP
program's tracked TCP-ports map when that port becomes bound via
`listen()` or `connect()`, and SHALL add a UDP socket's local port to
the tracked UDP-ports map when that port becomes bound via `bind()` or
`connect()`; in both cases the backend SHALL remove the port when the
owning socket is closed or its connection is torn down.

#### Scenario: Port tracked on successful bind or connect
- **WHEN** a `smoltcp` TCP socket successfully binds to or connects from
  a local port while the `smoltcp-xdp` backend is active
- **THEN** that local port is added to the XDP program's tracked-ports
  map so inbound return traffic for it is redirected to the backend

#### Scenario: Port untracked on close
- **WHEN** a `smoltcp` TCP socket owning a tracked local port is closed
- **THEN** that local port is removed from the XDP program's
  tracked-ports map

### Requirement: Configurable interface and addressing parameters
The `smoltcp-xdp` backend SHALL accept configuration for the network
interface, queue ID, and destination MAC address to use, and SHALL
auto-detect the interface's own IPv4 address and default-route gateway
MAC address when not explicitly configured.

#### Scenario: Explicit configuration is honored
- **WHEN** the `smoltcp-xdp` backend is started with explicit interface,
  queue, and destination MAC flags
- **THEN** it uses exactly those values instead of auto-detecting them

#### Scenario: Auto-detection fills in unset addressing parameters
- **WHEN** the `smoltcp-xdp` backend is started without an explicit
  destination MAC or IPv4 address
- **THEN** it auto-detects the interface's own IPv4 address and the
  default-route gateway MAC address before servicing any socket syscalls
