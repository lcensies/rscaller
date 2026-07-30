## ADDED Requirements

### Requirement: Pluggable network syscall execution backend
rsbeacon SHALL execute the socket-related syscalls it receives
(`socket`, `bind`, `connect`, `listen`, `accept4`, `sendto`, `recvfrom`,
`sendmsg`, `recvmsg`, `getsockopt`, `setsockopt`, and fd-generic
`read`/`write`/`close`/`poll`/`ppoll` when the fd belongs to a
backend-owned socket) through a selectable `NetBackend` implementation,
rather than unconditionally through the direct `libc::syscall`
passthrough used for all other syscalls.

#### Scenario: Non-socket syscalls are unaffected by backend selection
- **WHEN** rsbeacon receives a `SyscallRequest` whose `number` is not one
  of the intercepted socket-related syscall numbers, regardless of which
  `NetBackend` is active
- **THEN** rsbeacon executes it via the existing generic `libc::syscall`
  passthrough exactly as before this change

#### Scenario: fd-generic syscalls fall through when the fd is not backend-owned
- **WHEN** rsbeacon receives a `read`, `write`, `close`, `poll`, or
  `ppoll` request for a file descriptor that is not tracked in the
  active backend's socket table
- **THEN** rsbeacon executes it via the existing generic `libc::syscall`
  passthrough, regardless of which `NetBackend` is active

### Requirement: `direct` backend preserves current behavior exactly
rsbeacon SHALL provide a `direct` network backend whose behavior for
every intercepted socket-related syscall is identical to executing that
syscall via `libc::syscall` against the beacon host's kernel, matching
rsbeacon's behavior prior to this change.

#### Scenario: `direct` is the default backend
- **WHEN** rsbeacon is started without specifying a network backend
- **THEN** rsbeacon operates with the `direct` backend, executing all
  socket-related syscalls via the beacon host's kernel exactly as before
  this change was introduced

#### Scenario: `direct` backend executes a socket syscall
- **WHEN** the `direct` backend receives a `SyscallRequest` for any
  intercepted socket-related syscall number
- **THEN** rsbeacon executes it via `libc::syscall` against the beacon
  host's real kernel and returns the resulting `SyscallResponse`
  unchanged from today's behavior

### Requirement: Backend selection via CLI flag
rsbeacon SHALL expose a `--netstack` CLI flag accepting `direct` or
`smoltcp-xdp` to select the active `NetBackend` at startup, following
the same flat-CLI-flag configuration convention as the existing
`--transport` and `--encryption` flags. No configuration file mechanism
SHALL be introduced.

#### Scenario: Valid backend name selected
- **WHEN** rsbeacon is started with `--netstack smoltcp-xdp`
- **THEN** rsbeacon initializes and activates the `smoltcp-xdp` backend
  for the lifetime of the process

#### Scenario: Unknown backend name rejected
- **WHEN** rsbeacon is started with `--netstack <unknown-value>` where
  `<unknown-value>` is neither `direct` nor `smoltcp-xdp`
- **THEN** rsbeacon fails to start with an actionable error identifying
  the invalid value, without silently falling back to `direct`

### Requirement: Backend initialization failures are fail-fast
rsbeacon SHALL fail to start, with an actionable error message, if the
selected `NetBackend` cannot be initialized (e.g. missing privileges,
missing required flags, unavailable network interface), rather than
starting successfully and silently falling back to a different backend.

#### Scenario: Backend initialization error surfaces at startup
- **WHEN** the selected `NetBackend` fails to initialize for any reason
- **THEN** rsbeacon exits with a non-zero status and logs an actionable
  error describing the initialization failure, and does not accept
  client connections
