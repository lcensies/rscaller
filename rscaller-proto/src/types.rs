use serde::{Deserialize, Serialize};

/// First virtual (beacon-allocated, not backed by any real kernel fd on
/// either side) file descriptor value. Shared between:
/// - `rsbeacon`'s `NetBackend` implementations (e.g. `smoltcp-xdp`), which
///   allocate fds from this range for sockets serviced entirely in
///   userspace against their own stack (see `SocketTable`);
/// - the client-side seccomp filter (`ctls`/`rsc`), which uses this exact
///   value as the threshold for deciding whether `read`/`write`/`close`/
///   `poll`/`ppoll` on a given fd need to be forwarded to rsbeacon at all
///   (fd >= this value) or can run against the tracee's real kernel
///   locally (fd < this value, i.e. an ordinary file/pipe/real-socket fd).
///
/// Both sides must agree on this value: rsbeacon is the one handing out
/// fd numbers (as `SyscallResponse::ret` for `socket()`/`accept4()`), and
/// the seccomp filter is the one deciding — independently, in the
/// tracee's kernel, before any round-trip to rsbeacon — whether a later
/// `read`/`write`/`close`/`poll`/`ppoll` on that same fd number is even
/// worth intercepting.
pub const VIRTUAL_FD_BASE: i64 = 1 << 30;

/// A single pointer-argument buffer payload.
///
/// For IN/INOUT params, `data` contains bytes copied from the process's
/// userspace memory by kmod (via copy_from_user).  For OUT params returning
/// from the beacon, `data` contains the bytes the syscall wrote into the
/// beacon-side buffer; kmod will copy_to_user them back into the originating
/// process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallBuf {
    pub arg_idx: u8,
    pub data: Vec<u8>,
}

/// A request to execute a raw syscall on the beacon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallRequest {
    /// Slot index for correlating requests/responses.
    pub slot_idx: u64,
    /// Linux syscall number.
    pub number: u64,
    /// Up to 6 syscall arguments.
    pub args: [u64; 6],
    /// Contents of IN/INOUT pointer params (copied from the process's memory by kmod).
    pub in_bufs: Vec<SyscallBuf>,
    /// `(arg_idx, size)` for OUT/INOUT pointer params — beacon must allocate
    /// a local buffer of `size` bytes and return its post-syscall contents.
    pub out_sizes: Vec<(u8, u64)>,
}

/// The result of executing a syscall on the beacon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallResponse {
    /// Matches the slot_idx from the request.
    pub slot_idx: u64,
    /// Raw return value from libc::syscall().
    pub ret: i64,
    /// OUT/INOUT buffer contents after syscall execution, for copy_to_user.
    pub out_bufs: Vec<SyscallBuf>,
}

// ── Rendezvous server (rsserver) handshake ─────────────────────────────────

/// First frame on every rsserver connection: identifies the role and the
/// session to join. After the server replies with [`RelayAck`], the
/// connection becomes a raw byte pipe to the paired peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayHello {
    /// A beacon dialing out; parked until a client for `name` arrives.
    Beacon { name: String, token: String },
    /// A client; paired with a waiting beacon for `name` (or parked).
    Client { name: String, token: String },
}

/// Server's answer to a [`RelayHello`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayAck {
    pub ok: bool,
    pub msg: String,
}
