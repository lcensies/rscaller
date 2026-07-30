//! XDP eBPF program load/attach and `tcp_ports`/`udp_ports` map
//! management, via `aya`.
//!
//! The program itself lives in `bpf/xdp_prog.c` (compiled ahead-of-time to
//! `bpf/xdp_prog.o`, embedded here via `include_bytes!`) — see design
//! decision D4. It redirects ICMP, tracked-TCP-port, and tracked-UDP-port
//! traffic into the backend's AF_XDP socket via `xsks_map`, `XDP_PASS`-ing
//! everything else. TCP and UDP ports are tracked in two separate maps
//! (`tcp_ports`/`udp_ports`) since they're independent port namespaces —
//! see the file header comment in `xdp_prog.c` for why.

use std::os::unix::io::RawFd;

use anyhow::{Context, Result};
use aya::maps::xdp::XskMap;
use aya::maps::HashMap as AyaHashMap;
use aya::programs::xdp::XdpMode;
use aya::programs::Xdp;
use aya::Ebpf;

/// The compiled XDP object, produced ahead-of-time from `bpf/xdp_prog.c`
/// (see that file's header comment for the exact rebuild command). Checked
/// into the repo, matching xdplganger's approach of not requiring a BPF
/// toolchain on the beacon host at run time — only the build host (per the
/// two-VM topology, that's always dev-vm-1, never dev-vm-2/the beacon
/// itself) needs clang, and only when *rebuilding* the object (see
/// `build.rs`).
static XDP_PROG_OBJ: &[u8] = include_bytes!("../../../bpf/xdp_prog.o");

const XDP_PROG_NAME: &str = "xdp_sock_prog";
const XSKS_MAP_NAME: &str = "xsks_map";
const TCP_PORTS_MAP_NAME: &str = "tcp_ports";
const UDP_PORTS_MAP_NAME: &str = "udp_ports";

/// Owns the loaded/attached XDP program and its maps for the lifetime of
/// the `smoltcp-xdp` backend. Detaches/unloads on drop.
pub struct XdpProgram {
    // Order matters for drop: `_ebpf` must outlive the maps borrowed from
    // it, so maps are dropped first (declared first), `_ebpf` last.
    xsks_map: XskMap<aya::maps::MapData>,
    tcp_ports: AyaHashMap<aya::maps::MapData, u32, u8>,
    udp_ports: AyaHashMap<aya::maps::MapData, u32, u8>,
    _ebpf: Ebpf,
}

impl XdpProgram {
    /// Loads the embedded XDP object, attaches its `xdp` program to
    /// `iface` in generic (SKB) mode — portable across all NIC drivers,
    /// including veth, matching the design's copy-mode-first portability
    /// goal for v1 (see Non-Goals re: zero-copy/native mode).
    pub fn load_and_attach(iface: &str) -> Result<Self> {
        let mut ebpf = Ebpf::load(XDP_PROG_OBJ).context("loading embedded xdp_prog.o")?;

        let program: &mut Xdp = ebpf
            .program_mut(XDP_PROG_NAME)
            .with_context(|| format!("no program named '{XDP_PROG_NAME}' in xdp_prog.o"))?
            .try_into()
            .context("program is not an XDP program")?;
        program.load().context("loading xdp program into kernel")?;
        program
            .attach(iface, XdpMode::Skb)
            .with_context(|| format!("attaching xdp program to interface '{iface}'"))?;

        let xsks_map: XskMap<_> = ebpf
            .take_map(XSKS_MAP_NAME)
            .with_context(|| format!("no map named '{XSKS_MAP_NAME}' in xdp_prog.o"))?
            .try_into()
            .context("xsks_map is not an XSKMAP")?;

        let tcp_ports: AyaHashMap<_, u32, u8> = ebpf
            .take_map(TCP_PORTS_MAP_NAME)
            .with_context(|| format!("no map named '{TCP_PORTS_MAP_NAME}' in xdp_prog.o"))?
            .try_into()
            .context("tcp_ports is not a HASH map")?;

        let udp_ports: AyaHashMap<_, u32, u8> = ebpf
            .take_map(UDP_PORTS_MAP_NAME)
            .with_context(|| format!("no map named '{UDP_PORTS_MAP_NAME}' in xdp_prog.o"))?
            .try_into()
            .context("udp_ports is not a HASH map")?;

        Ok(Self {
            xsks_map,
            tcp_ports,
            udp_ports,
            _ebpf: ebpf,
        })
    }

    /// Registers the backend's AF_XDP socket fd into `xsks_map` at
    /// `queue_id`, so the XDP program's `bpf_redirect_map` calls for that
    /// RX queue land on this socket.
    pub fn register_xsk(&mut self, queue_id: u32, xsk_fd: RawFd) -> Result<()> {
        self.xsks_map
            .set(queue_id, xsk_fd, 0)
            .context("registering AF_XDP socket fd into xsks_map")
    }

    /// Marks `port` (host byte order) as owned by the smoltcp-xdp backend,
    /// so inbound TCP traffic for it gets redirected instead of passed to
    /// the normal kernel stack. Called on successful TCP bind/connect.
    pub fn track_tcp_port(&mut self, port: u16) -> Result<()> {
        self.tcp_ports
            .insert(port as u32, 1u8, 0)
            .with_context(|| format!("adding port {port} to tcp_ports map"))
    }

    /// Reverses [`XdpProgram::track_tcp_port`]. Called on socket close /
    /// connection teardown. Not finding the port is not an error (it may
    /// already have been removed, or never successfully added).
    pub fn untrack_tcp_port(&mut self, port: u16) {
        let _ = self.tcp_ports.remove(&(port as u32));
    }

    /// Marks `port` (host byte order) as owned by the smoltcp-xdp
    /// backend's UDP sockets, so inbound UDP traffic for it gets
    /// redirected instead of passed to the normal kernel stack. Called on
    /// successful UDP bind (and on connect(), for the ephemeral local
    /// port a UDP socket gets assigned if it wasn't already bound).
    pub fn track_udp_port(&mut self, port: u16) -> Result<()> {
        self.udp_ports
            .insert(port as u32, 1u8, 0)
            .with_context(|| format!("adding port {port} to udp_ports map"))
    }

    /// Reverses [`XdpProgram::track_udp_port`]. Called on socket close.
    /// Not finding the port is not an error (it may already have been
    /// removed, or never successfully added).
    pub fn untrack_udp_port(&mut self, port: u16) {
        let _ = self.udp_ports.remove(&(port as u32));
    }
}

// `XdpProgram` is dropped when the `smoltcp-xdp` backend shuts down;
// `Ebpf`'s own `Drop` impl detaches/unloads the program and closes the map
// fds, so no explicit teardown code is needed here beyond struct field
// ordering (maps before `_ebpf`, enforced by declaration order above and
// Rust's field drop order).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_object_is_nonempty_and_elf() {
        // Sanity check that the checked-in .o is present and at least
        // structurally an ELF file — catches an accidentally-empty or
        // corrupted embed without needing root/a real interface.
        assert!(XDP_PROG_OBJ.len() > 64);
        assert_eq!(&XDP_PROG_OBJ[0..4], b"\x7fELF");
    }

    #[test]
    fn embedded_object_loads_or_fails_cleanly_without_privileges() {
        // `Ebpf::load` doesn't just parse the ELF — it also creates the
        // program's maps in the kernel (bpf_create_map), which requires
        // CAP_BPF/root. Without privileges (the common case for `cargo
        // test`) this must fail cleanly with an `EbpfError`, never panic;
        // when it *does* succeed (privileged CI runner / dev-vm-1 as
        // root), the expected program and maps must be present. Full
        // load+attach+redirect behavior is covered separately by a
        // root-requiring integration test (see task 8.x).
        match Ebpf::load(XDP_PROG_OBJ) {
            Ok(ebpf) => {
                assert!(ebpf.program(XDP_PROG_NAME).is_some(), "missing xdp program");
                assert!(ebpf.map(XSKS_MAP_NAME).is_some(), "missing xsks_map");
                assert!(ebpf.map(TCP_PORTS_MAP_NAME).is_some(), "missing tcp_ports map");
                assert!(ebpf.map(UDP_PORTS_MAP_NAME).is_some(), "missing udp_ports map");
            }
            Err(e) => {
                // Expected in an unprivileged sandbox/CI environment.
                eprintln!("Ebpf::load failed without privileges (expected): {e}");
            }
        }
    }
}
