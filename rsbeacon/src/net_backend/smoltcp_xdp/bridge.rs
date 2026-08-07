//! `smoltcp::phy::Device` bridge over an AF_XDP socket, plus `Interface`
//! construction and the background poll loop that drives `smoltcp`
//! sockets through it. See design D5.
//!
//! Unlike `xdplganger`'s gVisor bridge — which operates its
//! `channel.Endpoint` at the IP layer and so must manually prepend/strip
//! the 14-byte Ethernet header crossing to/from the AF_XDP socket — this
//! bridge keeps `smoltcp::phy::Medium::Ethernet`, which natively speaks
//! full Ethernet framing. No manual header handling is needed here; RX
//! frames are handed to `smoltcp` as-is (including their Ethernet header)
//! and TX frames come back out of `smoltcp` already fully framed.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};

use super::xdp_abi::Desc;
use super::xdp_socket::XdpSocket;

/// Ethernet header length (dst MAC + src MAC + EtherType), used both to
/// pad `DeviceCapabilities::max_transmission_unit` (smoltcp counts the
/// full Ethernet frame in the MTU for `Medium::Ethernet`, see
/// `smoltcp::phy::RawSocket::new`) and to bounds-check/parse RX frames.
const ETHERNET_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;

/// Number of RX descriptors drained from the AF_XDP ring per `read_batch`
/// call. Chosen to match `xdplganger`'s `rxLoop` batch size.
const RX_BATCH: usize = 64;

/// The IPv4 MTU rsbeacon's `smoltcp-xdp` backend advertises on its
/// virtual interface (matches `xdplganger`'s `bridgeMTU`). The Ethernet
/// (`DeviceCapabilities`) MTU is this plus the Ethernet header length.
pub const BRIDGE_MTU: usize = 1500;

/// A `smoltcp::phy::Device` backed by an AF_XDP socket + UMEM.
///
/// Only IPv4 and ARP EtherTypes are ever handed up to `smoltcp`; IPv4
/// frames not addressed to `local_mac` (unicast or broadcast) are
/// dropped at this layer (the XDP program itself already restricts which
/// frames reach userspace at all — ICMP + tracked TCP ports only, see
/// `bpf.rs` — this is an additional, cheap sanity filter, not the
/// primary security boundary).
pub struct XdpDevice {
    sock: Arc<XdpSocket>,
    local_mac: EthernetAddress,
    /// RX descriptors already drained from the ring but not yet handed
    /// out as an `RxToken` (a single `read_batch` call may return more
    /// than one packet worth of work).
    pending: VecDeque<Desc>,
    /// Advertised MTU (drives smoltcp's TCP MSS). Defaults to
    /// [`BRIDGE_MTU`]; override via [`XdpDevice::with_mtu`].
    mtu: usize,
}

impl XdpDevice {
    pub fn new(sock: Arc<XdpSocket>, local_mac: EthernetAddress) -> Self {
        Self {
            sock,
            local_mac,
            pending: VecDeque::with_capacity(RX_BATCH),
            mtu: BRIDGE_MTU,
        }
    }

    /// Override the advertised MTU (smoltcp has no PMTUD — see
    /// `XdpConfig::mtu`).
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    /// Returns `true` if `desc`'s frame is one `smoltcp` should see:
    /// long enough for an Ethernet header, EtherType IPv4 (destined to
    /// our own MAC or broadcast) or ARP (let `smoltcp`'s own ARP/NDISC
    /// logic decide relevance).
    fn accept(&self, desc: Desc) -> bool {
        let len = desc.len as usize;
        if len < ETHERNET_HEADER_LEN {
            return false;
        }
        // SAFETY: `desc` was just returned by `XdpSocket::read_batch`, so
        // `desc.addr`/`desc.len` describe a currently-owned RX frame we
        // have not yet reclaimed, and `len >= ETHERNET_HEADER_LEN` was
        // just checked above and is `<= FRAME_SIZE` (the kernel never
        // reports a longer frame than the UMEM frame it was written into).
        let frame = unsafe { self.sock.umem().frame_slice(desc.addr, len) };
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        match ethertype {
            ETHERTYPE_IPV4 => {
                let dst = &frame[0..6];
                dst == self.local_mac.as_bytes() || dst == [0xff; 6]
            }
            ETHERTYPE_ARP => true,
            _ => false,
        }
    }
}

impl Device for XdpDevice {
    type RxToken<'a>
        = RxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken
    where
        Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu + ETHERNET_HEADER_LEN;
        caps.max_burst_size = Some(RX_BATCH);
        caps.medium = Medium::Ethernet;
        // RX checksum verification disabled for TCP/UDP. Verified by direct
        // A/B test (veth pair, peer netns running a Python TCP echo
        // server, connect()/sendto()/recvfrom() forwarded end-to-end
        // through this backend via `rsc exec --mount-profile shadow`):
        // with smoltcp's default (`Checksum::Both`, verify+compute),
        // connect() reproducibly timed out (ETIMEDOUT after the 5s poll
        // bound) even though tcpdump-equivalent capture showed the
        // peer's SYN-ACK arriving correctly — `iface: malformed
        // TcpRepr::parse` in smoltcp's own trace log confirmed RX
        // checksum verification was rejecting it. Root cause: the
        // peer's veth end has tx-checksum-ip-generic offload enabled
        // (`ethtool -k veth-peer0`), so its kernel leaves the real
        // checksum computation to "hardware" that doesn't exist for
        // veth — a raw AF_XDP capture sees whatever placeholder was
        // left in the frame, not a valid one. `Checksum::Tx` still
        // computes a correct checksum for frames *we* send (the peer's
        // real kernel socket verifies those normally), it only stops
        // verifying what we receive. With this set, the exact same test
        // passes in ~50ms. Toggling this line back to the default and
        // rerunning is the fastest way to re-confirm both halves of
        // this if the fix is ever questioned.
        caps.checksum.tcp = smoltcp::phy::Checksum::Tx;
        caps.checksum.udp = smoltcp::phy::Checksum::Tx;
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        loop {
            if self.pending.is_empty() {
                let mut buf = [Desc::default(); RX_BATCH];
                let n = self.sock.read_batch(&mut buf);
                if n == 0 {
                    return None;
                }
                tracing::info!("XDP_DIAG: read_batch got {n} descriptor(s)");
                self.pending.extend(buf[..n].iter().copied());
            }

            // `pending` was just confirmed non-empty (either already had
            // entries, or was just refilled with n > 0 descriptors).
            let desc = self.pending.pop_front().expect("just checked non-empty");
            let accepted = self.accept(desc);
            {
                let len = (desc.len as usize).min(64);
                let frame = unsafe { self.sock.umem().frame_slice(desc.addr, len) };
                tracing::info!(
                    "XDP_DIAG: rx desc len={} accepted={accepted} bytes={:02x?}",
                    desc.len,
                    frame
                );
            }
            if accepted {
                let rx = RxToken {
                    sock: self.sock.clone(),
                    desc,
                };
                let tx = TxToken {
                    sock: self.sock.clone(),
                };
                return Some((rx, tx));
            }
            // Not interesting to smoltcp (shouldn't normally happen given
            // the XDP program's own filtering, but the device layer must
            // stay correct independent of that) — recycle the frame back
            // to the fill ring immediately rather than leaking it.
            self.sock.reclaim_rx(&[desc]);
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        tracing::info!("XDP_DIAG: transmit() token requested");
        Some(TxToken {
            sock: self.sock.clone(),
        })
    }
}

/// Hands one already-received UMEM frame to `smoltcp`, then recycles it
/// back to the fill ring — the "RX descriptor recycling" half of task 4.2.
pub struct RxToken {
    sock: Arc<XdpSocket>,
    desc: Desc,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        // SAFETY: `self.desc` was returned by `XdpSocket::read_batch` and
        // has not been reclaimed yet (that happens right below, after
        // `f` is done with the slice) — no other live reference to this
        // frame region exists concurrently (single poll loop thread).
        let frame = unsafe { self.sock.umem().frame_slice(self.desc.addr, self.desc.len as usize) };
        let result = f(frame);
        self.sock.reclaim_rx(&[self.desc]);
        result
    }
}

/// Allocates a UMEM TX frame, hands it to `smoltcp` to fill, then enqueues
/// it on the TX ring and kicks the socket — the "TX completion draining"
/// half of task 4.2 happens opportunistically here too (draining before
/// allocating, matching `xdplganger`'s `sendRaw`).
pub struct TxToken {
    sock: Arc<XdpSocket>,
}

impl phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let umem = self.sock.umem();
        // Recycle any TX frames the kernel has finished with before
        // trying to allocate a new one, same as `sendRaw`/`DrainCompletion`.
        umem.drain_completion();

        match umem.alloc_frame() {
            Some(addr) => {
                // SAFETY: `addr` was just taken from the free-frame pool
                // (exclusively owned by us until enqueued/freed below),
                // and `len <= FRAME_SIZE` is guaranteed by smoltcp only
                // ever requesting up to `capabilities().max_transmission_unit`.
                let slice = unsafe { umem.frame_slice_mut(addr, len) };
                let result = f(slice);
                {
                    let dump_len = len.min(64);
                    tracing::info!("XDP_DIAG: tx len={len} bytes={:02x?}", &slice[..dump_len]);
                }
                let desc = Desc {
                    addr,
                    len: len as u32,
                    options: 0,
                };
                if self.sock.write_batch(&[desc]) > 0 {
                    let _ = self.sock.kick();
                } else {
                    // TX ring was full; drop the frame rather than leak it.
                    umem.free_frame(addr);
                }
                result
            }
            None => {
                // No free UMEM frame available — smoltcp's `TxToken`
                // contract still requires calling `f` exactly once; the
                // packet is simply dropped (equivalent to an interface
                // that's momentarily out of TX buffers).
                let mut scratch = vec![0u8; len];
                f(&mut scratch)
            }
        }
    }
}

/// Builds a `smoltcp::iface::Interface` bound to `device`, with the given
/// hardware/IPv4 address and (optional) default gateway — task 4.3.
/// `prefix_len` is the IPv4 CIDR prefix length for `local_ip` (e.g. `24`).
pub fn build_interface(
    device: &mut XdpDevice,
    local_mac: EthernetAddress,
    local_ip: Ipv4Address,
    prefix_len: u8,
    gateway: Option<Ipv4Address>,
    now: Instant,
) -> Interface {
    let config = Config::new(HardwareAddress::Ethernet(local_mac));
    let mut iface = Interface::new(config, device, now);
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(local_ip), prefix_len))
            .expect("fresh Interface's address list has room for one entry");
    });
    if let Some(gw) = gateway {
        iface
            .routes_mut()
            .add_default_ipv4_route(gw)
            .expect("fresh Interface's route table has room for a default route");
    }
    iface
}

/// Owns the poll loop's shared, lockable state: the `Interface` and its
/// `SocketSet`. Socket syscall handlers (task group 5) lock this to add/
/// configure/tear down sockets; the poll loop (below) locks it once per
/// iteration to drive `iface.poll()`.
pub struct PollState {
    pub iface: Interface,
    pub sockets: SocketSet<'static>,
}

/// Drives `state.iface.poll()` against `device` and `state.sockets` in a
/// tight loop until `stop` is set, servicing AF_XDP RX/TX on every
/// iteration — task 4.4. Runs on the calling thread; callers spawn this
/// onto a dedicated background thread (`smoltcp-xdp` backend init).
///
/// Generic over `D: Device` rather than hardcoded to `XdpDevice` so
/// `net_backend::smoltcp_xdp::backend`'s unit tests can drive the exact
/// same poll loop against a `smoltcp::phy::Loopback` device instead of a
/// real AF_XDP socket (which needs root/a real interface) — production
/// callers always pass an `XdpDevice`.
///
/// Sleeps briefly between iterations when there was no work, to avoid
/// spinning a full CPU core — matching the spirit of `xdplganger`'s
/// `rxLoop` `100µs` idle sleep (exact interval is one of this change's
/// open questions, tunable based on integration testing).
pub fn run_poll_loop<D: Device>(
    state: Arc<Mutex<PollState>>,
    mut device: D,
    stop: Arc<AtomicBool>,
) {
    const IDLE_SLEEP: Duration = Duration::from_micros(100);
    let mut iters: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        let result = {
            let mut state = state.lock().expect("PollState mutex poisoned");
            let PollState { iface, sockets } = &mut *state;
            iface.poll(now, &mut device, sockets)
        };
        iters += 1;
        if !matches!(result, smoltcp::iface::PollResult::None) {
            tracing::info!("XDP_DIAG: poll loop iters={iters} result={result:?}");
        }
        if matches!(result, smoltcp::iface::PollResult::None) {
            std::thread::sleep(IDLE_SLEEP);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_header_len_matches_smoltcp_header_len() {
        assert_eq!(
            ETHERNET_HEADER_LEN,
            smoltcp::wire::EthernetFrame::<&[u8]>::header_len()
        );
    }
}
