//! Interface IPv4 / default-gateway / gateway-MAC discovery for the
//! `smoltcp-xdp` backend (design D6, tasks 6.2/6.3).
//!
//! The concrete discovery mechanism (parsing `/proc/net/route` +
//! `/proc/net/arp`, matching `xdplganger`'s `DefaultRouteIface`/
//! `GatewayMAC`) is deliberately kept behind the [`InterfaceInfoProvider`]
//! trait rather than called directly from the backend: it's an
//! environment fingerprint/behavioral detail (reads specific `/proc`
//! files, may shell out to `ping` to prime the ARP cache) that call sites
//! should be able to swap out for a different strategy later — e.g. a
//! netlink-based lookup, or an operator-supplied static answer — without
//! any change beyond providing a different [`InterfaceInfoProvider`]
//! impl. [`ProcNetInterfaceInfo`] is only the default.
//!
//! The actual parsing logic is split into free functions taking plain
//! `&str` content, so it's unit-testable without touching the real
//! `/proc` filesystem or requiring root/a real NIC.

use std::io;
use std::net::Ipv4Addr;

use smoltcp::wire::{EthernetAddress, Ipv4Address};

/// Abstracts how the backend learns the three pieces of addressing
/// information it needs when they aren't explicitly supplied via CLI
/// flags: this interface's own IPv4 address, the default route's
/// (interface, gateway IPv4), and the gateway's MAC address.
pub trait InterfaceInfoProvider {
    /// The first IPv4 address configured on `iface`.
    fn local_ipv4(&self, iface: &str) -> io::Result<Ipv4Address>;

    /// `iface`'s IPv4 netmask, expressed as a CIDR prefix length.
    fn local_prefix_len(&self, iface: &str) -> io::Result<u8>;

    /// `iface`'s own MAC address — the smoltcp `Interface`'s hardware
    /// address (source MAC for every frame it emits) and the value the
    /// `XdpDevice` RX path matches inbound frames' destination MAC
    /// against. Always auto-detected (no CLI override): unlike the
    /// gateway's MAC (see [`Self::gateway_mac`]'s doc comment for why
    /// that one is speculative/unused), this interface's own MAC is
    /// always unambiguous and locally knowable without ARP.
    fn local_mac(&self, iface: &str) -> io::Result<EthernetAddress>;

    /// The interface name and gateway IPv4 for the system's default route.
    fn default_route(&self) -> io::Result<(String, Ipv4Address)>;

    /// The MAC address for `gateway` on `iface`, priming the ARP cache
    /// (best-effort) if there isn't already a cached entry.
    ///
    /// **Not currently called from `smoltcp-xdp` backend construction**:
    /// `smoltcp::iface::Interface` (`Medium::Ethernet`) resolves neighbor
    /// MACs itself via its own ARP requests sent over the `XdpDevice` as
    /// needed (see `bridge::build_interface`'s doc comment) and this
    /// smoltcp version exposes no public API to pre-seed its neighbor
    /// cache — unlike `xdplganger`, whose gVisor `channel.Endpoint`
    /// needed the gateway's MAC upfront to hand-build outgoing Ethernet
    /// frames itself (design D5). Kept for potential future use (e.g. a
    /// startup connectivity diagnostic), but backend init does not
    /// depend on it and no `--xdp-dst-mac` CLI flag calls it.
    #[allow(dead_code)]
    fn gateway_mac(&self, iface: &str, gateway: Ipv4Address) -> io::Result<EthernetAddress>;
}

/// Default [`InterfaceInfoProvider`]: parses `/proc/net/route` and
/// `/proc/net/arp`, with a best-effort `ping -c1 -W1` ARP-priming
/// fallback, and a `SIOCGIFADDR` ioctl for the local address — the same
/// approach `xdplganger`'s `DefaultRouteIface`/`GatewayMAC`/`firstIPv4`
/// take.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcNetInterfaceInfo;

impl InterfaceInfoProvider for ProcNetInterfaceInfo {
    fn local_ipv4(&self, iface: &str) -> io::Result<Ipv4Address> {
        ioctl_if_ipv4(iface)
    }

    fn local_prefix_len(&self, iface: &str) -> io::Result<u8> {
        let mask = ioctl_if_netmask(iface)?;
        Ok(netmask_to_prefix_len(mask))
    }

    fn local_mac(&self, iface: &str) -> io::Result<EthernetAddress> {
        ioctl_if_hwaddr(iface)
    }

    fn default_route(&self) -> io::Result<(String, Ipv4Address)> {
        let data = std::fs::read_to_string("/proc/net/route")?;
        parse_default_route(&data)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no default IPv4 route"))
    }

    fn gateway_mac(&self, iface: &str, gateway: Ipv4Address) -> io::Result<EthernetAddress> {
        let data = std::fs::read_to_string("/proc/net/arp")?;
        if let Some(mac) = parse_arp_table(&data, iface, gateway) {
            return Ok(mac);
        }
        // Best-effort ARP-priming ping, then retry once — matches
        // xdplganger's GatewayMAC fallback. Failure to even run `ping` is
        // not itself an error; the retry below still decides the outcome.
        let _ = std::process::Command::new("ping")
            .args(["-c1", "-W1", "-I", iface, &Ipv4Addr::from(gateway.octets()).to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let data = std::fs::read_to_string("/proc/net/arp")?;
        parse_arp_table(&data, iface, gateway).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no ARP entry for {gateway} on {iface} after ping"),
            )
        })
    }
}

/// Parses the interface name and gateway address of the default IPv4
/// route (destination `00000000`) out of `/proc/net/route`'s content.
/// Fields are whitespace-separated; the gateway field is an 8-hex-digit,
/// little-endian-encoded IPv4 address (as the kernel writes it).
fn parse_default_route(route_table: &str) -> Option<(String, Ipv4Address)> {
    for line in route_table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        if fields[1] != "00000000" {
            continue; // Destination != 0.0.0.0/0
        }
        if let Some(gw) = hex_le_to_ipv4(fields[2]) {
            return Some((fields[0].to_string(), gw));
        }
    }
    None
}

/// Parses `/proc/net/arp` for a complete entry mapping `target` to a MAC
/// on `iface`. Columns: `IP address / HW type / Flags / HW address /
/// Mask / Device`.
fn parse_arp_table(arp_table: &str, iface: &str, target: Ipv4Address) -> Option<EthernetAddress> {
    let target_str = Ipv4Addr::from(target.octets()).to_string();
    for line in arp_table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        if fields[0] != target_str || fields[5] != iface {
            continue;
        }
        // Flags "0x0" or an all-zero HW address means an incomplete entry.
        if fields[2] == "0x0" || fields[3] == "00:00:00:00:00:00" {
            continue;
        }
        if let Some(mac) = parse_mac(fields[3]) {
            return Some(mac);
        }
    }
    None
}

fn hex_le_to_ipv4(s: &str) -> Option<Ipv4Address> {
    if s.len() != 8 {
        return None;
    }
    let mut b = [0u8; 4];
    for i in 0..4 {
        b[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    // /proc/net/route stores addresses in host byte order (little-endian
    // on x86), so the last hex pair is the most-significant octet.
    Some(Ipv4Address::new(b[3], b[2], b[1], b[0]))
}

fn parse_mac(s: &str) -> Option<EthernetAddress> {
    let mut bytes = [0u8; 6];
    let mut parts = s.split(':');
    for b in bytes.iter_mut() {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None; // too many octets
    }
    Some(EthernetAddress(bytes))
}

/// Runs `ioctl(request)` against a throwaway `AF_INET`/`SOCK_DGRAM` socket
/// with `ifr_name` set to `iface` — the standard portable way to query
/// `SIOCGIF*` interface properties without parsing `ip addr`/`ip link`
/// output. Shared by [`ioctl_if_ipv4`], [`ioctl_if_netmask`] and
/// [`ioctl_if_hwaddr`], which differ only in `request` and which
/// `ifr_ifru` union field they read back out of the filled `ifreq`.
fn with_ioctl_ifreq(
    iface: &str,
    request: libc::c_ulong,
) -> io::Result<libc::ifreq> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        if iface.len() >= ifr.ifr_name.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("interface name '{iface}' too long"),
            ));
        }
        for (dst, src) in ifr.ifr_name.iter_mut().zip(iface.bytes()) {
            *dst = src as libc::c_char;
        }
        let ret = unsafe { libc::ioctl(sock, request as _, &mut ifr) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ifr)
    })();
    unsafe {
        libc::close(sock);
    }
    result
}

/// Extracts the `sockaddr_in` (IPv4) address out of an `ifreq`'s
/// `ifr_addr`-shaped union field — shared by [`ioctl_if_ipv4`] (reads
/// `ifru_addr`) and [`ioctl_if_netmask`] (reads `ifru_netmask`); both
/// fields are plain `crate::sockaddr` at the same union offset.
fn parse_ifru_sockaddr_in(sockaddr: libc::sockaddr, what: &str) -> io::Result<Ipv4Address> {
    let addr_bytes: [u8; 16] = unsafe { std::mem::transmute_copy(&sockaddr) };
    super::sockaddr::parse_sockaddr_in(&addr_bytes)
        .map(|(addr, _port)| addr)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{what} returned a non-AF_INET address"),
            )
        })
}

fn ioctl_if_ipv4(iface: &str) -> io::Result<Ipv4Address> {
    let ifr = with_ioctl_ifreq(iface, libc::SIOCGIFADDR)?;
    // ifr_addr is a `struct sockaddr`; for AF_INET it's really a
    // `struct sockaddr_in` with the IPv4 address at the same offset
    // (4 bytes) `crate::net_backend::smoltcp_xdp::sockaddr` assumes.
    parse_ifru_sockaddr_in(unsafe { ifr.ifr_ifru.ifru_addr }, "SIOCGIFADDR")
}

fn ioctl_if_netmask(iface: &str) -> io::Result<Ipv4Address> {
    let ifr = with_ioctl_ifreq(iface, libc::SIOCGIFNETMASK)?;
    parse_ifru_sockaddr_in(unsafe { ifr.ifr_ifru.ifru_netmask }, "SIOCGIFNETMASK")
}

fn ioctl_if_hwaddr(iface: &str) -> io::Result<EthernetAddress> {
    let ifr = with_ioctl_ifreq(iface, libc::SIOCGIFHWADDR)?;
    // ifr_hwaddr is a `struct sockaddr`; for `ARPHRD_ETHER` the 6-byte MAC
    // sits at the start of `sa_data` (no `sockaddr_in`-style port/family
    // layout — that's specific to `AF_INET`).
    let hw = unsafe { ifr.ifr_ifru.ifru_hwaddr };
    let mut mac = [0u8; 6];
    for (dst, src) in mac.iter_mut().zip(hw.sa_data.iter()) {
        *dst = *src as u8;
    }
    Ok(EthernetAddress(mac))
}

/// Converts an IPv4 netmask (e.g. `255.255.255.0`) to its CIDR prefix
/// length (e.g. `24`). Assumes a well-formed netmask (contiguous leading
/// one-bits) — malformed/non-contiguous masks are not validated, matching
/// what the kernel itself would have already accepted when the address
/// was configured.
fn netmask_to_prefix_len(mask: Ipv4Address) -> u8 {
    u32::from_be_bytes(mask.octets()).count_ones() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ROUTE_TABLE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0
eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
";

    const SAMPLE_ARP_TABLE: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.2      0x1         0x0         00:00:00:00:00:00     *        eth0
";

    #[test]
    fn parses_default_route_gateway() {
        let (iface, gw) = parse_default_route(SAMPLE_ROUTE_TABLE).unwrap();
        assert_eq!(iface, "eth0");
        // 0101A8C0 little-endian -> 192.168.1.1
        assert_eq!(gw, Ipv4Address::new(192, 168, 1, 1));
    }

    #[test]
    fn ignores_non_default_routes() {
        // The second line (destination 0001A8C0) must never be picked.
        let (_, gw) = parse_default_route(SAMPLE_ROUTE_TABLE).unwrap();
        assert_ne!(gw, Ipv4Address::new(1, 0, 168, 192));
    }

    #[test]
    fn no_default_route_returns_none() {
        assert!(parse_default_route("Iface\tDestination\n").is_none());
    }

    #[test]
    fn parses_complete_arp_entry() {
        let mac = parse_arp_table(SAMPLE_ARP_TABLE, "eth0", Ipv4Address::new(192, 168, 1, 1))
            .unwrap();
        assert_eq!(mac, EthernetAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
    }

    #[test]
    fn rejects_incomplete_arp_entry() {
        assert!(
            parse_arp_table(SAMPLE_ARP_TABLE, "eth0", Ipv4Address::new(192, 168, 1, 2)).is_none()
        );
    }

    #[test]
    fn rejects_arp_entry_on_wrong_iface() {
        assert!(
            parse_arp_table(SAMPLE_ARP_TABLE, "eth1", Ipv4Address::new(192, 168, 1, 1)).is_none()
        );
    }

    #[test]
    fn parses_mac_address() {
        assert_eq!(
            parse_mac("01:23:45:67:89:ab"),
            Some(EthernetAddress([0x01, 0x23, 0x45, 0x67, 0x89, 0xab]))
        );
        assert_eq!(parse_mac("not-a-mac"), None);
        assert_eq!(parse_mac("01:23"), None);
    }

    #[test]
    fn netmask_to_prefix_len_common_values() {
        assert_eq!(netmask_to_prefix_len(Ipv4Address::new(255, 255, 255, 0)), 24);
        assert_eq!(netmask_to_prefix_len(Ipv4Address::new(255, 255, 255, 128)), 25);
        assert_eq!(netmask_to_prefix_len(Ipv4Address::new(255, 255, 0, 0)), 16);
        assert_eq!(netmask_to_prefix_len(Ipv4Address::new(255, 255, 255, 255)), 32);
        assert_eq!(netmask_to_prefix_len(Ipv4Address::new(0, 0, 0, 0)), 0);
    }
}
