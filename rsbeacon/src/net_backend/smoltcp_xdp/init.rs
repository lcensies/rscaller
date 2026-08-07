//! `smoltcp-xdp` backend construction (task 6.4) — loads/attaches the XDP
//! program, binds the AF_XDP socket, constructs the `smoltcp` `Interface`
//! (address auto-detected per design D6 unless overridden by
//! [`XdpConfig`]'s fields), spawns the background poll loop (design D5),
//! and returns the ready-to-use [`NetBackend`].
//!
//! Deliberately kept out of `main.rs`: the CLI layer only needs to parse
//! flags into an [`XdpConfig`] and call [`init`] — it has no business
//! knowing about `XdpProgram`/`XdpSocket`/`XdpDevice`/`PollState` wiring,
//! which is this module's job, not the entrypoint's.

use std::net::Ipv4Addr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use smoltcp::iface::SocketSet;
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::Ipv4Address;

use super::addr_detect::{InterfaceInfoProvider, ProcNetInterfaceInfo};
use super::backend::SmoltcpXdpBackend;
use super::bpf::XdpProgram;
use super::bridge::{build_interface, run_poll_loop, PollState, XdpDevice};
use super::xdp_socket::XdpSocket;
use crate::net_backend::NetBackend;

/// Everything the CLI layer can override about the `smoltcp-xdp` backend;
/// anything left as `None` is auto-detected (see each field's doc).
/// One struct instead of a handful of loose `main.rs` locals/args, so
/// adding/removing an override is a one-line change here rather than a
/// signature change threaded through `main.rs`.
#[derive(Debug, Clone)]
pub struct XdpConfig {
    /// Interface to attach the XDP program / bind the AF_XDP socket to.
    pub iface: String,
    /// AF_XDP queue index to bind.
    pub queue: u32,
    /// Local IPv4 address override; auto-detected via `SIOCGIFADDR` on
    /// `iface` when `None`.
    pub ip: Option<Ipv4Addr>,
    /// CIDR prefix length override for `ip`; auto-detected via
    /// `SIOCGIFNETMASK` on `iface` when `None`.
    pub prefix: Option<u8>,
    /// Default-gateway IPv4 override; auto-detected from
    /// `/proc/net/route` when `None`. If auto-detection also fails,
    /// [`init`] proceeds without a default route rather than failing —
    /// only on-link traffic for `ip`'s subnet is reachable in that case.
    pub gateway: Option<Ipv4Addr>,
}

/// Builds the `smoltcp-xdp` [`NetBackend`]. Every failure path is fatal —
/// callers (`main.rs::init_backend`) must treat `Err` as fatal (non-zero
/// exit) before accepting any client connections, per that function's own
/// doc comment.
pub fn init(config: XdpConfig) -> Result<Arc<dyn NetBackend>> {
    let iface = config.iface.as_str();

    let ifindex = {
        let cstr = std::ffi::CString::new(iface.as_bytes())
            .with_context(|| format!("interface name '{iface}' contains a NUL byte"))?;
        let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
        if idx == 0 {
            anyhow::bail!(
                "interface '{iface}' not found (if_nametoindex failed: {})",
                std::io::Error::last_os_error()
            );
        }
        idx
    };

    let info = ProcNetInterfaceInfo;

    let local_mac = info
        .local_mac(iface)
        .with_context(|| format!("detecting MAC address of interface '{iface}'"))?;

    let kernel_ip = info.local_ipv4(iface).ok();

    let local_ip = match config.ip {
        Some(ip) => Ipv4Address::from(ip),
        None => info.local_ipv4(iface).with_context(|| {
            format!("auto-detecting IPv4 address of interface '{iface}' (pass --xdp-ip to override)")
        })?,
    };

    // smoltcp MUST own a distinct IPv4 on a shared interface. The XDP
    // program redirects ARP/ICMP/TCP/UDP by destination address; if the
    // smoltcp address equals the kernel's, every ARP resolution for the
    // host gets stolen, the host's neighbors' caches expire, and the host
    // becomes unreachable (observed on dev-vm-2: SSH + outbound died
    // minutes after attach). Refuse that configuration.
    if kernel_ip == Some(local_ip) {
        anyhow::bail!(
            "smoltcp-xdp address {local_ip} equals interface '{iface}'s kernel address; \
             pass a distinct --xdp-ip on the same subnet (sharing the kernel address \
             lets the XDP program steal the host's ARP and kills host networking)"
        );
    }

    let prefix_len = match config.prefix {
        Some(p) => p,
        None => info.local_prefix_len(iface).with_context(|| {
            format!("auto-detecting IPv4 netmask of interface '{iface}' (pass --xdp-prefix to override)")
        })?,
    };

    let gateway = match config.gateway {
        Some(gw) => Some(Ipv4Address::from(gw)),
        None => match info.default_route() {
            Ok((_route_iface, gw)) => Some(gw),
            Err(e) => {
                tracing::warn!(
                    "no default IPv4 route auto-detected ({e}); smoltcp-xdp will only reach \
                     hosts on {local_ip}/{prefix_len}'s own subnet (pass --xdp-gateway to override)"
                );
                None
            }
        },
    };

    tracing::info!(
        "smoltcp-xdp: iface={iface} (ifindex={ifindex}) queue={} mac={local_mac} \
         ip={local_ip}/{prefix_len} gateway={gateway:?}",
        config.queue
    );

    let mut xdp_program = XdpProgram::load_and_attach(iface)
        .with_context(|| format!("loading/attaching XDP program to interface '{iface}'"))?;

    xdp_program
        // `octets()` are wire order; the BPF program compares against the
        // raw in-packet __u32, so store them exactly as they appear on the
        // wire (native-endian load of the 4 octets).
        .set_local_ip(u32::from_ne_bytes(local_ip.octets()))
        .context("arming XDP redirect filter with smoltcp's IPv4 address")?;

    let xsk = XdpSocket::bind(ifindex, config.queue)
        .with_context(|| format!("binding AF_XDP socket to '{iface}' queue {}", config.queue))?;
    let xsk = Arc::new(xsk);

    xdp_program
        .register_xsk(config.queue, xsk.fd())
        .context("registering AF_XDP socket fd into xsks_map")?;

    let mut device = XdpDevice::new(xsk, local_mac);
    let iface_state = build_interface(
        &mut device,
        local_mac,
        local_ip,
        prefix_len,
        gateway,
        SmoltcpInstant::now(),
    );

    let state = Arc::new(Mutex::new(PollState {
        iface: iface_state,
        sockets: SocketSet::new(vec![]),
    }));

    // The poll thread runs for the lifetime of the process: rsbeacon has
    // no graceful netstack-backend shutdown path today (see design.md's
    // Migration Plan "Rollback" note, which assumes a process restart),
    // so `stop` is never flipped in production — only tests (`backend.rs`
    // `TestHarness`) ever set it, to join their poll thread on drop.
    let stop = Arc::new(AtomicBool::new(false));
    {
        let state = state.clone();
        let stop = stop.clone();
        std::thread::spawn(move || run_poll_loop(state, device, stop));
    }

    Ok(Arc::new(SmoltcpXdpBackend::new(
        state,
        Box::new(xdp_program),
        local_ip,
    )))
}
