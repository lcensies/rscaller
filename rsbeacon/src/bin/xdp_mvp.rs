//! Minimal smoltcp-over-AF_XDP TCP pump — reproduces (or clears) the
//! rsbeacon `smoltcp-xdp` large-transfer stall in isolation.
//!
//! Wires the exact same stack as `net_backend::smoltcp_xdp::init`
//! (XDP filter program, AF_XDP socket, XdpDevice bridge, poll loop) but
//! drives ONE raw smoltcp TCP socket directly — no NetBackend, no wire
//! protocol, no fd table. If the transfer stalls here, the bug lives in
//! the device/netstack layer; if it runs clean, the bug is in the
//! backend socket/protocol layer above.
//!
//! Usage (root):
//!   xdp_mvp --iface enp1s0 --ip 10.0.0.2 --peer 10.0.0.1:9000 --recv 5000000
//!   xdp_mvp ... --send 5000000        # opposite direction
//!
//! Peer side: any TCP server that floods (recv test) or drains (send
//! test), e.g. `nc -l 9000 </dev/zero` / `nc -l 9000 >/dev/null`.

use std::net::Ipv4Addr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use smoltcp::iface::SocketSet;
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::Ipv4Address;

use rsbeacon::net_backend::smoltcp_xdp::addr_detect::{InterfaceInfoProvider, ProcNetInterfaceInfo};
use rsbeacon::net_backend::smoltcp_xdp::bpf::XdpProgram;
use rsbeacon::net_backend::smoltcp_xdp::bridge::{build_interface, run_poll_loop, PollState, XdpDevice};
use rsbeacon::net_backend::smoltcp_xdp::xdp_socket::XdpSocket;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    iface: String,
    #[arg(long)]
    ip: Ipv4Addr,
    #[arg(long, default_value_t = 24)]
    prefix: u8,
    #[arg(long)]
    gateway: Option<Ipv4Addr>,
    /// Peer endpoint host:port to connect to.
    #[arg(long)]
    peer: String,
    /// Local TCP port (must be free; gets tracked by the XDP filter).
    #[arg(long, default_value_t = 40000)]
    local_port: u16,
    /// Bytes to RECEIVE from peer before exiting.
    #[arg(long, default_value_t = 0)]
    recv: u64,
    /// Bytes to SEND to peer before exiting.
    #[arg(long, default_value_t = 0)]
    send: u64,
    /// TCP socket buffer size (mirror backend's TCP_BUFFER_SIZE=65536).
    #[arg(long, default_value_t = 65536)]
    buf: usize,
    /// MTU advertised to smoltcp.
    #[arg(long, default_value_t = 1500)]
    mtu: usize,
    /// Verify received data as a u64 BE counter stream (peer must send
    /// 0,1,2,... packed big-endian). Reports first mismatch offset.
    #[arg(long)]
    verify: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    let (peer_ip, peer_port) = args
        .peer
        .split_once(':')
        .context("--peer must be host:port")?;
    let peer_ip: Ipv4Addr = peer_ip.parse().context("parsing --peer ip")?;
    let peer_port: u16 = peer_port.parse().context("parsing --peer port")?;
    eprintln!(
        "args: iface={} ip={}/{} peer={}:{} local_port={} buf={} mtu={}",
        args.iface, args.ip, args.prefix, peer_ip, peer_port, args.local_port, args.buf, args.mtu
    );

    let info = ProcNetInterfaceInfo;
    let local_mac = info.local_mac(&args.iface).context("detecting MAC")?;
    let local_ip = Ipv4Address::from(args.ip);
    let gateway = args.gateway.map(Ipv4Address::from);

    let ifindex = {
        let cstr = std::ffi::CString::new(args.iface.as_bytes())?;
        let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
        if idx == 0 {
            anyhow::bail!("if_nametoindex({}) failed", args.iface);
        }
        idx
    };

    let mut prog = XdpProgram::load_and_attach(&args.iface).context("attaching XDP program")?;
    prog.set_local_ip(u32::from_ne_bytes(local_ip.octets()))?;
    let xsk = Arc::new(XdpSocket::bind(ifindex, 0).context("binding AF_XDP socket")?);
    prog.register_xsk(0, xsk.fd())?;
    prog.track_tcp_port(args.local_port)?;

    let mut device = XdpDevice::new(xsk, local_mac).with_mtu(args.mtu);
    let iface = build_interface(
        &mut device,
        local_mac,
        local_ip,
        args.prefix,
        gateway,
        SmoltcpInstant::now(),
    );

    let state = Arc::new(Mutex::new(PollState {
        iface,
        sockets: SocketSet::new(vec![]),
    }));
    let stop = Arc::new(AtomicBool::new(false));
    {
        let state = state.clone();
        let stop = stop.clone();
        std::thread::spawn(move || run_poll_loop(state, device, stop));
    }

    // One raw TCP socket, backend-identical buffer sizing.
    let handle = {
        let rx = tcp::SocketBuffer::new(vec![0u8; args.buf]);
        let tx = tcp::SocketBuffer::new(vec![0u8; args.buf]);
        let mut st = state.lock().unwrap();
        st.sockets.add(tcp::Socket::new(rx, tx))
    };
    {
        use smoltcp::wire::{IpEndpoint, IpListenEndpoint};
        let mut st = state.lock().unwrap();
        let PollState { iface, sockets } = &mut *st;
        let remote = IpEndpoint::new(smoltcp::wire::IpAddress::Ipv4(peer_ip), peer_port);
        let local = IpListenEndpoint { addr: None, port: args.local_port };
        sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(iface.context(), remote, local)
            .map_err(|e| anyhow::anyhow!("connect: {e}"))?;
    }

    // Wait for handshake.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        {
            let mut st = state.lock().unwrap();
            let sock = st.sockets.get_mut::<tcp::Socket>(handle);
            if sock.may_send() && sock.may_recv() {
                break;
            }
            if Instant::now() > deadline {
                anyhow::bail!("connect timed out, state={:?}", sock.state());
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    eprintln!("connected to {peer_ip}:{peer_port}, starting pump");

    let mut total: u64 = 0;
    let goal: u64 = args.recv.max(args.send);
    let mut buf = vec![0u8; 16384];
    let mut verifier = Verifier::default();
    let mut last_progress = Instant::now();
    let mut last_reported: u64 = u64::MAX;
    loop {
        let progressed = {
            let mut st = state.lock().unwrap();
            let sock = st.sockets.get_mut::<tcp::Socket>(handle);
            if args.recv > 0 {
                match sock.recv_slice(&mut buf) {
                    Ok(0) => false,
                    Ok(n) => {
                        if args.verify {
                            verifier.check(&buf[..n]);
                        }
                        total += n as u64;
                        true
                    }
                    Err(_) => false,
                }
            } else {
                let remaining = (goal - total) as usize;
                if remaining == 0 {
                    break;
                }
                let chunk = remaining.min(buf.len());
                match sock.send_slice(&buf[..chunk]) {
                    Ok(0) => false,
                    Ok(n) => {
                        total += n as u64;
                        true
                    }
                    Err(_) => false,
                }
            }
        };
        if progressed {
            last_progress = Instant::now();
            if total / (512 * 1024) != last_reported / (512 * 1024) {
                eprintln!("progress: {total}/{goal} bytes");
                last_reported = total;
            }
        } else {
            if total >= goal {
                break;
            }
            if last_progress.elapsed() > Duration::from_secs(5) {
                let mut st = state.lock().unwrap();
                let sock = st.sockets.get_mut::<tcp::Socket>(handle);
                eprintln!(
                    "STALL at {total} bytes: state={:?} recv_queue={} send_queue={}",
                    sock.state(),
                    sock.recv_queue(),
                    sock.send_queue()
                );
                std::process::exit(2);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    eprintln!("done: {total} bytes transferred cleanly");
    Ok(())
}

/// Streaming verifier for a u64 big-endian counter stream (peer sends
/// 0,1,2,... packed BE). First mismatch prints the exact byte offset and
/// exits(3); resync is pointless for a corruption hunt.
#[derive(Default)]
struct Verifier {
    expected: u64,
    partial: Vec<u8>,
}

impl Verifier {
    fn check(&mut self, data: &[u8]) {
        let mut buf = std::mem::take(&mut self.partial);
        buf.extend_from_slice(data);
        let mut words = buf.chunks_exact(8);
        for w in &mut words {
            let v = u64::from_be_bytes(w.try_into().unwrap());
            if v != self.expected {
                eprintln!(
                    "CORRUPTION at stream byte {}: got counter {v}, expected {}",
                    self.expected * 8,
                    self.expected
                );
                std::process::exit(3);
            }
            self.expected += 1;
        }
        self.partial = words.remainder().to_vec();
    }
}
