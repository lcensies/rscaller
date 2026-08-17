use anyhow::{Context, Result};
use clap::Parser;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use rustls;

mod executor;
mod net_backend;
mod server;

use net_backend::direct::DirectBackend;
use net_backend::smoltcp_xdp::init::{self as xdp_init, XdpConfig};
use net_backend::NetBackend;

// Certs embedded at compile time by build.rs
const EMBEDDED_CERT_PEM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/cert.pem"));
const EMBEDDED_KEY_PEM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/key.pem"));
pub const EMBEDDED_CA_PEM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ca.pem"));

#[derive(Parser)]
#[command(name = "rsbeacon", about = "Remote syscall execution beacon")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:9999")]
    listen: String,

    #[arg(long, default_value = "tcp", help = "Transport: tcp|uds")]
    transport: String,

    #[arg(long, default_value = "none", help = "Encryption: none|tls")]
    encryption: String,

    /// Override embedded TLS certificate (PEM)
    #[arg(long)]
    cert: Option<String>,

    /// Override embedded TLS private key (PEM)
    #[arg(long)]
    key: Option<String>,

    /// UDS socket path (only with --transport uds)
    #[arg(long)]
    uds_path: Option<String>,

    #[arg(long, default_value = "10")]
    max_connections: usize,

    /// Network syscall execution backend: `direct` (today's kernel-stack
    /// passthrough) or `smoltcp-xdp` (userspace TCP/IP stack over AF_XDP).
    #[arg(long, default_value = "direct")]
    netstack: String,

    /// Interface to attach the XDP program / bind the AF_XDP socket to.
    /// Required when `--netstack smoltcp-xdp` is selected; ignored otherwise.
    #[arg(long)]
    xdp_iface: Option<String>,

    /// AF_XDP queue index to bind (`--netstack smoltcp-xdp` only).
    #[arg(long, default_value_t = 0)]
    xdp_queue: u32,

    /// AF_XDP ring mode: only `copy` is implemented in v1 (see design
    /// Non-Goals); `zerocopy` is accepted as a value so the error message
    /// is actionable, but always rejected.
    #[arg(long, default_value = "copy")]
    xdp_mode: String,

    /// Override auto-detected local IPv4 address for `--xdp-iface`
    /// (`--netstack smoltcp-xdp` only). Auto-detected via `SIOCGIFADDR`
    /// when omitted.
    #[arg(long)]
    xdp_ip: Option<String>,

    /// Override auto-detected IPv4 CIDR prefix length for `--xdp-ip`/
    /// `--xdp-iface` (`--netstack smoltcp-xdp` only). Auto-detected via
    /// `SIOCGIFNETMASK` when omitted.
    #[arg(long)]
    xdp_prefix: Option<u8>,

    /// Override auto-detected default-gateway IPv4 address
    /// (`--netstack smoltcp-xdp` only). Auto-detected from
    /// `/proc/net/route` when omitted; if auto-detection also fails, the
    /// backend starts without a default route (only on-link traffic for
    /// `--xdp-ip`'s subnet will be reachable).
    #[arg(long)]
    xdp_gateway: Option<String>,

    /// MTU for the smoltcp virtual interface (`--netstack smoltcp-xdp`
    /// only). smoltcp does no PMTU discovery — lower this to the path
    /// MTU when a tunnel/overlay sits between the beacon and its peers
    /// (lab DLP tunnel: 1376), or full-size DF segments blackhole.
    #[arg(long, default_value = "1500")]
    xdp_mtu: usize,
}

/// Builds and initializes the selected [`NetBackend`]. Fails fast with an
/// actionable error if the selected backend can't be constructed — callers
/// must treat this as fatal (non-zero exit) before accepting any client
/// connections, so a broken `--netstack` selection never silently falls
/// back to a different backend than the operator asked for.
fn init_backend(args: &Args) -> Result<Arc<dyn NetBackend>> {
    match args.netstack.as_str() {
        "direct" => Ok(Arc::new(DirectBackend::new())),
        "smoltcp-xdp" => init_smoltcp_xdp_backend(args),
        other => anyhow::bail!(
            "Unknown --netstack '{}': expected 'direct' or 'smoltcp-xdp'",
            other
        ),
    }
}

/// Validates the `--xdp-*` CLI flags and hands off to
/// `net_backend::smoltcp_xdp::init` (task 6.4) for the actual backend
/// construction (XDP program load/attach, AF_XDP bind, `smoltcp`
/// `Interface`/poll-loop wiring) — kept out of `main.rs`, which only
/// needs to turn flags into an [`XdpConfig`].
fn init_smoltcp_xdp_backend(args: &Args) -> Result<Arc<dyn NetBackend>> {
    let iface = args.xdp_iface.as_deref().ok_or_else(|| {
        anyhow::anyhow!("--netstack smoltcp-xdp requires --xdp-iface <interface>")
    })?;

    if args.xdp_mode != "copy" {
        anyhow::bail!(
            "--xdp-mode '{}' is not supported: v1 only implements AF_XDP copy mode \
             (see design.md Non-Goals re: zero-copy); use --xdp-mode copy or omit the flag",
            args.xdp_mode
        );
    }

    let ip = args
        .xdp_ip
        .as_deref()
        .map(Ipv4Addr::from_str)
        .transpose()
        .with_context(|| format!("--xdp-ip '{}' is not a valid IPv4 address", args.xdp_ip.as_deref().unwrap_or("")))?;
    let gateway = args
        .xdp_gateway
        .as_deref()
        .map(Ipv4Addr::from_str)
        .transpose()
        .with_context(|| format!("--xdp-gateway '{}' is not a valid IPv4 address", args.xdp_gateway.as_deref().unwrap_or("")))?;

    xdp_init::init(XdpConfig {
        iface: iface.to_string(),
        queue: args.xdp_queue,
        ip,
        prefix: args.xdp_prefix,
        gateway,
        mtu: args.xdp_mtu,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 with both aws-lc-rs and ring compiled in — must pick one explicitly.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Ensure fd 0/1/2 stay occupied so remote file opens don't get fd<3
    unsafe {
        for fd in 0i32..3 {
            if libc::fcntl(fd, libc::F_GETFD) == -1 {
                let null = libc::open(
                    b"/dev/null\0".as_ptr() as *const libc::c_char,
                    libc::O_RDWR,
                );
                if null >= 0 && null != fd {
                    libc::dup2(null, fd);
                    libc::close(null);
                }
            }
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("rsbeacon=debug".parse()?),
        )
        .init();

    let args = Args::parse();

    let cert_pem = if let Some(p) = &args.cert {
        std::fs::read(p)?
    } else {
        EMBEDDED_CERT_PEM.to_vec()
    };
    let key_pem = if let Some(p) = &args.key {
        std::fs::read(p)?
    } else {
        EMBEDDED_KEY_PEM.to_vec()
    };

    let use_tls = args.encryption == "tls";

    // Fail fast, before binding any listener or accepting connections, if
    // the selected backend can't be initialized.
    let backend = init_backend(&args)?;
    tracing::info!("Network backend: {}", backend.name());

    match args.transport.as_str() {
        "tcp" => {
            let addr: SocketAddr = args.listen.parse()?;
            if use_tls {
                server::run_tls(addr, cert_pem, key_pem, backend).await
            } else {
                server::run_plain(addr, backend).await
            }
        }
        "uds" => {
            if use_tls {
                // UDS is local-only; TLS over UDS is unsupported, don't silently downgrade.
                anyhow::bail!("--encryption tls is not supported with --transport uds");
            }
            let path = args
                .uds_path
                .as_deref()
                .unwrap_or("/tmp/rsbeacon.sock");
            server::run_uds(path, backend).await
        }
        other => anyhow::bail!("Unknown transport: {}", other),
    }
}
