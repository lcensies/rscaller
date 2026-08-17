use anyhow::{bail, Result};
use clap::Parser;
use tracing::{info, warn};

mod beacon_conn;
mod kmod;
mod relay;
mod socket_proxy;
mod veth;

#[derive(Parser)]
#[command(name = "rsclient", about = "rscaller userspace relay client")]
struct Args {
    /// Address of rsbeacon
    #[arg(long, default_value = "127.0.0.1:9999")]
    beacon: String,

    /// Controller backend: kmod|seccomp
    #[arg(long, default_value = "kmod")]
    ctl: String,

    // ── Kmod backend options ─────────────────────────────────────────────────
    /// Path to rscaller proc device (kmod backend)
    #[arg(long, default_value = "/proc/rscaller")]
    proc_path: String,

    /// Target name written to kmod via TARGET command (kmod backend)
    #[arg(long)]
    name: Option<String>,

    // ── Veth auto-setup ──────────────────────────────────────────────────────
    /// Name of the local veth end (default: rsc0); only used if --veth-ip is set
    #[arg(long, default_value = "rsc0")]
    veth: String,

    /// IP address to assign to the local veth end (victim-subnet IP); triggers veth creation
    #[arg(long)]
    veth_ip: Option<String>,

    /// Name of the veth peer end (default: rsc1)
    #[arg(long, default_value = "rsc1")]
    veth_peer: String,

    // ── Network routing ──────────────────────────────────────────────────────
    /// Network routing rules: `--route "<subnet>[:port]=<direction>"`.
    /// Multiple routes allowed; first match wins.
    /// Direction: "local" (use real kernel) or "remote" (relay through beacon).
    /// Example: `--route "192.168.1.0/24=remote" --route "0.0.0.0/0=local"`
    #[arg(long, value_name = "RULE")]
    route: Vec<String>,

    /// Default direction for syscalls no --route rule matches (and for
    /// network syscalls like socket/bind that carry no destination):
    /// "local" (default) or "remote". "remote" relays the whole INET
    /// socket family through the beacon (used by the relay profile).
    #[arg(long, value_name = "local|remote", default_value = "local")]
    route_default: String,

    // ── Deprecated: legacy filter config ──────────────────────────────────────
    /// (Deprecated: use --route instead) Subnet to intercept and forward (e.g. 192.0.2.160/29)
    #[arg(long, hide = true)]
    filter_net: Option<String>,

    /// (Deprecated: use --route instead) Comma-separated ports to intercept (e.g. 80,443)
    #[arg(long, hide = true)]
    filter_ports: Option<String>,

    // ── Seccomp backend options ──────────────────────────────────────────────
    /// Seccomp notify fd integer (seccomp backend).
    /// If not set, reads RSCALLER_NOTIF_FD env var.
    #[arg(long)]
    notif_fd: Option<i32>,

    // ── Local cgroup filter ──────────────────────────────────────────────────
    /// Path to the per-session local cgroup (e.g. /sys/fs/cgroup/rscaller/session-<hex>).
    /// When set, signals targeting PIDs inside this cgroup are continued locally.
    #[arg(long)]
    local_cgroup: Option<String>,

    /// Comma-separated syscall numbers whose forwarding is gated by the local cgroup.
    /// Only meaningful when --local-cgroup is set.
    #[arg(long, value_delimiter = ',')]
    cgroup_gated_nrs: Vec<u32>,

    // ── Transport / encryption ───────────────────────────────────────────────
    /// Transport: tcp|uds
    #[arg(long, default_value = "tcp")]
    transport: String,

    /// Encryption: none|tls
    #[arg(long, default_value = "none")]
    encryption: String,

    /// Path to CA cert PEM for TLS verification
    #[arg(long)]
    ca_cert: Option<String>,

    /// Rendezvous mode: reach the beacon through an rsserver
    /// ([token@]host:port) instead of connecting to it directly.
    #[arg(long)]
    server: Option<String>,

    /// Auth token for rsserver (overridden by token@ in --server).
    #[arg(long)]
    auth: Option<String>,
}

fn default_ca_cert_path() -> std::path::PathBuf {
    let mut p = dirs::config_dir().unwrap_or_else(|| std::path::PathBuf::from("~/.config"));
    p.push("rscaller/ca.pem");
    p
}

fn load_ca_pem(ca_cert: Option<&str>) -> Result<Vec<u8>> {
    if let Some(path) = ca_cert {
        Ok(std::fs::read(path)?)
    } else {
        let default = default_ca_cert_path();
        std::fs::read(&default).map_err(|e| {
            anyhow::anyhow!(
                "TLS requires a CA cert: pass --ca-cert or place it at {}: {}",
                default.display(),
                e
            )
        })
    }
}

/// Write a single-line command to the kmod proc file (e.g. "FILTER_NET 192.0.2.0/29\n").
fn write_filter_cmd(ctl: &mut ctls::kmod::KmodController, key: &str, value: &str) -> Result<()> {
    ctl.write_cmd(&format!("{} {}\n", key, value))?;
    info!("kmod config: {} {}", key, value);
    Ok(())
}

/// Resolve the beacon endpoint: direct by default, rsserver rendezvous when
/// --server is given. Session name = --name, falling back to "default" in
/// rendezvous mode (matching rsbeacon's default).
fn connect_target(
    args: &Args,
    beacon_addr: std::net::SocketAddr,
) -> Result<rscaller_proto::transport::ConnectTarget> {
    use rscaller_proto::transport::{parse_relay_target, ConnectTarget};
    if let Some(server) = &args.server {
        let name = args.name.as_deref().unwrap_or("default");
        return parse_relay_target(server, args.auth.as_deref(), name);
    }
    Ok(ConnectTarget::Direct(beacon_addr))
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // RUST_LOG wins when set; default keeps rsclient=debug for dev runs.
    let log_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("rsclient=debug"));
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(log_filter)
        .init();

    let args = Args::parse();

    // ── Veth setup ───────────────────────────────────────────────────────────
    // Only create veth if --veth-ip is given (opt-in).
    if let Some(ref ip) = args.veth_ip {
        veth::setup_veth(&args.veth, ip, &args.veth_peer)?;

        // Add a host route for the filter subnet via the veth, if specified.
        if let Some(ref net) = args.filter_net {
            // Ignore failure — route may already exist.
            if let Err(e) = veth::add_route(net, &args.veth) {
                warn!("add_route skipped: {}", e);
            }
        }
    }

    let beacon_addr = tokio::net::lookup_host(&args.beacon)
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve beacon address: {}", args.beacon))?;

    match args.ctl.as_str() {
        "kmod" => run_kmod(args, beacon_addr).await,
        "seccomp" => run_seccomp(args, beacon_addr).await,
        other => bail!("Unknown controller backend '{other}'. Valid: kmod, seccomp"),
    }
}

// ---------------------------------------------------------------------------
// Kmod backend — reconnecting relay loop
// ---------------------------------------------------------------------------

/// Builds the network routing filter from `--route` / `--route-default`.
fn build_net_filter(args: &Args) -> Result<relay::NetFilter> {
    let mut filter = relay::NetFilter::from_cli(args.route.clone())?;
    filter.default_direction = match args.route_default.as_str() {
        "local" => relay::NetRouteDirection::Local,
        "remote" => relay::NetRouteDirection::Remote,
        other => bail!("invalid --route-default '{other}': expected 'local' or 'remote'"),
    };
    Ok(filter)
}

async fn run_kmod(args: Args, beacon_addr: std::net::SocketAddr) -> Result<()> {
    use ctls::kmod::KmodController;

    let filter = build_net_filter(&args)?;

    // Keep the original fd open so kmod sees rsclient_active=1.
    info!("Opening kmod proc at {}", args.proc_path);
    let mut _keepalive = KmodController::open(&args.proc_path)?;
    if let Some(ref name) = args.name {
        _keepalive.set_target_name(name)?;
        info!("Set kmod target name: {}", name);
    }
    if let Some(ref net) = args.filter_net {
        write_filter_cmd(&mut _keepalive, "FILTER_NET", net)?;
    }
    if let Some(ref ports) = args.filter_ports {
        write_filter_cmd(&mut _keepalive, "FILTER_PORTS", ports)?;
    }

    let use_tls = args.encryption == "tls";
    let target = connect_target(&args, beacon_addr)?;
    let ca_pem = if use_tls {
        Some(load_ca_pem(args.ca_cert.as_deref())?)
    } else {
        None
    };

    loop {
        info!("Connecting to beacon at {:?}", target);

        let result: Result<()> = async {
            let ctl = KmodController::open(&args.proc_path)?;
            let (r, w) = rscaller_proto::transport::connect(&target, use_tls, ca_pem.as_deref())
                .await?;
            relay::Relay::new(ctl, r, w).with_filter(filter.clone()).run().await
        }
        .await;

        warn!("Relay ended: {:?} — reconnecting in 1s", result);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

// ---------------------------------------------------------------------------
// Seccomp backend — single-shot (notify fd is per-tracee)
// ---------------------------------------------------------------------------

async fn run_seccomp(args: Args, beacon_addr: std::net::SocketAddr) -> Result<()> {
    use ctls::seccomp::SeccompController;
    use std::os::unix::io::{FromRawFd, OwnedFd};

    let raw_fd: i32 = if let Some(fd) = args.notif_fd {
        fd
    } else {
        std::env::var("RSCALLER_NOTIF_FD")
            .map_err(|_| anyhow::anyhow!("seccomp backend requires --notif-fd or RSCALLER_NOTIF_FD"))?
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("RSCALLER_NOTIF_FD is not a valid fd integer"))?
    };

    info!("Using seccomp notify fd {}", raw_fd);
    let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let ctl = SeccompController::from_fd(owned);

    let filter = build_net_filter(&args)?;

    let cgroup_filter = args.local_cgroup.as_deref().map(|cgroup| {
        relay::CgroupFilter::new(cgroup.to_string(), args.cgroup_gated_nrs.clone())
    });

    info!("Connecting to beacon at {}", beacon_addr);

    let use_tls = args.encryption == "tls";
    let target = connect_target(&args, beacon_addr)?;
    // The socket-proxy data plane opens its own per-socket connections to the
    // beacon; that path isn't rendezvous-aware yet, so via --server every
    // data syscall round-trips through the main relay connection instead
    // (the same mode the relay profile uses with RSC_SOCKET_PROXY=0).
    let socket_proxy = !matches!(std::env::var("RSC_SOCKET_PROXY").as_deref(), Ok("0"));
    let socket_proxy = match target {
        rscaller_proto::transport::ConnectTarget::Relay { .. } if socket_proxy => {
            warn!("--server: socket data-plane not rendezvous-aware, using main relay connection");
            false
        }
        _ => socket_proxy,
    };
    let ca_pem = if use_tls {
        Some(load_ca_pem(args.ca_cert.as_deref())?)
    } else {
        None
    };
    let (r, w) = rscaller_proto::transport::connect(&target, use_tls, ca_pem.as_deref()).await?;
    let mut relay = relay::Relay::new(ctl, r, w)
        .with_filter(filter)
        .with_cgroup_filter(cgroup_filter);
    let result = if socket_proxy {
        relay.with_socket_proxy(beacon_addr, use_tls, ca_pem).run().await
    } else {
        relay.run().await
    };

    // Child has exited (notify fd closed). Clean up the session cgroup.
    if let Some(ref cgroup) = args.local_cgroup {
        if let Err(e) = std::fs::remove_dir(cgroup) {
            warn!("cleanup session cgroup {cgroup}: {e}");
        }
    }

    result
}
