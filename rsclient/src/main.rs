use anyhow::{bail, Result};
use clap::Parser;
use tracing::{info, warn};

mod relay;

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

    // ── Seccomp backend options ──────────────────────────────────────────────
    /// Seccomp notify fd integer (seccomp backend).
    /// If not set, reads RSCALLER_NOTIF_FD env var.
    #[arg(long)]
    notif_fd: Option<i32>,

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

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("rsclient=debug".parse()?),
        )
        .init();

    let args = Args::parse();

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

async fn run_kmod(args: Args, beacon_addr: std::net::SocketAddr) -> Result<()> {
    use ctls::kmod::KmodController;

    // Keep the original fd open so kmod sees rsclient_active=1.
    info!("Opening kmod proc at {}", args.proc_path);
    let mut _keepalive = KmodController::open(&args.proc_path)?;
    if let Some(ref name) = args.name {
        _keepalive.set_target_name(name)?;
        info!("Set kmod target name: {}", name);
    }

    let use_tls = args.encryption == "tls";

    loop {
        info!("Connecting to beacon at {}", beacon_addr);

        let result: Result<()> = async {
            let ctl = KmodController::open(&args.proc_path)?;

            if use_tls {
                let ca_pem = load_ca_pem(args.ca_cert.as_deref())?;
                let (r, w) = rscaller_proto::transport::tls::connect_tls(
                    beacon_addr,
                    "rsbeacon",
                    &ca_pem,
                )
                .await?;
                relay::Relay::new(ctl, r, w).run().await
            } else {
                use tokio::net::TcpStream;
                let stream = TcpStream::connect(beacon_addr).await?;
                let _ = stream.set_nodelay(true);
                let (r, w) = tokio::io::split(stream);
                relay::Relay::new(ctl, r, w).run().await
            }
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

    info!("Connecting to beacon at {}", beacon_addr);

    let use_tls = args.encryption == "tls";
    if use_tls {
        let ca_pem = load_ca_pem(args.ca_cert.as_deref())?;
        let (r, w) = rscaller_proto::transport::tls::connect_tls(
            beacon_addr,
            "rsbeacon",
            &ca_pem,
        )
        .await?;
        relay::Relay::new(ctl, r, w).run().await
    } else {
        use tokio::net::TcpStream;
        let stream = TcpStream::connect(beacon_addr).await?;
        let _ = stream.set_nodelay(true);
        let (r, w) = tokio::io::split(stream);
        relay::Relay::new(ctl, r, w).run().await
    }
}
