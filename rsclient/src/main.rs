use anyhow::Result;
use clap::Parser;
use memmap2::MmapOptions;
use std::fs::OpenOptions;
use tokio::net::TcpStream;
use tracing::{info, warn};

mod kmod;
mod relay;

#[derive(Parser)]
#[command(name = "rsclient", about = "rscaller userspace relay client")]
struct Args {
    /// Address of rsbeacon
    #[arg(long, default_value = "127.0.0.1:9999")]
    beacon: String,

    /// Enable TLS for beacon connection
    #[arg(long)]
    tls: bool,

    /// CA cert for TLS verification (PEM)
    #[arg(long)]
    ca_cert: Option<String>,

    /// Path to rscaller proc device
    #[arg(long, default_value = "/proc/rscaller")]
    proc_path: String,

    /// Target name written to kmod via TARGET command (used for /rsc/<name>/ path routing)
    #[arg(long)]
    name: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("rsclient=debug".parse()?),
        )
        .init();

    let args = Args::parse();

    // Open /proc/rscaller once — keeps rsclient_active=1 for the kmod.
    info!("Opening {}", args.proc_path);
    let mut proc_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&args.proc_path)?;

    // Notify kmod of the target name for /rsc/<name>/ path routing.
    if let Some(ref name) = args.name {
        use std::io::Write as _;
        let msg = format!("TARGET {}\n", name);
        proc_file.write_all(msg.as_bytes())?;
        info!("Set target name: {}", name);
    }

    // Resolve beacon address (supports both IP:port and hostname:port).
    let beacon_addr = tokio::net::lookup_host(&args.beacon)
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve beacon address: {}", args.beacon))?;

    loop {
        info!("Connecting to beacon at {}", beacon_addr);

        // Each relay iteration gets its own dup of the fd and a fresh mmap.
        // Closing the relay's fd won't trigger kmod release() as long as the
        // original proc_file remains open.
        let relay_file = proc_file.try_clone()?;
        let relay_mmap = unsafe {
            MmapOptions::new()
                .len(std::mem::size_of::<kmod::ControlBuffer>())
                .map_mut(&relay_file)?
        };

        let result = if args.tls {
            let ca_path = args
                .ca_cert
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--ca-cert required with --tls"))?;
            let ca_pem = std::fs::read(ca_path)?;
            match rscaller_proto::transport::tls::connect_tls(beacon_addr, "rsbeacon", &ca_pem).await {
                Ok((reader, writer)) => {
                    let mut relay = relay::Relay::new(relay_mmap, relay_file, reader, writer);
                    relay.run().await
                }
                Err(e) => Err(e),
            }
        } else {
            match TcpStream::connect(beacon_addr).await {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    let (reader, writer) = tokio::io::split(stream);
                    let mut relay = relay::Relay::new(relay_mmap, relay_file, reader, writer);
                    relay.run().await
                }
                Err(e) => Err(e.into()),
            }
        };

        warn!("Relay ended: {:?} — reconnecting in 1s", result);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

