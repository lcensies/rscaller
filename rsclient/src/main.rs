use anyhow::Result;
use clap::Parser;
use memmap2::MmapOptions;
use std::fs::OpenOptions;
use tracing::{info, warn};

mod kmod;
mod relay;

#[derive(Parser)]
#[command(name = "rsclient", about = "rscaller userspace relay client")]
struct Args {
    /// Address of rsbeacon
    #[arg(long, default_value = "127.0.0.1:9999")]
    beacon: String,

    /// Target name written to kmod via TARGET command
    #[arg(long)]
    name: Option<String>,

    /// Transport: tcp|uds
    #[arg(long, default_value = "tcp")]
    transport: String,

    /// Encryption: none|tls
    #[arg(long, default_value = "tls")]
    encryption: String,

    /// Path to CA cert PEM for TLS verification
    #[arg(long)]
    ca_cert: Option<String>,

    /// Path to rscaller proc device
    #[arg(long, default_value = "/proc/rscaller")]
    proc_path: String,
}

/// Default CA cert location for TLS when --ca-cert is not specified.
fn default_ca_cert_path() -> std::path::PathBuf {
    let mut p = dirs::config_dir().unwrap_or_else(|| std::path::PathBuf::from("~/.config"));
    p.push("rscaller/ca.pem");
    p
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

    // Send TARGET keepalive if --name provided.
    if let Some(ref name) = args.name {
        let msg = format!("TARGET {}\n", name);
        std::io::Write::write_all(&mut proc_file, msg.as_bytes())?;
        info!("Set target name: {}", name);
    }

    // Resolve beacon address (supports both IP:port and hostname:port).
    let beacon_addr = tokio::net::lookup_host(&args.beacon)
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve beacon address: {}", args.beacon))?;

    let use_tls = args.encryption == "tls";

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

        let result = if use_tls {
            // Load CA cert from --ca-cert or ~/.config/rscaller/ca.pem.
            let ca_pem = if let Some(ref path) = args.ca_cert {
                std::fs::read(path)?
            } else {
                let default = default_ca_cert_path();
                std::fs::read(&default).map_err(|e| {
                    anyhow::anyhow!(
                        "TLS requires a CA cert: pass --ca-cert or place it at {}: {}",
                        default.display(),
                        e
                    )
                })?
            };
            match rscaller_proto::transport::tls::connect_tls(beacon_addr, "rsbeacon", &ca_pem)
                .await
            {
                Ok((reader, writer)) => {
                    let mut relay = relay::Relay::new(relay_mmap, relay_file, reader, writer);
                    relay.run().await
                }
                Err(e) => Err(e),
            }
        } else {
            use tokio::net::TcpStream;
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
