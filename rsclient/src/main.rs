use anyhow::Result;
use clap::Parser;
use memmap2::MmapOptions;
use std::fs::OpenOptions;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tracing::info;

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

    // Open /proc/rscaller for both mmap (read) and write (DONE signals).
    info!("Opening {}", args.proc_path);
    let proc_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&args.proc_path)?;

    let mmap = unsafe {
        MmapOptions::new()
            .len(std::mem::size_of::<kmod::ControlBuffer>())
            .map_mut(&proc_file)?
    };

    // Connect to beacon.
    let beacon_addr: SocketAddr = args.beacon.parse()?;
    info!("Connecting to beacon at {}", beacon_addr);

    if args.tls {
        let ca_path = args
            .ca_cert
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--ca-cert required with --tls"))?;
        let ca_pem = std::fs::read(ca_path)?;

        let (reader, writer) =
            rscaller_proto::transport::tls::connect_tls(beacon_addr, "rsbeacon", &ca_pem).await?;

        let write_file = OpenOptions::new()
            .write(true)
            .open(&args.proc_path)?;
        let mut relay = relay::Relay::new(mmap, write_file, reader, writer);
        relay.run().await
    } else {
        let stream = TcpStream::connect(beacon_addr).await?;
        let (reader, writer) = tokio::io::split(stream);

        let write_file = OpenOptions::new()
            .write(true)
            .open(&args.proc_path)?;
        let mut relay = relay::Relay::new(mmap, write_file, reader, writer);
        relay.run().await
    }
}
