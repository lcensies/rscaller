use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;

mod executor;
mod server;

#[derive(Parser)]
#[command(name = "rsbeacon", about = "Remote syscall execution beacon")]
struct Args {
    /// Address to listen on
    #[arg(long, default_value = "0.0.0.0:9999")]
    listen: String,

    /// Enable TLS mode
    #[arg(long)]
    tls: bool,

    /// Path to TLS certificate (PEM) — required if --tls
    #[arg(long)]
    tls_cert: Option<String>,

    /// Path to TLS private key (PEM) — required if --tls
    #[arg(long)]
    tls_key: Option<String>,

    /// Maximum concurrent connections (informational; not enforced yet)
    #[arg(long, default_value = "10")]
    max_connections: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("rsbeacon=warn".parse()?),
        )
        .init();

    let args = Args::parse();
    let addr: SocketAddr = args.listen.parse()?;

    if args.tls {
        let cert_path = args
            .tls_cert
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--tls-cert required with --tls"))?;
        let key_path = args
            .tls_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--tls-key required with --tls"))?;
        let cert_pem = std::fs::read(cert_path)?;
        let key_pem = std::fs::read(key_path)?;
        server::run_tls(addr, cert_pem, key_pem).await
    } else {
        server::run_plain(addr).await
    }
}
