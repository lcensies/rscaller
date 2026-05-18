use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;

mod executor;
mod server;

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

    #[arg(long, default_value = "tls", help = "Encryption: none|tls")]
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
}

#[tokio::main]
async fn main() -> Result<()> {
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

    match args.transport.as_str() {
        "tcp" => {
            let addr: SocketAddr = args.listen.parse()?;
            if use_tls {
                server::run_tls(addr, cert_pem, key_pem).await
            } else {
                server::run_plain(addr).await
            }
        }
        "uds" => {
            let path = args
                .uds_path
                .as_deref()
                .unwrap_or("/tmp/rsbeacon.sock");
            server::run_uds(path, use_tls, cert_pem, key_pem).await
        }
        other => anyhow::bail!("Unknown transport: {}", other),
    }
}
