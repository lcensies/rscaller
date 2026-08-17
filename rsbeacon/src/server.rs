use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use rscaller_proto::codec::{read_message, write_message};
use rscaller_proto::types::SyscallRequest;

use crate::executor::execute_syscall;
use crate::net_backend::NetBackend;

pub async fn run_plain(addr: SocketAddr, backend: Arc<dyn NetBackend>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("rsbeacon listening (plain TCP) on {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        info!("Connection from {}", peer);
        let _ = stream.set_nodelay(true);
        let backend = backend.clone();
        tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(stream);
            if let Err(e) = handle_connection(&mut reader, &mut writer, &*backend).await {
                warn!("Connection error from {}: {}", peer, e);
            }
        });
    }
}

pub async fn run_tls(
    addr: SocketAddr,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    backend: Arc<dyn NetBackend>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("rsbeacon listening (TLS) on {}", addr);

    loop {
        let (tcp_stream, peer) = listener.accept().await?;
        info!("TLS connection from {}", peer);
        let cert_pem = cert_pem.clone();
        let key_pem = key_pem.clone();
        let backend = backend.clone();
        tokio::spawn(async move {
            match rscaller_proto::transport::tls::accept_tls(tcp_stream, &cert_pem, &key_pem).await
            {
                Ok(tls_stream) => {
                    let (mut reader, mut writer) = tokio::io::split(tls_stream);
                    if let Err(e) = handle_connection(&mut reader, &mut writer, &*backend).await {
                        warn!("TLS connection error from {}: {}", peer, e);
                    }
                }
                Err(e) => error!("TLS handshake failed from {}: {}", peer, e),
            }
        });
    }
}

pub async fn run_uds(path: &str, backend: Arc<dyn NetBackend>) -> Result<()> {
    use tokio::net::UnixListener;

    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    info!("rsbeacon listening (UDS) on {}", path);

    loop {
        let (stream, _) = listener.accept().await?;
        let backend = backend.clone();
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(stream);
            if let Err(e) = handle_connection(&mut r, &mut w, &*backend).await {
                warn!("UDS connection error: {}", e);
            }
        });
    }
}

async fn handle_connection<R, W>(reader: &mut R, writer: &mut W, backend: &dyn NetBackend) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let req: SyscallRequest = match read_message(reader).await {
            Ok(r) => r,
            Err(e) => {
                let msg = e.to_string().to_lowercase();
                // EOF is normal: client disconnected cleanly
                if msg.contains("eof") || msg.contains("unexpectedeof") {
                    return Ok(());
                }
                return Err(e);
            }
        };

        tracing::info!("XDP_DIAG: req nr={} args={:?}", req.number, req.args);
        let resp = execute_syscall(&req, backend);
        tracing::info!("XDP_DIAG: resp ret={}", resp.ret);
        write_message(writer, &resp).await?;
    }
}
