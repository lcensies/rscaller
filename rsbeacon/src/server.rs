use anyhow::Result;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use rscaller_proto::codec::{read_message, write_message};
use rscaller_proto::types::SyscallRequest;

use crate::executor::execute_syscall;

pub async fn run_plain(addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("rsbeacon listening (plain TCP) on {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        info!("Connection from {}", peer);
        let _ = stream.set_nodelay(true);
        tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(stream);
            if let Err(e) = handle_connection(&mut reader, &mut writer).await {
                warn!("Connection error from {}: {}", peer, e);
            }
        });
    }
}

pub async fn run_tls(addr: SocketAddr, cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("rsbeacon listening (TLS) on {}", addr);

    loop {
        let (tcp_stream, peer) = listener.accept().await?;
        info!("TLS connection from {}", peer);
        let cert_pem = cert_pem.clone();
        let key_pem = key_pem.clone();
        tokio::spawn(async move {
            match rscaller_proto::transport::tls::accept_tls(tcp_stream, &cert_pem, &key_pem).await
            {
                Ok(tls_stream) => {
                    let (mut reader, mut writer) = tokio::io::split(tls_stream);
                    if let Err(e) = handle_connection(&mut reader, &mut writer).await {
                        warn!("TLS connection error from {}: {}", peer, e);
                    }
                }
                Err(e) => error!("TLS handshake failed from {}: {}", peer, e),
            }
        });
    }
}

pub async fn run_uds(
    path: &str,
    _use_tls: bool, // UDS+TLS is unusual; always run plain for UDS
    _cert_pem: Vec<u8>,
    _key_pem: Vec<u8>,
) -> Result<()> {
    use tokio::net::UnixListener;

    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    info!("rsbeacon listening (UDS) on {}", path);

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(stream);
            if let Err(e) = handle_connection(&mut r, &mut w).await {
                warn!("UDS connection error: {}", e);
            }
        });
    }
}

async fn handle_connection<R, W>(reader: &mut R, writer: &mut W) -> Result<()>
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

        let resp = execute_syscall(&req);
        write_message(writer, &resp).await?;
    }
}
